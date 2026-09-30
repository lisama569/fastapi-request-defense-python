"""FastAPI 应用装配：把防护层挂到各个 HTTP 入口（含带正文入口）。

统一保护口径（GET 读入口与 POST/PUT/PATCH 写入口完全一致）：
- 所有非豁免入口先过**来源额度预检**（限流 429，被拒不接收正文、不执行业务），
  再过特征规则与审计；带正文请求的正文计量/内容结论使用同一套 Reason 与审计结构；
- 放行时业务侧拿到的是客户端原始正文：正文被完整接收到有界缓冲（小正文驻留
  内存、超出检查上限的部分假脱机临时文件），放行时按原 ASGI 分片边界重放，
  防护层不提前消费、不截断、不改写长度与内容类型。

有界的内容检查与接收（policy.BodyPolicy）——**结论与送达方式无关**：
- 防护层先把正文完整接收再分类，整包 / 分多片 / 无 Content-Length 流式得到
  的结论严格一致；
- inspect_limit：内容规则匹配范围上限；正文总长度超过它 =>
  content_inspection_incomplete（默认 403，“太大无法完成内容判定”，
  fail-closed；检查范围之后的内容不会被当成“已检查、没问题”而绕过）；
- receive_limit：接收上限，超过 => body_too_large（413，“太大不接受”），
  在接收阶段、进入业务之前判定（含无 Content-Length 的分块流），不向业务透传；
- 在途名额信号量限制并发大正文的驻留总量；receive 超时 => body_receive_timeout。

运行时策略变更（不重启）：
- GET/PUT /admin/policy：整体校验 + 原子替换 + 版本单调，与规则集同一语义；
- 接收途中每收到一个分片即刷新策略快照，运行时调整两档上限对**在途的分段
  请求**也完整生效，不会一半旧一半新；响应/审计中的 policy_version 即最终
  分类实际使用的版本。
"""

from __future__ import annotations

import logging
from typing import Any

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field

from .auth import AuthError, authenticate, mask_token
from .bodyguard import (
    BODY_METHODS,
    BodyReceiveTimeout,
    BodyTooLarge,
    make_replay_receive,
    prefetch_body,
)
from .config import DefenseConfig
from .engine import DefenseEngine
from .policy import (
    MAX_INSPECT_LIMIT,
    MAX_RECEIVE_LIMIT,
    BodyPolicy,
    PolicyStore,
    PolicyValidationError,
)
from .ratelimiter import SlidingWindowRateLimiter
from .store import RuleStore, RuleSetValidationError
from .types import (
    Decision,
    Reason,
    RequestFeatures,
    RuleConfig,
    RuleEffect,
)

logger = logging.getLogger("request_defense")

# 不经过防护判定的路径
_EXEMPT_EXACT = frozenset({"/healthz", "/docs", "/openapi.json", "/redoc"})
_ADMIN_PREFIX = "/admin"

# 决策 -> HTTP 状态码（规则/限流类）
_STATUS_MAP = {
    Decision.ALLOW: 200,
    Decision.RATE_LIMITED: 429,
    Decision.DENY: 403,
}
# 正文阶段各原因 -> HTTP 状态码（与原因码同样可区分）
_BODY_STATUS_MAP = {
    Reason.BODY_TOO_LARGE: 413,
    Reason.CONTENT_INSPECTION_INCOMPLETE: 403,
    Reason.BODY_RECEIVE_TIMEOUT: 408,
    Reason.BODY_CONCURRENCY_LIMITED: 503,
}
# 引擎自身故障（区别于规则故障）使用 5xx
_SERVER_FAULT_REASONS = frozenset({Reason.ENGINE_INTERNAL_ERROR})


class RuleIn(BaseModel):
    rule_id: str = Field(min_length=1, max_length=128)
    priority: int = Field(ge=0)
    effect: RuleEffect
    field_name: str = Field(min_length=1, max_length=140)
    pattern: str = Field(min_length=1, max_length=2048)
    enabled: bool = True


class RuleSetIn(BaseModel):
    rules: list[RuleIn] = Field(min_length=1)


class PolicyIn(BaseModel):
    inspect_limit: int = Field(ge=1, le=MAX_INSPECT_LIMIT)
    receive_limit: int = Field(ge=1, le=MAX_RECEIVE_LIMIT)
    content_check_enabled: bool = True


def _error_body(code: str, message: str, **extra: Any) -> dict[str, Any]:
    body: dict[str, Any] = {"error": code, "message": message}
    body.update(extra)
    return body


class _InflightGate:
    """带正文请求的有界在途名额（事件循环单线程内的即时计数器）。

    - 容量在应用装配时固定（不在运行时策略变更范围内）；
    - 中间件全部运行在同一个事件循环线程上，计数器无需加锁；
    - 只提供非阻塞申请：满员立即背压（503），不排队、不堆积请求。
    """

    def __init__(self, cap: int) -> None:
        if cap <= 0:
            raise ValueError("body_inflight_cap must be positive")
        self._cap = cap
        self._in_use = 0

    def try_acquire(self) -> bool:
        if self._in_use >= self._cap:
            return False
        self._in_use += 1
        return True

    def release(self) -> None:
        if self._in_use > 0:
            self._in_use -= 1


def _client_source(scope_headers: list[tuple[bytes, bytes]], client: Any) -> str:
    """来源标识：优先 X-Forwarded-For 首段，其次 client.host。"""
    for k, v in scope_headers:
        if k == b"x-forwarded-for":
            first = v.decode("latin-1").split(",", 1)[0].strip()
            if first:
                return first
    return client[0] if client else "unknown"


def _headers_dict(scope_headers: list[tuple[bytes, bytes]]) -> dict[str, str]:
    return {k.decode("latin-1"): v.decode("latin-1") for k, v in scope_headers}


def _query_dict(scope: dict) -> dict[str, str]:
    # 取每个查询键的第一个值，与旧实现 dict(request.query_params) 口径一致
    from urllib.parse import parse_qsl

    raw = scope.get("query_string", b"").decode("latin-1")
    return dict(parse_qsl(raw, keep_blank_values=True))


def create_app(config: DefenseConfig | None = None) -> FastAPI:
    config = config or DefenseConfig.from_env()
    app = FastAPI(title="request-defense", version="0.2.0")

    rate_limiter = SlidingWindowRateLimiter(config.rate_limit, config.window_ms)
    rule_store = RuleStore(max_rules=config.max_rules)
    # 初始策略必须合法；不合法属于装配期编程错误，直接抛出
    initial_policy = BodyPolicy.validated(
        config.body_inspect_limit,
        config.body_receive_limit,
        config.body_inspect_enabled,
    )
    policy_store = PolicyStore(initial_policy)
    # 预置默认规则集，保证服务开箱即有确定行为（可被整体替换）
    rule_store.replace_rules(
        [
            RuleConfig(
                rule_id="block-secret-area",
                priority=100,
                effect=RuleEffect.DENY,
                field_name="path",
                pattern=r"^/secret-area/",
            )
        ]
    )
    engine = DefenseEngine(
        rate_limiter,
        rule_store,
        max_rules=config.max_rules,
        request_timeout_ms=config.request_timeout_ms,
        fail_open=config.fail_open,
    )
    inflight = _InflightGate(config.body_inflight_cap)
    app.state.config = config
    app.state.engine = engine
    app.state.rate_limiter = rate_limiter
    app.state.rule_store = rule_store
    app.state.policy_store = policy_store

    # ------------------------- 纯 ASGI 防护中间件 ------------------------- #
    async def _send_json(send, status_code: int, payload: dict[str, Any]) -> None:
        body = JSONResponse(status_code=status_code, content=payload).body
        await send({"type": "http.response.start", "status": status_code,
                    "headers": [(b"content-type", b"application/json"),
                                (b"content-length", str(len(body)).encode())]})
        await send({"type": "http.response.body", "body": body})

    def _deny_status(outcome) -> int:
        reason = outcome.reason
        if reason in _SERVER_FAULT_REASONS:
            return 500
        if reason in _BODY_STATUS_MAP:
            return _BODY_STATUS_MAP[reason]
        return _STATUS_MAP.get(outcome.decision, 403)

    # 纯 ASGI 防护中间件（在函数末尾构建好默认栈后替换 app.middleware_stack）：
    # 必须在 ASGI 层包装 receive，BaseHTTPMiddleware 无法保证正文原样到达下游。
    async def defense_asgi_app(scope, receive, send):
        if scope["type"] != "http":
            await app_default(scope, receive, send)
            return
        path = scope.get("path", "")
        if path in _EXEMPT_EXACT or path.startswith(_ADMIN_PREFIX):
            await app_default(scope, receive, send)
            return

        headers_raw: list[tuple[bytes, bytes]] = scope.get("headers", [])
        source = _client_source(headers_raw, scope.get("client"))
        headers = _headers_dict(headers_raw)
        method = scope.get("method", "GET").upper()
        query = _query_dict(scope)
        # 进入防护即固定本次请求的策略快照；规则快照由引擎在判定时同次读取，
        # 结论中的 rule_version / policy_version 即本次请求实际使用的版本。
        policy_version, policy = policy_store.snapshot()

        def features_from(summary: str) -> RequestFeatures:
            return RequestFeatures(
                source=source, path=path, method=method,
                headers=headers, query=query, body_summary=summary,
            )

        async def deny(outcome) -> None:
            status = _deny_status(outcome)
            payload = {
                "error": outcome.reason.value,
                "message": outcome.detail,
                "decision": outcome.decision.value,
                "rule_version": outcome.rule_version,
                "policy_version": outcome.policy_version,
                "elapsed_ms": round(outcome.elapsed_ms, 3),
            }
            await _send_json(send, status, payload)

        # 1) 来源额度预检（任何方法一致）：被拒不读正文、不进业务
        try:
            pre = engine.precheck_rate_limit(
                features_from(""), policy_version=policy_version
            )
        except Exception:  # noqa: BLE001 - 装配外意外统一 500，不泄漏内部细节
            logger.exception("defense precheck failure")
            await _send_json(send, 500, _error_body(
                Reason.ENGINE_INTERNAL_ERROR.value, "internal defense failure"))
            return
        if pre is not None:
            await deny(pre)
            return

        # 2) 无正文/非带正文方法：沿用特征判定（不触碰 receive，GET 等不受影响）
        if method not in BODY_METHODS:
            try:
                outcome = engine.evaluate_rules(features_from(""))
            except Exception:  # noqa: BLE001
                logger.exception("defense rule evaluation failure")
                await _send_json(send, 500, _error_body(
                    Reason.ENGINE_INTERNAL_ERROR.value, "internal defense failure"))
                return
            if outcome.decision is not Decision.ALLOW:
                await deny(outcome)
                return
            await app_default(scope, receive, send)
            return

        # 3) 带正文入口：申请在途名额（并发缓冲有界背压）
        if not inflight.try_acquire():
            outcome = engine.deny_body_stage(
                features_from(""),
                Reason.BODY_CONCURRENCY_LIMITED,
                f"inflight body capacity {config.body_inflight_cap} saturated",
                policy_version=policy_version,
            )
            await deny(outcome)
            return

        slot_held = True

        def release_slot() -> None:
            nonlocal slot_held
            if slot_held:
                slot_held = False
                inflight.release()

        try:
            try:
                # 完整、有界地接收正文后再下结论：结论与送达方式（整包/分片/
                # 有无 Content-Length）无关；接收途中每次分片都刷新策略快照，
                # 运行时调整的上限对在途的分段请求完整生效。
                prefetch = await prefetch_body(
                    scope_headers=headers_raw,
                    receive=receive,
                    policy=policy,
                    receive_timeout_ms=config.body_receive_timeout_ms,
                    policy_provider=policy_store.snapshot,
                    # 单请求驻留内存 ≤ 检查上限：放行的小正文留内存（快路径），
                    # 超过检查上限的部分假脱机临时文件，最坏驻留 ≈ inflight×inspect。
                    spool_threshold=policy.inspect_limit,
                )
            except BodyTooLarge as exc:
                outcome = engine.deny_body_stage(
                    features_from(""),
                    Reason.BODY_TOO_LARGE,
                    f"declared/chunked body {exc.received} exceeds receive_limit {exc.limit}",
                    policy_version=exc.policy_version or policy_version,
                    body_meta={"declared": exc.received, "receive_limit": exc.limit},
                )
                await deny(outcome)
                return
            except BodyReceiveTimeout as exc:
                outcome = engine.deny_body_stage(
                    features_from(""),
                    Reason.BODY_RECEIVE_TIMEOUT,
                    str(exc),
                    policy_version=policy_version,
                )
                await deny(outcome)
                return

            # 整次正文接收使用的最终策略快照（在途策略变更后可能不同于入口版本）：
            # prefetch 按每个分片后的最新策略计量与分类，返回的 policy_version
            # 即分类时使用的版本。此处到规则判定之间没有 await，再取一次快照
            # 必然与 prefetch 完成时一致；body_meta / 审计都以它为准，
            # 杜绝一半旧一半新。
            final_version = prefetch.policy_version
            _, final_policy = policy_store.snapshot()

            summary = prefetch.inspected.decode("utf-8", "replace")
            body_meta = {
                "content_length": prefetch.content_length,
                "content_type": prefetch.content_type,
                "inspected_bytes": len(prefetch.inspected),
                "exceeds_inspect_limit": prefetch.exceeds_inspect,
                "total_bytes": prefetch.total_seen,
                "inspect_limit": final_policy.inspect_limit,
                "receive_limit": final_policy.receive_limit,
            }

            # 4) 超过检查上限：默认 fail-closed（不猜测未检查部分）。
            #    正文已完整接收，整包与分片在此结论完全一致。
            if final_policy.content_check_enabled and prefetch.exceeds_inspect:
                try:
                    outcome = engine.deny_body_stage(
                        features_from(summary),
                        Reason.CONTENT_INSPECTION_INCOMPLETE,
                        f"body exceeds inspect_limit {final_policy.inspect_limit}; "
                        "content verdict cannot be completed",
                        policy_version=final_version,
                        body_meta=body_meta,
                    )
                    await deny(outcome)
                finally:
                    prefetch.close()
                return

            # 5) 内容判定（开关关闭时 body 规则整体不参与）+ 其余特征规则
            try:
                outcome = engine.evaluate_rules(
                    features_from(summary),
                    policy_version=final_version,
                    body_meta=body_meta,
                    body_rule_scoped=not final_policy.content_check_enabled,
                )
                if outcome.decision is not Decision.ALLOW:
                    await deny(outcome)
                    return

                # 6) 放行：从假脱机按原 ASGI 事件边界重放完整正文，
                #    业务读到与客户端发送逐字节一致的原始正文（长度/类型不变）。
                replay = make_replay_receive(
                    receive, prefetch.spool, prefetch.terminal_event
                )
                await app_default(scope, replay, send)
            finally:
                prefetch.close()
        except Exception:  # noqa: BLE001 - 预取/判定/下游阶段的意外统一 500
            logger.exception("defense body-stage failure")
            await _send_json(send, 500, _error_body(
                Reason.ENGINE_INTERNAL_ERROR.value, "internal defense failure"))
        finally:
            release_slot()

    # ------------------------- 业务入口（示例） ------------------------- #
    @app.get("/api/echo")
    async def echo(request: Request) -> dict[str, str]:
        return {"path": request.url.path, "status": "served"}

    @app.post("/api/submit/json")
    async def submit_json(request: Request) -> dict[str, Any]:
        # 直接读取防护层重放的原始正文，再由业务侧自行解析（不改协议）
        raw = await request.body()
        import json as _json
        payload = _json.loads(raw.decode("utf-8"))
        return {
            "received_bytes": len(raw),
            "content_type": request.headers.get("content-type", ""),
            "payload": payload,
        }

    @app.api_route("/api/submit/form", methods=["POST", "PUT", "PATCH"])
    async def submit_form(request: Request) -> dict[str, Any]:
        form = await request.form()
        fields: dict[str, Any] = {}
        for k, v in form.multi_items():
            if hasattr(v, "filename"):  # UploadFile：只回显文件名/类型/大小
                content = await v.read()
                fields[k] = {
                    "filename": v.filename,
                    "content_type": v.content_type,
                    "size": len(content),
                }
            else:
                fields[k] = v
        return {
            "received_bytes": int(request.headers.get("content-length", "-1")),
            "content_type": request.headers.get("content-type", ""),
            "fields": fields,
        }

    @app.api_route("/api/upload/raw", methods=["POST", "PUT", "PATCH"])
    async def upload_raw(request: Request) -> dict[str, Any]:
        raw = await request.body()
        import base64
        return {
            "received_bytes": len(raw),
            "content_type": request.headers.get("content-type", ""),
            "body_b64": base64.b64encode(raw).decode("ascii"),
        }

    @app.get("/healthz")
    async def healthz() -> dict[str, str]:
        return {"status": "ok"}

    # 带副作用的业务入口：仅用于自动化断言“被限流/拒绝时业务入口不会被执行”
    @app.api_route("/api/side-effect", methods=["GET", "POST", "PUT", "PATCH"])
    async def side_effect(request: Request):
        app.state.business_called = getattr(app.state, "business_called", 0) + 1
        raw = await request.body()
        return {
            "called": app.state.business_called,
            "received_bytes": len(raw),
            "content_type": request.headers.get("content-type", ""),
        }

    # ------------------------- 管理接口 ------------------------- #
    def require_admin(request: Request) -> JSONResponse | None:
        try:
            authenticate(request.headers.get("authorization"), config.admin_token)
        except AuthError:
            presented = request.headers.get("authorization", "")
            token = presented.removeprefix("Bearer ").strip() if presented.startswith("Bearer ") else ""
            logger.warning(
                "admin auth failed source=%s token=%s path=%s",
                request.client.host if request.client else "unknown",
                mask_token(token),
                request.url.path,
            )
            return JSONResponse(
                status_code=401,
                content=_error_body("unauthorized", "unauthorized"),
            )
        return None

    @app.get(f"{_ADMIN_PREFIX}/rules")
    async def get_rules(request: Request):
        denied = require_admin(request)
        if denied is not None:
            return denied
        version, rules = rule_store.snapshot()
        return {
            "version": version,
            "rules": [
                {
                    "rule_id": r.config.rule_id,
                    "priority": r.config.priority,
                    "effect": r.config.effect.value,
                    "field_name": r.config.field_name,
                    "pattern": r.config.pattern,
                    "enabled": r.config.enabled,
                }
                for r in rules
            ],
        }

    @app.put(f"{_ADMIN_PREFIX}/rules")
    async def put_rules(payload: RuleSetIn, request: Request):
        denied = require_admin(request)
        if denied is not None:
            return denied
        configs = [
            RuleConfig(
                rule_id=item.rule_id,
                priority=item.priority,
                effect=item.effect,
                field_name=item.field_name,
                pattern=item.pattern,
                enabled=item.enabled,
            )
            for item in payload.rules
        ]
        try:
            version = rule_store.replace_rules(configs)
        except RuleSetValidationError as exc:
            logger.warning("rule set rejected: %s (index=%s)", exc, exc.index)
            return JSONResponse(
                status_code=422,
                content=_error_body(
                    "invalid_rule_set",
                    str(exc),
                    index=exc.index,
                    current_version=rule_store.snapshot()[0],
                ),
            )
        logger.info("rule set replaced atomically version=%s", version)
        return {"status": "ok", "version": version, "rule_count": len(payload.rules)}

    @app.get(f"{_ADMIN_PREFIX}/policy")
    async def get_policy(request: Request):
        denied = require_admin(request)
        if denied is not None:
            return denied
        version, policy = policy_store.snapshot()
        return {
            "version": version,
            "inspect_limit": policy.inspect_limit,
            "receive_limit": policy.receive_limit,
            "content_check_enabled": policy.content_check_enabled,
        }

    @app.put(f"{_ADMIN_PREFIX}/policy")
    async def put_policy(payload: PolicyIn, request: Request):
        denied = require_admin(request)
        if denied is not None:
            return denied
        current_version = policy_store.snapshot()[0]
        try:
            new_policy = BodyPolicy.validated(
                payload.inspect_limit,
                payload.receive_limit,
                payload.content_check_enabled,
            )
            version = policy_store.replace(new_policy)
        except PolicyValidationError as exc:
            logger.warning("policy rejected: %s (field=%s)", exc, exc.field)
            return JSONResponse(
                status_code=422,
                content=_error_body(
                    "invalid_policy",
                    str(exc),
                    field=exc.field,
                    current_version=current_version,
                ),
            )
        logger.info("body policy replaced atomically version=%s", version)
        return {
            "status": "ok",
            "version": version,
            "inspect_limit": new_policy.inspect_limit,
            "receive_limit": new_policy.receive_limit,
            "content_check_enabled": new_policy.content_check_enabled,
        }

    # BodyTooLarge 的纵深防御兜底：正常路径下接收上限在 prefetch 阶段即被
    # 拦截（见 defense_asgi_app），业务不会再触发它；此处仅在有代码绕过
    # prefetch 直接向下游 receive 抛 BodyTooLarge 时统一转成 413。
    # 必须在 build_middleware_stack 前注册（ExceptionMiddleware 构建时快照）。
    @app.exception_handler(BodyTooLarge)
    async def _body_too_large_handler(request: Request, exc: BodyTooLarge):
        return JSONResponse(
            status_code=413,
            content=_error_body(
                Reason.BODY_TOO_LARGE.value,
                f"received body {exc.received} exceeds receive_limit {exc.limit}",
                received=exc.received,
                receive_limit=exc.limit,
            ),
        )

    # 全部路由/处理器注册完毕后再构建默认栈；纯 ASGI 防护层在外层包装它，
    # 因此防护层可以替换 receive 而业务侧完全无感（不调用方改协议）。
    app_default = app.build_middleware_stack()
    app.middleware_stack = defense_asgi_app

    return app


def create_default_app() -> FastAPI:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )
    return create_app()


app = create_default_app()
