"""FastAPI 应用装配：把防护层挂到各个 HTTP 入口（含带正文入口）。

- GET 等读入口与 POST/PUT/PATCH 写入口统一经过纯 ASGI 防护中间件：
  来源限流(429) / 规则拒绝(403) / 正文容量与降级(413/422/408/503) /
  服务故障(500)，结论与原因在响应体、日志、审计中保持一致且可区分；
- 写入口在**限流通过后**有界接收正文（接收硬上限 / 检查上限 / 超时 / 并发容量），
  放行则把与客户端所发完全一致的正文原样回放给业务；任何拒绝都不触达业务；
- /admin/* 管理接口先过 Bearer 令牌校验，未授权一律 401 固定错误体，
  不泄漏任何内部状态（规则数、版本等）；
- 规则集与内容策略写入均为"整体校验 + 原子替换"，非法值返回 422 且旧版本继续生效，
  可在不重启的情况下调整检查上限、接收上限与内容判定开关；
- /healthz 等运维路径放行，便于存活探测（不消耗限流配额）。
"""

from __future__ import annotations

import hashlib
import json
import logging
from typing import Any
from urllib.parse import parse_qsl

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from python_multipart.multipart import FormParser, parse_options_header
from pydantic import BaseModel, Field

from .auth import AuthError, authenticate, mask_token
from .config import DefenseConfig
from .engine import DefenseEngine
from .middleware import DefenseASGIMiddleware
from .policy import ContentPolicy, ContentPolicyStore, ContentPolicyValidationError
from .ratelimiter import SlidingWindowRateLimiter
from .store import RuleStore, RuleSetValidationError
from .types import (
    RuleConfig,
    RuleEffect,
)

logger = logging.getLogger("request_defense")

# 不经过防护判定的路径
_EXEMPT_EXACT = frozenset({"/healthz", "/docs", "/openapi.json", "/redoc"})
_ADMIN_PREFIX = "/admin"
_MAX_BODY_SUMMARY_BYTES = 512


class RuleIn(BaseModel):
    rule_id: str = Field(min_length=1, max_length=128)
    priority: int = Field(ge=0)
    effect: RuleEffect
    field_name: str = Field(min_length=1, max_length=140)
    pattern: str = Field(min_length=1, max_length=2048)
    enabled: bool = True


class RuleSetIn(BaseModel):
    rules: list[RuleIn] = Field(min_length=1)


class ContentPolicyIn(BaseModel):
    inspect_limit_bytes: int = Field(gt=0)
    receive_limit_bytes: int = Field(gt=0)
    content_check_enabled: bool


def _error_body(code: str, message: str, **extra: Any) -> dict[str, Any]:
    body: dict[str, Any] = {"error": code, "message": message}
    body.update(extra)
    return body


def _client_source(request: Request) -> str:
    """来源标识：优先 X-Forwarded-For 首段，其次 client.host。"""
    xff = request.headers.get("x-forwarded-for")
    if xff:
        first = xff.split(",", 1)[0].strip()
        if first:
            return first
    return request.client.host if request.client else "unknown"


def _parse_form(raw: bytes, content_type: str) -> dict[str, str]:
    """解析 urlencoded 表单字段；multipart 仅返回普通字段（文件见 _parse_multipart_files）。"""
    ctype = content_type.lower()
    if ctype.startswith("application/x-www-form-urlencoded"):
        return {
            k: v for k, v in parse_qsl(raw.decode("utf-8"), keep_blank_values=True)
        }
    files, fields = _parse_multipart(raw, content_type)
    return fields


def _parse_multipart_files(raw: bytes, content_type: str) -> list[tuple[str, bytes]]:
    """从 multipart 正文中提取 (filename, bytes) 列表。"""
    files, _fields = _parse_multipart(raw, content_type)
    return files


def _parse_multipart(
    raw: bytes, content_type: str
) -> tuple[list[tuple[str, bytes]], dict[str, str]]:
    """用 python-multipart 解析一次性已读入的 multipart 正文。

    返回 (文件列表[(filename, bytes)], 普通字段{name: value})。
    业务侧仅读取一次原始正文后自行解析，防护层不参与解析过程。
    """
    _, options = parse_options_header(content_type.encode("latin-1"))
    boundary = options.get(b"boundary", b"")
    files: list[tuple[str, bytes]] = []
    fields: dict[str, str] = {}

    def on_field(field) -> None:
        name = (field.field_name or b"").decode("utf-8")
        fields[name] = field.value.decode("utf-8")

    def on_file(f) -> None:
        name = (f.field_name or b"").decode("utf-8")
        # 解析后文件已落内存 BytesIO，读取其完整字节
        f.file_object.seek(0)
        data = f.file_object.read()
        files.append(((f.file_name or name).decode("utf-8"), data))

    parser = FormParser(
        "multipart/form-data",
        on_field,
        on_file,
        boundary=boundary,
    )
    parser.write(raw)
    parser.finalize()
    return files, fields


def create_app(config: DefenseConfig | None = None) -> FastAPI:
    config = config or DefenseConfig.from_env()
    app = FastAPI(title="request-defense", version="0.1.0")

    rate_limiter = SlidingWindowRateLimiter(config.rate_limit, config.window_ms)
    rule_store = RuleStore(max_rules=config.max_rules)
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
    # 内容策略：启动默认值来自配置；运行时可经管理接口整体原子替换
    policy_store = ContentPolicyStore(
        ContentPolicy(
            inspect_limit_bytes=config.inspect_limit_bytes,
            receive_limit_bytes=config.receive_limit_bytes,
            content_check_enabled=config.content_check_enabled,
        )
    )
    app.state.config = config
    app.state.engine = engine
    app.state.rate_limiter = rate_limiter
    app.state.rule_store = rule_store
    app.state.policy_store = policy_store

    # 纯 ASGI 防护中间件：读入口与 POST/PUT/PATCH 走同一套来源额度、
    # 特征规则、内容接收策略与审计口径；放行后原样回放完整正文。
    app.add_middleware(
        DefenseASGIMiddleware,
        engine=engine,
        policy_store=policy_store,
        body_timeout_ms=config.body_timeout_ms,
        body_ingress_concurrency=config.body_ingress_concurrency,
        exempt_exact=_EXEMPT_EXACT,
        admin_prefix=_ADMIN_PREFIX,
        read_body_summary_bytes=_MAX_BODY_SUMMARY_BYTES,
    )

    # ------------------------- 业务入口（示例） ------------------------- #
    @app.get("/api/echo")
    async def echo(request: Request) -> dict[str, str]:
        return {"path": request.url.path, "status": "served"}

    @app.post("/api/submit/json")
    async def submit_json(request: Request) -> dict[str, Any]:
        """JSON 提交入口：防护层放行后业务侧自行解析，正文原样可达。"""
        raw = await request.body()
        parsed = json.loads(raw.decode("utf-8"))
        return {
            "status": "served",
            "content_type": request.headers.get("content-type", ""),
            "length": len(raw),
            "name": parsed.get("name"),
            "raw_sha256": hashlib.sha256(raw).hexdigest(),
        }

    @app.post("/api/submit/form")
    async def submit_form(request: Request) -> dict[str, Any]:
        """表单（urlencoded / multipart）提交入口：业务侧只读取一次原始正文再自行解析。"""
        raw = await request.body()
        ctype = request.headers.get("content-type", "")
        fields: dict[str, Any] = _parse_form(raw, ctype)
        return {
            "status": "served",
            "content_type": ctype,
            "length": len(raw),
            "fields": fields,
            "raw_sha256": hashlib.sha256(raw).hexdigest(),
        }

    @app.put("/api/upload/binary")
    async def upload_binary(request: Request) -> dict[str, Any]:
        """二进制上传入口：业务侧拿到与客户端所发完全一致的字节与内容类型。"""
        raw = await request.body()
        ctype = request.headers.get("content-type", "")
        files = _parse_multipart_files(raw, ctype)
        first = files[0] if files else None
        return {
            "status": "served",
            "content_type": ctype,
            "length": len(raw),
            "filename": first[0] if first else None,
            "file_length": len(first[1]) if first else 0,
            "file_sha256": (
                hashlib.sha256(first[1]).hexdigest() if first else None
            ),
            "raw_sha256": hashlib.sha256(raw).hexdigest(),
        }

    @app.patch("/api/submit/json")
    async def patch_json(request: Request) -> dict[str, Any]:
        """PATCH 与 POST 走同一套防护口径与正文回放。"""
        raw = await request.body()
        parsed = json.loads(raw.decode("utf-8"))
        return {
            "status": "served",
            "content_type": request.headers.get("content-type", ""),
            "length": len(raw),
            "name": parsed.get("name"),
            "raw_sha256": hashlib.sha256(raw).hexdigest(),
        }

    @app.get("/healthz")
    async def healthz() -> dict[str, str]:
        return {"status": "ok"}

    # ------------------------- 管理接口 ------------------------- #
    def require_admin(request: Request) -> JSONResponse | None:
        try:
            authenticate(request.headers.get("authorization"), config.admin_token)
        except AuthError:
            presented = request.headers.get("authorization", "")
            token = presented.removeprefix("Bearer ").strip() if presented.startswith("Bearer ") else ""
            # 审计只记录令牌短摘要，绝不记录完整凭据
            logger.warning(
                "admin auth failed source=%s token=%s path=%s",
                _client_source(request),
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
            logger.warning(
                "rule set rejected: %s (index=%s) source=%s",
                exc,
                exc.index,
                _client_source(request),
            )
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

    # --------------------- 运行时内容策略（无需重启） --------------------- #
    @app.get(f"{_ADMIN_PREFIX}/content-policy")
    async def get_content_policy(request: Request):
        denied = require_admin(request)
        if denied is not None:
            return denied
        version, policy = policy_store.snapshot()
        return {
            "version": version,
            "inspect_limit_bytes": policy.inspect_limit_bytes,
            "receive_limit_bytes": policy.receive_limit_bytes,
            "content_check_enabled": policy.content_check_enabled,
        }

    @app.put(f"{_ADMIN_PREFIX}/content-policy")
    async def put_content_policy(payload: ContentPolicyIn, request: Request):
        denied = require_admin(request)
        if denied is not None:
            return denied
        new_policy = ContentPolicy(
            inspect_limit_bytes=payload.inspect_limit_bytes,
            receive_limit_bytes=payload.receive_limit_bytes,
            content_check_enabled=payload.content_check_enabled,
        )
        try:
            version = policy_store.replace(new_policy)
        except ContentPolicyValidationError as exc:
            logger.warning(
                "content policy rejected: %s (field=%s) source=%s",
                exc,
                exc.field,
                _client_source(request),
            )
            current = policy_store.snapshot()[0]
            return JSONResponse(
                status_code=422,
                content=_error_body(
                    "invalid_content_policy",
                    str(exc),
                    field=exc.field,
                    current_version=current,
                ),
            )
        logger.info("content policy replaced atomically version=%s", version)
        return {
            "status": "ok",
            "version": version,
            "inspect_limit_bytes": new_policy.inspect_limit_bytes,
            "receive_limit_bytes": new_policy.receive_limit_bytes,
            "content_check_enabled": new_policy.content_check_enabled,
        }

    return app


def create_default_app() -> FastAPI:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )
    return create_app()


app = create_default_app()
