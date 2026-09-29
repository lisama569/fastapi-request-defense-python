"""统一防护 ASGI 中间件：读入口与带正文入口（POST/PUT/PATCH）同一套口径。

处理顺序（确定、可解释、可审计）：
  1. 豁免路径（/healthz 等）与 /admin/* 直接透传，不消耗来源配额；
  2. 抽取来源/路径/方法/头/查询，取规则快照与内容策略快照（之后整次处理
     只使用这两个固定版本，不存在新旧混用）；
  3. **来源限流先行**：被限流直接 429，绝不缓冲正文、不执行业务；
  4. POST/PUT/PATCH：有界接收正文（接收硬上限/检查上限/超时/并发容量），
     得到可区分的接收结论；其余方法沿用读请求路径；
  5. 内容判定：超出接收上限 -> 413；超过检查上限无法判定 -> 422；
     超时 -> 408；并发饱和 -> 503；这些早拒绝都不执行业务；
  6. 通过后按内容策略（是否启用内容判定）做规则组合判定；
     放行则把**与客户端所发完全一致**的正文回放给业务，正文/长度/内容
     类型不被消费、截断或改写；限流/任何拒绝都不触达业务入口。

中间件为纯 ASGI 实现：接收时直接消费原始 receive，放行时用回放 receive
替换，避免 BaseHTTPMiddleware 下流(stream) 后业务拿到空体的问题。
"""

from __future__ import annotations

import asyncio
import json
import logging
import time
from typing import Any, Awaitable, Callable

from . import ingress
from .engine import DefenseEngine
from .ingress import BodyStatus
from .policy import ContentPolicyStore
from .types import (
    Decision,
    Reason,
    RequestFeatures,
)

logger = logging.getLogger("request_defense")

Scope = dict[str, Any]
Message = dict[str, Any]
Receive = Callable[[], Awaitable[Message]]
Send = Callable[[Message], Awaitable[None]]
ASGIApp = Callable[[Scope, Receive, Send], Awaitable[None]]

BODY_METHODS = frozenset({"POST", "PUT", "PATCH"})

# 原因码 -> HTTP 状态（限流/规则结论之外，正文接收侧的可区分状态）
_INGRESS_STATUS = {
    Reason.BODY_TOO_LARGE: 413,
    Reason.BODY_INSPECTION_INCOMPLETE: 422,
    Reason.BODY_RECEIVE_TIMEOUT: 408,
    Reason.BODY_INGRESS_BUSY: 503,
}
_DECISION_STATUS = {
    Decision.RATE_LIMITED: 429,
    Decision.DENY: 403,
}


class DefenseASGIMiddleware:
    """把限流 + 特征规则 + 内容接收策略统一挂到所有受保护入口。"""

    def __init__(
        self,
        app: ASGIApp,
        engine: DefenseEngine,
        policy_store: ContentPolicyStore,
        *,
        body_timeout_ms: int,
        body_ingress_concurrency: int = 32,
        exempt_exact: frozenset[str] = frozenset(),
        admin_prefix: str = "/admin",
        read_body_summary_bytes: int = 512,
    ) -> None:
        self.app = app
        self._engine = engine
        self._policies = policy_store
        self._body_timeout_s = max(0.001, body_timeout_ms / 1000.0)
        self._exempt = exempt_exact
        self._admin_prefix = admin_prefix
        self._read_summary_bytes = read_body_summary_bytes
        if body_ingress_concurrency <= 0:
            raise ValueError("body_ingress_concurrency must be positive")
        self._slots = asyncio.Semaphore(body_ingress_concurrency)

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        path = scope.get("path", "")
        if path in self._exempt or path.startswith(self._admin_prefix):
            await self.app(scope, receive, send)
            return

        started = time.perf_counter_ns()
        headers = _flat_headers(scope.get("headers", []))
        source = _client_source(scope, headers)
        method = scope.get("method", "GET").upper()
        query = _query_params(scope.get("query_string", b""))
        policy_version, policy = self._policies.snapshot()

        def make_features(
            body_summary: str = "",
            body_length: int = 0,
            fully_inspected: bool = True,
        ) -> RequestFeatures:
            return RequestFeatures(
                source=source,
                path=path,
                method=method,
                headers=headers,
                query=query,
                body_summary=body_summary,
                body_length=body_length,
                body_fully_inspected=fully_inspected,
                content_policy_version=policy_version,
            )

        # 3) 来源限流先行：被限流不缓冲正文、不触达业务
        pre_features = make_features()
        limited = self._engine.reserve_quota(
            pre_features, policy_version=policy_version, started_ns=started
        )
        if limited is not None:
            await self._send_decision(send, limited)
            return
        # 配额已扣减；后续路径复用同一份限流信息口径
        rate_info = {"allowed": True}

        try:
            if method in BODY_METHODS:
                await self._handle_body(
                    scope, receive, send, started, headers, policy_version,
                    policy, make_features, rate_info,
                )
            else:
                await self._handle_read(
                    scope, receive, send, started, make_features, rate_info,
                )
        except Exception:  # noqa: BLE001 - 装配外意外统一 500，不泄漏内部细节
            logger.exception("defense middleware internal failure")
            await self._send_raw(
                send,
                500,
                {
                    "error": Reason.ENGINE_INTERNAL_ERROR.value,
                    "message": "internal defense failure",
                },
            )

    # ------------------------------------------------------------------ #
    # 读请求：沿用历史行为（body 仅取定长前缀，GET 一般无正文）
    # ------------------------------------------------------------------ #
    async def _handle_read(
        self, scope, receive, send, started, make_features, rate_info
    ) -> None:
        summary = ""
        body_length = 0
        # 读请求一般无正文；仅当声明带正文时才取定长前缀，
        # 避免无正文请求被提前消费 receive 而影响下游。
        declared = _declared_content_length(scope.get("headers", []))
        if declared and declared > 0:
            chunks: list[bytes] = []
            total = 0
            while total < self._read_summary_bytes:
                message = await receive()
                if message["type"] == "http.disconnect":
                    return
                chunk = message.get("body", b"") or b""
                if chunk:
                    room = self._read_summary_bytes - total
                    chunks.append(chunk[:room])
                    total += min(len(chunk), room)
                if not message.get("more_body", False):
                    break
            summary = b"".join(chunks)[: self._read_summary_bytes].decode(
                "utf-8", "replace"
            )
            body_length = total
        features = make_features(body_summary=summary, body_length=body_length)
        outcome = self._engine.decide_rules(
            features,
            rate_info=rate_info,
            content_check_enabled=True,
            started_ns=started,
        )
        if outcome.decision is Decision.ALLOW:
            await self.app(scope, receive, send)
            return
        await self._send_decision(send, outcome)

    # ------------------------------------------------------------------ #
    # 带正文请求：有界接收 -> 内容判定 -> 规则判定 -> 原样回放
    # ------------------------------------------------------------------ #
    async def _handle_body(
        self,
        scope,
        receive,
        send,
        started,
        headers,
        policy_version,
        policy,
        make_features,
        rate_info,
    ) -> None:
        slots = self._slots
        result = await ingress.receive_body(
            receive=receive,
            headers=headers,
            policy=policy,
            ingress_slots=slots,
            timeout_s=self._body_timeout_s,
        )

        # 客户端在接收正文期间断开：无响应对象可写，直接结束（不触达业务）
        if result.status is BodyStatus.DISCONNECTED:
            return

        # 4b) 接收侧硬拒绝：超过接收上限/超时/容量饱和，状态与原因可区分
        early = self._early_reject(result, make_features, rate_info, started)
        if early is not None:
            await self._send_decision(send, early)
            return

        buffered = result.body  # 非 None：ACCEPTED / INCOMPLETE
        assert buffered is not None
        try:
            # 超过检查上限、无法完成内容判定：默认 fail-closed。
            # 管理侧可通过关闭内容判定（content_check_enabled=False）显式放行此类正文。
            if (
                result.status is BodyStatus.INCOMPLETE
                and policy.content_check_enabled
            ):
                features = make_features(
                    body_summary=buffered.inspect_text(),
                    body_length=buffered.length,
                    fully_inspected=False,
                )
                outcome = self._engine.reject_ingress(
                    features,
                    Reason.BODY_INSPECTION_INCOMPLETE,
                    result.detail,
                    rate_info=rate_info,
                    started_ns=started,
                )
                await self._send_decision(send, outcome)
                return

            # 仅在启用内容判定时，把检查前缀交给规则；否则正文仍完整转发
            summary = buffered.inspect_text() if policy.content_check_enabled else ""
            features = make_features(
                body_summary=summary,
                body_length=buffered.length,
                fully_inspected=result.status is BodyStatus.ACCEPTED,
            )
            outcome = self._engine.decide_rules(
                features,
                rate_info=rate_info,
                content_check_enabled=policy.content_check_enabled,
                started_ns=started,
            )
            if outcome.decision is not Decision.ALLOW:
                await self._send_decision(send, outcome)
                return
            # 6) 放行：原样回放完整正文，长度/内容类型/字节均不改变
            await self.app(scope, buffered.receive, send)
        finally:
            buffered.close()

    def _early_reject(self, result, make_features, rate_info, started):
        mapping = {
            BodyStatus.TOO_LARGE: Reason.BODY_TOO_LARGE,
            BodyStatus.TIMEOUT: Reason.BODY_RECEIVE_TIMEOUT,
            BodyStatus.BUSY: Reason.BODY_INGRESS_BUSY,
        }
        reason = mapping.get(result.status)
        if reason is None:
            return None
        features = make_features(
            body_length=result.length, fully_inspected=False
        )
        return self._engine.reject_ingress(
            features, reason, result.detail, rate_info=rate_info, started_ns=started
        )

    # ------------------------------------------------------------------ #
    # 响应
    # ------------------------------------------------------------------ #
    async def _send_decision(self, send: Send, outcome) -> None:
        if outcome.reason in _INGRESS_STATUS:
            http_status = _INGRESS_STATUS[outcome.reason]
        elif outcome.reason is Reason.ENGINE_INTERNAL_ERROR:
            http_status = 500
        else:
            http_status = _DECISION_STATUS.get(outcome.decision, 403)
        body = {
            "error": outcome.reason.value,
            "message": outcome.detail,
            "decision": outcome.decision.value,
            "rule_version": outcome.rule_version,
            "content_policy_version": outcome.content_policy_version,
            "elapsed_ms": round(outcome.elapsed_ms, 3),
        }
        await self._send_raw(send, http_status, body)

    @staticmethod
    async def _send_raw(send: Send, status_code: int, body: dict) -> None:
        payload = json.dumps(body, ensure_ascii=False).encode("utf-8")
        await send(
            {
                "type": "http.response.start",
                "status": status_code,
                "headers": [
                    (b"content-type", b"application/json"),
                    (b"content-length", str(len(payload)).encode("ascii")),
                ],
            }
        )
        await send(
            {"type": "http.response.body", "body": payload, "more_body": False}
        )


# 每个中间件实例持有一把并发在途信号量（受构造参数 body_ingress_concurrency 约束）。


def _flat_headers(raw: list[tuple[bytes, bytes]]) -> dict[str, str]:
    return {
        k.decode("latin-1").lower(): v.decode("latin-1")
        for k, v in raw
    }


def _declared_content_length(raw: list[tuple[bytes, bytes]]) -> int | None:
    for k, v in raw:
        if k == b"content-length":
            try:
                value = int(v.decode("latin-1"))
            except ValueError:
                return None
            return value if value >= 0 else None
    return None


def _client_source(scope: Scope, headers: dict[str, str]) -> str:
    xff = headers.get("x-forwarded-for")
    if xff:
        first = xff.split(",", 1)[0].strip()
        if first:
            return first
    client = scope.get("client")
    return client[0] if client else "unknown"


def _query_params(raw: bytes) -> dict[str, str]:
    from urllib.parse import parse_qsl

    parsed = parse_qsl(raw.decode("latin-1"), keep_blank_values=True)
    return {k: v for k, v in parsed}

