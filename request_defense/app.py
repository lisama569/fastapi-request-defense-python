"""FastAPI 应用装配：把防护层挂到各个 HTTP 入口。

- 所有非管理入口统一经过防护中间件：限流(429) / 拒绝(403) / 服务故障(500)，
  结论与原因在响应体、日志、审计中保持一致且可区分；
- /admin/* 管理接口先过 Bearer 令牌校验，未授权一律 401 固定错误体，
  不泄漏任何内部状态（规则数、版本等）；
- 规则集写入为"整体校验 + 原子替换"，非法集返回 422 且旧规则继续生效；
- /healthz 等运维路径放行，便于存活探测（不消耗限流配额）。
"""

from __future__ import annotations

import logging
from typing import Any

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field

from .auth import AuthError, authenticate, mask_token
from .config import DefenseConfig
from .engine import DefenseEngine
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
_MAX_BODY_SUMMARY_BYTES = 512

# 决策 -> HTTP 状态码
_STATUS_MAP = {
    Decision.ALLOW: 200,
    Decision.RATE_LIMITED: 429,
    Decision.DENY: 403,
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


async def _build_features(request: Request) -> RequestFeatures:
    """抽取请求特征；body 只取定长前缀，避免大请求体无界占用内存。"""
    chunks: list[bytes] = []
    total = 0
    async for chunk in request.stream():
        if total >= _MAX_BODY_SUMMARY_BYTES:
            break
        remaining = _MAX_BODY_SUMMARY_BYTES - total
        chunks.append(chunk[:remaining])
        total += min(len(chunk), remaining)
    body_summary = b"".join(chunks)[:_MAX_BODY_SUMMARY_BYTES].decode("utf-8", "replace")
    headers = {k.lower(): v for k, v in request.headers.items()}
    return RequestFeatures(
        source=_client_source(request),
        path=request.url.path,
        method=request.method,
        headers=headers,
        query=dict(request.query_params),
        body_summary=body_summary,
    )


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
    app.state.config = config
    app.state.engine = engine
    app.state.rate_limiter = rate_limiter
    app.state.rule_store = rule_store

    # ------------------------- 防护中间件 ------------------------- #
    @app.middleware("http")
    async def defense_middleware(request: Request, call_next):
        path = request.url.path
        if path in _EXEMPT_EXACT or path.startswith(_ADMIN_PREFIX):
            return await call_next(request)

        try:
            features = await _build_features(request)
            outcome = engine.evaluate(features)
        except Exception:  # noqa: BLE001 - 装配外的意外统一 500，不泄漏内部细节
            logger.exception("defense middleware internal failure")
            return JSONResponse(
                status_code=500,
                content=_error_body(
                    Reason.ENGINE_INTERNAL_ERROR.value,
                    "internal defense failure",
                ),
            )

        if outcome.decision is Decision.ALLOW:
            return await call_next(request)

        http_status = (
            500
            if outcome.reason in _SERVER_FAULT_REASONS
            else _STATUS_MAP[outcome.decision]
        )
        headers: dict[str, str] = {}
        body: dict[str, Any] = {
            "error": outcome.reason.value,
            "message": outcome.detail,
            "decision": outcome.decision.value,
            "rule_version": outcome.rule_version,
            "elapsed_ms": round(outcome.elapsed_ms, 3),
        }
        return JSONResponse(status_code=http_status, content=body, headers=headers)

    # ------------------------- 业务入口（示例） ------------------------- #
    @app.get("/api/echo")
    async def echo(request: Request) -> dict[str, str]:
        return {"path": request.url.path, "status": "served"}

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

    return app


def create_default_app() -> FastAPI:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )
    return create_app()


app = create_default_app()
