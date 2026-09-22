"""HTTP 适配层：把请求映射为特征，把判定渲染为统一响应。

各入口经过同一个 gate，结论（放行/限流/拒绝/规则故障/服务故障）的
HTTP 状态码与响应体字段保持一致、原因可区分。
"""

from __future__ import annotations

import hashlib
import math

from fastapi import Request
from fastapi.responses import JSONResponse

from app.audit import REDACTED
from app.models import Decision, DefenseVerdict, RequestFeatures
from app.security import AdminAuthenticator

_SENSITIVE_HEADERS = frozenset(
    {"authorization", "cookie", "set-cookie", "x-admin-token", "proxy-authorization"}
)


def build_features(request: Request, body: bytes) -> RequestFeatures:
    headers: dict[str, str] = {}
    for key, value in request.headers.items():
        headers[key.lower()] = REDACTED if key.lower() in _SENSITIVE_HEADERS else value
    query = {k: v for k, v in request.query_params.multi_items()}
    digest = hashlib.sha256(body).hexdigest()[:16] if body else ""
    source = request.client.host if request.client else "unknown"
    return RequestFeatures(
        source=source,
        path=request.url.path,
        method=request.method,
        headers=headers,
        query=query,
        body_digest=digest,
    )


class DefenseGate:
    def render(self, verdict: DefenseVerdict) -> JSONResponse:
        payload = {
            "decision": verdict.decision,
            "reason": verdict.reason,
            "rule_version": verdict.rule_version,
        }
        if verdict.decision == Decision.RATE_LIMITED.value:
            retry_after = int(math.ceil(verdict.window_seconds or 1))
            resp = JSONResponse(
                status_code=429,
                content=payload,
                headers={"Retry-After": str(retry_after)},
            )
        elif verdict.decision == Decision.DENY.value:
            resp = JSONResponse(status_code=403, content=payload)
        elif verdict.decision == Decision.RULE_ERROR.value:
            # fail-closed：以策略拒绝（非 5xx），原因可区分
            resp = JSONResponse(status_code=403, content=payload)
        elif verdict.decision == Decision.SERVICE_ERROR.value:
            resp = JSONResponse(status_code=500, content=payload)
        else:
            resp = JSONResponse(status_code=200, content=payload)
        resp.headers["X-Defense-Decision"] = verdict.decision
        resp.headers["X-Defense-Reason"] = verdict.reason
        resp.headers["X-Rule-Version"] = str(verdict.rule_version)
        if verdict.limit is not None:
            resp.headers["X-RateLimit-Limit"] = str(verdict.limit)
            remaining = verdict.remaining_quota
            resp.headers["X-RateLimit-Remaining"] = str(
                remaining if remaining is not None else ""
            )
        return resp


def require_admin(request: Request, authenticator: AdminAuthenticator) -> None:
    """管理接口鉴权依赖；失败统一 401，不回显凭据或内部状态。"""
    from fastapi import HTTPException

    if not authenticator.authenticate(request.headers.get("authorization")):
        raise HTTPException(
            status_code=401,
            detail="unauthorized",
            headers={"WWW-Authenticate": "Bearer"},
        )
