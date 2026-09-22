"""FastAPI 服务：组装限流、规则引擎、规则存储、审计与管理接口。"""

from __future__ import annotations

import logging

from fastapi import Depends, FastAPI, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field
from starlette.responses import Response

from app.audit import AuditLogger
from app.config import DefenseConfig
from app.defense import RequestDefense
from app.models import RuleDef, RuleSetSpec
from app.ratelimit import SlidingWindowRateLimiter
from app.rules import RuleSetValidationError
from app.rule_store import RuleStore
from app.security import AdminAuthenticator
from app.web import DefenseGate, build_features, require_admin

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s %(message)s",
)
log = logging.getLogger("request_defense.service")

config = DefenseConfig.default().validated()
audit = AuditLogger()
rate_limiter = SlidingWindowRateLimiter(config.rate_limit, config.window_seconds)
# 开箱示例：命中可疑前缀直接拒绝；可通过管理接口整体替换
_seed = RuleSetSpec(
    (RuleDef("seed-deny-suspicious", 10, "deny", "path", "prefix", "/suspicious"),)
)
rule_store = RuleStore(config, _seed)
defense = RequestDefense(rate_limiter, rule_store, audit)
authenticator = AdminAuthenticator(config.admin_token)
gate = DefenseGate()

app = FastAPI(title="fastapi-request-defense", version="0.1.0")

# 管理与健康检查路径不走统一防护门（/admin/* 各自强制鉴权）
_EXEMPT_PREFIXES = ("/admin", "/healthz", "/docs", "/openapi.json", "/redoc")


@app.middleware("http")
async def defense_middleware(request: Request, call_next) -> Response:
    path = request.url.path
    if path.startswith(_EXEMPT_PREFIXES):
        return await call_next(request)

    body = await request.body()

    async def receive() -> dict:
        return {"type": "http.request", "body": body, "more_body": False}

    request = Request(request.scope, receive)

    features = build_features(request, body)
    verdict = defense.inspect(features)
    if verdict.decision != "allow":
        return gate.render(verdict)
    response = await call_next(request)
    # 放行响应同样携带限流信息，保证各入口处置结论字段一致
    if verdict.limit is not None:
        response.headers["X-RateLimit-Limit"] = str(verdict.limit)
        response.headers["X-RateLimit-Remaining"] = str(
            verdict.remaining_quota if verdict.remaining_quota is not None else ""
        )
        response.headers["X-Defense-Decision"] = "allow"
        response.headers["X-Defense-Reason"] = verdict.reason
        response.headers["X-Rule-Version"] = str(verdict.rule_version)
    return response


@app.get("/healthz")
def healthz():
    return {"status": "ok"}


@app.get("/")
def read_root():
    return {"Hello": "World"}


@app.post("/ingest")
async def ingest(request: Request):
    body = await request.body()
    return {"received_bytes": len(body)}


class RuleIn(BaseModel):
    rule_id: str = Field(min_length=1)
    priority: int
    action: str
    field_name: str
    operator: str
    expected: str
    enabled: bool = True


class RuleSetIn(BaseModel):
    rules: list[RuleIn]


def _to_spec(payload: RuleSetIn) -> RuleSetSpec:
    return RuleSetSpec(
        tuple(
            RuleDef(
                rule_id=r.rule_id,
                priority=r.priority,
                action=r.action,
                field_name=r.field_name,
                operator=r.operator,
                expected=r.expected,
                enabled=r.enabled,
            )
            for r in payload.rules
        )
    )


def admin_required(request: Request) -> None:
    require_admin(request, authenticator)


@app.get("/admin/rules")
def list_rules(_: None = Depends(admin_required)):
    engine, version = rule_store.snapshot()
    return {
        "version": version,
        "rules": [
            {
                "rule_id": r.rule_id,
                "priority": r.priority,
                "action": r.action,
                "field_name": r.definition.field_name,
                "operator": r.definition.operator,
                "expected": r.definition.expected,
                "enabled": r.definition.enabled,
            }
            for r in engine.rules
        ],
    }


@app.put("/admin/rules")
def replace_rules(
    payload: RuleSetIn,
    _: None = Depends(admin_required),
):
    spec = _to_spec(payload)
    try:
        version = defense.replace_ruleset(spec)
    except RuleSetValidationError as exc:
        # 规则集非法：整体拒绝，当前在效规则与版本不变
        return JSONResponse(
            status_code=400,
            content={"error": "invalid_ruleset", "detail": str(exc)},
        )
    log.info("ruleset replaced, new version=%d", version)
    return {"ok": True, "version": version}


@app.get("/admin/audit")
def show_audit(_: None = Depends(admin_required)):
    return {
        "entries": [
            {
                "decision": e.decision,
                "reason": e.reason,
                "source": e.source,
                "method": e.method,
                "path": e.path,
                "rule_version": e.rule_version,
                "elapsed_ms": round(e.elapsed_ms, 3),
                "remaining_quota": e.remaining_quota,
                "degraded": e.degraded,
                "input_summary": e.input_summary,
                "traces": [
                    {"rule_id": t.rule_id, "priority": t.priority,
                     "outcome": t.outcome, "detail": t.detail}
                    for t in e.traces
                ],
            }
            for e in audit.entries()
        ]
    }
