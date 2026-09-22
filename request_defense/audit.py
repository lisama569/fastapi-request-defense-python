"""审计与日志。

每条请求防护判定输出一条结构化（JSON）审计记录，包含：
  - 最终结论 decision 与可区分原因 reason；
  - 判定依据 rule_results（每条规则的结论/优先级/动作/耗时/错误类型）；
  - 足以复现判定的输入摘要（来源、方法、路径、查询、脱敏后的头、body 摘要）；
  - 规则版本、限流信息、单请求耗时。

安全要求：authorization / x-admin-token / cookie 等头一律脱敏，
任何凭据/令牌都不得完整出现在日志中。
"""

from __future__ import annotations

import json
import logging
from typing import Any

logger = logging.getLogger("request_defense")

# 永不落日志的请求头（比较时统一小写）
SENSITIVE_HEADERS = frozenset(
    {"authorization", "x-admin-token", "cookie", "proxy-authorization"}
)
_MAX_HEADER_VALUE_LOG = 64
_MAX_BODY_LOG = 512


def redact_headers(headers: dict[str, str]) -> dict[str, str]:
    """脱敏请求头：敏感头只保留方案/长度线索，其余值截断。"""
    redacted: dict[str, str] = {}
    for name, value in headers.items():
        if name.lower() in SENSITIVE_HEADERS:
            scheme = ""
            if " " in value:
                scheme = value.split(" ", 1)[0]
            redacted[name] = f"<redacted:{scheme or 'secret'}:len={len(value)}>"
        elif len(value) > _MAX_HEADER_VALUE_LOG:
            redacted[name] = value[:_MAX_HEADER_VALUE_LOG] + "...<truncated>"
        else:
            redacted[name] = value
    return redacted


def build_audit_record(
    *,
    source: str,
    method: str,
    path: str,
    headers: dict[str, str],
    query: dict[str, str],
    body_summary: str,
    decision: str,
    reason: str,
    detail: str,
    rule_version: int,
    rule_results: list[dict[str, Any]],
    rate_limit: dict[str, Any] | None,
    elapsed_ms: float,
) -> dict[str, Any]:
    """构造审计记录（dict）。输入摘要足以复现判定，敏感信息已脱敏。"""
    body = body_summary
    if len(body) > _MAX_BODY_LOG:
        body = body[:_MAX_BODY_LOG] + "...<truncated>"
    return {
        "event": "request_defense_decision",
        "decision": decision,
        "reason": reason,
        "detail": detail,
        "input": {
            "source": source,
            "method": method,
            "path": path,
            "query": dict(query),
            "headers": redact_headers(headers),
            "body_summary": body,
        },
        "basis": {
            "rule_version": rule_version,
            "rule_results": rule_results,
            "rate_limit": rate_limit,
        },
        "elapsed_ms": round(elapsed_ms, 3),
    }


def log_decision(record: dict[str, Any]) -> None:
    """按结论分级输出审计日志，原因可区分。"""
    decision = record.get("decision")
    level = logging.INFO
    if decision == "rate_limited":
        level = logging.WARNING
    elif decision == "deny":
        level = logging.WARNING
    logger.log(level, json.dumps(record, ensure_ascii=False, sort_keys=True))
