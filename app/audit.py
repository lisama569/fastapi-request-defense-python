"""判定审计与日志。

- 每条判定产生一条 :class:`AuditEntry`，包含结论、可区分原因、规则版本、
  输入摘要与逐规则轨迹（足以复现判定）。
- 日志按结论分级：放行 INFO、限流/拒绝 WARNING、规则故障 ERROR，
  且消息中携带结构化字段，三类处置肉眼与机器都可区分。
- 凭据与敏感头（authorization/cookie/x-admin-token 等）一律打码，
  审计与日志中绝不出现完整令牌。
"""

from __future__ import annotations

import logging
from collections import deque
from dataclasses import dataclass, field

from app.models import DefenseVerdict, RequestFeatures, RuleTrace

_SENSITIVE_HEADERS = frozenset(
    {"authorization", "cookie", "set-cookie", "x-admin-token", "proxy-authorization"}
)
REDACTED = "***redacted***"


def mask_secret(value: str | None) -> str:
    """凭据脱敏：任何非空凭据都只返回固定掩码，绝不回显原文或长度。"""
    if not value:
        return ""
    return REDACTED


def _summarize_headers(headers: dict[str, str]) -> str:
    parts = []
    for name in sorted(headers):
        if name.lower() in _SENSITIVE_HEADERS:
            parts.append(f"{name}={REDACTED}")
        else:
            val = headers[name]
            parts.append(f"{name}={val[:80]}")
    return "{" + ",".join(parts) + "}"


def input_summary(features: RequestFeatures) -> str:
    """生成足以复现判定的输入摘要（敏感字段打码）。"""
    query = "{" + ",".join(
        f"{k}={features.query[k][:80]}" for k in sorted(features.query)
    ) + "}"
    return (
        f"source={features.source} method={features.method} path={features.path} "
        f"query={query} headers={_summarize_headers(features.headers)} "
        f"body_digest={features.body_digest}"
    )


@dataclass(frozen=True)
class AuditEntry:
    decision: str
    reason: str
    source: str
    method: str
    path: str
    rule_version: int
    input_summary: str
    traces: tuple[RuleTrace, ...] = field(default_factory=tuple)
    elapsed_ms: float = 0.0
    remaining_quota: int | None = None
    degraded: bool = False


class AuditLogger:
    def __init__(
        self,
        logger: logging.Logger | None = None,
        capacity: int = 1000,
    ) -> None:
        self._logger = logger or logging.getLogger("request_defense.audit")
        self._entries: deque[AuditEntry] = deque(maxlen=capacity)

    def record(
        self, features: RequestFeatures, verdict: DefenseVerdict
    ) -> AuditEntry:
        entry = AuditEntry(
            decision=verdict.decision,
            reason=verdict.reason,
            source=features.source,
            method=features.method,
            path=features.path,
            rule_version=verdict.rule_version,
            input_summary=input_summary(features),
            traces=verdict.traces,
            elapsed_ms=verdict.elapsed_ms,
            remaining_quota=verdict.remaining_quota,
            degraded=verdict.degraded,
        )
        self._entries.append(entry)
        self._log(entry)
        return entry

    def entries(self) -> list[AuditEntry]:
        return list(self._entries)

    def _log(self, entry: AuditEntry) -> None:
        trace_desc = ";".join(
            f"{t.rule_id}[p{t.priority}]={t.outcome}" for t in entry.traces
        )
        msg = (
            f"decision={entry.decision} reason={entry.reason} "
            f"source={entry.source} {entry.method} {entry.path} "
            f"rule_version={entry.rule_version} elapsed_ms={entry.elapsed_ms:.3f} "
            f"remaining_quota={entry.remaining_quota} degraded={entry.degraded} "
            f"input=({entry.input_summary}) traces=[{trace_desc}]"
        )
        if entry.decision == "allow":
            self._logger.info(msg)
        elif entry.decision == "rate_limited":
            self._logger.warning(msg)
        elif entry.decision == "rule_error":
            self._logger.error(msg)
        else:  # deny
            self._logger.warning(msg)
