"""共享数据契约与枚举。

所有跨模块传递的结构均为不可变值对象，避免并发下被部分修改。
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum


class Decision(str, Enum):
    ALLOW = "allow"
    RATE_LIMITED = "rate_limited"
    DENY = "deny"
    # 规则自身故障且按降级策略拒绝；与"命中拒绝规则"的 DENY 区分
    RULE_ERROR = "rule_error"
    # 防护层自身（非规则）故障，与规则故障严格区分
    SERVICE_ERROR = "service_error"


class RateLimitReason(str, Enum):
    # 窗口内事件数已达到配额（滑动日志中：有事件过期即必然放行，
    # 因此拒绝必然发生在配额耗尽的当前窗口内）
    QUOTA_EXHAUSTED = "quota_exhausted"


class RuleOutcome(str, Enum):
    MATCH_ALLOW = "match_allow"
    MATCH_DENY = "match_deny"
    NO_MATCH = "no_match"
    ERROR = "error"
    SKIPPED_TIMEOUT = "skipped_timeout"
    SKIPPED_CAPACITY = "skipped_capacity"


class RuleAction(str, Enum):
    ALLOW = "allow"
    DENY = "deny"


class VerdictReason:
    """最终判定原因（字符串常量，保证可区分、可解释）。"""

    RL_QUOTA_EXHAUSTED = "rate_limit_quota_exhausted"

    RULE_MATCH_DENY = "rule_match_deny"
    RULE_ERROR_DENY = "rule_evaluation_error_fail_closed"
    RULE_TIMEOUT_DENY = "rule_budget_exceeded_fail_closed"
    RULE_CAPACITY_DENY = "rule_capacity_exceeded_fail_closed"

    NO_RULE_MATCHED = "no_rule_matched"
    RULE_MATCH_ALLOW = "rule_match_allow"
    RULE_ERROR_ALLOW = "rule_evaluation_error_fail_open"
    RULE_TIMEOUT_ALLOW = "rule_budget_exceeded_fail_open"
    RULE_CAPACITY_ALLOW = "rule_capacity_exceeded_fail_open"

    SERVICE_FAILURE = "defense_internal_error"


@dataclass(frozen=True)
class RequestFeatures:
    """一次请求的特征摘要（足够复现判定，不含完整凭据）。"""

    source: str
    path: str
    method: str
    headers: dict[str, str] = field(default_factory=dict)
    query: dict[str, str] = field(default_factory=dict)
    body_digest: str = ""


@dataclass(frozen=True)
class RuleDef:
    """声明式规则定义。

    对 ``field_name`` 取出的特征值，按 ``operator`` 与 ``expected`` 比较。
    """

    rule_id: str
    priority: int          # 数值越小优先级越高
    action: str            # allow / deny
    field_name: str        # path / method / source / header:<name> / query:<name> / body_digest
    operator: str          # eq / ne / prefix / suffix / contains / regex / in
    expected: str
    enabled: bool = True


@dataclass(frozen=True)
class RuleTrace:
    """单条规则的求值轨迹，作为审计依据。"""

    rule_id: str
    priority: int
    outcome: str
    detail: str = ""


@dataclass(frozen=True)
class DefenseVerdict:
    decision: str
    reason: str
    source: str
    rule_version: int
    traces: tuple[RuleTrace, ...] = ()
    remaining_quota: int | None = None
    limit: int | None = None
    window_seconds: float | None = None
    elapsed_ms: float = 0.0
    degraded: bool = False


@dataclass(frozen=True)
class RuleSetSpec:
    rules: tuple[RuleDef, ...] = ()
