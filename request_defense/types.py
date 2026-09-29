"""请求防护层的核心类型定义。"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum


class Decision(str, Enum):
    """最终处置结论。"""

    ALLOW = "allow"
    RATE_LIMITED = "rate_limited"
    DENY = "deny"


class Reason(str, Enum):
    """可区分的判定原因（审计/日志使用，保证各结论可解释）。"""

    OK = "ok"
    RATE_LIMIT_QUOTA_EXHAUSTED = "rate_limit_quota_exhausted"
    RULE_MATCH_DENY = "rule_match_deny"
    RULE_CONFLICT_DENY = "rule_conflict_deny"
    RULE_EVALUATION_ERROR = "rule_evaluation_error"
    RULE_TIMEOUT = "rule_timeout"
    RULE_LIMIT_EXCEEDED = "rule_limit_exceeded"
    ENGINE_INTERNAL_ERROR = "engine_internal_error"
    # ---- 带正文入口（POST/PUT/PATCH）相关原因，状态码与语义均相互可区分 ----
    # 正文超过"接收上限"：不接受，明确拒绝（HTTP 413）
    BODY_TOO_LARGE = "body_too_large"
    # 正文未超接收上限、但超过"检查上限"，无法完成内容判定：内容不可判定（HTTP 422）
    BODY_INSPECTION_INCOMPLETE = "body_inspection_incomplete"
    # 正文接收超过单请求时间预算（HTTP 408）
    BODY_RECEIVE_TIMEOUT = "body_receive_timeout"
    # 并发正文缓冲容量饱和，服务暂时无法安全接收（HTTP 503）
    BODY_INGRESS_BUSY = "body_ingress_busy"


class RuleVerdict(str, Enum):
    """单条规则的匹配结论。"""

    MATCH_ALLOW = "match_allow"
    MATCH_DENY = "match_deny"
    NO_MATCH = "no_match"
    ERROR = "error"


class RuleEffect(str, Enum):
    """规则命中后的动作。"""

    ALLOW = "allow"
    DENY = "deny"


@dataclass(frozen=True, slots=True)
class RequestFeatures:
    """规则求值所依赖的请求特征摘要（足以复现判定）。"""

    source: str
    path: str
    method: str
    headers: dict[str, str] = field(default_factory=dict)
    query: dict[str, str] = field(default_factory=dict)
    body_summary: str = ""
    # ---- 带正文入口（POST/PUT/PATCH）----
    # 客户端实际发送的正文总字节数（即使超过检查上限也如实记录）
    body_length: int = 0
    # 正文检查前缀是否覆盖完整正文（False 表示只检查了前 N 字节，内容判定不可完成）
    body_fully_inspected: bool = True
    # 本次处理所依据的内容策略版本（与规则版本一同进入审计，保证可复现）
    content_policy_version: int = 0


@dataclass(frozen=True, slots=True)
class DefenseDecision:
    """一次请求防护判定的结论。"""

    decision: Decision
    reason: Reason
    source: str
    rule_results: tuple["RuleEvalResult", ...] = ()
    detail: str = ""
    elapsed_ms: float = 0.0
    rule_version: int = 0
    content_policy_version: int = 0


@dataclass(frozen=True, slots=True)
class RuleEvalResult:
    """单条规则求值结果（异常被归类为 ERROR，而非抛出）。"""

    rule_id: str
    verdict: RuleVerdict
    priority: int
    effect: RuleEffect
    error_type: str = ""
    elapsed_ms: float = 0.0


@dataclass(frozen=True, slots=True)
class RuleConfig:
    """一条请求特征规则的静态配置。"""

    rule_id: str
    priority: int
    effect: RuleEffect
    field_name: str
    pattern: str
    enabled: bool = True
