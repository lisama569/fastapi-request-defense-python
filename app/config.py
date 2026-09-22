"""防护层配置。

可通过环境变量覆盖默认值；管理令牌默认仅用于本地开发，生产必须显式注入。
"""

from __future__ import annotations

import os
from dataclasses import dataclass

# 规则求值异常 / 超限时的降级策略
FAIL_CLOSED = "fail_closed"  # 可疑/不确定 -> 拒绝（默认，安全优先）
FAIL_OPEN = "fail_open"      # 放行但给出可区分原因（仅在显式配置时使用）


@dataclass(frozen=True)
class DefenseConfig:
    # 每个来源在 window_seconds 滑动窗口内允许的请求数
    rate_limit: int = 10
    window_seconds: float = 1.0
    # 单请求参与求值的规则数量上限
    max_rules: int = 100
    # 单请求规则求值总耗时上限（毫秒）
    per_request_budget_ms: float = 50.0
    # 规则故障（异常 / 超时）时的降级策略
    on_rule_error: str = FAIL_CLOSED
    # 管理接口 Bearer 令牌
    admin_token: str = "dev-only-admin-token"

    @staticmethod
    def default() -> "DefenseConfig":
        return DefenseConfig(
            rate_limit=int(os.environ.get("DEFENSE_RATE_LIMIT", "10")),
            window_seconds=float(os.environ.get("DEFENSE_WINDOW_SECONDS", "1.0")),
            max_rules=int(os.environ.get("DEFENSE_MAX_RULES", "100")),
            per_request_budget_ms=float(
                os.environ.get("DEFENSE_BUDGET_MS", "50.0")
            ),
            on_rule_error=os.environ.get("DEFENSE_ON_RULE_ERROR", FAIL_CLOSED),
            admin_token=os.environ.get("DEFENSE_ADMIN_TOKEN", "dev-only-admin-token"),
        )

    def validated(self) -> "DefenseConfig":
        if self.rate_limit <= 0:
            raise ValueError("rate_limit must be positive")
        if self.window_seconds <= 0:
            raise ValueError("window_seconds must be positive")
        if self.max_rules <= 0:
            raise ValueError("max_rules must be positive")
        if self.per_request_budget_ms <= 0:
            raise ValueError("per_request_budget_ms must be positive")
        if self.on_rule_error not in (FAIL_CLOSED, FAIL_OPEN):
            raise ValueError("on_rule_error must be fail_closed or fail_open")
        if not self.admin_token:
            raise ValueError("admin_token must not be empty")
        return self
