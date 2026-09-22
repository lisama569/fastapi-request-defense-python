"""运行配置：环境变量加载，带安全默认值。"""

from __future__ import annotations

import os
from dataclasses import dataclass


def _env_int(name: str, default: int) -> int:
    raw = os.environ.get(name)
    if raw is None or raw == "":
        return default
    try:
        value = int(raw)
    except ValueError:
        return default
    return value if value > 0 else default


@dataclass(frozen=True, slots=True)
class DefenseConfig:
    rate_limit: int = 100
    window_ms: int = 60_000
    max_rules: int = 64
    request_timeout_ms: int = 200
    admin_token: str = ""
    # 规则故障时的降级策略：默认 fail-closed（拒绝）；
    # 仅在显式配置 REQUEST_DEFENSE_FAIL_OPEN=1 时 fail-open（放行但原因可区分）。
    fail_open: bool = False

    @classmethod
    def from_env(cls) -> "DefenseConfig":
        return cls(
            rate_limit=_env_int("REQUEST_DEFENSE_RATE_LIMIT", 100),
            window_ms=_env_int("REQUEST_DEFENSE_WINDOW_MS", 60_000),
            max_rules=_env_int("REQUEST_DEFENSE_MAX_RULES", 64),
            request_timeout_ms=_env_int("REQUEST_DEFENSE_TIMEOUT_MS", 200),
            admin_token=os.environ.get("REQUEST_DEFENSE_ADMIN_TOKEN", ""),
            fail_open=os.environ.get("REQUEST_DEFENSE_FAIL_OPEN", "0") == "1",
        )
