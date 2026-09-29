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


def _env_bool(name: str, default: bool) -> bool:
    raw = os.environ.get(name)
    if raw is None or raw == "":
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}


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
    # 带正文入口（POST/PUT/PATCH）的容量与内容策略初始值（均可运行时调整）
    body_inspect_limit: int = 64 * 1024       # 内容规则检查范围上限：64 KiB
    body_receive_limit: int = 1024 * 1024    # 接收上限：1 MiB
    body_inspect_enabled: bool = True        # 内容判定总开关
    body_receive_timeout_ms: int = 5_000     # 单请求正文接收时间预算
    body_inflight_cap: int = 32              # 同时处理带正文请求的在途上限

    @classmethod
    def from_env(cls) -> "DefenseConfig":
        return cls(
            rate_limit=_env_int("REQUEST_DEFENSE_RATE_LIMIT", 100),
            window_ms=_env_int("REQUEST_DEFENSE_WINDOW_MS", 60_000),
            max_rules=_env_int("REQUEST_DEFENSE_MAX_RULES", 64),
            request_timeout_ms=_env_int("REQUEST_DEFENSE_TIMEOUT_MS", 200),
            admin_token=os.environ.get("REQUEST_DEFENSE_ADMIN_TOKEN", ""),
            fail_open=os.environ.get("REQUEST_DEFENSE_FAIL_OPEN", "0") == "1",
            body_inspect_limit=_env_int("REQUEST_DEFENSE_INSPECT_LIMIT", 64 * 1024),
            body_receive_limit=_env_int("REQUEST_DEFENSE_RECEIVE_LIMIT", 1024 * 1024),
            body_inspect_enabled=not _env_bool("REQUEST_DEFENSE_INSPECT_DISABLED", False),
            body_receive_timeout_ms=_env_int("REQUEST_DEFENSE_BODY_TIMEOUT_MS", 5_000),
            body_inflight_cap=_env_int("REQUEST_DEFENSE_BODY_INFLIGHT", 32),
        )
