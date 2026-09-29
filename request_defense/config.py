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
    # ---- 带正文入口（POST/PUT/PATCH）内容策略的启动默认值 ----
    # 内容规则检查上限：只缓冲/匹配前 N 字节，超出则结论为"无法完成内容判定"
    inspect_limit_bytes: int = 65_536
    # 正文接收上限（硬上限）：超过即"内容太大不接受"，不再读取
    receive_limit_bytes: int = 2_097_152
    # 是否开启内容判定（False 时正文仍完整转发业务，只是不做内容规则匹配）
    content_check_enabled: bool = True
    # 单请求正文接收时间预算（毫秒），超时按 body_receive_timeout 拒绝
    body_timeout_ms: int = 10_000
    # 同时进行正文缓冲的请求数上限（并发在途容量），饱和按 body_ingress_busy 拒绝
    body_ingress_concurrency: int = 32

    @classmethod
    def from_env(cls) -> "DefenseConfig":
        return cls(
            rate_limit=_env_int("REQUEST_DEFENSE_RATE_LIMIT", 100),
            window_ms=_env_int("REQUEST_DEFENSE_WINDOW_MS", 60_000),
            max_rules=_env_int("REQUEST_DEFENSE_MAX_RULES", 64),
            request_timeout_ms=_env_int("REQUEST_DEFENSE_TIMEOUT_MS", 200),
            admin_token=os.environ.get("REQUEST_DEFENSE_ADMIN_TOKEN", ""),
            fail_open=os.environ.get("REQUEST_DEFENSE_FAIL_OPEN", "0") == "1",
            inspect_limit_bytes=_env_int(
                "REQUEST_DEFENSE_INSPECT_LIMIT_BYTES", 65_536
            ),
            receive_limit_bytes=_env_int(
                "REQUEST_DEFENSE_RECEIVE_LIMIT_BYTES", 2_097_152
            ),
            content_check_enabled=os.environ.get(
                "REQUEST_DEFENSE_CONTENT_CHECK_ENABLED", "1"
            )
            == "1",
            body_timeout_ms=_env_int("REQUEST_DEFENSE_BODY_TIMEOUT_MS", 10_000),
            body_ingress_concurrency=_env_int(
                "REQUEST_DEFENSE_BODY_INGRESS_CONCURRENCY", 32
            ),
        )
