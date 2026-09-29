"""运行时内容策略：不可变快照 + 整体校验 + 原子替换。

与规则集（RuleStore）完全一致的一致性口径：
  - 一次更新必须**整体**合法（检查上限/接收上限为正、检查上限不超过接收上限、
    开关为布尔）后才在同一把锁内原子替换不可变快照；
  - 任一非法 -> 抛 ContentPolicyValidationError，旧版本继续生效，不存在半更新；
  - 版本号单调递增；正在处理的请求拿到一次快照后，整个处理过程只使用该版本，
    不会一半旧一半新。
"""

from __future__ import annotations

import threading
from dataclasses import dataclass


class ContentPolicyValidationError(ValueError):
    """非法内容策略，整体拒绝，旧策略继续生效。"""

    def __init__(self, message: str, field: str | None = None) -> None:
        super().__init__(message)
        self.field = field


@dataclass(frozen=True, slots=True)
class ContentPolicy:
    """单次内容接收/检查所依据的完整策略（不可变）。"""

    inspect_limit_bytes: int
    receive_limit_bytes: int
    content_check_enabled: bool

    def validate(self) -> None:
        if not isinstance(self.inspect_limit_bytes, int) or isinstance(
            self.inspect_limit_bytes, bool
        ):
            raise ContentPolicyValidationError(
                "inspect_limit_bytes must be a positive int", "inspect_limit_bytes"
            )
        if not isinstance(self.receive_limit_bytes, int) or isinstance(
            self.receive_limit_bytes, bool
        ):
            raise ContentPolicyValidationError(
                "receive_limit_bytes must be a positive int", "receive_limit_bytes"
            )
        if self.inspect_limit_bytes <= 0:
            raise ContentPolicyValidationError(
                "inspect_limit_bytes must be positive", "inspect_limit_bytes"
            )
        if self.receive_limit_bytes <= 0:
            raise ContentPolicyValidationError(
                "receive_limit_bytes must be positive", "receive_limit_bytes"
            )
        if self.inspect_limit_bytes > self.receive_limit_bytes:
            raise ContentPolicyValidationError(
                "inspect_limit_bytes must not exceed receive_limit_bytes",
                "inspect_limit_bytes",
            )
        if not isinstance(self.content_check_enabled, bool):
            raise ContentPolicyValidationError(
                "content_check_enabled must be a bool", "content_check_enabled"
            )


class ContentPolicyStore:
    """保存当前生效内容策略快照，版本号单调递增。"""

    __slots__ = ("_lock", "_version", "_policy")

    def __init__(self, initial: ContentPolicy) -> None:
        initial.validate()
        self._lock = threading.Lock()
        self._version = 1
        self._policy = initial

    def snapshot(self) -> tuple[int, ContentPolicy]:
        """返回 (版本号, 不可变策略)；处理期间持有该对象即锁定一致视图。"""
        with self._lock:
            return self._version, self._policy

    def replace(self, policy: ContentPolicy) -> int:
        """整体校验后原子替换，返回新版本号；失败时旧策略原样保留。"""
        if not isinstance(policy, ContentPolicy):
            raise ContentPolicyValidationError("policy must be a ContentPolicy")
        policy.validate()
        with self._lock:
            self._version += 1
            self._policy = policy
            return self._version
