"""运行时正文容量与内容判定策略：不可变快照 + 整体校验 + 原子替换。

与规则集（``store.RuleStore``）相同的一致性口径：

  - 策略对象本身不可变；请求在进入防护时取一次快照，整次处理（读正文、
    规则求值、审计）始终使用同一个版本，不会半旧半新；
  - 更新必须**整体**合法（字段范围、检查上限不超过接收上限、不超硬天花板），
    任意一项非法即整体拒绝（``PolicyValidationError``），旧版本继续生效；
  - 版本号单调递增，替换在同一把锁内完成，读快照永远拿到完整版本。

字段语义：
  - ``inspect_limit``：内容规则的检查上限（字节）。内容规则只在此范围内匹配，
    防止大正文无界占用内存；正文超过该上限时给出“无法完成内容判定”的
    可区分结论（``content_inspection_incomplete``），而不是静默放过。
  - ``receive_limit``：接收上限（字节）。超过即拒绝接收
    （``body_too_large``，HTTP 413），业务入口不会被执行。
  - ``content_check_enabled``：内容判定总开关。关闭时内容规则不参与判定，
    但接收上限、限流、来源/路径等规则仍然生效。
"""

from __future__ import annotations

import threading
from dataclasses import dataclass

# 管理侧可调上限的硬天花板：即使误配置也不能让单请求/检查范围无界。
MAX_INSPECT_LIMIT = 1 * 1024 * 1024        # 1 MiB
MAX_RECEIVE_LIMIT = 16 * 1024 * 1024       # 16 MiB


class PolicyValidationError(ValueError):
    """非法的容量/内容策略，整体拒绝，旧策略继续生效。"""

    def __init__(self, message: str, field: str | None = None) -> None:
        super().__init__(message)
        self.field = field


@dataclass(frozen=True, slots=True)
class BodyPolicy:
    """一次生效的正文容量与内容判定策略（不可变）。"""

    inspect_limit: int
    receive_limit: int
    content_check_enabled: bool = True

    @staticmethod
    def validated(
        inspect_limit: int,
        receive_limit: int,
        content_check_enabled: bool = True,
    ) -> "BodyPolicy":
        """整体校验并构造；任一非法项抛 PolicyValidationError。"""
        if isinstance(inspect_limit, bool) or not isinstance(inspect_limit, int):
            raise PolicyValidationError("inspect_limit must be an int", "inspect_limit")
        if isinstance(receive_limit, bool) or not isinstance(receive_limit, int):
            raise PolicyValidationError("receive_limit must be an int", "receive_limit")
        if not 1 <= inspect_limit <= MAX_INSPECT_LIMIT:
            raise PolicyValidationError(
                f"inspect_limit must be within [1, {MAX_INSPECT_LIMIT}]",
                "inspect_limit",
            )
        if not 1 <= receive_limit <= MAX_RECEIVE_LIMIT:
            raise PolicyValidationError(
                f"receive_limit must be within [1, {MAX_RECEIVE_LIMIT}]",
                "receive_limit",
            )
        if inspect_limit > receive_limit:
            raise PolicyValidationError(
                "inspect_limit must not exceed receive_limit",
                "inspect_limit",
            )
        if not isinstance(content_check_enabled, bool):
            raise PolicyValidationError(
                "content_check_enabled must be a bool", "content_check_enabled"
            )
        return BodyPolicy(inspect_limit, receive_limit, content_check_enabled)


class PolicyStore:
    """保存当前生效策略快照，版本号单调递增。"""

    __slots__ = ("_lock", "_version", "_policy")

    def __init__(self, policy: BodyPolicy) -> None:
        if not isinstance(policy, BodyPolicy):
            raise PolicyValidationError("initial policy must be a BodyPolicy")
        self._lock = threading.Lock()
        self._version = 1
        self._policy = policy

    def snapshot(self) -> tuple[int, BodyPolicy]:
        """返回 (版本号, 策略)；策略不可变，可安全跨线程使用。"""
        with self._lock:
            return self._version, self._policy

    def replace(self, policy: BodyPolicy) -> int:
        """整体校验后原子替换，返回新版本号。

        非法策略抛 PolicyValidationError，当前生效版本保持不变。
        """
        if not isinstance(policy, BodyPolicy):
            raise PolicyValidationError("policy must be a BodyPolicy")
        # 即使调用方直接构造 BodyPolicy 也重新整体校验，杜绝绕过上限
        validated = BodyPolicy.validated(
            policy.inspect_limit,
            policy.receive_limit,
            policy.content_check_enabled,
        )
        with self._lock:
            self._version += 1
            self._policy = validated
            return self._version
