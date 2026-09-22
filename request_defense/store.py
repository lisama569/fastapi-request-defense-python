"""规则集存储：不可变快照 + 原子替换。

一致性保证：
  - 新规则集必须**整体**校验通过（编译、ID 唯一、非空、数量上限）后才替换；
  - 任何一条非法 -> 抛 RuleSetValidationError，旧版本继续生效，
    绝不会出现"部分规则已更新"的半更新状态；
  - 版本号单调递增，替换在同一把锁内完成，读取快照永远拿到一个完整版本；
  - 快照按 (priority, rule_id) 排序，使组合判定顺序确定。
"""

from __future__ import annotations

import threading

from .rule import Rule, RuleDefinitionError
from .types import RuleConfig


class RuleSetValidationError(ValueError):
    """非法或部分无效的规则集，整体拒绝，旧规则继续生效。"""

    def __init__(self, message: str, index: int | None = None) -> None:
        super().__init__(message)
        self.index = index


class RuleStore:
    """保存当前生效规则快照，版本号单调递增。"""

    __slots__ = ("_lock", "_version", "_rules", "_max_rules")

    def __init__(self, max_rules: int = 64) -> None:
        if max_rules <= 0:
            raise ValueError("max_rules must be positive")
        self._lock = threading.Lock()
        self._version = 0
        self._rules: tuple[Rule, ...] = ()
        self._max_rules = max_rules

    @property
    def max_rules(self) -> int:
        return self._max_rules

    def snapshot(self) -> tuple[int, tuple[Rule, ...]]:
        """返回 (版本号, 规则元组)；规则元组不可变，可安全并发遍历。"""
        with self._lock:
            return self._version, self._rules

    def replace_rules(self, configs: list[RuleConfig]) -> int:
        """整体校验后原子替换，返回新版本号。

        失败时抛 RuleSetValidationError，当前生效版本保持不变。
        """
        if not isinstance(configs, list):
            raise RuleSetValidationError("rules must be a list")
        if not configs:
            raise RuleSetValidationError("rule set must not be empty")
        if len(configs) > self._max_rules:
            raise RuleSetValidationError(
                f"rule count {len(configs)} exceeds max {self._max_rules}"
            )

        compiled: list[Rule] = []
        seen_ids: set[str] = set()
        for index, cfg in enumerate(configs):
            if not isinstance(cfg, RuleConfig):
                raise RuleSetValidationError(
                    f"item #{index}: must be RuleConfig", index
                )
            if cfg.rule_id in seen_ids:
                raise RuleSetValidationError(
                    f"duplicate rule_id: {cfg.rule_id!r}", index
                )
            seen_ids.add(cfg.rule_id)
            try:
                compiled.append(Rule.compile(cfg))
            except RuleDefinitionError as exc:
                raise RuleSetValidationError(str(exc), index) from exc

        # 只让启用的规则参与判定；停用通过配置 enabled=False 生效。
        active = [r for r in compiled if r.config.enabled]
        if not active:
            raise RuleSetValidationError("rule set has no enabled rules")
        active.sort(key=lambda r: (r.config.priority, r.config.rule_id))

        with self._lock:
            self._version += 1
            self._rules = tuple(active)
            return self._version

    def replace_compiled_for_test(
        self, rules: list[Rule], version: int | None = None
    ) -> int:
        """测试辅助：直接装入已编译规则（例如会抛异常的自定义规则）。"""
        ordered = sorted(rules, key=lambda r: (r.config.priority, r.config.rule_id))
        with self._lock:
            if version is not None:
                if version <= self._version:
                    raise ValueError("version must be greater than current")
                self._version = version
            else:
                self._version += 1
            self._rules = tuple(ordered)
            return self._version
