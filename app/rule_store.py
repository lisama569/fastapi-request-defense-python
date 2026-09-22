"""规则集运行时原子变更。

变更协议（杜绝半更新）：
1. 新规则集**先在局部变量上整体校验**（任一条非法即抛异常，锁内状态不触碰）；
2. 校验通过后在局部构建全部 Rule 对象；
3. 加锁后以单次属性赋值整体替换当前引擎，版本号单调 +1。

读侧通过 :meth:`snapshot` 在同一把锁内同时取得 (引擎, 版本)，
保证“用哪一版规则判定”与审计记录的版本严格一致，版本永不回退。

所有版本的引擎共享一个有界求值线程池：版本切换不创建/销毁线程池，
避免频繁变更造成线程泄漏；线程池容量即为规则求值的总并发上限。
"""

from __future__ import annotations

import os
import threading
from concurrent.futures import ThreadPoolExecutor

from app.config import DefenseConfig
from app.models import RuleSetSpec
from app.rules import RuleEngine, build_rule, validate_ruleset

class RuleStore:
    def __init__(
        self,
        config: DefenseConfig,
        initial: RuleSetSpec | None = None,
        executor: ThreadPoolExecutor | None = None,
    ) -> None:
        self._config = config
        self._lock = threading.Lock()
        self._owns_executor = executor is None
        if executor is None:
            workers = min(32, (os.cpu_count() or 2) + 4)
            executor = ThreadPoolExecutor(
                max_workers=workers, thread_name_prefix="rule-eval"
            )
        self._executor = executor
        # 与池等大的求值信号量：所有版本共享，版本切换不重建
        self._slots = threading.BoundedSemaphore(executor._max_workers)
        spec = initial or RuleSetSpec()
        validate_ruleset(spec, config.max_rules)
        self._engine = self._build(spec, version=0)

    def _build(self, spec: RuleSetSpec, version: int) -> RuleEngine:
        rules = tuple(build_rule(d) for d in spec.rules if d.enabled)
        return RuleEngine(
            rules=rules,
            version=version,
            max_rules=self._config.max_rules,
            budget_seconds=self._config.per_request_budget_ms / 1000.0,
            on_error=self._config.on_rule_error,
            executor=self._executor,
            slots=self._slots,
        )

    def close(self) -> None:
        if self._owns_executor:
            self._executor.shutdown(wait=False, cancel_futures=True)

    @property
    def version(self) -> int:
        with self._lock:
            return self._engine.version

    def current(self) -> RuleEngine:
        with self._lock:
            return self._engine

    def snapshot(self) -> tuple[RuleEngine, int]:
        with self._lock:
            return self._engine, self._engine.version

    def replace(self, spec: RuleSetSpec) -> int:
        """校验并整体替换；非法规则集抛异常且当前版本保持不变。"""
        if not isinstance(spec, RuleSetSpec):
            raise TypeError("spec must be RuleSetSpec")
        # 锁外完成重活：整体校验 + 构建，失败不影响在效规则
        validate_ruleset(spec, self._config.max_rules)
        with self._lock:
            new_version = self._engine.version + 1
            new_engine = self._build(spec, new_version)
            self._engine = new_engine  # 单次赋值：读侧只见旧版或新版
            return new_version
