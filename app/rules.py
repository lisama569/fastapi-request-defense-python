"""请求特征规则与组合判定引擎。

规则模型（声明式）：
- ``field_name`` 指定取值来源：path / method / source / header:<名> /
  query:<名> / body_digest；
- ``operator`` 相对于 expected 的比较：eq / ne / prefix / suffix /
  contains / regex / in（逗号分隔白名单）；
- ``action`` 为命中后的处置倾向：allow / deny；
- ``priority`` 数值越小优先级越高，同优先级按 rule_id 字典序，保证冲突时
  结论唯一确定。

组合语义：
- 启用规则按优先级依次求值；**优先级最高的命中规则**决定动作，allow/deny
  规则同时命中（冲突）时由此得到唯一确定结论；
- 无命中且无决定性故障 -> 放行（默认允许），原因 no_rule_matched；
- 单条规则抛异常被隔离为该规则的 error 轨迹，其余规则正常参与；
- 故障（异常 / 预算超时跳过 / 超容量跳过）若位于不劣于最高命中规则的
  优先级，则结论不确定并按策略降级：fail_closed -> rule_error 拒绝；
  fail_open -> 放行但原因可区分。位于最高命中之后的低优先级故障不影响结论。
"""

from __future__ import annotations

import re
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from concurrent.futures import TimeoutError as FuturesTimeoutError

from app.config import FAIL_CLOSED, FAIL_OPEN
from app.models import (
    Decision,
    RuleAction,
    RuleDef,
    RuleOutcome,
    RuleSetSpec,
    RuleTrace,
    RequestFeatures,
    VerdictReason,
)


class RuleEvaluationError(Exception):
    """单条规则求值阶段的错误（坏规则，而非服务故障）。"""


class RuleSetValidationError(ValueError):
    """规则集任一条非法即抛此异常，规则集必须整体拒绝、不得半更新。"""


_OPERATORS = frozenset({"eq", "ne", "prefix", "suffix", "contains", "regex", "in"})
_SCALAR_FIELDS = frozenset({"path", "method", "source", "body_digest"})
_PREFIXED_FIELDS = ("header:", "query:")
_FAULT_OUTCOMES = frozenset(
    {
        RuleOutcome.ERROR.value,
        RuleOutcome.SKIPPED_TIMEOUT.value,
        RuleOutcome.SKIPPED_CAPACITY.value,
    }
)


def _extract_value(features: RequestFeatures, field_name: str) -> str:
    if field_name in _SCALAR_FIELDS:
        return getattr(features, field_name)
    if field_name.startswith("header:"):
        return features.headers.get(field_name[len("header:"):].lower(), "")
    if field_name.startswith("query:"):
        return features.query.get(field_name[len("query:"):], "")
    raise RuleEvaluationError(f"unknown field: {field_name!r}")


class Rule:
    """一条可求值规则；测试可通过子类化注入异常/延迟。"""

    def __init__(self, definition: RuleDef) -> None:
        self._def = definition

    @property
    def definition(self) -> RuleDef:
        return self._def

    @property
    def rule_id(self) -> str:
        return self._def.rule_id

    @property
    def priority(self) -> int:
        return self._def.priority

    @property
    def action(self) -> str:
        return self._def.action

    def _compare(self, actual: str) -> bool:
        op = self._def.operator
        expected = self._def.expected
        if op == "eq":
            return actual == expected
        if op == "ne":
            return actual != expected
        if op == "prefix":
            return actual.startswith(expected)
        if op == "suffix":
            return actual.endswith(expected)
        if op == "contains":
            return expected in actual
        if op == "regex":
            return re.search(expected, actual) is not None
        if op == "in":
            return actual in expected.split(",")
        raise RuleEvaluationError(f"unsupported operator: {op!r}")

    def evaluate(self, features: RequestFeatures) -> bool:
        try:
            actual = _extract_value(features, self._def.field_name)
            return self._compare(actual)
        except RuleEvaluationError:
            raise
        except Exception as exc:  # 正则运行期错误等归类为规则故障
            raise RuleEvaluationError(f"{self._def.rule_id}: {exc}") from exc


def build_rule(definition: RuleDef) -> Rule:
    return Rule(definition)


def validate_definition(defn: RuleDef) -> None:
    if not isinstance(defn.rule_id, str) or not defn.rule_id.strip():
        raise RuleSetValidationError("rule_id must be a non-empty string")
    if not isinstance(defn.priority, int) or isinstance(defn.priority, bool):
        raise RuleSetValidationError(f"{defn.rule_id}: priority must be int")
    if defn.action not in (RuleAction.ALLOW.value, RuleAction.DENY.value):
        raise RuleSetValidationError(f"{defn.rule_id}: action must be allow/deny")
    field_name = defn.field_name
    if not (
        field_name in _SCALAR_FIELDS
        or any(field_name.startswith(p) for p in _PREFIXED_FIELDS)
    ):
        raise RuleSetValidationError(
            f"{defn.rule_id}: invalid field_name {field_name!r}"
        )
    for prefix in _PREFIXED_FIELDS:
        if field_name.startswith(prefix) and not field_name[len(prefix):]:
            raise RuleSetValidationError(
                f"{defn.rule_id}: empty {prefix.rstrip(':')} name"
            )
    if defn.operator not in _OPERATORS:
        raise RuleSetValidationError(
            f"{defn.rule_id}: invalid operator {defn.operator!r}"
        )
    if not isinstance(defn.expected, str):
        raise RuleSetValidationError(f"{defn.rule_id}: expected must be string")
    if defn.operator == "regex":
        try:
            re.compile(defn.expected)
        except re.error as exc:
            raise RuleSetValidationError(
                f"{defn.rule_id}: invalid regex: {exc}"
            ) from exc


def validate_ruleset(spec: RuleSetSpec, max_rules: int) -> None:
    """整体校验：任一条非法即抛异常，调用方不得让规则集进入半更新。"""
    seen: set[str] = set()
    enabled = 0
    for defn in spec.rules:
        if defn.rule_id in seen:
            raise RuleSetValidationError(f"duplicate rule_id: {defn.rule_id}")
        seen.add(defn.rule_id)
        validate_definition(defn)
        if defn.enabled:
            enabled += 1
    if enabled > max_rules:
        raise RuleSetValidationError(
            f"enabled rules {enabled} exceed capacity {max_rules}"
        )


def _sort_key(rule: Rule) -> tuple[int, str]:
    return rule.priority, rule.rule_id


def _safe_release(sem: "threading.BoundedSemaphore") -> None:
    """释放信号量；重复释放（理论上不应发生）不得打挂判定流程。"""
    try:
        sem.release()
    except ValueError:
        pass


class RuleEngine:
    """按优先级组合判定；隔离单规则故障；超限时确定性降级。

    单规则求值通过“有界线程池 + 与池等大的非阻塞信号量”执行：获得槽位
    才提交任务，池满立即按容量故障降级，任务不在队列中堆积（排队耗时不
    计入请求预算，避免把排队误判为规则超时）；池满/超预算均按既定策略
    确定性降级，绝不无界占用线程或内存。
    """

    def __init__(
        self,
        rules: tuple[Rule, ...],
        version: int,
        max_rules: int,
        budget_seconds: float,
        on_error: str,
        executor: ThreadPoolExecutor | None = None,
        slots: "threading.BoundedSemaphore | None" = None,
        max_workers: int | None = None,
    ) -> None:
        if on_error not in (FAIL_CLOSED, FAIL_OPEN):
            raise ValueError("on_error must be fail_closed/fail_open")
        self._rules = tuple(sorted(rules, key=_sort_key))
        self._version = version
        self._max_rules = max_rules
        self._budget = float(budget_seconds)
        self._on_error = on_error
        self._owns_executor = executor is None
        if executor is not None:
            self._executor = executor
        else:
            import os

            workers = max_workers or min(8, (os.cpu_count() or 2) + 2)
            self._executor = ThreadPoolExecutor(
                max_workers=workers, thread_name_prefix="rule-eval"
            )
        self._slots = slots or threading.BoundedSemaphore(
            self._executor._max_workers
        )

    def close(self) -> None:
        """关闭自有的求值线程池（规则集替换时调用，避免资源泄漏）。"""
        if self._owns_executor:
            self._executor.shutdown(wait=False, cancel_futures=True)

    @property
    def version(self) -> int:
        return self._version

    @property
    def rules(self) -> tuple[Rule, ...]:
        return self._rules

    def evaluate(
        self, features: RequestFeatures
    ) -> tuple[str, str, tuple[RuleTrace, ...], float]:
        """返回 ``(decision, reason, traces, elapsed_seconds)``。"""
        started = time.monotonic()
        deadline = started + self._budget
        traces: list[RuleTrace] = []

        best_match: Rule | None = None  # 排序列表中第一个命中即最高优先级命中
        fault_kind: str | None = None   # error / timeout / capacity（记录最早出现）

        for index, rule in enumerate(self._rules):
            if index >= self._max_rules:
                fault_kind = fault_kind or "capacity"
                traces.append(
                    RuleTrace(
                        rule_id=rule.rule_id,
                        priority=rule.priority,
                        outcome=RuleOutcome.SKIPPED_CAPACITY.value,
                        detail=f"rule capacity {self._max_rules} reached",
                    )
                )
                continue

            if time.monotonic() >= deadline:
                fault_kind = fault_kind or "timeout"
                traces.append(
                    RuleTrace(
                        rule_id=rule.rule_id,
                        priority=rule.priority,
                        outcome=RuleOutcome.SKIPPED_TIMEOUT.value,
                        detail=f"budget {self._budget * 1000:.1f}ms exceeded",
                    )
                )
                continue

            remaining = deadline - time.monotonic()
            if not self._slots.acquire(blocking=False):
                # 求值槽位耗尽：立即按容量故障降级，不排队、不阻塞
                if best_match is None:
                    fault_kind = fault_kind or "capacity"
                traces.append(
                    RuleTrace(
                        rule_id=rule.rule_id,
                        priority=rule.priority,
                        outcome=RuleOutcome.SKIPPED_CAPACITY.value,
                        detail="rule evaluation slots exhausted",
                    )
                )
                continue

            try:
                future = self._executor.submit(rule.evaluate, features)
            except RuntimeError as exc:
                # 提交阶段失败：线程池已关闭等服务侧资源问题 -> 容量故障
                self._slots.release()
                if best_match is None:
                    fault_kind = fault_kind or "capacity"
                traces.append(
                    RuleTrace(
                        rule_id=rule.rule_id,
                        priority=rule.priority,
                        outcome=RuleOutcome.SKIPPED_CAPACITY.value,
                        detail=f"executor unavailable: {type(exc).__name__}",
                    )
                )
                continue

            try:
                matched = future.result(timeout=remaining)
            except FuturesTimeoutError:
                if not future.running():
                    # 任务从未开始执行（在排队等待 worker）：属于资源容量受限
                    # 而非规则自身慢，归为容量故障。槽位仍由该排队任务持有，
                    # 任务结束/被取消时由回调释放，避免双释放。
                    if best_match is None:
                        fault_kind = fault_kind or "capacity"
                    traces.append(
                        RuleTrace(
                            rule_id=rule.rule_id,
                            priority=rule.priority,
                            outcome=RuleOutcome.SKIPPED_CAPACITY.value,
                            detail="rule never started within budget (eval backlog)",
                        )
                    )
                    future.add_done_callback(lambda _f: _safe_release(self._slots))
                    continue
                # 规则确实开始执行但超时：槽位移交给后台任务，任务结束时释放；
                # 请求线程不等待，后台线程数量受线程池容量约束而有界。
                future.add_done_callback(lambda _f: _safe_release(self._slots))
                if best_match is None:
                    fault_kind = fault_kind or "timeout"
                traces.append(
                    RuleTrace(
                        rule_id=rule.rule_id,
                        priority=rule.priority,
                        outcome=RuleOutcome.SKIPPED_TIMEOUT.value,
                        detail=f"rule exceeded remaining budget {remaining * 1000:.1f}ms",
                    )
                )
                continue
            except Exception as exc:
                self._slots.release()
                traces.append(
                    RuleTrace(
                        rule_id=rule.rule_id,
                        priority=rule.priority,
                        outcome=RuleOutcome.ERROR.value,
                        detail=f"{type(exc).__name__}: {exc}"[:300],
                    )
                )
                if best_match is None:
                    # 尚无命中：该故障位于（或可能位于）决定性位置
                    fault_kind = fault_kind or "error"
                continue
            else:
                self._slots.release()

            if matched and best_match is None:
                best_match = rule
                traces.append(
                    RuleTrace(
                        rule_id=rule.rule_id,
                        priority=rule.priority,
                        outcome=(
                            RuleOutcome.MATCH_DENY.value
                            if rule.action == RuleAction.DENY.value
                            else RuleOutcome.MATCH_ALLOW.value
                        ),
                        detail=f"highest-priority match -> {rule.action}",
                    )
                )
            else:
                traces.append(
                    RuleTrace(
                        rule_id=rule.rule_id,
                        priority=rule.priority,
                        outcome=RuleOutcome.NO_MATCH.value,
                    )
                )

        elapsed = time.monotonic() - started

        decisive_fault: str | None = None
        if best_match is None:
            decisive_fault = fault_kind
        elif fault_kind is not None and self._fault_precedes_match(
            traces, best_match
        ):
            decisive_fault = fault_kind

        return self._conclude(best_match, decisive_fault) + (tuple(traces), elapsed)

    @staticmethod
    def _fault_precedes_match(
        traces: list[RuleTrace], best_match: Rule
    ) -> bool:
        for tr in traces:
            if tr.rule_id == best_match.rule_id:
                return False
            if tr.outcome in _FAULT_OUTCOMES:
                return True
        return False

    def _conclude(
        self, best_match: Rule | None, fault_kind: str | None
    ) -> tuple[str, str]:
        if fault_kind is None:
            if best_match is None:
                return Decision.ALLOW.value, VerdictReason.NO_RULE_MATCHED
            if best_match.action == RuleAction.DENY.value:
                return Decision.DENY.value, VerdictReason.RULE_MATCH_DENY
            return Decision.ALLOW.value, VerdictReason.RULE_MATCH_ALLOW

        # 存在决定性故障：按降级策略，原因可区分
        if self._on_error == FAIL_CLOSED:
            decision = Decision.RULE_ERROR.value
            if fault_kind == "timeout":
                return decision, VerdictReason.RULE_TIMEOUT_DENY
            if fault_kind == "capacity":
                return decision, VerdictReason.RULE_CAPACITY_DENY
            return decision, VerdictReason.RULE_ERROR_DENY

        if fault_kind == "timeout":
            return Decision.ALLOW.value, VerdictReason.RULE_TIMEOUT_ALLOW
        if fault_kind == "capacity":
            return Decision.ALLOW.value, VerdictReason.RULE_CAPACITY_ALLOW
        return Decision.ALLOW.value, VerdictReason.RULE_ERROR_ALLOW
