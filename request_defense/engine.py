"""防护引擎：限流 + 多规则组合判定。

决策顺序（确定、可解释）：
  1. 滑动窗口限流：配额耗尽 -> RATE_LIMITED / rate_limit_quota_exhausted（429），
     被限流的请求不进入规则求值；
  2. 规则数量上限：超过 max_rules -> DENY / rule_limit_exceeded（403）；
  3. 按 (priority, rule_id) 顺序在总时间预算内逐条求值：
       - 单条规则抛异常 => 该规则记为 error（带异常类型），其余规则继续；
       - 单条规则超时 => 该规则记为 timeout，其余规则继续；
  4. 组合结论：
       MATCH_DENY 与 MATCH_ALLOW 同时命中 => DENY / rule_conflict_deny（冲突从严，确定）
       仅 MATCH_DENY                        => DENY / rule_match_deny
       无命中、无错误                        => ALLOW / ok
       有错误无拒绝（默认 fail-closed）       => DENY / rule_evaluation_error|rule_timeout
  5. 引擎自身故障（线程池不可用等）与规则故障严格区分：
       => DENY / engine_internal_error（500）。

一致性：整次求值只读取规则快照的不可变元组，规则无状态，
因此单条规则失败/超时不会残留部分判定状态；并发变更规则时，
本次请求始终对应同一个 rule_version，不存在版本回退/混用。
"""

from __future__ import annotations

import dataclasses
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from concurrent.futures import TimeoutError as FutureTimeout
from typing import Callable

from . import audit
from .ratelimiter import SlidingWindowRateLimiter
from .rule import Rule
from .store import RuleStore
from .types import (
    Decision,
    DefenseDecision,
    Reason,
    RequestFeatures,
    RuleEvalResult,
    RuleVerdict,
)

_WORKERS = 4
_INFLIGHT_CAP = 8  # 排队中的求值上限，防止无界占用资源


class _EngineBusy(RuntimeError):
    """求值线程池/队列饱和：服务自身资源故障。"""


class DefenseEngine:
    def __init__(
        self,
        rate_limiter: SlidingWindowRateLimiter,
        rule_store: RuleStore,
        *,
        max_rules: int = 64,
        request_timeout_ms: int = 200,
        fail_open: bool = False,
        executor: ThreadPoolExecutor | None = None,
    ) -> None:
        if request_timeout_ms <= 0:
            raise ValueError("request_timeout_ms must be positive")
        self._rl = rate_limiter
        self._store = rule_store
        self._max_rules = max_rules
        self._timeout_ns = request_timeout_ms * 1_000_000
        self._fail_open = fail_open
        self._lock = threading.Lock()
        self._executor = executor
        self._owns_executor = executor is None
        self._slots = threading.BoundedSemaphore(_INFLIGHT_CAP)
        self._closed = False

    # ------------------------------------------------------------------ #
    # 资源管理
    # ------------------------------------------------------------------ #
    def _ensure_executor(self) -> ThreadPoolExecutor:
        with self._lock:
            if self._closed:
                raise _EngineBusy("engine closed")
            if self._executor is None:
                self._executor = ThreadPoolExecutor(
                    max_workers=_WORKERS,
                    thread_name_prefix="rule-eval",
                )
            return self._executor

    def shutdown(self) -> None:
        with self._lock:
            if self._closed:
                return
            self._closed = True
            executor = self._executor
        if executor is not None and self._owns_executor:
            executor.shutdown(wait=False, cancel_futures=True)

    # ------------------------------------------------------------------ #
    # 单规则求值（异常隔离 + 超时 + 资源有界）
    # ------------------------------------------------------------------ #
    def _eval_one(self, rule: Rule, features: RequestFeatures, deadline_ns: int) -> RuleEvalResult:
        cfg = rule.config
        remaining_s = max(0.0, (deadline_ns - time.perf_counter_ns())) / 1e9
        if remaining_s <= 0:
            return RuleEvalResult(
                cfg.rule_id, RuleVerdict.ERROR, cfg.priority, cfg.effect,
                error_type="budget_exhausted", elapsed_ms=0.0,
            )
        started = time.perf_counter_ns()
        try:
            executor = self._ensure_executor()
        except (_EngineBusy, RuntimeError):
            raise  # 服务自身故障，交由上层归类为 engine_internal_error

        acquired = self._slots.acquire(timeout=remaining_s)
        if not acquired:
            raise _EngineBusy("rule eval queue saturated")
        try:
            future = executor.submit(rule.evaluate, features)
        except RuntimeError as exc:  # executor 已关闭/损坏
            self._slots.release()
            raise _EngineBusy(str(exc)) from exc

        def _release(_: object) -> None:
            try:
                self._slots.release()
            except ValueError:
                pass

        future.add_done_callback(_release)
        try:
            verdict = future.result(timeout=remaining_s)
        except FutureTimeout:
            future.cancel()
            elapsed = (time.perf_counter_ns() - started) / 1e6
            return RuleEvalResult(
                cfg.rule_id, RuleVerdict.ERROR, cfg.priority, cfg.effect,
                error_type="rule_timeout", elapsed_ms=elapsed,
            )
        except Exception as exc:  # 规则自身故障：隔离，不影响其他规则
            elapsed = (time.perf_counter_ns() - started) / 1e6
            return RuleEvalResult(
                cfg.rule_id, RuleVerdict.ERROR, cfg.priority, cfg.effect,
                error_type=type(exc).__name__, elapsed_ms=elapsed,
            )
        elapsed = (time.perf_counter_ns() - started) / 1e6
        return RuleEvalResult(cfg.rule_id, verdict, cfg.priority, cfg.effect, elapsed_ms=elapsed)

    # ------------------------------------------------------------------ #
    # 主入口
    # ------------------------------------------------------------------ #
    def evaluate(
        self,
        features: RequestFeatures,
        *,
        content_check_enabled: bool = True,
    ) -> DefenseDecision:
        """限流 + 规则组合判定（读请求与已接收正文的写请求共用）。

        保持历史行为：内部先限流后规则求值。带正文入口应在接收正文**之前**
        调用 ``reserve_quota``，再在接收后调用 ``decide_rules``，避免被
        限流的请求白白缓冲正文。
        """
        started = time.perf_counter_ns()
        version, rules = self._store.snapshot()

        rate = self._rl.try_acquire(features.source)
        rate_info = self._rate_info(rate)
        if not rate.allowed:
            return self._finish(
                started,
                version,
                features,
                Decision.RATE_LIMITED,
                Reason.RATE_LIMIT_QUOTA_EXHAUSTED,
                f"quota exhausted; retry_after_ms={rate.retry_after_ms}",
                rate_info=rate_info,
            )
        return self._decide_rules(
            started, version, rules, features, rate_info, content_check_enabled
        )

    @staticmethod
    def _rate_info(rl) -> dict:
        return {
            "allowed": rl.allowed,
            "remaining": rl.remaining,
            "limit": rl.limit,
            "window_ms": rl.window_ms,
            "retry_after_ms": rl.retry_after_ms,
        }

    def reserve_quota(
        self,
        features: RequestFeatures,
        *,
        policy_version: int = 0,
        started_ns: int | None = None,
    ) -> DefenseDecision | None:
        """正文接收前的来源限流判定。

        成功返回 None（配额已扣减）；被限流返回 RATE_LIMITED 结论，调用方
        必须立即拒绝且**不得**再调用规则判定/接收正文。
        """
        started = time.perf_counter_ns() if started_ns is None else started_ns
        version, _rules = self._store.snapshot()
        rl = self._rl.try_acquire(features.source)
        if not rl.allowed:
            features = _with_policy_version(features, policy_version)
            return self._finish(
                started,
                version,
                features,
                Decision.RATE_LIMITED,
                Reason.RATE_LIMIT_QUOTA_EXHAUSTED,
                f"quota exhausted; retry_after_ms={rl.retry_after_ms}",
                rate_info=self._rate_info(rl),
            )
        return None

    def reject_ingress(
        self,
        features: RequestFeatures,
        reason: Reason,
        detail: str,
        *,
        rate_info: dict | None = None,
        started_ns: int | None = None,
    ) -> DefenseDecision:
        """正文接收阶段的早拒绝（太大/检查不完整/超时/容量饱和/断开）。

        与限流、规则拒绝走完全一致的审计口径；此时不进行规则求值。
        """
        started = time.perf_counter_ns() if started_ns is None else started_ns
        version, _rules = self._store.snapshot()
        return self._finish(
            started,
            version,
            features,
            Decision.DENY,
            reason,
            detail,
            rate_info=rate_info,
        )

    def decide_rules(
        self,
        features: RequestFeatures,
        *,
        rate_info: dict,
        content_check_enabled: bool = True,
        started_ns: int | None = None,
    ) -> DefenseDecision:
        """正文接收后的规则组合判定（配额已由 reserve_quota 扣减）。"""
        started = time.perf_counter_ns() if started_ns is None else started_ns
        version, rules = self._store.snapshot()
        return self._decide_rules(
            started, version, rules, features, rate_info, content_check_enabled
        )

    # ------------------------------------------------------------------ #
    # 内部：审计收口与规则求值
    # ------------------------------------------------------------------ #
    def _finish(
        self,
        started_ns: int,
        version: int,
        features: RequestFeatures,
        decision: Decision,
        reason: Reason,
        detail: str,
        results: list[RuleEvalResult] | None = None,
        rate_info: dict | None = None,
    ) -> DefenseDecision:
        elapsed = (time.perf_counter_ns() - started_ns) / 1e6
        outcome = DefenseDecision(
            decision=decision,
            reason=reason,
            source=features.source,
            rule_results=tuple(results or ()),
            detail=detail,
            elapsed_ms=elapsed,
            rule_version=version,
            content_policy_version=features.content_policy_version,
        )
        record = audit.build_audit_record(
            source=features.source,
            method=features.method,
            path=features.path,
            headers=features.headers,
            query=features.query,
            body_summary=features.body_summary,
            decision=decision.value,
            reason=reason.value,
            detail=detail,
            rule_version=version,
            rule_results=[
                {
                    "rule_id": r.rule_id,
                    "verdict": r.verdict.value,
                    "priority": r.priority,
                    "effect": r.effect.value,
                    "error_type": r.error_type,
                    "elapsed_ms": round(r.elapsed_ms, 3),
                }
                for r in (results or ())
            ],
            rate_limit=rate_info,
            elapsed_ms=elapsed,
            body_length=features.body_length,
            body_fully_inspected=features.body_fully_inspected,
            content_policy_version=features.content_policy_version,
        )
        audit.log_decision(record)
        return outcome

    def _decide_rules(
        self,
        started: int,
        version: int,
        rules: tuple,
        features: RequestFeatures,
        rate_info: dict,
        content_check_enabled: bool,
    ) -> DefenseDecision:
        # 内容判定关闭时，body 类规则不参与求值（其余字段规则照常），
        # 避免在未检查正文上做出基于内容的错误判定。
        effective_rules = rules
        if not content_check_enabled:
            effective_rules = tuple(
                r for r in rules if r.config.field_name != "body"
            )

        # 2) 规则数量上限（纵深防御；store 在写入侧已拒绝超量规则集）
        if len(rules) > self._max_rules:
            return self._finish(
                started,
                version,
                features,
                Decision.DENY,
                Reason.RULE_LIMIT_EXCEEDED,
                f"rule count {len(rules)} exceeds max {self._max_rules}",
                rate_info=rate_info,
            )

        # 3) 逐条求值（异常/超时隔离）
        deadline = started + self._timeout_ns
        results: list[RuleEvalResult] = []
        engine_fault = ""
        for rule in effective_rules:
            try:
                results.append(self._eval_one(rule, features, deadline))
            except _EngineBusy as exc:
                engine_fault = str(exc)
                break

        elapsed_total = (time.perf_counter_ns() - started) / 1e6

        # 5) 服务自身故障：独立分类，绝不与规则故障混淆
        if engine_fault:
            return self._finish(
                started,
                version,
                features,
                Decision.DENY,
                Reason.ENGINE_INTERNAL_ERROR,
                f"rule evaluation infrastructure failure: {engine_fault}",
                results=results,
                rate_info=rate_info,
            )

        denies = [r for r in results if r.verdict is RuleVerdict.MATCH_DENY]
        allows = [r for r in results if r.verdict is RuleVerdict.MATCH_ALLOW]
        errors = [r for r in results if r.verdict is RuleVerdict.ERROR]
        timeouts = [r for r in errors if r.error_type in ("rule_timeout", "budget_exhausted")]
        other_errors = [r for r in errors if r not in timeouts]

        # 4a) 冲突从严且确定：allow 与 deny 同时命中
        if denies and allows:
            return self._finish(
                started,
                version,
                features,
                Decision.DENY,
                Reason.RULE_CONFLICT_DENY,
                "conflicting allow/deny rules matched; deny wins: "
                + ",".join(r.rule_id for r in denies),
                results=results,
                rate_info=rate_info,
            )
        # 4b) 明确拒绝
        if denies:
            return self._finish(
                started,
                version,
                features,
                Decision.DENY,
                Reason.RULE_MATCH_DENY,
                "matched deny rules: " + ",".join(r.rule_id for r in denies),
                results=results,
                rate_info=rate_info,
            )
        # 4c) 规则故障：默认 fail-closed；显式配置 fail_open 时降级放行但仍可解释
        if errors:
            if timeouts:
                reason = Reason.RULE_TIMEOUT
                detail = (
                    f"{len(timeouts)} rule(s) timed out within budget; "
                    f"other_errors={len(other_errors)}"
                )
            else:
                reason = Reason.RULE_EVALUATION_ERROR
                detail = "rule evaluation errors: " + ",".join(
                    f"{r.rule_id}:{r.error_type}" for r in other_errors
                )
            decision = Decision.ALLOW if self._fail_open else Decision.DENY
            return self._finish(
                started, version, features, decision, reason, detail,
                results=results, rate_info=rate_info,
            )

        # 4d) 无命中 => 放行（正常流量不被误拒）
        return self._finish(
            started,
            version,
            features,
            Decision.ALLOW,
            Reason.OK,
            f"no rule matched ({len(results)} evaluated) in {elapsed_total:.2f}ms",
            results=results,
            rate_info=rate_info,
        )


def _with_policy_version(
    features: RequestFeatures, policy_version: int
) -> RequestFeatures:
    """返回带内容策略版本的特征副本（frozen dataclass 不可原地修改）。"""
    if features.content_policy_version == policy_version:
        return features
    return dataclasses.replace(features, content_policy_version=policy_version)
