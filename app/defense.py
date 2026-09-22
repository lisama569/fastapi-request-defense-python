"""防护门面：限流 + 规则组合判定 + 审计，给出一致可解释的结论。

执行顺序与一致性：
1. 判定开始即对规则存储做一次快照（同一把锁内取得引擎与版本），
   整个请求使用同一版本规则，判定中即使规则集被替换也不影响本请求；
2. 限流检查在前：被限流的请求不再进入规则求值，结论与原因可区分，
   且每次请求在限流器中恰好计数一次（不重复扣减、不漏计）；
3. 规则引擎内部隔离规则异常；防护层自身的意外异常被兜底为
   SERVICE_ERROR，与规则故障 RULE_ERROR 严格区分，不混为一类；
4. 所有路径（含失败）都尝试写审计，保留输入摘要与依据。
"""

from __future__ import annotations

import logging
import time

from app.models import (
    DefenseVerdict,
    Decision,
    RateLimitReason,
    RequestFeatures,
    RuleSetSpec,
    VerdictReason,
)
from app.ratelimit import SlidingWindowRateLimiter
from app.rule_store import RuleStore

_DEGRADED_REASONS = frozenset(
    {
        VerdictReason.RULE_ERROR_DENY,
        VerdictReason.RULE_ERROR_ALLOW,
        VerdictReason.RULE_TIMEOUT_DENY,
        VerdictReason.RULE_TIMEOUT_ALLOW,
        VerdictReason.RULE_CAPACITY_DENY,
        VerdictReason.RULE_CAPACITY_ALLOW,
    }
)


class RequestDefense:
    def __init__(
        self,
        rate_limiter: SlidingWindowRateLimiter,
        rule_store: RuleStore,
        audit_logger,
        clock=time.monotonic,
    ) -> None:
        self._rl = rate_limiter
        self._store = rule_store
        self._audit = audit_logger
        self._clock = clock
        self._log = logging.getLogger("request_defense")

    def inspect(self, features: RequestFeatures) -> DefenseVerdict:
        started = self._clock()
        try:
            return self._inspect_locked_flow(features, started)
        except Exception as exc:
            # 防护层自身（非规则）故障：规则异常已在引擎内隔离，
            # 能走到这里的属于服务故障，与 RULE_ERROR 严格区分。
            self._log.exception("defense service failure: %s", exc)
            verdict = DefenseVerdict(
                decision=Decision.SERVICE_ERROR.value,
                reason=VerdictReason.SERVICE_FAILURE,
                source=features.source,
                rule_version=-1,
                elapsed_ms=(self._clock() - started) * 1000.0,
            )
            self._safe_audit(features, verdict)
            return verdict

    def _inspect_locked_flow(
        self, features: RequestFeatures, started: float
    ) -> DefenseVerdict:
        engine, version = self._store.snapshot()

        # 1) 限流（先计数，保证每次请求恰好一次）
        allowed, remaining, rl_reason = self._rl.check(features.source, started)
        if not allowed:
            verdict = DefenseVerdict(
                decision=Decision.RATE_LIMITED.value,
                reason=self._rate_reason(rl_reason),
                source=features.source,
                rule_version=version,
                remaining_quota=0,
                limit=self._rl.limit,
                window_seconds=self._rl.window_seconds,
                elapsed_ms=(self._clock() - started) * 1000.0,
            )
            self._safe_audit(features, verdict)
            return verdict

        # 2) 规则组合判定（规则故障已在引擎内隔离）
        decision, reason, traces, elapsed = engine.evaluate(features)
        verdict = DefenseVerdict(
            decision=decision,
            reason=reason,
            source=features.source,
            rule_version=version,
            traces=traces,
            remaining_quota=remaining,
            limit=self._rl.limit,
            window_seconds=self._rl.window_seconds,
            elapsed_ms=(self._clock() - started) * 1000.0,
            degraded=reason in _DEGRADED_REASONS,
        )
        self._safe_audit(features, verdict)
        return verdict

    def replace_ruleset(self, spec: RuleSetSpec) -> int:
        return self._store.replace(spec)

    @staticmethod
    def _rate_reason(rl_reason: str) -> str:
        if rl_reason == RateLimitReason.QUOTA_EXHAUSTED.value:
            return VerdictReason.RL_QUOTA_EXHAUSTED
        return rl_reason

    def _safe_audit(self, features, verdict) -> None:
        try:
            self._audit.record(features, verdict)
        except Exception:
            # 审计失败不得影响判定结论；记录到服务日志即可
            self._log.exception("audit recording failed")
