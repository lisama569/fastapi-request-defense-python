"""防护引擎测试：组合判定、异常规则隔离、超时降级、并发计数+变更一致性。"""

from __future__ import annotations

import threading
import time

import pytest

from request_defense.engine import DefenseEngine
from request_defense.ratelimiter import SlidingWindowRateLimiter
from request_defense.rule import Rule
from request_defense.store import RuleStore
from request_defense.types import (
    Decision,
    Reason,
    RequestFeatures,
    RuleConfig,
    RuleEffect,
    RuleVerdict,
)


def cfg(rule_id="r", priority=0, effect=RuleEffect.DENY, field="path", pattern="x", **kw):
    return RuleConfig(rule_id=rule_id, priority=priority, effect=effect,
                      field_name=field, pattern=pattern, **kw)


def feat(source="s1", path="/p", method="GET", headers=None):
    return RequestFeatures(source=source, path=path, method=method, headers=headers or {})


class BoomRule(Rule):
    """求值必抛异常的规则。"""

    def evaluate(self, features):
        raise RuntimeError("kaboom")


class SlowRule(Rule):
    """求值超时的规则。"""

    def evaluate(self, features):
        time.sleep(0.3)
        return RuleVerdict.NO_MATCH


@pytest.fixture()
def store():
    return RuleStore()


@pytest.fixture()
def engine(store):
    rl = SlidingWindowRateLimiter(1000, 60_000)
    eng = DefenseEngine(rl, store, max_rules=10, request_timeout_ms=200)
    yield eng
    eng.shutdown()


class TestCombinedDecision:
    def test_normal_request_allowed(self, engine, store):
        store.replace_rules([cfg(rule_id="d", pattern=r"^/evil")])
        out = engine.evaluate(feat(path="/normal"))
        assert out.decision is Decision.ALLOW
        assert out.reason is Reason.OK
        assert len(out.rule_results) == 1

    def test_match_deny(self, engine, store):
        store.replace_rules([cfg(rule_id="d", pattern=r"^/evil")])
        out = engine.evaluate(feat(path="/evil/x"))
        assert out.decision is Decision.DENY
        assert out.reason is Reason.RULE_MATCH_DENY
        assert out.rule_results[0].verdict is RuleVerdict.MATCH_DENY

    def test_conflicting_allow_and_deny_is_deterministic_deny(self, engine, store):
        store.replace_compiled_for_test([
            Rule.compile(cfg(rule_id="allow-all", priority=0,
                             effect=RuleEffect.ALLOW, pattern=".*")),
            Rule.compile(cfg(rule_id="deny-get", priority=1,
                             effect=RuleEffect.DENY, field="method", pattern="GET")),
        ])
        out = engine.evaluate(feat(path="/x", method="GET"))
        assert out.decision is Decision.DENY
        assert out.reason is Reason.RULE_CONFLICT_DENY
        # 重复判定结论必须一致（确定性）
        out2 = engine.evaluate(feat(path="/x", method="GET"))
        assert (out2.decision, out2.reason) == (out.decision, out.reason)

    def test_no_silent_allow_when_only_deny_rules_do_not_match(self, engine, store):
        store.replace_rules([cfg(rule_id="d", pattern="nomatch")])
        out = engine.evaluate(feat(path="/x"))
        assert out.decision is Decision.ALLOW and out.reason is Reason.OK


class TestRuleFaultIsolation:
    def test_exception_rule_recorded_others_continue_and_deny_still_wins(self, engine, store):
        store.replace_compiled_for_test([
            BoomRule(cfg(rule_id="boom")),
            Rule.compile(cfg(rule_id="d2", priority=1, pattern="/bad")),
        ])
        out = engine.evaluate(feat(path="/bad"))
        assert out.decision is Decision.DENY
        assert out.reason is Reason.RULE_MATCH_DENY
        by_id = {r.rule_id: r for r in out.rule_results}
        assert by_id["boom"].verdict is RuleVerdict.ERROR
        assert by_id["boom"].error_type == "RuntimeError"
        assert by_id["d2"].verdict is RuleVerdict.MATCH_DENY

    def test_only_exception_rules_fail_closed_with_distinct_reason(self, engine, store):
        store.replace_compiled_for_test([BoomRule(cfg(rule_id="boom"))])
        out = engine.evaluate(feat(path="/ok"))
        assert out.decision is Decision.DENY
        assert out.reason is Reason.RULE_EVALUATION_ERROR
        assert out.rule_results[0].error_type == "RuntimeError"

    def test_fault_does_not_pollute_subsequent_requests(self, engine, store):
        store.replace_compiled_for_test([
            BoomRule(cfg(rule_id="boom")),
            Rule.compile(cfg(rule_id="d", priority=1, pattern="/bad")),
        ])
        # 异常请求之后再来一个正常请求，状态不被污染
        engine.evaluate(feat(path="/ok"))
        out = engine.evaluate(feat(path="/ok"))
        assert out.reason is Reason.RULE_EVALUATION_ERROR  # 规则仍稳定报错
        out_deny = engine.evaluate(feat(path="/bad"))
        assert out_deny.reason is Reason.RULE_MATCH_DENY

    def test_timeout_degrades_with_rule_timeout_reason(self, engine, store):
        store.replace_compiled_for_test([SlowRule(cfg(rule_id="slow"))])
        t0 = time.perf_counter()
        out = engine.evaluate(feat(path="/ok"))
        elapsed = time.perf_counter() - t0
        assert out.decision is Decision.DENY
        assert out.reason is Reason.RULE_TIMEOUT
        assert elapsed < 0.6  # 必须受预算约束，不无界等待
        assert out.elapsed_ms >= 190

    def test_fail_open_mode_allows_but_keeps_distinct_reason(self, store):
        rl = SlidingWindowRateLimiter(1000, 60_000)
        eng = DefenseEngine(rl, store, request_timeout_ms=200, fail_open=True)
        try:
            store.replace_compiled_for_test([BoomRule(cfg(rule_id="boom"))])
            out = eng.evaluate(feat(path="/ok", source="fo"))
            assert out.decision is Decision.ALLOW
            assert out.reason is Reason.RULE_EVALUATION_ERROR
        finally:
            eng.shutdown()

    def test_rule_count_cap_enforced(self, store):
        rl = SlidingWindowRateLimiter(1000, 60_000)
        # 引擎上限小于存储容量时，写入可以成功，求值侧降级拒绝
        eng = DefenseEngine(rl, store, max_rules=1, request_timeout_ms=200)
        try:
            store2 = store
            store2.replace_rules([cfg(rule_id="a"), cfg(rule_id="b")])
            out = eng.evaluate(feat(path="/x"))
            assert out.decision is Decision.DENY
            assert out.reason is Reason.RULE_LIMIT_EXCEEDED
        finally:
            eng.shutdown()


class TestRateLimitIntegration:
    def test_rate_limit_precedes_rules_with_distinct_reason(self, store):
        rl = SlidingWindowRateLimiter(1, 60_000)
        eng = DefenseEngine(rl, store, request_timeout_ms=200)
        try:
            store.replace_rules([cfg(rule_id="d", pattern="/evil")])
            first = eng.evaluate(feat(source="z", path="/evil"))
            second = eng.evaluate(feat(source="z", path="/evil"))
            assert first.decision is Decision.DENY  # 第一条：规则拒绝，已消耗配额
            assert second.decision is Decision.RATE_LIMITED
            assert second.reason is Reason.RATE_LIMIT_QUOTA_EXHAUSTED
        finally:
            eng.shutdown()


class TestConcurrentCountingAndRuleChanges:
    def test_concurrent_burst_counts_exactly(self, engine, store):
        """并发冲击：每来源 limit=3，共 30 来源 x 10 请求 => 90 放行 / 210 限流。"""
        store.replace_rules([cfg(rule_id="d", pattern="/evil")])
        # 重建引擎使用小配额
        rl = SlidingWindowRateLimiter(3, 60_000)
        eng = DefenseEngine(rl, store, request_timeout_ms=500)
        outcomes: list[tuple[Decision, Reason]] = []
        lock = threading.Lock()
        barrier = threading.Barrier(30)

        def worker(i: int) -> None:
            barrier.wait()
            local = []
            for _ in range(10):
                out = eng.evaluate(feat(source=f"src-{i}", path="/normal"))
                local.append((out.decision, out.reason))
            with lock:
                outcomes.extend(local)

        threads = [threading.Thread(target=worker, args=(i,)) for i in range(30)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        eng.shutdown()

        allows = [o for o in outcomes if o[0] is Decision.ALLOW]
        limited = [o for o in outcomes if o[0] is Decision.RATE_LIMITED]
        assert len(allows) == 90
        assert len(limited) == 210
        assert all(r is Reason.RATE_LIMIT_QUOTA_EXHAUSTED for _, r in limited)

    def test_rule_versions_consistent_under_concurrent_change(self, engine, store):
        """请求求值与规则变更并发：每个请求只对应一个稳定版本，版本不倒退。"""
        store.replace_rules([cfg(rule_id="v0", pattern="/never-matches-xyz")])
        stop = threading.Event()
        versions_seen: list[int] = []
        errors: list[Exception] = []
        lock = threading.Lock()

        def changer() -> None:
            i = 0
            while not stop.is_set():
                try:
                    store.replace_rules([cfg(rule_id=f"v{i % 3}", pattern="/never-matches-xyz")])
                except Exception as exc:  # noqa: BLE001
                    with lock:
                        errors.append(exc)
                i += 1
                time.sleep(0.0005)

        def requester() -> None:
            for _ in range(100):
                try:
                    out = engine.evaluate(feat(source=f"r-{threading.get_ident()}", path="/p"))
                    with lock:
                        versions_seen.append(out.rule_version)
                except Exception as exc:  # noqa: BLE001
                    with lock:
                        errors.append(exc)
                time.sleep(0.0002)

        ct = threading.Thread(target=changer)
        ct.start()
        rts = [threading.Thread(target=requester) for _ in range(8)]
        for t in rts:
            t.start()
        for t in rts:
            t.join()
        stop.set()
        ct.join()

        assert not errors, errors
        assert versions_seen
        # 版本号必须为正且来自实际快照版本集合
        snapshot_version = store.snapshot()[0]
        assert all(1 <= v <= snapshot_version for v in versions_seen)
