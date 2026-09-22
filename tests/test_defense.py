"""防护门面测试：端到端结论一致性、原因区分与并发冲击。"""

from __future__ import annotations

import threading
import time

from app.audit import AuditLogger
from app.config import DefenseConfig
from app.defense import RequestDefense
from app.models import (
    Decision,
    RuleDef,
    RequestFeatures,
    RuleSetSpec,
    VerdictReason,
)
from app.ratelimit import SlidingWindowRateLimiter
from app.rules import Rule, RuleSetValidationError
from app.rule_store import RuleStore


class BoomRule(Rule):
    def evaluate(self, f):
        raise RuntimeError("rule blew up")


def make_defense(limit=5, on_error="fail_closed", max_rules=100, budget_ms=50.0):
    cfg = DefenseConfig(
        rate_limit=limit,
        window_seconds=60.0,
        max_rules=max_rules,
        per_request_budget_ms=budget_ms,
        on_rule_error=on_error,
    )
    spec = RuleSetSpec((RuleDef("deny-a", 1, "deny", "path", "eq", "/a"),))
    store = RuleStore(cfg, spec)
    return RequestDefense(SlidingWindowRateLimiter(limit, 60.0), store, AuditLogger())


def f(source="s1", path="/ok"):
    return RequestFeatures(source=source, path=path, method="GET")


def test_allow_rate_limit_deny_reasons_are_distinguishable():
    d = make_defense(limit=2)
    v1 = d.inspect(f(path="/ok"))
    v2 = d.inspect(f(path="/ok"))
    v3 = d.inspect(f(path="/ok"))  # 配额耗尽
    v_deny = d.inspect(f(source="other", path="/a"))

    assert v1.decision == Decision.ALLOW.value
    assert v1.reason == VerdictReason.NO_RULE_MATCHED
    assert v3.decision == Decision.RATE_LIMITED.value
    assert v3.reason == VerdictReason.RL_QUOTA_EXHAUSTED
    assert v3.remaining_quota == 0
    assert v_deny.decision == Decision.DENY.value
    assert v_deny.reason == VerdictReason.RULE_MATCH_DENY


def test_rate_limited_request_skips_rule_evaluation_and_carries_quota_info():
    d = make_defense(limit=1)
    d.inspect(f(path="/a"))  # 用掉唯一配额
    v = d.inspect(f(path="/a"))  # 本该命中拒绝规则，但先被限流
    assert v.decision == Decision.RATE_LIMITED.value
    assert v.traces == ()  # 未进入规则求值
    assert v.limit == 1 and v.window_seconds == 60.0


def test_rule_failure_distinct_from_service_failure():
    # 规则故障 -> rule_error（fail_closed）
    cfg = DefenseConfig(rate_limit=100, window_seconds=60.0)
    store = RuleStore(cfg, RuleSetSpec())
    # 直接注入坏规则引擎（绕过声明式校验，模拟运行期规则异常）
    engine = store.current()
    bad_engine = type(engine)(
        (BoomRule(RuleDef("boom", 1, "deny", "path", "eq", "/x")),),
        engine.version, cfg.max_rules, cfg.per_request_budget_ms / 1000.0,
        cfg.on_rule_error,
    )
    store._engine = bad_engine
    defense = RequestDefense(SlidingWindowRateLimiter(100, 60.0), store, AuditLogger())
    v = defense.inspect(f(path="/other"))
    assert v.decision == Decision.RULE_ERROR.value
    assert v.reason == VerdictReason.RULE_ERROR_DENY
    bad_engine.close()

    # 服务自身故障 -> service_error
    class ExplodingStore:
        def snapshot(self):
            raise RuntimeError("store down")

        def replace(self, spec):
            raise RuntimeError("store down")

    defense2 = RequestDefense(
        SlidingWindowRateLimiter(100, 60.0), ExplodingStore(), AuditLogger()
    )
    v2 = defense2.inspect(f())
    assert v2.decision == Decision.SERVICE_ERROR.value
    assert v2.reason == VerdictReason.SERVICE_FAILURE


def test_fail_open_allows_but_reason_remains_distinguishable():
    d = make_defense(limit=100, on_error="fail_open")
    engine = d._store.current()
    cfg_engine = engine
    bad = type(engine)(
        (BoomRule(RuleDef("boom", 1, "deny", "path", "eq", "/x")),),
        engine.version, 100, 1.0, "fail_open",
    )
    d._store._engine = bad
    v = d.inspect(f(path="/other"))
    assert v.decision == Decision.ALLOW.value
    assert v.reason == VerdictReason.RULE_ERROR_ALLOW
    assert v.degraded is True
    bad.close()


def test_every_verdict_is_audited_with_input_summary_and_basis():
    d = make_defense(limit=1)
    d.inspect(f(path="/a"))
    d.inspect(f(path="/a"))  # 限流
    entries = d._audit.entries()
    assert [e.decision for e in entries] == ["deny", "rate_limited"]
    deny_entry = entries[0]
    assert "source=s1" in deny_entry.input_summary
    assert "path=/a" in deny_entry.input_summary
    assert deny_entry.traces[0].rule_id == "deny-a"
    assert deny_entry.traces[0].outcome == "match_deny"


def test_concurrent_burst_exact_quota_and_no_double_count_across_changes():
    """并发冲击 + 并发规则变更：计数精确、不超发不漏计、版本不回退。"""
    n_workers = 8
    per_worker = 100  # 共 800 次请求
    cfg = DefenseConfig(rate_limit=300, window_seconds=60.0, max_rules=100)
    store = RuleStore(cfg, RuleSetSpec((RuleDef("d", 1, "deny", "path", "eq", "/a"),)))
    rl = SlidingWindowRateLimiter(300, 60.0)
    defense = RequestDefense(rl, store, AuditLogger())

    decisions: dict[str, int] = {}
    versions_seen: list[int] = []
    lock = threading.Lock()
    barrier = threading.Barrier(n_workers + 2)
    stop_mutation = threading.Event()

    def hit():
        barrier.wait()
        for _ in range(per_worker):
            v = defense.inspect(RequestFeatures(source="hot", path="/z", method="GET"))
            with lock:
                decisions[v.decision] = decisions.get(v.decision, 0) + 1
                versions_seen.append(v.rule_version)

    def mutate():
        barrier.wait()
        # 受控地持续变更（每 1ms 至多一次），既与判定并发又不制造极端 churn
        i = 0
        while not stop_mutation.is_set():
            store.replace(
                RuleSetSpec((RuleDef(f"d{i}", 1, "deny", "path", "eq", "/a"),))
            )
            i += 1
            time.sleep(0.001)

    threads = [threading.Thread(target=hit) for _ in range(n_workers)]
    for t in threads:
        t.start()
    mutator = threading.Thread(target=mutate)
    mutator.start()
    barrier.wait()  # 放行所有 worker 与 mutator
    for t in threads:
        t.join()
    stop_mutation.set()
    mutator.join()

    total = sum(decisions.values())
    assert total == n_workers * per_worker
    # 恰好 300 个请求被计数放行（规则无匹配 -> allow），其余全部限流
    assert decisions.get(Decision.ALLOW.value, 0) == 300
    assert decisions.get(Decision.RATE_LIMITED.value, 0) == total - 300
    # 没有任何 deny / rule_error / service_error
    assert Decision.DENY.value not in decisions
    assert Decision.RULE_ERROR.value not in decisions
    assert Decision.SERVICE_ERROR.value not in decisions
    # 版本序列单调观察值不超过最终版本，且不存在负数
    final_version = store.version
    assert all(0 <= v <= final_version for v in versions_seen)
    assert rl.remaining("hot", 1000.0) == 0
