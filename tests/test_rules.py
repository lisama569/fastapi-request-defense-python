"""规则引擎测试：异常规则、降级策略、冲突确定性为核心场景。"""

from __future__ import annotations

import logging
import threading
import time

from app.config import FAIL_CLOSED, FAIL_OPEN
from app.models import (
    Decision,
    RuleDef,
    RuleSetSpec,
    RequestFeatures,
    VerdictReason,
)
from app.rules import (
    Rule,
    RuleEngine,
    RuleSetValidationError,
    validate_ruleset,
)

logging.basicConfig(level=logging.DEBUG)
log = logging.getLogger("test_rules")


def feat(path="/x", **kw):
    base = dict(source="s1", path=path, method="GET", headers={}, query={})
    base.update(kw)
    return RequestFeatures(**base)


def rd(rid, pri, action, field, op, expected, enabled=True):
    return RuleDef(rid, pri, action, field, op, expected, enabled)


class BoomRule(Rule):
    def evaluate(self, f):
        raise RuntimeError("boom from rule %s" % self.rule_id)


class SlowRule(Rule):
    def __init__(self, definition, delay):
        super().__init__(definition)
        self._delay = delay

    def evaluate(self, f):
        time.sleep(self._delay)
        return False


def _log_verdict(name, features, decision, reason, traces, elapsed):
    summary = f"{features.method} {features.path} source={features.source}"
    basis = ";".join(f"{t.rule_id}:{t.outcome}" for t in traces)
    log.info(
        "CASE %s | input=[%s] | decision=%s reason=%s elapsed_ms=%.3f | basis=[%s]",
        name, summary, decision, reason, elapsed * 1000, basis,
    )


# ---------- 基础判定 ----------

def test_normal_request_is_never_falsely_rejected():
    e = RuleEngine(
        (Rule(rd("deny-admin", 1, "deny", "path", "prefix", "/admin")),),
        1, 100, 1.0, FAIL_CLOSED,
    )
    d, r, traces, el = e.evaluate(feat("/public"))
    _log_verdict("normal_not_denied", feat("/public"), d, r, traces, el)
    assert d == Decision.ALLOW.value
    assert r == VerdictReason.NO_RULE_MATCHED


def test_suspicious_request_is_not_silently_allowed():
    e = RuleEngine(
        (Rule(rd("deny-admin", 1, "deny", "path", "prefix", "/admin")),),
        1, 100, 1.0, FAIL_CLOSED,
    )
    d, r, traces, _ = e.evaluate(feat("/admin/users"))
    assert d == Decision.DENY.value
    assert r == VerdictReason.RULE_MATCH_DENY


def test_conflicting_rules_resolve_by_priority_deterministically():
    deny_high = Rule(rd("deny", 10, "deny", "path", "prefix", "/a"))
    allow_low = Rule(rd("allow", 20, "allow", "path", "prefix", "/a"))
    e1 = RuleEngine((allow_low, deny_high), 1, 100, 1.0, FAIL_CLOSED)
    d1, _, _, _ = e1.evaluate(feat("/a/b"))
    # 反向构造顺序传入，排序后结论仍一致
    e2 = RuleEngine((deny_high, allow_low), 1, 100, 1.0, FAIL_CLOSED)
    d2, _, _, _ = e2.evaluate(feat("/a/b"))
    assert d1 == d2 == Decision.DENY.value

    allow_high = Rule(rd("allow2", 10, "allow", "path", "prefix", "/a"))
    deny_low = Rule(rd("deny2", 20, "deny", "path", "prefix", "/a"))
    e3 = RuleEngine((deny_low, allow_high), 1, 100, 1.0, FAIL_CLOSED)
    d3, r3, _, _ = e3.evaluate(feat("/a/b"))
    assert d3 == Decision.ALLOW.value and r3 == VerdictReason.RULE_MATCH_ALLOW


def test_same_priority_conflict_tie_break_by_rule_id():
    a = Rule(rd("aaa", 10, "allow", "path", "eq", "/x"))
    b = Rule(rd("bbb", 10, "deny", "path", "eq", "/x"))
    e = RuleEngine((b, a), 1, 100, 1.0, FAIL_CLOSED)
    d, _, _, _ = e.evaluate(feat("/x"))
    assert d == Decision.ALLOW.value  # aaa 先求值 -> 最高优先级命中为 allow


def test_operators_and_fields():
    rules = (
        Rule(rd("m", 1, "deny", "method", "eq", "POST")),
        Rule(rd("h", 2, "deny", "header:x-role", "in", "admin,root")),
        Rule(rd("q", 3, "allow", "query:token", "eq", "abc")),
        Rule(rd("b", 4, "deny", "body_digest", "prefix", "deadbeef")),
        Rule(rd("src", 5, "deny", "source", "suffix", ".evil")),
    )
    e = RuleEngine(rules, 1, 100, 1.0, FAIL_CLOSED)
    assert e.evaluate(feat("/", method="POST"))[0] == Decision.DENY.value
    assert e.evaluate(feat("/", headers={"x-role": "root"}))[0] == Decision.DENY.value
    assert e.evaluate(feat("/?x=1".split("?")[0], query={"token": "abc"}))[0] == Decision.ALLOW.value
    assert e.evaluate(feat("/", body_digest="deadbeef12345678"))[0] == Decision.DENY.value
    assert e.evaluate(feat("/", source="host.evil"))[0] == Decision.DENY.value
    assert e.evaluate(feat("/", source="host.good"))[0] == Decision.ALLOW.value


# ---------- 异常隔离 ----------

def test_rule_exception_is_isolated_closed_open_distinguishable():
    boom = BoomRule(rd("boom", 1, "deny", "path", "eq", "/x"))
    ec = RuleEngine((boom,), 1, 100, 1.0, FAIL_CLOSED)
    d, r, traces, el = ec.evaluate(feat("/other"))
    _log_verdict("exception_fail_closed", feat("/other"), d, r, traces, el)
    assert d == Decision.RULE_ERROR.value
    assert r == VerdictReason.RULE_ERROR_DENY
    assert traces[0].outcome == "error"
    assert "RuntimeError" in traces[0].detail

    eo = RuleEngine((boom,), 1, 100, 1.0, FAIL_OPEN)
    d, r, _, _ = eo.evaluate(feat("/other"))
    assert d == Decision.ALLOW.value
    assert r == VerdictReason.RULE_ERROR_ALLOW  # 放行但原因可区分，非静默放行


def test_one_bad_rule_does_not_stop_other_rules_from_deciding():
    f = feat("/other")
    boom = BoomRule(rd("boom", 5, "deny", "path", "eq", "/x"))
    deny = Rule(rd("deny-low", 9, "deny", "path", "eq", "/other"))
    e = RuleEngine((boom, deny), 1, 100, 1.0, FAIL_CLOSED)
    d, r, traces, _ = e.evaluate(f)
    _log_verdict("bad_rule_others_still_run", f, d, r, traces, 0)
    # 高优先级故障使结论不确定 -> 降级拒绝（可疑不静默放行）
    assert d == Decision.RULE_ERROR.value
    outcomes = {t.rule_id: t.outcome for t in traces}
    assert outcomes["boom"] == "error"
    assert outcomes["deny-low"] == "match_deny"  # 其余规则确实参与了


def test_low_priority_fault_does_not_override_high_priority_match():
    deny = Rule(rd("deny-high", 1, "deny", "path", "eq", "/x"))
    boom = BoomRule(rd("boom-low", 9, "deny", "path", "eq", "/x"))
    e = RuleEngine((deny, boom), 1, 100, 1.0, FAIL_CLOSED)
    d, r, _, _ = e.evaluate(feat("/x"))
    assert d == Decision.DENY.value
    assert r == VerdictReason.RULE_MATCH_DENY


# ---------- 超时与容量 ----------

def test_budget_exceeded_degrades_by_policy_and_is_bounded():
    slow = SlowRule(rd("slow", 1, "deny", "path", "eq", "/x"), 0.3)
    ec = RuleEngine((slow,), 1, 100, budget_seconds=0.05, on_error=FAIL_CLOSED)
    t0 = time.monotonic()
    d, r, traces, _ = ec.evaluate(feat("/x"))
    wall = time.monotonic() - t0
    assert d == Decision.RULE_ERROR.value
    assert r == VerdictReason.RULE_TIMEOUT_DENY
    assert traces[0].outcome == "skipped_timeout"
    assert wall < 0.25  # 不会无界等待

    eo = RuleEngine((slow,), 1, 100, 0.05, FAIL_OPEN)
    d, r, _, _ = eo.evaluate(feat("/x"))
    assert d == Decision.ALLOW.value and r == VerdictReason.RULE_TIMEOUT_ALLOW


def test_rule_capacity_skipped_and_degrades():
    rules = tuple(
        Rule(rd(f"r{i:03d}", i + 1, "deny", "path", "eq", "/nomatch"))
        for i in range(5)
    )
    e = RuleEngine(rules, 1, max_rules=3, budget_seconds=1.0, on_error=FAIL_CLOSED)
    d, r, traces, _ = e.evaluate(feat("/x"))
    assert d == Decision.RULE_ERROR.value
    assert r == VerdictReason.RULE_CAPACITY_DENY
    assert sum(t.outcome == "skipped_capacity" for t in traces) == 2


# ---------- 规则集校验 ----------


def test_invalid_rulesets_rejected_wholesale():
    bad_cases = [
        (rd("", 1, "deny", "path", "eq", "/x"), "empty id"),
        (rd("a", 1.5, "deny", "path", "eq", "/x"), "float priority"),
        (rd("a", 1, "wat", "path", "eq", "/x"), "bad action"),
        (rd("a", 1, "deny", "body", "eq", "x"), "bad field"),
        (rd("a", 1, "deny", "header:", "eq", "x"), "empty header"),
        (rd("a", 1, "deny", "path", "xx", "x"), "bad operator"),
        (rd("a", 1, "deny", "path", "regex", "([0-9"), "bad regex"),
    ]
    for defn, label in bad_cases:
        try:
            validate_ruleset(RuleSetSpec((defn,)), 100)
        except RuleSetValidationError:
            pass
        else:
            raise AssertionError(f"should reject: {label}")


def test_duplicate_ids_and_capacity_rejected():
    spec = RuleSetSpec(
        (rd("dup", 1, "deny", "path", "eq", "/a"),
         rd("dup", 2, "allow", "path", "eq", "/b"))
    )
    try:
        validate_ruleset(spec, 100)
    except RuleSetValidationError:
        pass
    else:
        raise AssertionError("duplicate id must be rejected")

    big = RuleSetSpec(tuple(
        rd(f"r{i}", i, "deny", "path", "eq", "/x") for i in range(4)
    ))
    try:
        validate_ruleset(big, 3)
    except RuleSetValidationError:
        pass
    else:
        raise AssertionError("over-capacity must be rejected")


def test_disabled_rules_are_not_evaluated():
    spec = RuleSetSpec((rd("off", 1, "deny", "path", "eq", "/x", enabled=False),))
    validate_ruleset(spec, 100)
    from app.rules import build_rule
    engine = RuleEngine(
        tuple(build_rule(d) for d in spec.rules if d.enabled),
        1, 100, 1.0, FAIL_CLOSED,
    )
    d, r, traces, _ = engine.evaluate(feat("/x"))
    assert d == Decision.ALLOW.value and not traces
    engine.close()


def test_capacity_fault_when_evaluation_slots_exhausted():
    """用只有 1 个 worker 的池：后台慢任务占住唯一槽位时，规则容量降级。"""
    from concurrent.futures import ThreadPoolExecutor

    pool = ThreadPoolExecutor(max_workers=1)
    event = threading.Event()

    class BlockingRule(Rule):
        def evaluate(self, f):
            event.wait(timeout=2.0)
            return False

    try:
        blocking = BlockingRule(rd("block", 1, "deny", "path", "eq", "/x"))
        # 先在唯一 worker 上启动一个占槽后台任务
        fut = pool.submit(blocking.evaluate, feat("/z"))
        time.sleep(0.05)

        quick = Rule(rd("quick", 2, "deny", "path", "eq", "/y"))
        slots = threading.BoundedSemaphore(1)
        ec = RuleEngine(
            (quick,), 1, 100, 1.0, FAIL_CLOSED, executor=pool, slots=slots
        )
        d, r, traces, _ = ec.evaluate(feat("/z"))
        assert d == Decision.RULE_ERROR.value
        assert r == VerdictReason.RULE_CAPACITY_DENY
        assert traces[0].outcome == "skipped_capacity"

        eo = RuleEngine(
            (quick,), 1, 100, 1.0, FAIL_OPEN, executor=pool, slots=slots
        )
        d, r, _, _ = eo.evaluate(feat("/z"))
        assert d == Decision.ALLOW.value
        assert r == VerdictReason.RULE_CAPACITY_ALLOW

        event.set()
        assert fut.result(timeout=2.0) is False
    finally:
        pool.shutdown(wait=True, cancel_futures=True)


def test_timeout_releases_slot_no_resource_leak():
    """连续多次超时后槽位仍可复用（超时不泄漏求值槽位）。"""
    slow = SlowRule(rd("slow", 1, "deny", "path", "eq", "/x"), 0.3)
    e = RuleEngine((slow,), 1, 100, 0.05, FAIL_CLOSED)
    try:
        for _ in range(5):
            d, r, _, _ = e.evaluate(feat("/z"))
            assert d == Decision.RULE_ERROR.value
            assert r == VerdictReason.RULE_TIMEOUT_DENY
        # 等后台慢任务把槽位还回后，一条快规则可以正常求值
        time.sleep(0.7)
        fast_engine = RuleEngine(
            (Rule(rd("fast", 1, "deny", "path", "eq", "/hit")),),
            2, 100, 1.0, FAIL_CLOSED,
            executor=e._executor, slots=e._slots,
        )
        d, _, _, _ = fast_engine.evaluate(feat("/hit"))
        assert d == Decision.DENY.value
    finally:
        e.close()
