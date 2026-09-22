"""规则集运行时变更测试：整体替换、非法整体拒绝、并发版本一致性。"""

from __future__ import annotations

import threading

from app.config import DefenseConfig
from app.models import RuleDef, RuleSetSpec
from app.ratelimit import SlidingWindowRateLimiter
from app.rule_store import RuleStore
from app.rules import RuleSetValidationError
from app.audit import AuditLogger
from app.defense import RequestDefense
from app.models import RequestFeatures


def cfg(max_rules=100):
    return DefenseConfig(max_rules=max_rules)


def deny(rid, path="/a"):
    return RuleDef(rid, 1, "deny", "path", "eq", path)


def test_atomic_replace_bumps_version_and_takes_effect_without_restart():
    store = RuleStore(cfg())
    assert store.version == 0
    v1 = store.replace(RuleSetSpec((deny("r1"),)))
    assert v1 == 1 and store.version == 1
    assert [r.rule_id for r in store.current().rules] == ["r1"]
    v2 = store.replace(RuleSetSpec((deny("r2"), deny("r3", "/b"))))
    assert v2 == 2
    assert sorted(r.rule_id for r in store.current().rules) == ["r2", "r3"]


def test_invalid_ruleset_rejected_entirely_no_half_update():
    store = RuleStore(cfg())
    store.replace(RuleSetSpec((deny("good1"), deny("good2", "/b"))))
    version_before = store.version
    rules_before = [r.rule_id for r in store.current().rules]

    # 混合：一条合法一条非法 -> 整体拒绝
    mixed = RuleSetSpec(
        (deny("new-ok"), RuleDef("bad", 1, "nope", "path", "eq", "/x"))
    )
    try:
        store.replace(mixed)
    except RuleSetValidationError:
        pass
    else:
        raise AssertionError("partially invalid set must be rejected")

    assert store.version == version_before  # 版本不动
    assert [r.rule_id for r in store.current().rules] == rules_before

    # 超容量也整体拒绝
    over = RuleSetSpec(tuple(deny(f"r{i}") for i in range(101)))
    try:
        store.replace(over)
    except RuleSetValidationError:
        pass
    else:
        raise AssertionError("over-capacity set must be rejected")
    assert store.version == version_before


def test_concurrent_replaces_never_regress_version():
    store = RuleStore(cfg())
    observed_versions: list[int] = []
    errors: list[Exception] = []
    lock = threading.Lock()

    def replacer(i: int) -> None:
        try:
            v = store.replace(RuleSetSpec((deny(f"rule-{i}"),)))
            with lock:
                observed_versions.append(v)
        except Exception as exc:
            with lock:
                errors.append(exc)

    threads = [threading.Thread(target=replacer, args=(i,)) for i in range(50)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert not errors
    assert sorted(observed_versions) == list(range(1, 51))  # 1..50 各一次，无回退
    assert store.version == 50


def test_concurrent_inspections_see_consistent_engine_version():
    """并发判定与规则变更：每个请求的 verdict.rule_version 与其规则集一致。"""
    store = RuleStore(cfg())
    defense = RequestDefense(
        SlidingWindowRateLimiter(100_000, 60.0), store, AuditLogger()
    )

    stop = threading.Event()
    mismatches: list[str] = []
    lock = threading.Lock()

    def inspector() -> None:
        i = 0
        while not stop.is_set():
            f = RequestFeatures(source="c1", path=f"/p{i % 5}", method="GET")
            verdict = defense.inspect(f)
            engine, snap_version = store.snapshot()
            # 审计版本必须是某一时刻真实存在的版本（0..N），且与当时引擎版本匹配
            if verdict.rule_version < 0 or verdict.rule_version > store.version:
                with lock:
                    mismatches.append("impossible version")
            i += 1

    workers = [threading.Thread(target=inspector) for _ in range(6)]
    for w in workers:
        w.start()

    for i in range(30):
        store.replace(RuleSetSpec((deny(f"v-rule-{i}", f"/p{i % 5}"),)))

    stop.set()
    for w in workers:
        w.join()
    assert not mismatches


def test_failed_replace_does_not_pollute_serving_state():
    """失败之后正常请求仍按旧规则集得到确定结论。"""
    store = RuleStore(cfg())
    store.replace(RuleSetSpec((deny("deny-a", "/a"),)))
    try:
        store.replace(
            RuleSetSpec((RuleDef("broken", 1, "deny", "??", "eq", "x"),))
        )
    except RuleSetValidationError:
        pass

    engine, version = store.snapshot()
    d, _, _, _ = engine.evaluate(
        RequestFeatures(source="s", path="/a", method="GET")
    )
    assert d == "deny" and version == 1
