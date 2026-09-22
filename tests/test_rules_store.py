"""规则求值与规则集存储测试：命中/未命中、非法整集拒绝、原子性、并发变更。"""

from __future__ import annotations

import threading

import pytest

from request_defense.rule import Rule, RuleDefinitionError
from request_defense.store import RuleStore, RuleSetValidationError
from request_defense.types import (
    RequestFeatures,
    RuleConfig,
    RuleEffect,
    RuleVerdict,
)


def cfg(rule_id="r", priority=0, effect=RuleEffect.DENY, field="path", pattern="x", **kw):
    return RuleConfig(
        rule_id=rule_id,
        priority=priority,
        effect=effect,
        field_name=field,
        pattern=pattern,
        **kw,
    )


def feat(path="/p", headers=None, query=None):
    return RequestFeatures(
        source="1.1.1.1",
        path=path,
        method="GET",
        headers=headers or {},
        query=query or {},
    )


class TestRuleCompile:
    @pytest.mark.parametrize(
        "bad",
        [
            cfg(rule_id=""),
            cfg(priority=-1),
            cfg(pattern=""),
            cfg(field="unknown-field"),
            cfg(pattern="["),              # 非法正则
            cfg(field="header:"),          # 空头名
            cfg(field="query:"),
        ],
    )
    def test_invalid_rule_rejected_at_compile(self, bad):
        with pytest.raises(RuleDefinitionError):
            Rule.compile(bad)

    def test_match_no_match_and_effects(self):
        deny = Rule.compile(cfg(rule_id="d", effect=RuleEffect.DENY, pattern=r"^/evil"))
        allow = Rule.compile(cfg(rule_id="a", effect=RuleEffect.ALLOW, pattern="ok"))
        assert deny.evaluate(feat("/evil/x")) is RuleVerdict.MATCH_DENY
        assert deny.evaluate(feat("/good")) is RuleVerdict.NO_MATCH
        assert allow.evaluate(feat("/ok")) is RuleVerdict.MATCH_ALLOW

    def test_header_and_query_fields(self):
        h = Rule.compile(cfg(field="header:x-token", pattern="abc"))
        q = Rule.compile(cfg(field="query:action", pattern="run"))
        assert h.evaluate(feat(headers={"x-token": "abc"})) is RuleVerdict.MATCH_DENY
        assert h.evaluate(feat(headers={"x-token": "zzz"})) is RuleVerdict.NO_MATCH
        assert q.evaluate(feat(query={"action": "run"})) is RuleVerdict.MATCH_DENY
        # 缺失字段按空串处理，不抛异常
        assert q.evaluate(feat()) is RuleVerdict.NO_MATCH


class TestRuleStore:
    def test_replace_succeeds_and_versions_monotonic(self):
        store = RuleStore()
        v1 = store.replace_rules([cfg(rule_id="a")])
        v2 = store.replace_rules([cfg(rule_id="b"), cfg(rule_id="c")])
        assert v1 == 1 and v2 == 2
        version, rules = store.snapshot()
        assert version == 2 and {r.config.rule_id for r in rules} == {"b", "c"}

    def test_snapshot_sorted_by_priority_then_id(self):
        store = RuleStore()
        store.replace_rules(
            [cfg(rule_id="z", priority=5), cfg(rule_id="a", priority=1), cfg(rule_id="m", priority=1)]
        )
        _, rules = store.snapshot()
        assert [r.config.rule_id for r in rules] == ["a", "m", "z"]

    @pytest.mark.parametrize(
        "bad",
        [
            [],  # 空集
            [cfg(pattern="[")],  # 单条非法 => 整集拒绝
            [cfg(rule_id="x"), cfg(rule_id="x")],  # 重复 id
            [cfg(rule_id="off", enabled=False)],  # 全部停用
            "not-a-list",
        ],
    )
    def test_invalid_set_rejected_entirely(self, bad):
        store = RuleStore()
        store.replace_rules([cfg(rule_id="keep")])
        with pytest.raises(RuleSetValidationError):
            store.replace_rules(bad)
        # 旧版本必须原样保留，不进入半更新状态
        version, rules = store.snapshot()
        assert version == 1 and [r.config.rule_id for r in rules] == ["keep"]

    def test_too_many_rules_rejected(self):
        store = RuleStore(max_rules=2)
        with pytest.raises(RuleSetValidationError):
            store.replace_rules([cfg(rule_id=f"r{i}") for i in range(3)])
        assert store.snapshot()[0] == 0

    def test_disabled_rule_excluded_but_enabled_rules_kept(self):
        store = RuleStore()
        store.replace_rules([cfg(rule_id="on"), cfg(rule_id="off", enabled=False)])
        _, rules = store.snapshot()
        assert [r.config.rule_id for r in rules] == ["on"]

    def test_concurrent_replacements_versions_strict_monotonic(self):
        store = RuleStore(max_rules=200)

        def worker(i: int) -> None:
            store.replace_rules([cfg(rule_id=f"rule-{i}")])

        threads = [threading.Thread(target=worker, args=(i,)) for i in range(40)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        assert store.snapshot()[0] == 40  # 每次成功替换恰好 +1，无回退/跳变
