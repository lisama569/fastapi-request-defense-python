"""引擎分段接口单测：限流预留、正文接收拒绝、正文特征的规则判定。"""

from __future__ import annotations

import pytest

from request_defense.engine import DefenseEngine
from request_defense.ratelimiter import SlidingWindowRateLimiter
from request_defense.store import RuleStore
from request_defense.types import (
    Decision,
    Reason,
    RequestFeatures,
    RuleConfig,
    RuleEffect,
)


def cfg(rule_id="r", field="body", pattern="x", effect=RuleEffect.DENY, priority=0):
    return RuleConfig(rule_id=rule_id, priority=priority, effect=effect,
                      field_name=field, pattern=pattern)


def feat(source="s1", path="/p", method="POST", summary="", length=0,
         fully=True, pv=3):
    return RequestFeatures(
        source=source, path=path, method=method,
        headers={"content-type": "application/json"},
        body_summary=summary, body_length=length,
        body_fully_inspected=fully, content_policy_version=pv,
    )


@pytest.fixture()
def engine(store):
    rl = SlidingWindowRateLimiter(2, 60_000)
    eng = DefenseEngine(rl, store, max_rules=10, request_timeout_ms=200)
    yield eng
    eng.shutdown()


@pytest.fixture()
def store():
    return RuleStore()


class TestReserveQuota:
    def test_first_requests_reserved(self, engine):
        assert engine.reserve_quota(feat(source="a"), policy_version=3) is None
        assert engine.reserve_quota(feat(source="a"), policy_version=3) is None

    def test_third_request_rate_limited_and_audited(self, engine):
        engine.reserve_quota(feat(source="a"), policy_version=3)
        engine.reserve_quota(feat(source="a"), policy_version=3)
        out = engine.reserve_quota(feat(source="a"), policy_version=3)
        assert out is not None
        assert out.decision is Decision.RATE_LIMITED
        assert out.reason is Reason.RATE_LIMIT_QUOTA_EXHAUSTED

    def test_sources_are_independent(self, engine):
        engine.reserve_quota(feat(source="a"))
        engine.reserve_quota(feat(source="a"))
        assert engine.reserve_quota(feat(source="b")) is None


class TestDecideRulesOnBody:
    def test_body_deny_rule_matches_summary(self, engine, store):
        store.replace_rules([cfg(pattern="EVIL")])
        engine.reserve_quota(feat(source="a"))
        out = engine.decide_rules(
            feat(source="a", summary='{"x":"EVIL"}', length=13, fully=True),
            rate_info={"allowed": True},
            content_check_enabled=True,
        )
        assert out.decision is Decision.DENY
        assert out.reason is Reason.RULE_MATCH_DENY

    def test_body_rule_skipped_when_content_check_disabled(self, engine, store):
        store.replace_rules([cfg(pattern="EVIL")])
        engine.reserve_quota(feat(source="a"))
        out = engine.decide_rules(
            feat(source="a", summary='{"x":"EVIL"}', length=13),
            rate_info={"allowed": True},
            content_check_enabled=False,
        )
        assert out.decision is Decision.ALLOW
        assert out.reason is Reason.OK
        assert out.rule_results == ()  # body 规则被整体跳过

    def test_non_body_rules_still_run_when_check_disabled(self, engine, store):
        store.replace_rules([cfg(field="path", pattern=r"^/secret")])
        engine.reserve_quota(feat(source="a", path="/secret/x"))
        out = engine.decide_rules(
            feat(source="a", path="/secret/x"),
            rate_info={"allowed": True},
            content_check_enabled=False,
        )
        assert out.decision is Decision.DENY
        assert out.reason is Reason.RULE_MATCH_DENY


class TestRejectIngress:
    @pytest.mark.parametrize(
        "reason",
        [
            Reason.BODY_TOO_LARGE,
            Reason.BODY_INSPECTION_INCOMPLETE,
            Reason.BODY_RECEIVE_TIMEOUT,
            Reason.BODY_INGRESS_BUSY,
        ],
    )
    def test_ingress_reasons_are_distinct_denials(self, engine, reason):
        engine.reserve_quota(feat(source="a"), policy_version=7)
        out = engine.reject_ingress(
            feat(source="a", length=999, fully=False, pv=7),
            reason,
            "detail-for-" + reason.value,
            rate_info={"allowed": True},
        )
        assert out.decision is Decision.DENY
        assert out.reason is reason
        assert out.detail == "detail-for-" + reason.value
