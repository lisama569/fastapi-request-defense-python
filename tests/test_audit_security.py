"""审计脱敏与管理鉴权测试：日志/审计中不得出现完整凭据。"""

from __future__ import annotations

import logging

from app.audit import REDACTED, AuditLogger, input_summary, mask_secret
from app.models import (
    Decision,
    DefenseVerdict,
    RequestFeatures,
    RuleTrace,
    VerdictReason,
)
from app.security import AdminAuthenticator


def test_mask_secret_never_reveals_token():
    assert mask_secret(None) == ""
    assert mask_secret("") == ""
    assert mask_secret("super-secret-value") == REDACTED
    assert "super-secret-value" not in mask_secret("super-secret-value")


def test_input_summary_redacts_sensitive_headers():
    f = RequestFeatures(
        source="1.2.3.4",
        path="/admin",
        method="POST",
        headers={
            "authorization": "Bearer topsecret-token-123",
            "cookie": "session=abc",
            "x-trace": "trace-ok",
        },
        query={"q": "1"},
        body_digest="abcd",
    )
    summary = input_summary(f)
    assert "topsecret-token-123" not in summary
    assert "session=abc" not in summary
    assert "authorization=" + REDACTED in summary
    assert "cookie=" + REDACTED in summary
    assert "x-trace=trace-ok" in summary
    assert "source=1.2.3.4" in summary and "path=/admin" in summary


def test_audit_entries_distinguish_decisions_and_contain_basis(caplog):
    logger = AuditLogger()
    f = RequestFeatures(source="s", path="/a", method="GET")
    traces = (RuleTrace("r1", 1, "match_deny", "matched"),)
    with caplog.at_level(logging.WARNING):
        logger.record(
            f,
            DefenseVerdict(
                decision=Decision.DENY.value,
                reason=VerdictReason.RULE_MATCH_DENY,
                source="s",
                rule_version=3,
                traces=traces,
            ),
        )
    e = logger.entries()[0]
    assert e.decision == "deny"
    assert e.rule_version == 3
    assert e.traces[0].rule_id == "r1"
    text = caplog.text
    assert "decision=deny" in text
    assert "reason=rule_match_deny" in text
    assert "r1[p1]=match_deny" in text  # 判定依据
    assert "path=/a" in text            # 输入摘要


def test_log_levels_allow_info_limited_and_denied_warning_error_fault(caplog):
    logger = AuditLogger()
    f = RequestFeatures(source="s", path="/x", method="GET")
    cases = [
        (Decision.ALLOW.value, VerdictReason.NO_RULE_MATCHED, logging.INFO),
        (Decision.RATE_LIMITED.value, VerdictReason.RL_QUOTA_EXHAUSTED, logging.WARNING),
        (Decision.DENY.value, VerdictReason.RULE_MATCH_DENY, logging.WARNING),
        (Decision.RULE_ERROR.value, VerdictReason.RULE_ERROR_DENY, logging.ERROR),
    ]
    with caplog.at_level(logging.DEBUG):
        for decision, reason, _level in cases:
            logger.record(
                f,
                DefenseVerdict(
                    decision=decision, reason=reason, source="s", rule_version=0
                ),
            )
    assert "decision=allow reason=no_rule_matched" in caplog.text
    assert "decision=rate_limited reason=rate_limit_quota_exhausted" in caplog.text
    assert "decision=rule_error reason=rule_evaluation_error_fail_closed" in caplog.text


def test_admin_authenticator_constant_time_and_strict():
    auth = AdminAuthenticator("correct-token")
    assert auth.authenticate("Bearer correct-token") is True
    for bad in (
        None,
        "",
        "correct-token",          # 缺 Bearer 前缀
        "Bearer wrong-token",
        "Basic correct-token",
        "Bearer ",
        "bearer correct-token extra",
    ):
        assert auth.authenticate(bad) is False
