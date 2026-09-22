"""管理鉴权与审计脱敏测试。"""

from __future__ import annotations

import json
import logging

import pytest

from request_defense.audit import build_audit_record, redact_headers
from request_defense.auth import AuthError, authenticate, mask_token


class TestAuthenticate:
    def test_valid_token_passes(self):
        authenticate("Bearer tok", "tok")  # 不抛即通过

    @pytest.mark.parametrize(
        "header_value",
        [None, "", "Bearer", "Bearer ", "Basic tok", "Bearer tok2", "bearer tok"],
    )
    def test_invalid_credentials_rejected(self, header_value):
        with pytest.raises(AuthError):
            authenticate(header_value, "tok")

    def test_unconfigured_token_fails_closed(self):
        with pytest.raises(AuthError):
            authenticate("Bearer tok", "")

    def test_error_message_is_generic(self):
        try:
            authenticate(None, "tok")
        except AuthError as exc:
            assert str(exc) == "unauthorized"


class TestRedaction:
    def test_sensitive_headers_never_leak(self):
        redacted = redact_headers({
            "Authorization": "Bearer super-secret-value",
            "X-Admin-Token": "another-secret",
            "Cookie": "session=abc123",
            "X-Trace": "trace-value",
        })
        dumped = json.dumps(redacted)
        assert "super-secret-value" not in dumped
        assert "another-secret" not in dumped
        assert "abc123" not in dumped
        assert redacted["X-Trace"] == "trace-value"

    def test_mask_token_never_contains_raw(self):
        token = "secret-admin-token"
        masked = mask_token(token)
        assert token not in masked and masked.startswith("sha256:")
        assert mask_token("") == "<absent>"

    def test_audit_record_contains_basis_and_input_summary(self, caplog):
        rec = build_audit_record(
            source="9.9.9.9",
            method="POST",
            path="/evil",
            headers={"Authorization": "Bearer leaked-token"},
            query={"a": "1"},
            body_summary="payload",
            decision="deny",
            reason="rule_match_deny",
            detail="matched deny rules: d1",
            rule_version=3,
            rule_results=[{"rule_id": "d1", "verdict": "match_deny"}],
            rate_limit={"allowed": True},
            elapsed_ms=0.5,
        )
        # 依据完整
        assert rec["basis"]["rule_version"] == 3
        assert rec["basis"]["rule_results"][0]["rule_id"] == "d1"
        # 输入摘要足以复现
        assert rec["input"]["source"] == "9.9.9.9"
        assert rec["input"]["path"] == "/evil"
        assert rec["input"]["query"] == {"a": "1"}
        assert rec["input"]["body_summary"] == "payload"
        # 凭据不出现在任何字段
        assert "leaked-token" not in json.dumps(rec)

        with caplog.at_level(logging.WARNING, logger="request_defense"):
            logging.getLogger("request_defense").warning(json.dumps(rec))
        assert "rule_match_deny" in caplog.text
        assert "leaked-token" not in caplog.text
