"""HTTP 端到端测试：各入口结论一致、原因可区分、管理端鉴权、非法规则集拒绝。"""

from __future__ import annotations

import importlib

import pytest


@pytest.fixture()
def client(monkeypatch):
    # 每个测试独立的服务实例（限流配额重置）
    monkeypatch.setenv("DEFENSE_RATE_LIMIT", "3")
    monkeypatch.setenv("DEFENSE_WINDOW_SECONDS", "1")
    monkeypatch.setenv("DEFENSE_ADMIN_TOKEN", "unit-test-token")
    import main
    importlib.reload(main)
    from fastapi.testclient import TestClient

    main.rate_limiter.reset()
    main.audit._entries.clear()
    return TestClient(main.app), main


AUTH = {"authorization": "Bearer unit-test-token"}


def test_healthz_is_exempt_from_defense(client):
    c, _ = client
    for _ in range(5):
        assert c.get("/healthz").status_code == 200


def test_allow_then_rate_limit_with_distinguishable_body_and_headers(client):
    c, _ = client
    r1 = c.get("/")
    assert r1.status_code == 200
    assert r1.headers["X-RateLimit-Limit"] == "3"
    assert int(r1.headers["X-RateLimit-Remaining"]) == 2

    assert c.get("/").status_code == 200
    assert c.get("/").status_code == 200

    r4 = c.get("/")
    assert r4.status_code == 429
    body = r4.json()
    assert body["decision"] == "rate_limited"
    assert body["reason"] == "rate_limit_quota_exhausted"
    assert r4.headers["Retry-After"] == "1"


def test_deny_returns_403_with_reason_and_rule_version(client):
    c, _ = client
    r = c.get("/suspicious/x")
    assert r.status_code == 403
    body = r.json()
    assert body["decision"] == "deny"
    assert body["reason"] == "rule_match_deny"
    assert body["rule_version"] == 0


def test_window_slides_and_requests_allowed_again(client):
    c, main_mod = client
    for _ in range(3):
        assert c.get("/").status_code == 200
    assert c.get("/").status_code == 429
    # 手动推进时间：限流器使用 monotonic，直接重置模拟窗口滑过
    import time

    src = "testclient"
    # 将该来源的时间戳队列平移一个窗口，等价于等待窗口过期
    events = main_mod.rate_limiter._events[src]
    shift = main_mod.config.window_seconds + 0.01
    import collections

    new = collections.deque(t - shift for t in events)
    main_mod.rate_limiter._events[src] = new
    assert c.get("/").status_code == 200


def test_admin_requires_auth_and_does_not_leak_state(client):
    c, _ = client
    assert c.get("/admin/rules").status_code == 401
    r = c.get("/admin/rules", headers={"authorization": "Bearer wrong"})
    assert r.status_code == 401
    assert r.json() == {"detail": "unauthorized"}
    assert r.headers.get("WWW-Authenticate") == "Bearer"


def test_admin_rules_crud_roundtrip_and_invalid_set_rejected(client):
    c, main_mod = client
    payload = {
        "rules": [
            {"rule_id": "block-post", "priority": 1, "action": "deny",
             "field_name": "method", "operator": "eq", "expected": "POST"},
        ]
    }
    r = c.put("/admin/rules", json=payload, headers=AUTH)
    assert r.status_code == 200
    assert r.json()["version"] == 1

    # 立即生效：POST 被拒，GET / 仍放行
    assert c.post("/ingest", content=b"x").status_code == 403
    assert c.get("/").status_code == 200

    # 非法集合：整体拒绝，版本保持 1
    bad = {"rules": [{"rule_id": "x", "priority": 1, "action": "wat",
                      "field_name": "path", "operator": "eq", "expected": "/"}]}
    r = c.put("/admin/rules", json=bad, headers=AUTH)
    assert r.status_code == 400
    assert r.json()["error"] == "invalid_ruleset"
    assert c.get("/admin/rules", headers=AUTH).json()["version"] == 1
    # 旧规则仍生效
    assert c.post("/ingest", content=b"x").status_code == 403


def test_unauthenticated_rule_change_is_rejected_and_state_untouched(client):
    c, _ = client
    before = c.get("/admin/rules", headers=AUTH).json()
    r = c.put(
        "/admin/rules",
        json={"rules": []},
        headers={"authorization": "Bearer guess"},
    )
    assert r.status_code == 401
    after = c.get("/admin/rules", headers=AUTH).json()
    assert before["version"] == after["version"]


def test_audit_endpoint_records_basis_and_no_token_leak(client):
    c, main_mod = client
    c.get("/suspicious/x", headers={"authorization": "Bearer leaked-tok"})
    r = c.get("/admin/audit", headers=AUTH)
    assert r.status_code == 200
    text = r.text
    assert "leaked-tok" not in text
    assert "match_deny" in text  # 判定依据
    assert "seed-deny-suspicious" in text
