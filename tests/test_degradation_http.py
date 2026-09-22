"""降级策略的端到端验证：运行期异常规则 + fail_open/fail_closed 切换。"""

from __future__ import annotations

import importlib

import pytest


@pytest.fixture()
def client(monkeypatch):
    monkeypatch.setenv("DEFENSE_RATE_LIMIT", "100")
    monkeypatch.setenv("DEFENSE_ADMIN_TOKEN", "t")
    import main
    importlib.reload(main)
    from fastapi.testclient import TestClient

    main.rate_limiter.reset()
    main.audit._entries.clear()
    return TestClient(main.app), main


AUTH = {"authorization": "Bearer t"}


def _install_boilerule(main_mod):
    """直接向在效引擎注入一条运行期必抛异常的规则。"""
    from app.rules import Rule
    from app.models import RuleDef

    class BoomRule(Rule):
        def evaluate(self, features):
            raise RuntimeError("disk exploded")

    engine = main_mod.rule_store.current()
    boom = type(engine)(
        (BoomRule(RuleDef("boom", 1, "deny", "path", "eq", "/x")),),
        engine.version, 100, 1.0, "fail_closed",
        executor=engine._executor,
    )
    main_mod.rule_store._engine = boom


def test_runtime_rule_exception_fail_closed_is_distinguishable_deny(client):
    c, main_mod = client
    _install_boilerule(main_mod)
    r = c.get("/")
    assert r.status_code == 403
    body = r.json()
    # 与"命中规则"的 deny 原因必须不同
    assert body["decision"] == "rule_error"
    assert body["reason"] == "rule_evaluation_error_fail_closed"


def test_runtime_rule_exception_fail_open_allows_with_marker(client):
    c, main_mod = client
    from app.rules import Rule
    from app.models import RuleDef

    class BoomRule(Rule):
        def evaluate(self, features):
            raise RuntimeError("disk exploded")

    engine = main_mod.rule_store.current()
    boom = type(engine)(
        (BoomRule(RuleDef("boom", 1, "deny", "path", "eq", "/x")),),
        engine.version, 100, 1.0, "fail_open",
        executor=engine._executor,
    )
    main_mod.rule_store._engine = boom

    r = c.get("/")
    assert r.status_code == 200
    # 放行但带可区分标记：响应头声明降级原因（非静默放行）
    assert r.headers["X-Defense-Decision"] == "allow"
    assert r.headers["X-Defense-Reason"] == "rule_evaluation_error_fail_open"

    entry = main_mod.audit.entries()[-1]
    assert entry.degraded is True
    assert entry.traces[0].outcome == "error"
    assert "disk exploded" in entry.traces[0].detail
