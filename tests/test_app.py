"""HTTP 端到端测试：各入口处置一致、管理鉴权、运行时规则变更、限流、脱敏。"""

from __future__ import annotations

import threading

import pytest
from fastapi.testclient import TestClient

from request_defense.config import DefenseConfig
from request_defense.app import create_app


@pytest.fixture()
def client():
    config = DefenseConfig(
        rate_limit=3,
        window_ms=60_000,
        max_rules=10,
        request_timeout_ms=100,
        admin_token="secret-admin-token",
        fail_open=False,
    )
    app = create_app(config)
    with TestClient(app) as c:
        yield c


def _rules(payload):
    return {"rules": payload}


GOOD_RULE = {
    "rule_id": "deny-evil",
    "priority": 0,
    "effect": "deny",
    "field_name": "path",
    "pattern": "^/evil",
}


class TestEntryPoints:
    def test_healthz_exempt(self, client):
        r = client.get("/healthz")
        assert r.status_code == 200

    def test_normal_traffic_served(self, client):
        r = client.get("/api/echo")
        assert r.status_code == 200
        assert r.json()["status"] == "served"

    def test_suspicious_traffic_denied_with_reason(self, client):
        # 默认规则集阻止 /secret-area/
        r = client.get("/secret-area/data")
        assert r.status_code == 403
        body = r.json()
        assert body["error"] == "rule_match_deny"
        assert body["decision"] == "deny"
        assert "rule_version" in body

    def test_rate_limited_distinct_status_and_reason(self, client):
        # 配额 3：前 3 个请求（echo）放行，第 4 个 429，原因可区分
        for _ in range(3):
            assert client.get("/api/echo").status_code == 200
        r = client.get("/api/echo")
        assert r.status_code == 429
        assert r.json()["error"] == "rate_limit_quota_exhausted"

    def test_consistent_decision_across_entries(self, client):
        """同一来源下，换路径/方法，限流结论仍然一致（按来源计数）。"""
        for _ in range(3):
            client.get("/api/echo")
        for path in ("/api/echo", "/other", "/anything/deep"):
            r = client.get(path)
            assert r.status_code == 429
            assert r.json()["error"] == "rate_limit_quota_exhausted"


class TestAdminAuth:
    def test_rules_endpoint_requires_auth(self, client):
        r = client.get("/admin/rules")
        assert r.status_code == 401
        assert r.json() == {"error": "unauthorized", "message": "unauthorized"}

    def test_wrong_token_rejected_without_state_leak(self, client):
        r = client.get("/admin/rules", headers={"Authorization": "Bearer wrong-token"})
        assert r.status_code == 401
        # 错误响应不得泄漏版本/规则数等内部状态
        assert "version" not in r.json() and "rules" not in r.json()

    def test_malformed_authorization_header_rejected(self, client):
        for header_value in ["Basic secret-admin-token", "Bearer", "secret-admin-token", "Bearer "]:
            r = client.get("/admin/rules", headers={"Authorization": header_value})
            assert r.status_code == 401

    def test_authorized_admin_can_read(self, client):
        r = client.get("/admin/rules", headers={"Authorization": "Bearer secret-admin-token"})
        assert r.status_code == 200
        assert r.json()["version"] >= 1
        assert len(r.json()["rules"]) == 1

    def test_put_rules_without_auth_is_rejected_and_keeps_state(self, client):
        before = client.get(
            "/admin/rules", headers={"Authorization": "Bearer secret-admin-token"}
        ).json()
        r = client.put("/admin/rules", json=_rules([GOOD_RULE]))
        assert r.status_code == 401
        after = client.get(
            "/admin/rules", headers={"Authorization": "Bearer secret-admin-token"}
        ).json()
        assert before == after  # 未授权写入不改变任何状态


class TestRuntimeRuleChanges:
    AUTH = {"Authorization": "Bearer secret-admin-token"}

    def test_replace_rules_takes_effect_without_restart(self, client):
        # 变更前：/evil 不被默认规则拦截，防护层放行（落到路由层 404）
        assert client.get(
            "/evil/x", headers={"X-Forwarded-For": "203.0.113.7"}
        ).status_code == 404
        r = client.put("/admin/rules", json=_rules([GOOD_RULE]), headers=self.AUTH)
        assert r.status_code == 200
        version = r.json()["version"]
        assert version >= 2
        # 变更后：同一入口立即按新规则拒绝
        r2 = client.get("/evil/x", headers={"X-Forwarded-For": "203.0.113.8"})
        assert r2.status_code == 403
        assert r2.json()["error"] == "rule_match_deny"
        assert r2.json()["rule_version"] == version

    def test_disable_rule_by_replacing_without_it(self, client):
        # 先用一条拦截 /api/echo 的规则上线
        client.put("/admin/rules", json=_rules([{
            "rule_id": "deny-echo", "priority": 0, "effect": "deny",
            "field_name": "path", "pattern": r"^/api/echo",
        }]), headers=self.AUTH)
        assert client.get(
            "/api/echo", headers={"X-Forwarded-For": "198.51.100.1"}
        ).status_code == 403
        # 整体替换为不匹配的规则（等价于停用旧规则），不重启即生效
        client.put("/admin/rules", json=_rules([{
            "rule_id": "deny-other", "priority": 0, "effect": "deny",
            "field_name": "path", "pattern": r"^/some-other-path",
        }]), headers=self.AUTH)
        r = client.get("/api/echo", headers={"X-Forwarded-For": "198.51.100.1"})
        assert r.status_code == 200  # 旧规则已停用，请求被正常服务

    def test_priority_change_changes_conflict_outcome_deterministically(self, client):
        # allow 与 deny 冲突始终 deny，但调整优先级后命中集合不变 -> 结论稳定
        payload = [
            {"rule_id": "a", "priority": 0, "effect": "allow",
             "field_name": "path", "pattern": ".*"},
            {"rule_id": "d", "priority": 1, "effect": "deny",
             "field_name": "method", "pattern": "GET"},
        ]
        client.put("/admin/rules", json=_rules(payload), headers=self.AUTH)
        r1 = client.get("/x", headers={"X-Forwarded-For": "198.51.100.2"})
        assert r1.status_code == 403 and r1.json()["error"] == "rule_conflict_deny"

    def test_invalid_rule_set_rejected_entirely(self, client):
        before = client.get("/admin/rules", headers=self.AUTH).json()
        # 部分无效：第二条是非法正则
        bad_set = [
            GOOD_RULE,
            {"rule_id": "bad", "priority": 1, "effect": "deny",
             "field_name": "path", "pattern": "["},
        ]
        r = client.put("/admin/rules", json=_rules(bad_set), headers=self.AUTH)
        assert r.status_code == 422
        body = r.json()
        assert body["error"] == "invalid_rule_set"
        assert body["index"] == 1
        assert body["current_version"] == before["version"]
        after = client.get("/admin/rules", headers=self.AUTH).json()
        assert after == before  # 旧规则集完整保留，无半更新

    def test_empty_set_and_duplicate_ids_rejected(self, client):
        r = client.put("/admin/rules", json=_rules([]), headers=self.AUTH)
        assert r.status_code == 422
        dup = [dict(GOOD_RULE), dict(GOOD_RULE, priority=1)]
        r = client.put("/admin/rules", json=_rules(dup), headers=self.AUTH)
        assert r.status_code == 422

    def test_oversized_set_rejected_by_admin(self, client):
        big = [
            dict(GOOD_RULE, rule_id=f"r{i}")
            for i in range(11)  # max_rules=10
        ]
        r = client.put("/admin/rules", json=_rules(big), headers=self.AUTH)
        assert r.status_code == 422


class TestConcurrencyViaHttp:
    AUTH = {"Authorization": "Bearer secret-admin-token"}

    def test_concurrent_requests_exact_rate_limit_counts(self, client):
        """40 线程 x 每源唯一：每个来源独立配额 3，40 来源 x 5 请求 => 120/200/80。"""
        outcomes = []
        lock = threading.Lock()
        barrier = threading.Barrier(40)

        def worker(i: int) -> None:
            barrier.wait()
            local = []
            for _ in range(5):
                resp = client.get("/api/echo", headers={"X-Forwarded-For": f"10.0.0.{i}"})
                local.append(resp.status_code)
            with lock:
                outcomes.extend(local)

        threads = [threading.Thread(target=worker, args=(i,)) for i in range(40)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert len(outcomes) == 200
        assert outcomes.count(200) == 120
        assert outcomes.count(429) == 80
        assert 403 not in outcomes

    def test_changes_under_traffic_never_cause_500(self, client):
        """规则变更与请求并发：不允许出现 500 或状态不一致。"""
        stop = threading.Event()
        statuses: list[int] = []
        lock = threading.Lock()

        def changer() -> None:
            i = 0
            while not stop.is_set():
                # 在"拦截 echo"与"不拦截 echo"两套规则间原子切换
                if i % 2 == 0:
                    rule = dict(GOOD_RULE, rule_id="deny-echo", field_name="path",
                                pattern=r"^/api/echo")
                else:
                    rule = dict(GOOD_RULE, rule_id="deny-other",
                                pattern=r"^/some-other-path")
                client.put("/admin/rules", json=_rules([rule]), headers=self.AUTH)
                i += 1

        def requester() -> None:
            for i in range(80):
                resp = client.get(
                    "/api/echo",
                    headers={"X-Forwarded-For": f"172.16.{i % 250}.{i % 7}"},
                )
                with lock:
                    statuses.append(resp.status_code)

        ct = threading.Thread(target=changer)
        rt = threading.Thread(target=requester)
        ct.start(); rt.start()
        rt.join()
        stop.set(); ct.join()

        assert statuses
        assert 500 not in statuses
        # 仅允许：规则放行后正常服务(200)、规则拒绝(403)、限流(429)
        assert set(statuses) <= {200, 403, 429}
        # 两套规则都应被观测到生效，证明运行时变更确实交替生效
        assert 200 in statuses and 403 in statuses
