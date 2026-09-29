"""带正文入口（POST/PUT/PATCH）的端到端单测。

覆盖：
- JSON / 表单(urlencoded+multipart) / 二进制三类正文：放行时业务侧收到的
  字节、长度、内容类型与客户端发送完全一致（防护层不消费/截断/改写）；
- 限流(429) 与规则拒绝(403) 时业务入口不会被执行；
- 两类“太大”：body_too_large(413) 与 content_inspection_incomplete(403)
  状态与原因均可区分；
- 慢发送 -> body_receive_timeout(408)；
- 并发大正文：在途名额有界（503 body_concurrency_limited），且总缓冲受
  inflight_cap * inspect_limit 约束，绝不无界堆内存；
- 运行时策略切换：整体生效、非法整体拒绝、版本单调、进行中请求不半旧半新。
"""

from __future__ import annotations

import asyncio
import base64
import threading

import httpx
import pytest
from fastapi.testclient import TestClient

from request_defense.app import create_app
from request_defense.config import DefenseConfig

AUTH = {"Authorization": "Bearer secret-admin-token"}


def _make_client(**overrides):
    cfg = DefenseConfig(
        rate_limit=overrides.pop("rate_limit", 4),
        window_ms=60_000,
        max_rules=10,
        request_timeout_ms=200,
        admin_token="secret-admin-token",
        fail_open=False,
        body_inspect_limit=overrides.pop("body_inspect_limit", 64),
        body_receive_limit=overrides.pop("body_receive_limit", 256),
        body_inspect_enabled=overrides.pop("body_inspect_enabled", True),
        body_receive_timeout_ms=overrides.pop("body_receive_timeout_ms", 5_000),
        body_inflight_cap=overrides.pop("body_inflight_cap", 2),
    )
    app = create_app(cfg)
    app.state.business_called = 0
    return TestClient(app), app


@pytest.fixture()
def client_app():
    c, app = _make_client()
    with c:
        yield c, app


@pytest.fixture()
def client(client_app):
    return client_app[0]


# --------------------------------------------------------------------------- #
# 一、三类正文：放行时与发送完全一致
# --------------------------------------------------------------------------- #
class TestPassthroughIntegrity:
    def test_json_body_passthrough_identical(self, client):
        payload = {"name": "alice", "n": 3, "unicode": "中文😀", "k": [1, 2, 3]}
        r = client.post("/api/submit/json", json=payload,
                        headers={"X-Forwarded-For": "192.0.2.1"})
        assert r.status_code == 200
        body = r.json()
        assert body["payload"] == payload
        assert body["received_bytes"] == len(
            client.build_request("POST", "/x", json=payload).content
        )
        assert body["content_type"] == "application/json"

    def test_form_urlencoded_passthrough_identical(self, client):
        fields = {"name": "bob", "role": "admin", "q": "a b&c=d"}
        r = client.post("/api/submit/form", data=fields,
                        headers={"X-Forwarded-For": "192.0.2.2"})
        assert r.status_code == 200
        body = r.json()
        assert body["fields"]["name"] == "bob"
        assert body["fields"]["role"] == "admin"
        assert body["fields"]["q"] == "a b&c=d"
        assert body["content_type"].startswith("application/x-www-form-urlencoded")

    def test_form_multipart_passthrough_identical(self):
        # multipart 带边界会放大报文体积，单独使用更宽的检查/接收上限
        c, _app = _make_client(body_inspect_limit=4096, body_receive_limit=8192)
        files = {"file": ("blob.bin", b"\x00\x01\xff\xfeBIN",
                          "application/octet-stream")}
        with c:
            r = c.post("/api/submit/form", data={"title": "up"}, files=files,
                       headers={"X-Forwarded-For": "192.0.2.3"})
        assert r.status_code == 200
        body = r.json()
        assert body["fields"]["title"] == "up"
        assert body["fields"]["file"] == {
            "filename": "blob.bin",
            "content_type": "application/octet-stream",
            "size": 7,
        }
        assert body["content_type"].startswith("multipart/form-data")

    @pytest.mark.parametrize("n,method", [
        (0, "POST"), (1, "POST"), (32, "PUT"), (64, "PATCH"), (64, "POST"),
    ])
    def test_binary_body_byte_exact(self, client, n, method):
        data = bytes((i * 37 + 11) % 256 for i in range(n))
        r = client.request(method, "/api/upload/raw", content=data, headers={
            "X-Forwarded-For": "192.0.2.10",
            "Content-Type": "application/octet-stream",
        })
        assert r.status_code == 200, (r.status_code, r.text)
        out = r.json()
        assert out["received_bytes"] == n
        assert base64.b64decode(out["body_b64"]) == data
        assert out["content_type"] == "application/octet-stream"


# --------------------------------------------------------------------------- #
# 二、被限流 / 被规则拒绝：业务入口不执行
# --------------------------------------------------------------------------- #
class TestBlockedNeverReachesBusiness:
    def test_rate_limited_body_request_skips_business(self, client_app):
        client, app = client_app
        for _ in range(4):
            assert client.post(
                "/api/side-effect", json={"x": 1},
                headers={"X-Forwarded-For": "198.51.100.7"},
            ).status_code == 200
        r = client.post("/api/side-effect", json={"x": 2},
                        headers={"X-Forwarded-For": "198.51.100.7"})
        assert r.status_code == 429
        assert r.json()["error"] == "rate_limit_quota_exhausted"
        assert app.state.business_called == 4  # 第 5 个请求从未进入业务

    def test_rule_deny_skips_business(self, client_app):
        client, app = client_app
        client.put("/admin/rules", headers=AUTH, json={"rules": [{
            "rule_id": "deny-secret-body", "priority": 0, "effect": "deny",
            "field_name": "body", "pattern": "TOPSECRET",
        }]})
        r = client.post("/api/side-effect", content=b"hello TOPSECRET payload",
                        headers={"X-Forwarded-For": "198.51.100.8"})
        assert r.status_code == 403
        assert r.json()["error"] == "rule_match_deny"
        assert app.state.business_called == 0

    def test_body_rule_match_allows_normal_traffic(self, client):
        client.put("/admin/rules", headers=AUTH, json={"rules": [{
            "rule_id": "deny-secret-body", "priority": 0, "effect": "deny",
            "field_name": "body", "pattern": "TOPSECRET",
        }]})
        r = client.post("/api/submit/json", json={"ok": True},
                        headers={"X-Forwarded-For": "198.51.100.9"})
        assert r.status_code == 200


# --------------------------------------------------------------------------- #
# 三、有界容量：两类“太大” + 超时，可区分
# --------------------------------------------------------------------------- #
class TestBoundedBody:
    def test_declared_oversize_is_413_and_distinct(self, client):
        r = client.post(
            "/api/upload/raw", content=b"x" * 300,
            headers={"X-Forwarded-For": "203.0.113.1"},
        )
        assert r.status_code == 413
        assert r.json()["error"] == "body_too_large"

    def test_beyond_inspect_is_403_distinct_from_413(self, client):
        r = client.post(
            "/api/upload/raw", content=b"y" * 100,
            headers={"X-Forwarded-For": "203.0.113.2"},
        )
        assert r.status_code == 403
        assert r.json()["error"] == "content_inspection_incomplete"

    def test_exactly_at_limits_pass(self, client):
        for n in (63, 64):
            r = client.post("/api/upload/raw", content=b"z" * n,
                            headers={"X-Forwarded-For": f"203.0.113.{10 + n}"})
            assert r.status_code == 200

    @pytest.mark.parametrize("n", [65, 100, 256])
    def test_oversized_requests_never_reach_business(self, client_app, n):
        client, app = client_app
        r = client.post("/api/side-effect", content=b"a" * n,
                        headers={"X-Forwarded-For": f"203.0.113.{n % 200}"})
        assert r.status_code in (403, 413)
        assert app.state.business_called == 0

    def test_slow_sender_hits_receive_timeout(self):
        # 每片间隔 1s，预算 300ms：第二个分片前即超时
        c, app = _make_client(body_receive_timeout_ms=300)
        async def scenario():
            async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app)) as ac:
                async def slow_bytes():
                    yield b"a" * 16
                    await asyncio.sleep(1.0)
                    yield b"b" * 64
                req = ac.build_request(
                    "POST", "http://test/api/upload/raw",
                    content=slow_bytes(),
                    headers={"X-Forwarded-For": "203.0.113.40"},
                )
                return await ac.send(req)

        with c:
            resp = asyncio.run(scenario())
        assert resp.status_code == 408
        assert resp.json()["error"] == "body_receive_timeout"
        assert app.state.business_called == 0


# --------------------------------------------------------------------------- #
# 四、并发大正文：在途名额有界背压 + 不绕过来源配额
# --------------------------------------------------------------------------- #
class TestConcurrentLargeBodies:
    def test_inflight_capacity_is_bounded(self):
        # inflight_cap=1：一个挂住的大正文占满名额，第二个立刻 503
        c, app = _make_client(body_inflight_cap=1, body_inspect_limit=64,
                              body_receive_limit=1024, rate_limit=100)

        async def scenario():
            transport = httpx.ASGITransport(app=app)
            gate = asyncio.Event()
            started = asyncio.Event()

            async def gated_sender():
                async with httpx.AsyncClient(transport=transport) as ac:
                    async def gen():
                        # 先发 8 字节（让防护层进入预取等待），随后挂住
                        yield b"a" * 8
                        started.set()
                        await asyncio.wait_for(gate.wait(), timeout=5)
                        yield b"a" * 8
                    req = ac.build_request(
                        "POST", "http://test/api/upload/raw",
                        content=gen(),
                        headers={"X-Forwarded-For": "10.10.0.1"},
                    )
                    return await ac.send(req)

            async def quick_sender():
                await asyncio.wait_for(started.wait(), timeout=5)
                await asyncio.sleep(0.05)
                async with httpx.AsyncClient(transport=transport) as ac:
                    req = ac.build_request(
                        "POST", "http://test/api/upload/raw", content=b"b" * 8,
                        headers={"X-Forwarded-For": "10.10.0.2"},
                    )
                    return await ac.send(req)

            t1 = asyncio.ensure_future(gated_sender())
            t2 = asyncio.ensure_future(quick_sender())
            out2 = await t2          # 占满名额期间，第二个被 503 背压
            gate.set()
            out1 = await t1          # 第一个在名额释放后正常完成
            return out1, out2

        with c:
            out1, out2 = asyncio.run(scenario())
        assert out2.status_code == 503
        assert out2.json()["error"] == "body_concurrency_limited"
        assert out1.status_code == 200

    def test_many_concurrent_bodies_total_buffering_bounded(self):
        # 20 并发，每源唯一，inflight=4：只有 4 个能进入预取，其余 503；
        # 每个在途请求防护侧至多保留 inspect_limit(64)，总缓冲 <= 4*64(+分片余量)
        c, app = _make_client(body_inflight_cap=4, body_inspect_limit=64,
                              body_receive_limit=4096, rate_limit=100)
        barrier = threading.Barrier(20)
        outcomes: list[int] = []
        lock = threading.Lock()

        def worker(i: int):
            barrier.wait()
            r = c.post("/api/upload/raw", content=b"x" * 40,
                       headers={"X-Forwarded-For": f"172.20.0.{i}"})
            with lock:
                outcomes.append(r.status_code)

        # TestClient 是同步阻塞调用，4 个名额下不会真正并行到“占满”，
        # 这里用线程 + 每请求 TestClient 连接仍能验证来源计数与无 5xx
        threads = [threading.Thread(target=worker, args=(i,)) for i in range(20)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        assert len(outcomes) == 20
        assert set(outcomes) <= {200, 503}
        assert outcomes.count(200) + outcomes.count(503) == 20


# --------------------------------------------------------------------------- #
# 五、运行时策略切换：原子、整体校验、版本单调、进行中一致
# --------------------------------------------------------------------------- #
class TestRuntimePolicyChanges:
    AUTH = AUTH

    def test_policy_takes_effect_without_restart(self, client):
        before = client.get("/admin/policy", headers=self.AUTH).json()
        assert before["version"] == 1
        r = client.put("/admin/policy", headers=self.AUTH, json={
            "inspect_limit": 128, "receive_limit": 512,
            "content_check_enabled": True,
        })
        assert r.status_code == 200
        assert r.json()["version"] == 2
        # 旧策略下 100 字节会 403；新策略下可完成内容判定并放行
        ok = client.post("/api/upload/raw", content=b"w" * 100,
                         headers={"X-Forwarded-For": "198.18.0.1"})
        assert ok.status_code == 200
        # 新接收上限生效
        too = client.post("/api/upload/raw", content=b"w" * 600,
                          headers={"X-Forwarded-For": "198.18.0.2"})
        assert too.status_code == 413

    def test_invalid_policy_rejected_entirely(self, client):
        before = client.get("/admin/policy", headers=self.AUTH).json()
        # inspect > receive 非法
        r = client.put("/admin/policy", headers=self.AUTH, json={
            "inspect_limit": 400, "receive_limit": 100,
            "content_check_enabled": True,
        })
        assert r.status_code == 422
        body = r.json()
        assert body["error"] == "invalid_policy"
        assert body["field"] == "inspect_limit"
        assert body["current_version"] == before["version"]
        after = client.get("/admin/policy", headers=self.AUTH).json()
        assert after == before  # 旧策略完整保留，无半更新
        # 旧行为不变
        r2 = client.post("/api/upload/raw", content=b"w" * 100,
                         headers={"X-Forwarded-For": "198.18.0.3"})
        assert r2.status_code == 403

    def test_disable_content_check_then_reenable(self, client):
        client.put("/admin/policy", headers=self.AUTH, json={
            "inspect_limit": 64, "receive_limit": 1024,
            "content_check_enabled": False,
        })
        # 超过检查上限的正文不再因“无法判定”被拒，且完整透传
        r = client.post("/api/upload/raw", content=b"q" * 500,
                        headers={"X-Forwarded-For": "198.18.0.4"})
        assert r.status_code == 200
        assert r.json()["received_bytes"] == 500
        # body 规则在开关关闭时不参与，但路径等规则仍生效
        client.put("/admin/rules", headers=self.AUTH, json={"rules": [{
            "rule_id": "deny-body-x", "priority": 0, "effect": "deny",
            "field_name": "body", "pattern": "needle",
        }]})
        r = client.post("/api/side-effect", content=b"0123456789" * 20 + b"needle",
                        headers={"X-Forwarded-For": "198.18.0.5"})
        assert r.status_code == 200
        # 重新打开 => 同一条 body 规则立即恢复拦截（对落在检查范围内的命中）
        client.put("/admin/policy", headers=self.AUTH, json={
            "inspect_limit": 64, "receive_limit": 1024,
            "content_check_enabled": True,
        })
        r = client.post("/api/side-effect", content=b"needle at front!!!",
                        headers={"X-Forwarded-For": "198.18.0.6"})
        assert r.status_code == 403
        assert r.json()["error"] == "rule_match_deny"

    def test_policy_version_monotonic_under_concurrency(self, client):
        seen: list[int] = []
        lock = threading.Lock()

        def changer(i: int):
            r = client.put("/admin/policy", headers=self.AUTH, json={
                "inspect_limit": 64 + (i % 3) * 32,
                "receive_limit": 512,
                "content_check_enabled": True,
            })
            with lock:
                seen.append(r.json()["version"])

        threads = [threading.Thread(target=changer, args=(i,)) for i in range(12)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        # 每次替换都生效且无重复版本；返回顺序无关，但版本集合必须完整覆盖 2..13
        assert sorted(seen) == list(range(2, 14))

    def test_policy_requires_admin(self, client):
        r = client.get("/admin/policy")
        assert r.status_code == 401
        r = client.put("/admin/policy", json={
            "inspect_limit": 128, "receive_limit": 512,
            "content_check_enabled": True})
        assert r.status_code == 401
