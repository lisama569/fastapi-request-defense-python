"""分段/流式正文判定一致性测试（复现 bugfix-b 场景）。

同一份正文，无论：
- 一次性整包（bytes + Content-Length）；
- 分多片推送（async generator，显式声明 Content-Length）；
- 不带长度一段段推（async generator => Transfer-Encoding: chunked）；
- 第一片就整段超过上限；

最终结论必须一致：
- <= inspect_limit：放行，业务侧收到与发送完全一致的完整正文；
- inspect_limit < len <= receive_limit：403 content_inspection_incomplete；
- > receive_limit：413 body_too_large（两类“太大”始终可区分）；
且被拒绝时业务入口绝不被调用。
"""

from __future__ import annotations

import asyncio
import base64

import httpx
import pytest

from request_defense.app import create_app
from request_defense.config import DefenseConfig

AUTH = {"Authorization": "Bearer secret-admin-token"}


def _make_client(**overrides):
    cfg = DefenseConfig(
        rate_limit=overrides.pop("rate_limit", 100),
        window_ms=60_000,
        max_rules=10,
        request_timeout_ms=200,
        admin_token="secret-admin-token",
        fail_open=False,
        body_inspect_limit=overrides.pop("body_inspect_limit", 64),
        body_receive_limit=overrides.pop("body_receive_limit", 256),
        body_inspect_enabled=overrides.pop("body_inspect_enabled", True),
        body_receive_timeout_ms=overrides.pop("body_receive_timeout_ms", 5_000),
        body_inflight_cap=overrides.pop("body_inflight_cap", 4),
    )
    app = create_app(cfg)
    app.state.business_called = 0
    return app


def _chunk_gen(data: bytes, size: int | None):
    """size=None 时一次性给出整段（模拟第一片就超上限）。"""
    if size is None:
        async def gen_one():
            await asyncio.sleep(0)
            yield data
        return gen_one()

    async def gen():
        for i in range(0, len(data), size):
            await asyncio.sleep(0)
            yield data[i:i + size]
    return gen()


async def _send(app, data, *, chunk_size, declare_length, source):
    """以三种送达方式之一发送同一份正文，返回响应。"""
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport) as ac:
        headers = {"X-Forwarded-For": source}
        if chunk_size == "whole":
            # 整包：httpx 自动带 Content-Length
            content = data
        else:
            content = _chunk_gen(data, chunk_size)
            if declare_length:
                headers["content-length"] = str(len(data))
        req = ac.build_request(
            "POST", "http://test/api/upload/raw",
            content=content, headers=headers,
        )
        return await ac.send(req)


def _run(coro):
    return asyncio.run(coro)


# 送达方式矩阵：(分片大小, 是否声明长度)；"whole" 表示整包发送
# chunk=None 表示第一片就是整段（不带长度）
DELIVERY = [
    ("whole", False),   # 整包 bytes（httpx 自动带 Content-Length）
    (1, False),         # 1 字节/片，不带长度（chunked）
    (1, True),          # 1 字节/片，显式声明长度
    (7, False),
    (7, True),
    (32, False),
    (32, True),
    (64, False),
    (64, True),
    (None, False),      # 第一片就是整段、不带长度
]


class TestStreamingVerdictConsistency:
    """同一份正文，三种送达方式结论必须一致。"""

    @pytest.mark.parametrize("n,expected", [
        (0, 200), (1, 200), (63, 200), (64, 200),          # 恰好等于检查上限仍放行
        (65, 403), (100, 403), (256, 403),                  # 超过检查、未超接收 => 403
        (257, 413), (300, 413), (400, 413),                 # 超过接收 => 413
    ])
    def test_same_body_same_verdict_regardless_of_delivery(self, n, expected):
        app = _make_client()
        data = bytes((i * 31 + 7) % 256 for i in range(n))
        for idx, (chunk_size, declare_length) in enumerate(DELIVERY):
            resp = _run(_send(
                app, data, chunk_size=chunk_size,
                declare_length=declare_length,
                source=f"198.51.100.{(n + idx) % 250 + 1}",
            ))
            assert resp.status_code == expected, (
                f"n={n} delivery={chunk_size}/{declare_length}: "
                f"got {resp.status_code}, want {expected} body={resp.text[:200]}"
            )
            if expected == 403:
                assert resp.json()["error"] == "content_inspection_incomplete"
            elif expected == 413:
                assert resp.json()["error"] == "body_too_large"

    @pytest.mark.parametrize("chunk_size,declare_length", [
        (1, False), (7, True), (32, False), (64, True), ("whole", False),
    ])
    def test_allowed_streamed_body_arrives_byte_exact(self, chunk_size, declare_length):
        app = _make_client()
        data = bytes((i * 17 + 3) % 256 for i in range(64))
        resp = _run(_send(
            app, data, chunk_size=chunk_size,
            declare_length=declare_length, source="198.51.100.201",
        ))
        assert resp.status_code == 200, resp.text
        out = resp.json()
        assert out["received_bytes"] == 64
        assert base64.b64decode(out["body_b64"]) == data

    @pytest.mark.parametrize("chunk_size,declare_length", [
        (1, False), (10, True), (32, False), (None, False),
    ])
    def test_rejected_streamed_body_never_reaches_business(
        self, chunk_size, declare_length
    ):
        app = _make_client()

        async def post_side_effect(data):
            transport = httpx.ASGITransport(app=app)
            async with httpx.AsyncClient(transport=transport) as ac:
                headers = {"X-Forwarded-For": "198.51.100.202"}
                if chunk_size is None:
                    async def gen():
                        yield data
                    content = gen()
                else:
                    content = _chunk_gen(data, chunk_size)
                if declare_length:
                    headers["content-length"] = str(len(data))
                req = ac.build_request(
                    "POST", "http://test/api/side-effect",
                    content=content, headers=headers,
                )
                return await ac.send(req)

        # 100 字节：超过检查上限；400 字节：超过接收上限
        for n in (100, 400):
            resp = _run(post_side_effect(b"x" * n))
            assert resp.status_code in (403, 413)
            assert app.state.business_called == 0

    def test_chunked_receive_limit_classifies_413_not_403(self):
        """无长度分片流超过接收上限：必须是 413 而不是 403。"""
        app = _make_client()
        # 每片 100，共 400，无 Content-Length
        resp = _run(_send(
            app, b"z" * 400, chunk_size=100, declare_length=False,
            source="198.51.100.203",
        ))
        assert resp.status_code == 413
        assert resp.json()["error"] == "body_too_large"
        assert app.state.business_called == 0

    def test_chunked_declared_receive_limit_classifies_413(self):
        """分多片推送但声明了长度、且声明超接收上限：结论仍是 413。"""
        app = _make_client()
        resp = _run(_send(
            app, b"z" * 400, chunk_size=37, declare_length=True,
            source="198.51.100.204",
        ))
        assert resp.status_code == 413
        assert resp.json()["error"] == "body_too_large"


class TestRulesBehindInspectBoundary:
    """写在检查范围之后的正文规则不能因分片送达被绕过。"""

    def test_deny_rule_beyond_inspect_boundary_chunked_is_strict_403(self):
        app = _make_client()
        transport = httpx.ASGITransport(app=app)

        async def run():
            async with httpx.AsyncClient(transport=transport) as ac:
                await ac.put(
                    "http://test/admin/rules", headers=AUTH,
                    json={"rules": [{
                        "rule_id": "tail-needle", "priority": 0, "effect": "deny",
                        "field_name": "body", "pattern": "NEEDLE",
                    }]},
                )
                # 命中点位于第 100 字节，超出 inspect_limit=64
                data = b"a" * 94 + b"NEEDLE"
                req = ac.build_request(
                    "POST", "http://test/api/side-effect",
                    content=_chunk_gen(data, 3),
                    headers={"X-Forwarded-For": "198.51.100.210"},
                )
                return await ac.send(req)

        resp = _run(run())
        # 不能是 200（静默放行）；fail-closed 给出 403，原因是无法完成内容判定
        assert resp.status_code == 403
        assert resp.json()["error"] == "content_inspection_incomplete"
        assert app.state.business_called == 0


class TestStreamingMultiSegment:
    def test_multi_segment_concatenation_byte_exact(self):
        """多种分片大小拼接后，放行正文必须与发送逐字节一致。"""
        app = _make_client(body_inspect_limit=256, body_receive_limit=1024)
        data = bytes((i * 13 + 5) % 256 for i in range(200))
        for size in (1, 3, 17, 64, 128, 200):
            resp = _run(_send(
                app, data, chunk_size=size, declare_length=(size % 2 == 0),
                source=f"198.51.100.{size}",
            ))
            assert resp.status_code == 200, (size, resp.text)
            out = resp.json()
            assert out["received_bytes"] == 200
            assert base64.b64decode(out["body_b64"]) == data


class TestStreamingConcurrentLargeBodies:
    def test_concurrent_chunked_bodies_bounded_and_quota_enforced(self):
        # inflight=2；12 个并发分块大正文，每源唯一；只允许 200/503/403/413，无 5xx
        app = _make_client(body_inflight_cap=2, body_inspect_limit=64,
                           body_receive_limit=4096, rate_limit=100)

        async def one(i):
            transport = httpx.ASGITransport(app=app)

            async def gen():
                for j in range(4):
                    await asyncio.sleep(0.01)
                    yield b"x" * 40
            async with httpx.AsyncClient(transport=transport) as ac:
                req = ac.build_request(
                    "POST", "http://test/api/upload/raw", content=gen(),
                    headers={"X-Forwarded-For": f"172.30.{i // 10}.{i}"},
                )
                return await ac.send(req)

        async def run():
            return await asyncio.gather(*(one(i) for i in range(12)))

        resps = _run(run())
        statuses = sorted(r.status_code for r in resps)
        assert all(s in (200, 503, 403, 413) for s in statuses), statuses
        # 160 > inspect 64：完成预取的请求一律 403（不允许出现“分片就 200 放行”）
        assert 200 not in statuses

    def test_concurrent_chunked_does_not_bypass_source_quota(self):
        # 每源限额 3：同一来源用分块流式连发 6 个，恰好 3 个 429（限流先于读正文）
        app = _make_client(rate_limit=3)

        async def one(i):
            transport = httpx.ASGITransport(app=app)

            async def gen():
                yield b"q" * 10
            async with httpx.AsyncClient(transport=transport) as ac:
                req = ac.build_request(
                    "POST", "http://test/api/upload/raw", content=gen(),
                    headers={"X-Forwarded-For": "203.0.113.77"},
                )
                return await ac.send(req)

        async def run():
            return await asyncio.gather(*(one(i) for i in range(6)))

        resps = _run(run())
        codes = sorted(r.status_code for r in resps)
        assert codes.count(429) == 3, codes
        assert codes.count(200) == 3, codes


class TestStreamingSlowSender:
    def test_chunked_slow_sender_hits_timeout_without_business(self):
        """分多片慢推送：每片间隔超过正文时间预算 => 408，业务不执行。"""
        app = _make_client(body_receive_timeout_ms=200)
        transport = httpx.ASGITransport(app=app)

        async def scenario():
            async with httpx.AsyncClient(transport=transport) as ac:
                async def gen():
                    yield b"a" * 8
                    await asyncio.sleep(1.0)   # 后续片迟迟不来
                    yield b"b" * 8
                req = ac.build_request(
                    "POST", "http://test/api/side-effect", content=gen(),
                    headers={"X-Forwarded-For": "198.51.100.230"},
                )
                return await ac.send(req)

        resp = asyncio.run(scenario())
        assert resp.status_code == 408
        assert resp.json()["error"] == "body_receive_timeout"
        assert app.state.business_called == 0


class TestRuntimePolicyDuringSegmentedRequest:
    def test_policy_shrink_mid_flight_applies_new_limit_to_pending_body(self):
        """分段请求处理途中不重启调小接收上限：后续片必须按新策略判定为 413。"""
        app = _make_client(body_receive_limit=4096, body_inspect_limit=64,
                           body_receive_timeout_ms=5000)
        transport = httpx.ASGITransport(app=app)
        gate = asyncio.Event()
        started = asyncio.Event()

        async def scenario():
            async def upload():
                async with httpx.AsyncClient(transport=transport) as ac:
                    async def gen():
                        yield b"a" * 8                 # 让防护层进入正文阶段
                        started.set()
                        await asyncio.wait_for(gate.wait(), timeout=5)
                        for _ in range(40):
                            await asyncio.sleep(0)
                            yield b"a" * 100           # 随后推 4000 字节
                    req = ac.build_request(
                        "POST", "http://test/api/upload/raw", content=gen(),
                        headers={"X-Forwarded-For": "198.51.100.220"},
                    )
                    return await ac.send(req)

            async def change_policy():
                await asyncio.wait_for(started.wait(), timeout=5)
                await asyncio.sleep(0.05)
                async with httpx.AsyncClient(transport=transport) as ac:
                    return await ac.put(
                        "http://test/admin/policy", headers=AUTH,
                        json={"inspect_limit": 64, "receive_limit": 512,
                              "content_check_enabled": True},
                    )

            changer = asyncio.ensure_future(change_policy())
            uploader = asyncio.ensure_future(upload())
            pol = await changer
            gate.set()
            resp = await uploader
            return pol, resp

        pol, resp = asyncio.run(scenario())
        assert pol.status_code == 200
        assert resp.status_code == 413
        assert resp.json()["error"] == "body_too_large"
        assert app.state.business_called == 0

    def test_policy_inspect_grow_mid_flight_allows_complete_body(self):
        """分段请求途中不重启调大检查上限：在途请求按新上限完成判定并放行，
        不会仍按旧上限给 content_inspection_incomplete（不能一半旧一半新）。"""
        app = _make_client(body_receive_limit=4096, body_inspect_limit=64,
                           body_receive_timeout_ms=5000)
        transport = httpx.ASGITransport(app=app)
        gate = asyncio.Event()
        started = asyncio.Event()
        data = b"g" * 200

        async def scenario():
            async def upload():
                async with httpx.AsyncClient(transport=transport) as ac:
                    async def gen():
                        yield data[:8]
                        started.set()
                        await asyncio.wait_for(gate.wait(), timeout=5)
                        yield data[8:]
                    req = ac.build_request(
                        "POST", "http://test/api/upload/raw", content=gen(),
                        headers={"X-Forwarded-For": "198.51.100.221"},
                    )
                    return await ac.send(req)

            async def change_policy():
                await asyncio.wait_for(started.wait(), timeout=5)
                await asyncio.sleep(0.05)
                async with httpx.AsyncClient(transport=transport) as ac:
                    return await ac.put(
                        "http://test/admin/policy", headers=AUTH,
                        json={"inspect_limit": 256, "receive_limit": 4096,
                              "content_check_enabled": True},
                    )

            changer = asyncio.ensure_future(change_policy())
            uploader = asyncio.ensure_future(upload())
            pol = await changer
            gate.set()
            resp = await uploader
            return pol, resp

        pol, resp = asyncio.run(scenario())
        assert pol.status_code == 200
        assert resp.status_code == 200, resp.text
        assert resp.json()["received_bytes"] == 200
        assert base64.b64decode(resp.json()["body_b64"]) == data

    def test_policy_inspect_shrink_mid_flight_rejects_pending_body(self):
        """分段请求途中调小检查上限：在途请求按新上限判 403（完整生效）。"""
        app = _make_client(body_receive_limit=4096, body_inspect_limit=256,
                           body_receive_timeout_ms=5000)
        transport = httpx.ASGITransport(app=app)
        gate = asyncio.Event()
        started = asyncio.Event()
        data = b"s" * 200

        async def scenario():
            async def upload():
                async with httpx.AsyncClient(transport=transport) as ac:
                    async def gen():
                        yield data[:8]
                        started.set()
                        await asyncio.wait_for(gate.wait(), timeout=5)
                        yield data[8:]
                    req = ac.build_request(
                        "POST", "http://test/api/side-effect", content=gen(),
                        headers={"X-Forwarded-For": "198.51.100.222"},
                    )
                    return await ac.send(req)

            async def change_policy():
                await asyncio.wait_for(started.wait(), timeout=5)
                await asyncio.sleep(0.05)
                async with httpx.AsyncClient(transport=transport) as ac:
                    return await ac.put(
                        "http://test/admin/policy", headers=AUTH,
                        json={"inspect_limit": 64, "receive_limit": 4096,
                              "content_check_enabled": True},
                    )

            changer = asyncio.ensure_future(change_policy())
            uploader = asyncio.ensure_future(upload())
            pol = await changer
            gate.set()
            resp = await uploader
            return pol, resp

        pol, resp = asyncio.run(scenario())
        assert pol.status_code == 200
        assert resp.status_code == 403
        assert resp.json()["error"] == "content_inspection_incomplete"
        assert app.state.business_called == 0

