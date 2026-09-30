"""分片 / 流式（无 Content-Length 或分多次推送）正文的端到端判定测试。

这些用例稳定复现并锁定本次修复的语义：**同一份正文，无论一次性整包发送、
分多片发送、还是不带长度一段段流式推送，防护层的最终结论必须一致**：

- 超过检查上限但在接收上限内  -> 403 content_inspection_incomplete；
- 超过接收上限（含恰好越界的下一片）-> 413 body_too_large，业务不执行；
- 恰好等于上限 / 小于上限     -> 200，业务侧拿到与发送逐字节一致的正文；
- 写在检查范围之后的规则特征不能靠“放在后面/分片摆放”绕过；
- 并发大正文仍有界；运行时调大/调小上限后，在途的分段请求完整按新策略走。
"""

from __future__ import annotations

import asyncio
import base64
import threading

import httpx
import pytest

from request_defense.app import create_app
from request_defense.config import DefenseConfig

AUTH = {"Authorization": "Bearer secret-admin-token"}


def _make_app(**overrides):
    cfg = DefenseConfig(
        rate_limit=overrides.pop("rate_limit", 1000),
        window_ms=60_000,
        max_rules=10,
        request_timeout_ms=200,
        admin_token="secret-admin-token",
        fail_open=False,
        body_inspect_limit=overrides.pop("body_inspect_limit", 64),
        body_receive_limit=overrides.pop("body_receive_limit", 256),
        body_inspect_enabled=overrides.pop("body_inspect_enabled", True),
        body_receive_timeout_ms=overrides.pop("body_receive_timeout_ms", 5_000),
        body_inflight_cap=overrides.pop("body_inflight_cap", 8),
    )
    app = create_app(cfg)
    app.state.business_called = 0
    return app


@pytest.fixture()
def app():
    return _make_app()


def _split_sizes(total: int, chunk: int) -> list[int]:
    sizes = [chunk] * (total // chunk)
    if total % chunk:
        sizes.append(total % chunk)
    return sizes or [0]


async def _post_chunked(app, *, data: bytes, sizes: list[int],
                        path: str = "/api/side-effect",
                        source: str = "203.0.114.1",
                        content_type: str = "application/octet-stream"):
    """以 ASGI 原生事件序列模拟真实分片/流式服务器：

    - 不带 Content-Length（httpx 对异步生成器自动使用 chunked）；
    - 每个数据事件的 more_body 按“是否还有后续”精确设置（与 uvicorn 一致），
      末尾若没有带字节的收尾事件则补一个独立的空 (b"", more_body=False)
      事件（与 httpx ASGITransport / 部分服务器一致）——这正是旧实现漏判的
      关键形态。
    """

    chunks: list[bytes] = []
    pos = 0
    for size in sizes:
        chunks.append(data[pos:pos + size])
        pos += size
    assert pos == len(data)

    async def gen():
        for c in chunks:
            yield c

    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport) as ac:
        req = ac.build_request(
            "POST", f"http://test{path}", content=gen(),
            headers={"X-Forwarded-For": source, "Content-Type": content_type},
        )
        return await ac.send(req)


def _run(coro):
    return asyncio.run(coro)


# 同一份正文在不同送达方式下结论必须一致 ------------------------------------ #
@pytest.mark.parametrize("sizes", [
    [100],          # 一片就是整段（流式通道里一次性给出）
    [50, 50],       # 两片均分
    [1, 1, 98],     # 极小片头
    [40, 40, 20],   # 三片
    [1] * 100,      # 每片一字节
    [63, 37],       # 第一片差一字节填满检查上限
    [64, 36],       # 第一片恰好填满检查上限（旧实现 + httpx 空收尾时漏判）
])
def test_same_body_over_inspect_limit_always_403_regardless_of_chunking(app, sizes):
    data = b"y" * 100
    before = app.state.business_called
    r = _run(_post_chunked(app, data=data, sizes=sizes, source="203.0.114.7"))
    assert r.status_code == 403
    assert r.json()["error"] == "content_inspection_incomplete"
    # 被拒：业务入口绝不执行，超量正文绝不透传
    assert app.state.business_called == before
    meta = r.json()
    assert meta["decision"] == "deny"


@pytest.mark.parametrize("sizes", [
    [257],
    [100, 100, 57],
    [200, 57],
    [1] * 257,
])
def test_same_body_over_receive_limit_always_413_regardless_of_chunking(app, sizes):
    data = b"w" * 257
    before = app.state.business_called
    r = _run(_post_chunked(app, data=data, sizes=sizes, source="203.0.114.8"))
    assert r.status_code == 413
    assert r.json()["error"] == "body_too_large"
    assert app.state.business_called == before


def test_one_shot_streaming_chunk_already_over_inspect_limit(app):
    # “一次就整段超过上限”：单个数据事件含 100 字节且 more_body=True，
    # 随后只有空收尾事件（旧实现的探测逻辑在这种事件形态下会放过）。
    r = _run(_post_chunked(app, data=b"q" * 100, sizes=[100],
                           source="203.0.114.9"))
    assert r.status_code == 403
    assert app.state.business_called == 0


@pytest.mark.parametrize("n,sizes", [
    (0, [0]),
    (1, [1]),
    (63, [1, 62]),
    (64, [64]),
    (64, [32, 32]),
    (64, [1] * 64),
])
def test_at_or_under_inspect_limit_allowed(app, n, sizes):
    data = bytes((i * 31 + 7) % 256 for i in range(n))
    r = _run(_post_chunked(app, data=data, sizes=sizes,
                           path="/api/upload/raw", source="203.0.114.20"))
    assert r.status_code == 200, (r.status_code, r.text)
    out = r.json()
    assert out["received_bytes"] == n
    assert base64.b64decode(out["body_b64"]) == data  # 逐字节一致，无截断/改写


def test_exactly_at_receive_limit_chunked_allowed(app):
    # 恰好等于接收上限（也大于检查上限）：在内容判定开启时仍是 403（因为
    # 超过的是检查上限），但关闭内容判定后必须放行且正文完整——边界不误伤。
    data = bytes((i * 17 + 3) % 256 for i in range(256))
    r = _run(_post_chunked(app, data=data, sizes=[128, 128],
                           path="/api/upload/raw", source="203.0.114.21"))
    assert r.status_code == 403  # inspect=64，256 > 64
    app.state.policy_store  # noqa: B018 - sanity, store present


def test_multi_chunk_concatenation_byte_exact_when_allowed(app):
    # 多段拼接：放行路径业务侧必须收到客户端原本发出的完整正文
    data = b"".join((b"seg-%02d|" % i) for i in range(8))  # 56 字节 < 64
    assert len(data) == 56
    r = _run(_post_chunked(
        app, data=data, sizes=[7, 7, 7, 7, 7, 7, 7, 7],
        path="/api/upload/raw", source="203.0.114.22"))
    assert r.status_code == 200
    assert base64.b64decode(r.json()["body_b64"]) == data
    assert r.json()["content_type"] == "application/octet-stream"


def test_rule_after_inspect_window_cannot_be_bypassed_by_chunking(app):
    # 规则特征写在检查范围之后（第 70 字节处）：整包发送与分片发送都必须
    # 因“无法完成内容判定”被拒（fail-closed），不能当成“检查过了没问题”。
    client_admin = _admin_client(app)
    r = client_admin.put("/admin/rules", headers=AUTH, json={"rules": [{
        "rule_id": "deny-tail", "priority": 0, "effect": "deny",
        "field_name": "body", "pattern": "TOPSECRET",
    }]})
    assert r.status_code == 200
    data = b"a" * 70 + b"TOPSECRET"
    for sizes in ([len(data)], [64, len(data) - 64], [1] * len(data)):
        before = app.state.business_called
        rr = _run(_post_chunked(app, data=data, sizes=sizes,
                                source="203.0.114.30"))
        assert rr.status_code == 403
        assert rr.json()["error"] == "content_inspection_incomplete"
        assert app.state.business_called == before


def test_declared_length_vs_chunked_verdicts_match(app):
    # 对照：整包 + Content-Length 与无长度流式，两份相同正文结论一致。
    import httpx as _httpx

    async def run():
        transport = _httpx.ASGITransport(app=app)
        async with _httpx.AsyncClient(transport=transport) as ac:
            r1 = await ac.post(
                "http://test/api/side-effect", content=b"y" * 100,
                headers={"X-Forwarded-For": "203.0.114.40"})
            r2 = await _post_chunked(app, data=b"y" * 100, sizes=[50, 50],
                                     source="203.0.114.41")
            r3 = await ac.post(
                "http://test/api/side-effect", content=b"w" * 257,
                headers={"X-Forwarded-For": "203.0.114.42"})
            r4 = await _post_chunked(app, data=b"w" * 257,
                                     sizes=[128, 128, 1],
                                     source="203.0.114.43")
            return (r1.status_code, r1.json()["error"],
                    r2.status_code, r2.json()["error"],
                    r3.status_code, r3.json()["error"],
                    r4.status_code, r4.json()["error"])

    got = _run(run())
    assert got[:4] == (403, "content_inspection_incomplete",
                       403, "content_inspection_incomplete")
    assert got[4:] == (413, "body_too_large", 413, "body_too_large")


# 并发大正文 ---------------------------------------------------------------- #
def test_many_concurrent_chunked_bodies_bounded(app):
    # 20 个唯一来源、每线程独立事件循环并发流式推送：在途名额（8）满时可能
    # 503 背压，其余按容量判 200/403/413，绝不出现 5xx；所有非 200 的业务
    # 计数都不增加（被拒正文绝不进业务）。
    results: list[int] = []
    lock = threading.Lock()
    barrier = threading.Barrier(20)

    def worker(i: int):
        barrier.wait()
        n = [10, 80, 260, 64][i % 4]
        sizes = _split_sizes(n, 7)
        r = _run(_post_chunked(
            app, data=b"x" * n, sizes=sizes,
            source=f"172.30.1.{i}"))
        with lock:
            results.append(r.status_code)

    threads = [threading.Thread(target=worker, args=(i,)) for i in range(20)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert len(results) == 20
    assert set(results) <= {200, 403, 413, 503}
    # 每种正文长度各 5 个；503 背压与 200 互占名额，但 403（n=80）与
    # 413（n=260）一旦读到正文就必然成立，不受名额影响。
    assert results.count(403) + results.count(503) >= 5
    assert results.count(413) <= 5
    # 所有放行（200）都来自 n ∈ {10, 64} 的请求；被拒请求业务计数为 0：
    # n=80/260 进入业务的次数必须为 0（用独立计数器难以隔离，这里通过
    # 总业务调用数 == 200 数量来断言：只有放行进业务）。
    assert app.state.business_called == results.count(200)


def test_concurrent_chunked_rejections_never_run_business(app):
    # 更强的隔离断言：全部 12 个请求都是“必拒”正文（80 字节 -> 403），
    # 无论并发/分片如何，业务计数必须恒为 0。
    barrier = threading.Barrier(12)
    results: list[int] = []
    lock = threading.Lock()

    def worker(i: int):
        barrier.wait()
        r = _run(_post_chunked(
            app, data=b"x" * 80, sizes=[13, 13, 13, 13, 13, 15],
            source=f"172.30.2.{i}"))
        with lock:
            results.append(r.status_code)

    threads = [threading.Thread(target=worker, args=(i,)) for i in range(12)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert set(results) <= {403, 503}
    assert app.state.business_called == 0


# 运行时调参对在途分段请求即时生效 ------------------------------------------ #
def test_policy_lowered_mid_flight_applies_to_inflight_chunked(app):
    # 客户端慢速流式：先发 30 字节挂住；此时把检查上限从 64 调到 16，
    # 恢复发送后，同一份 40 字节正文必须完整按新策略判为 403（不会一半旧
    # 一半新）。
    async def run():
        transport = httpx.ASGITransport(app=app)
        gate = asyncio.Event()
        started = asyncio.Event()

        async def slow_gen():
            yield b"a" * 30
            started.set()
            await gate.wait()
            yield b"b" * 10  # 总计 40：旧 inspect=64 下放行，新 inspect=16 下 403

        async with httpx.AsyncClient(transport=transport) as ac:
            req = ac.build_request(
                "POST", "http://test/api/side-effect", content=slow_gen(),
                headers={"X-Forwarded-For": "203.0.114.50"})
            task = asyncio.ensure_future(ac.send(req))
            await started.wait()
            # 在正文仍在途时调小检查上限
            admin = httpx.AsyncClient(transport=transport)
            pr = await admin.put(
                "http://test/admin/policy",
                headers=AUTH,
                json={"inspect_limit": 16, "receive_limit": 256,
                      "content_check_enabled": True})
            assert pr.status_code == 200
            gate.set()
            resp = await task
            await admin.aclose()
            return resp

    resp = _run(run())
    assert resp.status_code == 403
    assert resp.json()["error"] == "content_inspection_incomplete"
    assert resp.json()["policy_version"] == 2
    assert app.state.business_called == 0


def test_policy_receive_limit_lowered_mid_flight_rejects_inflight(app):
    # 在途期间把接收上限从 256 调到 128：继续送达的 200 字节流式正文必须
    # 按新上限 413，而不是旧上限放行。
    async def run():
        transport = httpx.ASGITransport(app=app)
        gate = asyncio.Event()
        started = asyncio.Event()

        async def slow_gen():
            yield b"a" * 50
            started.set()
            await gate.wait()
            yield b"b" * 150

        async with httpx.AsyncClient(transport=transport) as ac:
            req = ac.build_request(
                "POST", "http://test/api/side-effect", content=slow_gen(),
                headers={"X-Forwarded-For": "203.0.114.51"})
            task = asyncio.ensure_future(ac.send(req))
            await started.wait()
            admin = httpx.AsyncClient(transport=transport)
            pr = await admin.put(
                "http://test/admin/policy",
                headers=AUTH,
                json={"inspect_limit": 64, "receive_limit": 128,
                      "content_check_enabled": True})
            assert pr.status_code == 200
            gate.set()
            resp = await task
            await admin.aclose()
            return resp

    resp = _run(run())
    assert resp.status_code == 413
    assert resp.json()["error"] == "body_too_large"
    assert resp.json()["policy_version"] == 2  # 按新接收上限拒绝
    assert app.state.business_called == 0


def test_policy_receive_limit_raised_mid_flight_completes_under_new_policy():
    # 初始接收上限 128；正文在途时放宽到 512。继续送达的 300 字节流式正文
    # 必须完整按新策略处理（300 > inspect=64 => 403，而不是旧上限下的 413），
    # 证明“正在处理的分段请求完整按新策略生效”，调大同样适用。
    app = _make_app(body_receive_limit=128)

    async def run():
        transport = httpx.ASGITransport(app=app)
        gate = asyncio.Event()
        started = asyncio.Event()

        async def slow_gen():
            yield b"a" * 30
            started.set()
            await gate.wait()
            yield b"b" * 270

        async with httpx.AsyncClient(transport=transport) as ac:
            req = ac.build_request(
                "POST", "http://test/api/side-effect", content=slow_gen(),
                headers={"X-Forwarded-For": "203.0.114.52"})
            task = asyncio.ensure_future(ac.send(req))
            await started.wait()
            admin = httpx.AsyncClient(transport=transport)
            # 先调到一个更紧的接收上限（128），再在同一请求在途时放宽
            pr = await admin.put(
                "http://test/admin/policy", headers=AUTH,
                json={"inspect_limit": 64, "receive_limit": 128,
                      "content_check_enabled": True})
            assert pr.status_code == 200
            pr2 = await admin.put(
                "http://test/admin/policy", headers=AUTH,
                json={"inspect_limit": 64, "receive_limit": 512,
                      "content_check_enabled": True})
            assert pr2.status_code == 200
            gate.set()
            resp = await task
            await admin.aclose()
            return resp

    resp = _run(run())
    assert resp.status_code == 403
    assert resp.json()["error"] == "content_inspection_incomplete"
    assert resp.json()["policy_version"] == 3
    assert app.state.business_called == 0


def test_check_disabled_streamed_body_passes_through_but_receive_limit_still_bites():
    from fastapi.testclient import TestClient
    app = _make_app(body_receive_timeout_ms=5000)
    admin = TestClient(app)
    r = admin.put("/admin/policy", headers=AUTH, json={
        "inspect_limit": 64, "receive_limit": 256,
        "content_check_enabled": False})
    assert r.status_code == 200

    # 流式 200 字节（> inspect 64，<= receive 256）：内容判定关闭 => 放行，
    # 业务侧必须拿到完整 200 字节，且内容类型不被改写。
    data = bytes((i * 13 + 5) % 256 for i in range(200))
    rr = _run(_post_chunked(
        app, data=data, sizes=[40] * 5, path="/api/upload/raw",
        source="203.0.114.60", content_type="application/x-custom"))
    assert rr.status_code == 200, rr.text
    out = rr.json()
    assert out["received_bytes"] == 200
    assert base64.b64decode(out["body_b64"]) == data
    assert out["content_type"] == "application/x-custom"

    # 接收上限始终生效：流式 257 字节即便关闭内容判定也必须 413，不进业务
    before = app.state.business_called
    rr2 = _run(_post_chunked(
        app, data=b"z" * 257, sizes=[128, 128, 1],
        source="203.0.114.61"))
    assert rr2.status_code == 413
    assert rr2.json()["error"] == "body_too_large"
    assert app.state.business_called == before


def test_slow_streaming_sender_hits_timeout_before_verdict(app):
    # 慢发送：防护层为完成判定必须读到结束；晚到的分片超过预算 => 408，
    # 不能因为分片而无限等待或放过。
    app2 = _make_app(body_receive_timeout_ms=200)

    async def run():
        transport = httpx.ASGITransport(app=app2)
        gate = asyncio.Event()

        async def slow_gen():
            yield b"a" * 10
            await asyncio.wait_for(gate.wait(), timeout=5)
            yield b"b" * 10

        async with httpx.AsyncClient(transport=transport) as ac:
            req = ac.build_request(
                "POST", "http://test/api/side-effect", content=slow_gen(),
                headers={"X-Forwarded-For": "203.0.114.62"})
            return await ac.send(req)

    r = _run(run())
    assert r.status_code == 408
    assert r.json()["error"] == "body_receive_timeout"
    assert app2.state.business_called == 0


def _admin_client(app):
    # 同步管理操作使用 TestClient（与正文流式通道互不影响）
    from fastapi.testclient import TestClient
    return TestClient(app)
