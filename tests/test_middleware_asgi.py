"""纯 ASGI 直连中间件测试：408 超时、503 并发饱和、回放正确性（不依赖 TestClient）。"""

from __future__ import annotations

import asyncio

import pytest

from request_defense.engine import DefenseEngine
from request_defense.middleware import DefenseASGIMiddleware
from request_defense.policy import ContentPolicy, ContentPolicyStore
from request_defense.ratelimiter import SlidingWindowRateLimiter
from request_defense.store import RuleStore


def _build(concurrency: int, timeout_ms: int = 1000):
    rl = SlidingWindowRateLimiter(1000, 60_000)
    store = RuleStore()
    engine = DefenseEngine(rl, store, max_rules=10, request_timeout_ms=500)
    policies = ContentPolicyStore(ContentPolicy(64, 1024, True))
    received: list[bytes] = []

    async def app(scope, receive, send):
        chunks = []
        while True:
            m = await receive()
            if m["type"] != "http.request":
                break
            if m.get("body"):
                chunks.append(m["body"])
            if not m.get("more_body", False):
                break
        received.append(b"".join(chunks))
        payload = b"ok"
        await send({"type": "http.response.start", "status": 200,
                    "headers": [(b"content-length", b"2")]})
        await send({"type": "http.response.body", "body": payload})

    mw = DefenseASGIMiddleware(
        app, engine, policies,
        body_timeout_ms=timeout_ms,
        body_ingress_concurrency=concurrency,
        exempt_exact=frozenset({"/healthz"}),
    )
    return mw, engine, received


def _scope(method="POST", path="/api/submit/json", length=None):
    headers = [(b"host", b"x")]
    if length is not None:
        headers.append((b"content-length", str(length).encode()))
    return {
        "type": "http", "method": method, "path": path,
        "headers": headers, "query_string": b"",
        "client": ("9.9.9.9", 4000),
    }


async def _call(mw, scope, receive, record):
    async def send(m):
        if m["type"] == "http.response.start":
            record["status"] = m["status"]
        elif m["type"] == "http.response.body" and m.get("body"):
            record["body"] = m["body"]
    await mw(scope, receive, send)


def test_receive_timeout_returns_408():
    mw, engine, _ = _build(concurrency=2, timeout_ms=50)

    async def scenario():
        async def slow():
            await asyncio.sleep(0.3)
            return {"type": "http.request", "body": b"x", "more_body": False}

        rec: dict = {}
        await _call(mw, _scope(length=1), slow, rec)
        assert rec["status"] == 408
        assert b"body_receive_timeout" in rec["body"]

    asyncio.run(scenario())
    engine.shutdown()


def test_ingress_capacity_saturation_returns_503():
    # 容量=1：第一请求占住唯一槽位（长超时）；第二请求短预算内拿不到槽 -> 503
    rl = SlidingWindowRateLimiter(1000, 60_000)
    store = RuleStore()
    engine = DefenseEngine(rl, store, max_rules=10, request_timeout_ms=500)
    policies = ContentPolicyStore(ContentPolicy(64, 1024, True))
    received: list[bytes] = []

    async def app(scope, receive, send):
        m = await receive()
        received.append(m.get("body", b""))
        await send({"type": "http.response.start", "status": 200,
                    "headers": [(b"content-length", b"2")]})
        await send({"type": "http.response.body", "body": b"ok"})

    mw_slow = DefenseASGIMiddleware(
        app, engine, policies, body_timeout_ms=5_000, body_ingress_concurrency=1
    )
    mw_fast = DefenseASGIMiddleware(
        app, engine, policies, body_timeout_ms=80, body_ingress_concurrency=1
    )

    async def scenario():
        # 两个中间件共享同一把信号量
        mw_fast._slots = mw_slow._slots

        first_unblock = asyncio.Event()

        async def slow_receive():
            await first_unblock.wait()
            return {"type": "http.request", "body": b"x", "more_body": False}

        async def fast_receive():
            return {"type": "http.request", "body": b"y", "more_body": False}

        rec1: dict = {}
        rec2: dict = {}
        t1 = asyncio.create_task(_call(mw_slow, _scope(length=1), slow_receive, rec1))
        await asyncio.sleep(0.02)  # 确保第一个已占住唯一槽位
        t2 = asyncio.create_task(_call(mw_fast, _scope(length=1), fast_receive, rec2))
        await asyncio.wait_for(t2, timeout=2.0)
        assert rec2["status"] == 503
        assert b"body_ingress_busy" in rec2["body"]
        # 第二个请求被容量拒绝，业务不应收到任何东西
        assert received == []
        first_unblock.set()
        await asyncio.wait_for(t1, timeout=2.0)
        assert rec1["status"] == 200

    asyncio.run(scenario())
    engine.shutdown()


def test_replay_passes_exact_bytes_to_app():
    # 检查上限给足，确保正文完整落在检查范围内并能原样回放
    rl = SlidingWindowRateLimiter(1000, 60_000)
    store = RuleStore()
    engine = DefenseEngine(rl, store, max_rules=10, request_timeout_ms=500)
    policies = ContentPolicyStore(ContentPolicy(4096, 8192, True))
    received: list[bytes] = []

    async def app(scope, receive, send):
        chunks = []
        while True:
            m = await receive()
            if m["type"] != "http.request":
                break
            if m.get("body"):
                chunks.append(m["body"])
            if not m.get("more_body", False):
                break
        received.append(b"".join(chunks))
        await send({"type": "http.response.start", "status": 200,
                    "headers": [(b"content-length", b"2")]})
        await send({"type": "http.response.body", "body": b"ok"})

    mw = DefenseASGIMiddleware(
        app, engine, policies, body_timeout_ms=1000, body_ingress_concurrency=4
    )

    async def scenario():
        payload = bytes(range(256))

        async def receive():
            return {"type": "http.request", "body": payload, "more_body": False}

        rec: dict = {}
        await _call(mw, _scope(length=len(payload)), receive, rec)
        assert rec["status"] == 200
        assert received == [payload]  # 业务侧拿到逐字节一致的完整正文

    asyncio.run(scenario())
    engine.shutdown()
