"""有界正文接收/重放原语与策略存储的直接单测（不经过 HTTP）。

重点验证判定与送达方式无关：整包 / 跨边界分片 / 不带长度流式 /
第一片整段超限，得到的 exceeds / BodyTooLarge 结论一致；
重放后的字节与原始完全一致。
"""

from __future__ import annotations

import asyncio

import pytest

from request_defense.bodyguard import (
    BodyReceiveTimeout,
    BodyTooLarge,
    make_replay_receive,
    prefetch_body,
)
from request_defense.policy import (
    MAX_INSPECT_LIMIT,
    MAX_RECEIVE_LIMIT,
    BodyPolicy,
    PolicyStore,
    PolicyValidationError,
)


def _hdrs(length: int | None = None, ctype: str = "application/octet-stream"):
    h = []
    if length is not None:
        h.append((b"content-length", str(length).encode()))
    h.append((b"content-type", ctype.encode()))
    return h


def _receiver(chunks, delay_after=None):
    """chunks: list of (body, more_body) 事件序列。"""
    delay_after = delay_after or set()
    q = list(chunks)
    idx = {"i": 0}

    async def receive():
        i = idx["i"]
        idx["i"] += 1
        if i in delay_after:
            await asyncio.sleep(1.0)
        if i < len(q):
            body, more = q[i]
            return {"type": "http.request", "body": body, "more_body": more}
        return {"type": "http.request", "body": b"", "more_body": False}

    return receive


def _collect_replay(prefetch, receive):
    replay = make_replay_receive(receive, prefetch.spool, prefetch.terminal_event)

    async def run():
        out = bytearray()
        while True:
            msg = await replay()
            if msg.get("type") != "http.request":
                break
            out.extend(msg.get("body", b""))
            if not msg.get("more_body", False):
                break
        return bytes(out)

    try:
        return asyncio.run(run())
    finally:
        prefetch.close()


def _run_prefetch(chunks, policy, *, headers=None, timeout_ms=1000, provider=None):
    receive = _receiver(chunks)
    pf = asyncio.run(prefetch_body(
        scope_headers=headers or _hdrs(None),
        receive=receive, policy=policy,
        receive_timeout_ms=timeout_ms, policy_provider=provider))
    return pf, receive


@pytest.mark.parametrize("n", [0, 1, 63, 64])
def test_prefetch_under_limit_exact_bytes(n):
    policy = BodyPolicy.validated(64, 256)
    pf, receive = _run_prefetch([(b"x" * n, False)], policy, headers=_hdrs(n))
    assert len(pf.inspected) == n
    assert pf.total_seen == n
    assert pf.exceeds_inspect is False
    # 重放后字节与原始完全一致
    assert _collect_replay(pf, receive) == b"x" * n


@pytest.mark.parametrize("n", [65, 100, 256])
def test_prefetch_beyond_inspect_flagged_but_replay_complete(n):
    policy = BodyPolicy.validated(64, 256)
    # 单分片（模拟 ASGI 服务器一次给出整个 body）
    pf, receive = _run_prefetch([(b"y" * n, False)], policy, headers=_hdrs(n))
    assert len(pf.inspected) == 64
    assert pf.total_seen == n
    assert pf.exceeds_inspect is True
    assert _collect_replay(pf, receive) == b"y" * n


@pytest.mark.parametrize("n", [65, 100, 256])
def test_prefetch_verdict_independent_of_chunking(n):
    """同一份正文：整包 / 各种分片 / 无 Content-Length，结论一致。"""
    policy = BodyPolicy.validated(64, 256)
    expected = n > 64

    deliveries = [
        ([(b"y" * n, False)], _hdrs(n)),                      # 整包带长度
        ([(b"y" * n, True), (b"", False)], _hdrs(None)),      # 整片 + 空收尾
        ([(b"y" * 40, True), (b"y" * (n - 40), False)], _hdrs(None)),
    ]
    for size in (1, 7, 32, 64):
        chunks = [(b"y" * size, True) for _ in range(n // size)]
        rem = n % size
        if rem:
            chunks.append((b"y" * rem, True))
        chunks.append((b"", False))
        deliveries.append((chunks, _hdrs(None)))

    for chunks, headers in deliveries:
        pf, receive = _run_prefetch(chunks, policy, headers=headers)
        assert pf.total_seen == n
        assert pf.exceeds_inspect is expected
        assert _collect_replay(pf, receive) == b"y" * n


def test_prefetch_multi_chunk_boundary_split_replay():
    policy = BodyPolicy.validated(64, 1024)
    # 40 + 40 = 80 字节，跨检查边界；两个不同字符段便于断言字节序
    pf, receive = _run_prefetch(
        [(b"a" * 40, True), (b"b" * 40, False)], policy, headers=_hdrs(80))
    assert pf.exceeds_inspect is True
    assert pf.inspected == b"a" * 40 + b"b" * 24
    assert _collect_replay(pf, receive) == b"a" * 40 + b"b" * 40


def test_prefetch_chunked_no_content_length_replay():
    policy = BodyPolicy.validated(64, 1024)
    pf, receive = _run_prefetch([
        (b"chunk1-", True), (b"chunk2-", True), (b"chunk3-end", False),
    ], policy)
    assert pf.content_length is None
    assert pf.exceeds_inspect is False
    assert _collect_replay(pf, receive) == b"chunk1-chunk2-chunk3-end"


def test_declared_oversize_rejected_without_reading():
    policy = BodyPolicy.validated(64, 256)
    called = {"n": 0}

    async def receive():
        called["n"] += 1
        return {"type": "http.request", "body": b"z", "more_body": False}

    with pytest.raises(BodyTooLarge) as exc:
        asyncio.run(prefetch_body(
            scope_headers=_hdrs(9999), receive=receive,
            policy=policy, receive_timeout_ms=1000))
    assert exc.value.limit == 256
    assert called["n"] == 0  # 声明超限：一个字节都不读


def test_chunked_oversize_rejected_during_receive():
    """无 Content-Length 分片流超过接收上限：接收阶段直接 413（不进业务）。"""
    policy = BodyPolicy.validated(64, 256)
    # 每片 100，共 400
    chunks = [(b"a" * 100, True), (b"b" * 100, True),
              (b"c" * 100, True), (b"d" * 100, False)]
    receive = _receiver(chunks)
    with pytest.raises(BodyTooLarge) as exc:
        asyncio.run(prefetch_body(
            scope_headers=_hdrs(None), receive=receive,
            policy=policy, receive_timeout_ms=1000))
    assert exc.value.received > 256
    assert exc.value.limit == 256


@pytest.mark.parametrize("n", [64, 256])
def test_exact_limits_not_flagged_as_too_large(n):
    """恰好等于检查/接收上限：不误伤，正常完整接收。"""
    policy = BodyPolicy.validated(64, 256)
    pf, receive = _run_prefetch(
        [(b"m" * n, True), (b"", False)], policy, headers=_hdrs(n))
    assert pf.total_seen == n
    assert pf.exceeds_inspect is (n > 64)
    assert _collect_replay(pf, receive) == b"m" * n


def test_receive_timeout_propagates():
    policy = BodyPolicy.validated(64, 256)
    # 第一个事件后挂起；正文未结束，继续接收会超时
    receive = _receiver([(b"x" * 16, True)], delay_after={1})
    with pytest.raises(BodyReceiveTimeout):
        asyncio.run(prefetch_body(
            scope_headers=_hdrs(100), receive=receive,
            policy=policy, receive_timeout_ms=50))


def test_policy_change_mid_flight_uses_latest_receive_limit():
    """在途分片请求：接收途中调小接收上限，后续片立即按新上限判 413。"""
    store = PolicyStore(BodyPolicy.validated(64, 4096))
    # 先发 8 字节，等待期间把 receive_limit 调成 64，再发 100 字节
    gate = asyncio.Event()

    async def scenario():
        idx = {"i": 0}

        async def receive():
            i = idx["i"]
            idx["i"] += 1
            if i == 0:
                return {"type": "http.request", "body": b"a" * 8, "more_body": True}
            if i == 1:
                await gate.wait()
                return {"type": "http.request", "body": b"b" * 100,
                        "more_body": False}
            return {"type": "http.request", "body": b"", "more_body": False}

        async def changer():
            store.replace(BodyPolicy.validated(64, 64))
            gate.set()

        change_task = asyncio.ensure_future(changer())
        with pytest.raises(BodyTooLarge) as exc:
            await prefetch_body(
                scope_headers=_hdrs(None), receive=receive,
                policy=store.snapshot()[1], receive_timeout_ms=2000,
                policy_provider=store.snapshot)
        await change_task
        return exc

    exc = asyncio.run(scenario())
    assert exc.value.limit == 64
    assert exc.value.received == 108


def test_spool_rolls_to_disk_but_replay_byte_exact():
    """超过假脱机阈值的正文落临时文件，重放仍逐字节一致。"""
    policy = BodyPolicy.validated(1024, 8192)
    data = bytes((i * 19 + 3) % 256 for i in range(3000))
    receive = _receiver([
        (data[:1500], True), (data[1500:], True), (b"", False),
    ])
    pf = asyncio.run(prefetch_body(
        scope_headers=_hdrs(3000), receive=receive, policy=policy,
        receive_timeout_ms=1000, spool_threshold=1024))
    assert pf.total_seen == 3000
    assert pf.spool._file._rolled  # type: ignore[attr-defined]  # 已翻到临时文件
    assert _collect_replay(pf, receive) == data


def test_disconnect_event_replayed_once():
    policy = BodyPolicy.validated(64, 256)
    receive = _receiver([(b"abc", True)])  # 之后测试框架自动给空收尾，这里手动给 disconnect

    async def run():
        q = [
            {"type": "http.request", "body": b"abc", "more_body": True},
            {"type": "http.disconnect"},
        ]
        i = {"n": 0}

        async def recv():
            if i["n"] < len(q):
                m = q[i["n"]]
                i["n"] += 1
                return m
            await asyncio.sleep(0)
            return {"type": "http.request", "body": b"", "more_body": False}

        pf = await prefetch_body(
            scope_headers=_hdrs(None), receive=recv,
            policy=policy, receive_timeout_ms=1000)
        replay = make_replay_receive(recv, pf.spool, pf.terminal_event)
        events = []
        for _ in range(3):
            events.append(await replay())
        pf.close()
        return events

    events = asyncio.run(run())
    assert events[0]["body"] == b"abc"
    assert events[1]["type"] == "http.disconnect"  # 原样交还且只一次


# ------------------------------ PolicyStore ------------------------------- #
class TestPolicyStore:
    def test_validated_rejects_bad_ranges_and_order(self):
        with pytest.raises(PolicyValidationError):
            BodyPolicy.validated(0, 10)
        with pytest.raises(PolicyValidationError):
            BodyPolicy.validated(10, MAX_RECEIVE_LIMIT + 1)
        with pytest.raises(PolicyValidationError):
            BodyPolicy.validated(MAX_INSPECT_LIMIT + 1, MAX_RECEIVE_LIMIT)
        with pytest.raises(PolicyValidationError) as exc:
            BodyPolicy.validated(100, 50)
        assert exc.value.field == "inspect_limit"
        with pytest.raises(PolicyValidationError):
            BodyPolicy.validated(10, 50, content_check_enabled="yes")  # type: ignore[arg-type]

    def test_replace_atomic_and_monotonic(self):
        store = PolicyStore(BodyPolicy.validated(64, 256))
        v0, p0 = store.snapshot()
        assert v0 == 1 and p0.inspect_limit == 64
        v1 = store.replace(BodyPolicy.validated(128, 512, False))
        assert v1 == 2 and store.snapshot()[1].content_check_enabled is False

        before = store.snapshot()[0]
        with pytest.raises(PolicyValidationError):
            store.replace(BodyPolicy(1000, 10))  # 直接构造非法对象也要被拦
        assert store.snapshot()[0] == before  # 非法更新不改变版本/内容

    def test_rejects_non_policy(self):
        store = PolicyStore(BodyPolicy.validated(64, 256))
        with pytest.raises(PolicyValidationError):
            store.replace(object())  # type: ignore[arg-type]
