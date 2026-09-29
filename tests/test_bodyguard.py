"""有界正文预取/重放与策略存储的直接单测（不经过 HTTP）。"""

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


def _collect_replay(prefetch, receive, policy):
    replay = make_replay_receive(receive, prefetch.events, policy)

    async def run():
        out = bytearray()
        while True:
            msg = await replay()
            out.extend(msg.get("body", b""))
            if not msg.get("more_body", False):
                break
        return bytes(out)

    return asyncio.run(run())


@pytest.mark.parametrize("n", [0, 1, 63, 64])
def test_prefetch_under_limit_exact_bytes(n):
    policy = BodyPolicy.validated(64, 256)
    receive = _receiver([(b"x" * n, False)])
    pf = asyncio.run(prefetch_body(
        scope_headers=_hdrs(n), receive=receive, policy=policy,
        receive_timeout_ms=1000))
    assert len(pf.inspected) == n
    assert pf.exceeds_inspect is False
    # 重放后字节与原始完全一致
    assert _collect_replay(pf, receive, policy) == b"x" * n


@pytest.mark.parametrize("n", [65, 100, 256])
def test_prefetch_beyond_inspect_flagged_but_replay_complete(n):
    policy = BodyPolicy.validated(64, 256)
    # 单分片（模拟 ASGI 服务器一次给出整个 body）
    receive = _receiver([(b"y" * n, False)])
    pf = asyncio.run(prefetch_body(
        scope_headers=_hdrs(n), receive=receive, policy=policy,
        receive_timeout_ms=1000))
    assert len(pf.inspected) == 64
    assert pf.exceeds_inspect is True
    assert _collect_replay(pf, receive, policy) == b"y" * n


def test_prefetch_multi_chunk_boundary_split_replay():
    policy = BodyPolicy.validated(64, 1024)
    # 40 + 40 = 80 字节，跨检查边界
    receive = _receiver([(b"a" * 40, True), (b"b" * 40, False)])
    pf = asyncio.run(prefetch_body(
        scope_headers=_hdrs(80), receive=receive, policy=policy,
        receive_timeout_ms=1000))
    assert pf.exceeds_inspect is True
    assert pf.inspected == b"a" * 40 + b"b" * 24
    assert _collect_replay(pf, receive, policy) == b"a" * 40 + b"b" * 40


def test_prefetch_chunked_no_content_length_replay():
    policy = BodyPolicy.validated(64, 1024)
    receive = _receiver([
        (b"chunk1-", True), (b"chunk2-", True), (b"chunk3-end", False),
    ])
    pf = asyncio.run(prefetch_body(
        scope_headers=_hdrs(None), receive=receive, policy=policy,
        receive_timeout_ms=1000))
    assert pf.content_length is None
    assert _collect_replay(pf, receive, policy) == b"chunk1-chunk2-chunk3-end"


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


def test_receive_timeout_propagates():
    policy = BodyPolicy.validated(64, 256)
    # 第一个事件后挂起；正文未结束，预取会等待第二个事件并超时
    receive = _receiver([(b"x" * 16, True)], delay_after={1})
    with pytest.raises(BodyReceiveTimeout):
        asyncio.run(prefetch_body(
            scope_headers=_hdrs(100), receive=receive,
            policy=policy, receive_timeout_ms=50))


def test_replay_enforces_receive_limit_for_chunked():
    policy = BodyPolicy.validated(64, 256)
    # 分块：每块 100，共 400；无 Content-Length，预取不越界，重放计量拒绝
    receive = _receiver([
        (b"a" * 100, True), (b"b" * 100, True),
        (b"c" * 100, True), (b"d" * 100, False),
    ])
    pf = asyncio.run(prefetch_body(
        scope_headers=_hdrs(None), receive=receive, policy=policy,
        receive_timeout_ms=1000))
    assert pf.exceeds_inspect is True

    async def run():
        replay = make_replay_receive(receive, pf.events, policy)
        delivered = 0
        raised = False
        try:
            while True:
                msg = await replay()
                delivered += len(msg.get("body", b""))
                if not msg.get("more_body", False):
                    break
        except BodyTooLarge as exc:
            raised = True
            assert exc.limit == 256
        return delivered, raised

    delivered, raised = asyncio.run(run())
    assert raised is True                       # 400 字节分块流被接收上限拒绝
    assert delivered <= 256 + 100               # 拒绝点之后不再透传（误差≤一个分片）
    assert delivered < 400                      # 完整正文绝不会全部交付给业务


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
