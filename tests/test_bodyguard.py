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


def test_streaming_oversize_rejected_at_prefetch_without_business():
    policy = BodyPolicy.validated(64, 256)
    # 分块：每块 100，共 400；无 Content-Length。新语义下预取必须持续计量
    # 并在越过 receive_limit 的当下直接拒绝——结论与整包/带长度完全一致，
    # 不会把超量正文留给重放阶段、更不可能透传给业务。
    receive = _receiver([
        (b"a" * 100, True), (b"b" * 100, True),
        (b"c" * 100, True), (b"d" * 100, False),
    ])
    with pytest.raises(BodyTooLarge) as exc:
        asyncio.run(prefetch_body(
            scope_headers=_hdrs(None), receive=receive, policy=policy,
            receive_timeout_ms=1000))
    assert exc.value.limit == 256
    assert exc.value.received > 256


def test_streaming_oversize_httpx_style_terminator_also_rejected():
    # httpx/ASGI 风格：每个数据事件都 more_body=True，末尾再来一个独立的
    # 空收尾事件。旧实现在“最后一片恰好填满接收上限 + 空收尾”时会漏判。
    policy = BodyPolicy.validated(64, 256)
    receive = _receiver([
        (b"a" * 100, True), (b"b" * 100, True),
        (b"c" * 100, True), (b"", False),
    ])
    with pytest.raises(BodyTooLarge):
        asyncio.run(prefetch_body(
            scope_headers=_hdrs(None), receive=receive, policy=policy,
            receive_timeout_ms=1000))


# --------------------- 送达方式无关的一致判定（回归） ---------------------- #
@pytest.mark.parametrize("n", [65, 100, 256])
def test_httpx_style_empty_terminator_is_not_treated_as_exact_limit(n):
    """关键回归：每个数据事件 more_body=True，末尾再给独立空收尾事件。

    旧实现的边界探测只看“探测事件”本身，当最后一片数据恰好填满
    inspect_limit、下一个事件是空收尾时，会把 >inspect_limit 的正文误判成
    “恰好等于上限”而放行。
    """
    policy = BodyPolicy.validated(64, 256)
    receive = _receiver([
        (b"y" * min(n, 50), True),
        (b"y" * max(0, n - 50), True),
        (b"", False),
    ])
    pf = asyncio.run(prefetch_body(
        scope_headers=_hdrs(None), receive=receive, policy=policy,
        receive_timeout_ms=1000))
    assert pf.total_bytes == n
    assert pf.exceeds_inspect is True
    assert pf.ended is True
    # 重放仍逐字节完整（供上层放行路径使用；此处虽为拒绝路径，事件保真）
    receive2 = _receiver([
        (b"y" * min(n, 50), True),
        (b"y" * max(0, n - 50), True),
        (b"", False),
    ])
    pf2 = asyncio.run(prefetch_body(
        scope_headers=_hdrs(None), receive=receive2, policy=policy,
        receive_timeout_ms=1000))
    assert _collect_replay(pf2, receive2, policy) == b"y" * n


@pytest.mark.parametrize("n", [0, 1, 63, 64])
def test_httpx_style_empty_terminator_exact_limit_still_allowed(n):
    policy = BodyPolicy.validated(64, 256)
    receive = _receiver([(b"z" * n, True), (b"", False)])
    pf = asyncio.run(prefetch_body(
        scope_headers=_hdrs(n), receive=receive, policy=policy,
        receive_timeout_ms=1000))
    assert pf.exceeds_inspect is False
    assert pf.total_bytes == n
    receive2 = _receiver([(b"z" * n, True), (b"", False)])
    pf2 = asyncio.run(prefetch_body(
        scope_headers=_hdrs(n), receive=receive2, policy=policy,
        receive_timeout_ms=1000))
    assert _collect_replay(pf2, receive2, policy) == b"z" * n


def test_policy_provider_lowers_inspect_limit_for_inflight_body():
    # 在途期间通过 provider 调小 inspect_limit：尚未读到的部分立即按新上限
    policy = BodyPolicy.validated(64, 256)
    new_policy = BodyPolicy.validated(16, 256)
    holder = {"v": 1, "p": policy}

    def provider():
        return holder["v"], holder["p"]

    q = [{"type": "http.request", "body": b"a" * 30, "more_body": True}]
    idx = {"i": 0}

    async def receive():
        i = idx["i"]
        idx["i"] += 1
        if i == 0:
            return q[0]
        if i == 1:
            # 第一个事件被消费后，策略更新为 inspect_limit=16
            holder["v"] = 2
            holder["p"] = new_policy
            return {"type": "http.request", "body": b"b" * 10,
                    "more_body": False}
        return {"type": "http.disconnect"}

    pf = asyncio.run(prefetch_body(
        scope_headers=_hdrs(40), receive=receive, policy=policy,
        receive_timeout_ms=1000, policy_provider=provider))
    assert pf.policy_version == 2
    assert pf.policy.inspect_limit == 16
    assert pf.total_bytes == 40
    assert pf.exceeds_inspect is True       # 40 > 新 inspect_limit 16
    # inspected 始终按“最终生效”的检查上限截取，供 body 规则/审计使用
    assert len(pf.inspected) == 16
    assert pf.inspected == b"a" * 16


def test_policy_provider_lowers_receive_limit_rejects_inflight_body():
    policy = BodyPolicy.validated(64, 256)
    holder = {"v": 1, "p": policy}

    def provider():
        return holder["v"], holder["p"]

    idx = {"i": 0}

    async def receive():
        i = idx["i"]
        idx["i"] += 1
        if i == 0:
            return {"type": "http.request", "body": b"a" * 50,
                    "more_body": True}
        if i == 1:
            holder["v"] = 2
            holder["p"] = BodyPolicy.validated(64, 128)
            return {"type": "http.request", "body": b"b" * 200,
                    "more_body": False}  # 累计 250 > 新 receive_limit 128
        return {"type": "http.disconnect"}

    with pytest.raises(BodyTooLarge) as exc:
        asyncio.run(prefetch_body(
            scope_headers=_hdrs(250), receive=receive, policy=policy,
            receive_timeout_ms=1000, policy_provider=provider))
    assert exc.value.limit == 128


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
