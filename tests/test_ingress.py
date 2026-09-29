"""有界正文接收/缓冲/回放单测：四类结果可区分、内存有界、回放字节一致。"""

from __future__ import annotations

import asyncio

import pytest

from request_defense.ingress import (
    BodyStatus,
    BufferedBody,
    declared_length,
    receive_body,
)
from request_defense.policy import ContentPolicy


def _policy(inspect=16, receive=64, check=True):
    return ContentPolicy(
        inspect_limit_bytes=inspect,
        receive_limit_bytes=receive,
        content_check_enabled=check,
    )


def run(coro):
    return asyncio.run(coro)


def _receiver(messages):
    seq = list(messages)

    async def receive():
        if seq:
            return seq.pop(0)
        return {"type": "http.disconnect"}

    return receive


class TestDeclaredLength:
    def test_parses_valid(self):
        assert declared_length({"content-length": "123"}) == 123

    @pytest.mark.parametrize("value", [None, "", "abc", "-1"])
    def test_missing_or_invalid_returns_none(self, value):
        headers = {} if value is None else {"content-length": value}
        assert declared_length(headers) is None


class TestBoundedReceive:
    def test_small_body_accepted_and_buffered(self):
        messages = [
            {"type": "http.request", "body": b"hello", "more_body": True},
            {"type": "http.request", "body": b" world", "more_body": False},
        ]
        res = run(receive_body(
            receive=_receiver(messages),
            headers={"content-type": "text/plain"},
            policy=_policy(),
            ingress_slots=asyncio.Semaphore(2),
            timeout_s=5.0,
        ))
        assert res.status is BodyStatus.ACCEPTED
        assert res.length == 11
        assert res.content_type == "text/plain"
        assert res.body is not None
        assert res.body.inspect_prefix == b"hello world"
        assert res.body.inspect_text() == "hello world"
        res.body.close()

    def test_declared_length_over_receive_limit_rejected_without_reading(self):
        read = {"called": False}

        async def receive():
            read["called"] = True
            return {"type": "http.request", "body": b"x", "more_body": False}

        res = run(receive_body(
            receive=receive,
            headers={"content-length": "65"},
            policy=_policy(inspect=16, receive=64),
            ingress_slots=asyncio.Semaphore(2),
            timeout_s=5.0,
        ))
        assert res.status is BodyStatus.TOO_LARGE
        assert res.length == 0
        assert res.body is None
        assert read["called"] is False  # 不读取任何正文

    def test_chunked_overflow_mid_stream_is_too_large(self):
        # 无 Content-Length：先给 40，再给 40 => 实际 80 > 64
        messages = [
            {"type": "http.request", "body": b"a" * 40, "more_body": True},
            {"type": "http.request", "body": b"b" * 40, "more_body": False},
        ]
        res = run(receive_body(
            receive=_receiver(messages),
            headers={},
            policy=_policy(inspect=16, receive=64),
            ingress_slots=asyncio.Semaphore(2),
            timeout_s=5.0,
        ))
        assert res.status is BodyStatus.TOO_LARGE
        assert res.length == 80
        assert res.body is None

    def test_body_between_inspect_and_receive_is_incomplete(self):
        # 长度 32，落在 (16, 64]：缓冲成功但检查不完整
        messages = [
            {"type": "http.request", "body": b"x" * 32, "more_body": False},
        ]
        res = run(receive_body(
            receive=_receiver(messages),
            headers={"content-type": "application/json"},
            policy=_policy(inspect=16, receive=64),
            ingress_slots=asyncio.Semaphore(2),
            timeout_s=5.0,
        ))
        assert res.status is BodyStatus.INCOMPLETE
        assert res.length == 32
        assert res.accepted is True  # 仍可放行转发，只是内容判定不可完成
        assert res.body is not None
        assert len(res.body.inspect_prefix) == 16  # 前缀严格有界
        assert res.body.inspect_prefix == b"x" * 16
        res.body.close()

    def test_inspect_prefix_is_bounded_for_large_body_on_disk(self):
        # 接收上限内但较大的正文落盘，内存前缀仍以 inspect 为界
        size = 64
        messages = [
            {"type": "http.request", "body": b"p" * 30, "more_body": True},
            {"type": "http.request", "body": b"q" * 34, "more_body": False},
        ]
        res = run(receive_body(
            receive=_receiver(messages),
            headers={"content-type": "application/octet-stream"},
            policy=_policy(inspect=16, receive=64),
            ingress_slots=asyncio.Semaphore(2),
            timeout_s=5.0,
        ))
        assert res.status is BodyStatus.INCOMPLETE
        body = res.body
        assert body is not None
        assert len(body.inspect_prefix) == 16
        # SpooledTemporaryFile 已落盘（max_size=inspect）
        assert getattr(body.spool, "_rolled", True) is True
        res.body.close()

    def test_timeout_returns_timeout_and_releases_slot(self):
        async def slow_receive():
            await asyncio.sleep(0.2)
            return {"type": "http.request", "body": b"x", "more_body": False}

        slots = asyncio.Semaphore(1)

        async def scenario():
            res = await receive_body(
                receive=slow_receive,
                headers={},
                policy=_policy(),
                ingress_slots=slots,
                timeout_s=0.05,
            )
            assert res.status is BodyStatus.TIMEOUT
            # 槽位必须释放，后续可再次获取
            await asyncio.wait_for(slots.acquire(), timeout=0.1)
            slots.release()

        run(scenario())

    def test_busy_when_no_capacity_within_budget(self):
        async def never_receive():
            await asyncio.sleep(1.0)
            return {"type": "http.request", "body": b"", "more_body": False}

        async def scenario():
            slots = asyncio.Semaphore(1)
            await slots.acquire()  # 占满唯一容量
            res = await receive_body(
                receive=never_receive,
                headers={},
                policy=_policy(),
                ingress_slots=slots,
                timeout_s=0.05,
            )
            assert res.status is BodyStatus.BUSY
            assert res.body is None
            # 未获取到容量，不应误释放
            assert slots.locked() is True
            slots.release()

        run(scenario())

    def test_disconnect_is_distinct(self):
        async def disconnect():
            return {"type": "http.disconnect"}

        res = run(receive_body(
            receive=disconnect,
            headers={},
            policy=_policy(),
            ingress_slots=asyncio.Semaphore(2),
            timeout_s=5.0,
        ))
        assert res.status is BodyStatus.DISCONNECTED
        assert res.body is None


class TestReplayFidelity:
    async def _gather(self, body: BufferedBody) -> bytes:
        chunks = []
        while True:
            msg = await body.receive()
            assert msg["type"] == "http.request"
            chunks.append(msg.get("body", b""))
            if not msg.get("more_body", False):
                break
        return b"".join(chunks)

    def test_small_body_replays_byte_for_byte(self):
        payload = bytes(range(256))
        messages = [
            {"type": "http.request", "body": payload[:100], "more_body": True},
            {"type": "http.request", "body": payload[100:], "more_body": False},
        ]
        res = run(receive_body(
            receive=_receiver(messages),
            headers={"content-type": "application/octet-stream"},
            policy=_policy(inspect=16, receive=640),
            ingress_slots=asyncio.Semaphore(2),
            timeout_s=5.0,
        ))
        assert res.status in (BodyStatus.ACCEPTED, BodyStatus.INCOMPLETE)
        replayed = run(self._gather(res.body))
        assert replayed == payload
        assert res.body.content_type == "application/octet-stream"
        res.body.close()

    def test_large_body_spooled_replays_exactly(self):
        payload = (b"json-form-binary" * 20)  # 320 字节，触发落盘
        assert len(payload) == 320
        messages = [
            {"type": "http.request", "body": payload[:150], "more_body": True},
            {"type": "http.request", "body": payload[150:], "more_body": False},
        ]
        res = run(receive_body(
            receive=_receiver(messages),
            headers={"content-type": "application/json"},
            policy=_policy(inspect=16, receive=640),
            ingress_slots=asyncio.Semaphore(2),
            timeout_s=5.0,
        ))
        assert res.status is BodyStatus.INCOMPLETE
        assert res.length == 320
        replayed = run(self._gather(res.body))
        assert replayed == payload
        res.body.close()
