"""带正文入口的有界接收、检查前缀缓冲与原样回放。

设计目标（对应"有界内容检查与接收上限"）：
  - **接收上限 receive_limit（硬上限）**：声明（Content-Length）或实际读取一旦超过，
    立即停止接收并返回 TOO_LARGE，区分"内容太大不接受"；
  - **检查上限 inspect_limit（检测范围）**：内容判定只看前 inspect_limit 字节；
    正文落在 (inspect_limit, receive_limit] 区间时缓冲成功但无法完成内容判定，
    返回 INCOMPLETE，与 TOO_LARGE 明确区分；
  - **内存有界**：检查前缀最多 inspect_limit 字节保存在内存供规则匹配/审计；
    完整正文写入 SpooledTemporaryFile（内存阈值=inspect_limit，超过自动落盘），
    因此无论正文多大，单请求内存占用都以检查上限为界；
  - **耗时有界**：每个 ASGI receive 受单请求截止时间约束，超时返回 TIMEOUT；
  - **并发有界**：用调用方传入的 asyncio.Semaphore 限制同时缓冲的请求数，
    在截止时间内拿不到容量返回 BUSY，不无限排队、不无界占用内存；
  - **原样回放**：放行后业务侧通过 BufferedBody.receive 拿到与客户端所发完全一致的
    http.request 序列（字节、长度、内容类型均不被截断/改写）。
"""

from __future__ import annotations

import asyncio
import tempfile
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Awaitable, Callable

from .policy import ContentPolicy

# ASGI 类型别名
Receive = Callable[[], Awaitable[dict]]

# 回放/读取时每块的最大字节（与检查上限无关，仅影响切分粒度）
_REPLAY_CHUNK = 65_536


class BodyStatus(str, Enum):
    """正文接收的可区分结果。"""

    ACCEPTED = "accepted"
    TOO_LARGE = "too_large"
    INCOMPLETE = "inspection_incomplete"
    TIMEOUT = "timeout"
    BUSY = "busy"
    DISCONNECTED = "disconnected"


@dataclass(slots=True)
class BufferedBody:
    """已接收正文的有界缓冲，可原样回放，用完必须 close()。"""

    spool: tempfile.SpooledTemporaryFile[bytes]
    inspect_prefix: bytes
    length: int
    content_type: str
    content_length: int | None
    inspect_limit: int
    _closed: bool = field(default=False, init=False)
    _position: int = field(default=0, init=False)

    def inspect_text(self) -> str:
        """供内容规则匹配/审计的检查前缀（UTF-8 替换解码，定长）。"""
        return self.inspect_prefix.decode("utf-8", "replace")

    async def receive(self) -> dict:
        """ASGI receive 回放：每次调用返回下一块缓冲正文。

        与客户端所发字节完全一致（不截断/不改写），但允许按固定块切分；
        Content-Length/Content-Type 等头由中间件保持原样。
        """
        if self._closed:
            return {"type": "http.disconnect"}
        if self._position >= self.length:
            self._position = self.length
            return {"type": "http.request", "body": b"", "more_body": False}
        self.spool.seek(self._position)
        chunk = self.spool.read(_REPLAY_CHUNK)
        self._position += len(chunk)
        more = self._position < self.length
        return {"type": "http.request", "body": chunk, "more_body": more}

    def close(self) -> None:
        if not self._closed:
            self._closed = True
            self.spool.close()


@dataclass(slots=True)
class IngressResult:
    status: BodyStatus
    length: int = 0
    content_type: str = ""
    content_length: int | None = None
    inspect_limit: int = 0
    receive_limit: int = 0
    body: BufferedBody | None = None
    detail: str = ""

    @property
    def accepted(self) -> bool:
        return self.status in (BodyStatus.ACCEPTED, BodyStatus.INCOMPLETE)


def declared_length(headers: dict[str, str]) -> int | None:
    """解析 Content-Length；缺失/非法返回 None（按 chunked/未知长度处理）。"""
    raw = headers.get("content-length")
    if raw is None:
        return None
    try:
        value = int(raw)
    except (TypeError, ValueError):
        return None
    return value if value >= 0 else None


async def receive_body(
    *,
    receive: Receive,
    headers: dict[str, str],
    policy: ContentPolicy,
    ingress_slots: asyncio.Semaphore,
    timeout_s: float,
    clock: Callable[[], float] | None = None,
) -> IngressResult:
    """有界接收单个请求正文。

    headers 为已小写化的请求头；调用方负责在接收前完成来源限流判定。
    """
    now = clock or time.monotonic
    inspect_limit = policy.inspect_limit_bytes
    receive_limit = policy.receive_limit_bytes
    content_type = headers.get("content-type", "")
    clen = declared_length(headers)

    base = IngressResult(
        status=BodyStatus.ACCEPTED,
        content_type=content_type,
        content_length=clen,
        inspect_limit=inspect_limit,
        receive_limit=receive_limit,
    )

    # 硬上限前置判定：声明长度已超接收上限 -> 直接不接受，且不读取正文
    if clen is not None and clen > receive_limit:
        base.status = BodyStatus.TOO_LARGE
        base.detail = (
            f"declared content-length {clen} exceeds receive_limit {receive_limit}"
        )
        return base

    deadline = now() + max(0.0, timeout_s)

    # 并发在途容量：只在接收期间占用，有界等待，不无限排队
    try:
        acquired = await asyncio.wait_for(
            ingress_slots.acquire(), timeout=max(0.0, deadline - now())
        )
    except (asyncio.TimeoutError, ValueError):
        base.status = BodyStatus.BUSY
        base.detail = "body ingress capacity saturated within receive budget"
        return base
    if not acquired:  # Semaphore.acquire 正常返回 None；保留显式分支便于阅读
        base.status = BodyStatus.BUSY
        base.detail = "body ingress capacity saturated"
        return base

    spool = tempfile.SpooledTemporaryFile(max_size=inspect_limit, mode="w+b")
    prefix = bytearray()
    total = 0
    try:
        while True:
            remaining = deadline - now()
            if remaining <= 0:
                spool.close()
                base.status = BodyStatus.TIMEOUT
                base.length = total
                base.detail = "body receive exceeded time budget"
                return base
            try:
                message = await asyncio.wait_for(receive(), timeout=remaining)
            except asyncio.TimeoutError:
                spool.close()
                base.status = BodyStatus.TIMEOUT
                base.length = total
                base.detail = "body receive exceeded time budget"
                return base

            if message["type"] == "http.disconnect":
                spool.close()
                base.status = BodyStatus.DISCONNECTED
                base.length = total
                base.detail = "client disconnected during body receive"
                return base

            chunk = message.get("body", b"") or b""
            if chunk:
                new_total = total + len(chunk)
                if new_total > receive_limit:
                    # 实际读取越过硬上限（chunked/大块场景）：不再把该块写入缓冲，
                    # 避免单个超大 ASGI 块把内存顶高；缓冲随后随拒绝一并丢弃。
                    spool.close()
                    base.status = BodyStatus.TOO_LARGE
                    base.length = new_total
                    base.detail = (
                        f"body length {new_total} exceeds receive_limit {receive_limit}"
                    )
                    return base
                total = new_total
                spool.write(chunk)
                if len(prefix) < inspect_limit:
                    room = inspect_limit - len(prefix)
                    prefix.extend(chunk[:room])
            if not message.get("more_body", False):
                break

        buffered = BufferedBody(
            spool=spool,
            inspect_prefix=bytes(prefix),
            length=total,
            content_type=content_type,
            content_length=clen,
            inspect_limit=inspect_limit,
        )
        base.body = buffered
        base.length = total
        if total > inspect_limit:
            base.status = BodyStatus.INCOMPLETE
            base.detail = (
                f"body length {total} exceeds inspect_limit {inspect_limit}; "
                "content decision cannot be completed"
            )
        else:
            base.status = BodyStatus.ACCEPTED
            base.detail = f"buffered {total} bytes within inspect range"
        return base
    finally:
        ingress_slots.release()
