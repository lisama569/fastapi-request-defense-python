"""有界正文接收：完整接收后再下结论 + 磁盘假脱机的原样重放。

旧实现只预取检查前缀、把“检查窗口之外是否还有数据”的判断建立在
``more_body`` 标志与“再探测一个事件”之上。但 ASGI 服务器的分片/标志
组合并不保证能区分“恰好等于上限”和“后面还有”：

  - 同一份正文，整包送达与分多片/不带长度流式送达会得到相反结论；
  - 跨边界分片的余量被直接放进重放队列却同时当成“已检查过、没问题”；
  - 无 Content-Length 的超大流要等业务侧透传读取时才发现超接收上限，
    此时请求可能已经进入业务。

本实现改为**先把正文完整、有界地接收下来，再下结论**：

1. **结论与送达方式无关**：读到 ``more_body=False`` 才做最终分类，
   因此一次性整包、分多片、带/不带 Content-Length，同一份正文结论完全一致。
2. **两类“太大”严格区分且都在进业务之前给出**：
   - 累计字节数超过 ``receive_limit``：立即 :class:`BodyTooLarge`（413），
     不再透传任何字节给业务（带声明长度时一个字节都不读）；
   - 正文完整接收后总长度超过 ``inspect_limit``：
     :data:`PrefetchResult.exceeds_inspect` 为真，由上层给出
     ``content_inspection_incomplete``（403，fail-closed）。
3. **内存仍有界**：正文写入 :class:`tempfile.SpooledTemporaryFile`，
   未超过 ``spool_threshold`` 时驻留内存，超过后自动假脱机到临时文件，
   防护侧驻留内存与正文总大小解耦；在途名额再限制并发驻留总量。
   放行时重放从同一假脱机对象按**原 ASGI 事件边界**逐段吐出，
   字节序、长度、内容类型与客户端发出的完全一致。
4. **耗时有界**：每次 ``receive`` 都有超时；慢发送不能无界占用连接/名额。
5. **运行时策略变更对在途分段请求完整生效**：每次收到分片后重新取一次
   策略快照，接收上限/检查上限按最新策略计量与分类，不会一半旧一半新
   （``policy_provider`` 由上层注入，返回 ``(version, BodyPolicy)``）。
"""

from __future__ import annotations

import asyncio
import tempfile
from collections import deque
from dataclasses import dataclass
from typing import Awaitable, Callable

from .policy import BodyPolicy

# 带正文的统一保护方法集合
BODY_METHODS = frozenset({"POST", "PUT", "PATCH"})

# 单请求正文假脱机阈值：驻留内存的正文部分不超过它，其余落临时文件。
DEFAULT_SPOOL_THRESHOLD = 1 * 1024 * 1024  # 1 MiB

Receive = Callable[[], Awaitable[dict]]
PolicyProvider = Callable[[], tuple[int, BodyPolicy]]


class BodyReceiveError(Exception):
    """正文接收阶段的防护异常基类。"""


class BodyTooLarge(BodyReceiveError):
    """正文超过接收上限（服务不接受）。"""

    def __init__(self, received: int, limit: int, policy_version: int = 0) -> None:
        super().__init__(f"body too large: {received} > receive_limit {limit}")
        self.received = received
        self.limit = limit
        # 触发该结论时所用的策略版本（在途策略变更后可能晚于入口版本）
        self.policy_version = policy_version


class BodyReceiveTimeout(BodyReceiveError):
    """正文接收超过单请求时间预算。"""

    def __init__(self, timeout_ms: int) -> None:
        super().__init__(f"body receive timed out after {timeout_ms}ms")
        self.timeout_ms = timeout_ms


@dataclass(frozen=True, slots=True)
class PrefetchResult:
    """接收结论：检查前缀 + 计量信息（不含任何判定，判定由上层做）。

    ``spool`` 持有完整正文（内存或假脱机临时文件），仅在放行时用于重放；
    拒绝路径上层应调用 :meth:`PrefetchResult.close` 立即释放。
    ``terminal_event`` 为接收阶段观测到的非 ``http.request`` 收尾事件
    （如 ``http.disconnect``），重放时原样交还给下游。
    """

    inspected: bytes
    content_length: int | None
    content_type: str
    total_seen: int
    exceeds_inspect: bool
    policy_version: int
    spool: "BodySpool"
    terminal_event: dict | None = None

    def close(self) -> None:
        self.spool.close()


class BodySpool:
    """完整正文的有界缓冲：小正文驻留内存，大正文自动假脱机临时文件。

    同时记录写入时的 ASGI 分片边界，重放按原边界逐段吐出（与客户端发送
    的字节/事件序列等价）；空事件（纯收尾）不计入分段。
    """

    __slots__ = ("_file", "_segments", "_total", "_closed")

    def __init__(self, threshold: int = DEFAULT_SPOOL_THRESHOLD) -> None:
        self._file = tempfile.SpooledTemporaryFile(max_size=threshold)
        # (起始偏移, 长度, 原始 more_body 标志)：重放沿用原 ASGI 事件边界
        self._segments: deque[tuple[int, int, bool]] = deque()
        self._total = 0
        self._closed = False

    @property
    def total(self) -> int:
        return self._total

    @property
    def segments(self) -> deque[tuple[int, int, bool]]:
        return self._segments

    def write(self, chunk: bytes, more_body: bool) -> None:
        if chunk:
            self._file.write(chunk)
            self._segments.append((self._total, len(chunk), more_body))
            self._total += len(chunk)

    def prefix(self, limit: int) -> bytes:
        """返回前 ``limit`` 字节的检查前缀（不越过实际长度）。"""
        n = min(limit, self._total)
        self._file.seek(0)
        data = self._file.read(n)
        return data if isinstance(data, bytes) else bytes(data)

    def read_segment(self, start: int, length: int) -> bytes:
        self._file.seek(start)
        data = self._file.read(length)
        return data if isinstance(data, bytes) else bytes(data)

    def close(self) -> None:
        if not self._closed:
            self._closed = True
            self._file.close()


def _header(scope_headers: list[tuple[bytes, bytes]], name: bytes) -> str | None:
    for k, v in scope_headers:
        if k == name:
            return v.decode("latin-1")
    return None


def _parse_content_length(scope_headers: list[tuple[bytes, bytes]]) -> int | None:
    raw = _header(scope_headers, b"content-length")
    if raw is None:
        return None
    try:
        value = int(raw)
    except ValueError:
        return None
    return value if value >= 0 else None


def _snapshot(
    current: BodyPolicy, provider: PolicyProvider | None
) -> tuple[int, BodyPolicy]:
    """取最新策略快照；无 provider 时沿用入口策略（版本 0 由上层覆盖）。"""
    if provider is None:
        return 0, current
    return provider()


async def prefetch_body(
    *,
    scope_headers: list[tuple[bytes, bytes]],
    receive: Receive,
    policy: BodyPolicy,
    receive_timeout_ms: int,
    policy_provider: PolicyProvider | None = None,
    spool_threshold: int = DEFAULT_SPOOL_THRESHOLD,
) -> PrefetchResult:
    """完整、有界地接收正文，再返回计量结论与可重放假脱机。

    - 声明的 Content-Length 超过（最新）``receive_limit``：不读任何字节，
      直接 :class:`BodyTooLarge`；
    - 接收过程中累计超过（最新）``receive_limit``：立即 :class:`BodyTooLarge`，
      适用于无长度/分片流式，结论不依赖送达方式；
    - 每次 receive 受 ``receive_timeout_ms`` 约束，超时 :class:`BodyReceiveTimeout`；
    - 正文完整接收后再按最新策略判断是否超过 ``inspect_limit``，
      ``exceeds_inspect`` 对整包与分片严格一致；
    - 每个分片到达后通过 ``policy_provider`` 刷新策略快照，使运行时调整
      对在途的分段请求完整生效；无 provider 时使用入口策略。
    """
    content_length = _parse_content_length(scope_headers)
    content_type = _header(scope_headers, b"content-type") or ""
    entry_version, current = _snapshot(policy, policy_provider)
    if content_length is not None and content_length > current.receive_limit:
        raise BodyTooLarge(content_length, current.receive_limit, entry_version)

    timeout_s = receive_timeout_ms / 1000.0
    spool = BodySpool(threshold=spool_threshold)
    total = 0
    version = entry_version
    terminal_event: dict | None = None
    try:
        while True:
            try:
                message = await asyncio.wait_for(receive(), timeout=timeout_s)
            except TimeoutError as exc:
                raise BodyReceiveTimeout(receive_timeout_ms) from exc
            if message.get("type") != "http.request":
                # http.disconnect 等非预期事件：按正文结束处理，事件原样留给下游
                terminal_event = message
                break

            chunk: bytes = message.get("body", b"") or b""
            more_body = bool(message.get("more_body", False))
            spool.write(chunk, more_body)
            total += len(chunk)

            # 每个分片后按最新策略计量（运行时调小上限也立即对后续片生效）
            new_version, latest = _snapshot(current, policy_provider)
            if policy_provider is not None:
                version, current = new_version, latest
            if total > current.receive_limit:
                raise BodyTooLarge(total, current.receive_limit, version)
            if not more_body:
                break
    except BaseException:
        spool.close()
        raise

    # 完整接收后再分类：同一份正文，整包/分片/有无长度结论一致
    exceeds = total > current.inspect_limit
    inspected = spool.prefix(current.inspect_limit)
    return PrefetchResult(
        inspected=inspected,
        content_length=content_length,
        content_type=content_type,
        total_seen=total,
        exceeds_inspect=exceeds,
        policy_version=version,
        spool=spool,
        terminal_event=terminal_event,
    )


def make_replay_receive(
    receive: Receive,
    spool: BodySpool,
    terminal_event: dict | None = None,
) -> Receive:
    """构造下游使用的 receive：先按原事件边界重放假脱机中的完整正文，
    再透传真实 receive。

    - 重放分段严格沿用接收时的 ASGI 分片边界（含原始 ``more_body`` 标志），
      字节序与长度与客户端发送完全一致；
    - 空正文至少给出一个空的 ``more_body=False`` 收尾事件；
    - 接收阶段观测到的非 ``http.request`` 事件（如 ``http.disconnect``）
      在缓存事件全部重放完后原样交还下游，且只交还一次。
    """
    segments: deque[tuple[int, int, bool]] = deque(spool.segments)
    state = {"phase": "segments"}

    async def replay_receive() -> dict:
        if state["phase"] == "segments":
            if segments:
                start, length, more = segments.popleft()
                return {
                    "type": "http.request",
                    "body": spool.read_segment(start, length),
                    "more_body": more,
                }
            if terminal_event is not None:
                state["phase"] = "passthrough"
                return terminal_event
            # 没有缓存收尾事件：合成一个，之后透传真实 receive
            state["phase"] = "passthrough"
            return {"type": "http.request", "body": b"", "more_body": False}
        return await receive()

    return replay_receive
