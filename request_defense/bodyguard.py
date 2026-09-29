"""有界正文接收：预取检查前缀 + 下游原样重放。

设计目标（对应带正文入口的防护要求）：

1. **防护层不提前消费正文**：预取的 ASGI ``http.request`` 事件会被原样重放给
   下游；跨检查上限边界的事件被拆成两段重放，字节序、长度、内容完全一致，
   下游 ``await request.body()/json()/form()`` 拿到的就是客户端原始正文。
2. **内存有界**：防护侧只保留至多 ``inspect_limit`` 字节的检查前缀（外加至多
   一个 ASGI 分片的剩余部分），绝不会因为正文很大而整体堆在内存里；
   在途名额（``BoundedBodyGuard`` 外层信号量）再限制并发缓冲总量。
3. **两类“太大”严格区分**：
   - 超过 ``receive_limit``（接收上限）：不接受，``BodyTooLarge``（413）；
   - 超过 ``inspect_limit``（检查上限）但在接收上限内：能收但无法对整体内容
     完成判定，由上层给出 ``content_inspection_incomplete``（默认 403）。
4. **耗时有界**：预取每次 receive 都有超时，慢发送不能无界占用连接/名额。
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass
from typing import Awaitable, Callable

from .policy import BodyPolicy

# 带正文的统一保护方法集合
BODY_METHODS = frozenset({"POST", "PUT", "PATCH"})

Receive = Callable[[], Awaitable[dict]]


class BodyReceiveError(Exception):
    """正文接收阶段的防护异常基类。"""


class BodyTooLarge(BodyReceiveError):
    """正文超过接收上限（服务不接受）。"""

    def __init__(self, received: int, limit: int) -> None:
        super().__init__(f"body too large: {received} > receive_limit {limit}")
        self.received = received
        self.limit = limit


class BodyReceiveTimeout(BodyReceiveError):
    """正文接收超过单请求时间预算。"""

    def __init__(self, timeout_ms: int) -> None:
        super().__init__(f"body receive timed out after {timeout_ms}ms")
        self.timeout_ms = timeout_ms


@dataclass(frozen=True, slots=True)
class PrefetchResult:
    """预取结论：检查前缀 + 计量信息（不含任何判定，判定由上层做）。"""

    inspected: bytes
    content_length: int | None
    content_type: str
    total_seen: int
    exceeds_inspect: bool
    events: tuple[dict, ...]


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


async def prefetch_body(
    *,
    scope_headers: list[tuple[bytes, bytes]],
    receive: Receive,
    policy: BodyPolicy,
    receive_timeout_ms: int,
) -> PrefetchResult:
    """有界预取：返回检查前缀（≤ inspect_limit）与可重放事件。

    - Content-Length 已知且超过 receive_limit：不读取任何字节，直接 BodyTooLarge；
    - receive 超时：BodyReceiveTimeout；
    - 超过 inspect_limit：正常返回（exceeds_inspect=True），由上层决定降级语义；
    - 分块传输在预取窗口内不可能越过 receive_limit（inspect_limit ≤ receive_limit），
      下游重放阶段继续计量并在越界时抛 BodyTooLarge。
    """
    content_length = _parse_content_length(scope_headers)
    content_type = _header(scope_headers, b"content-type") or ""
    if content_length is not None and content_length > policy.receive_limit:
        raise BodyTooLarge(content_length, policy.receive_limit)

    inspect_limit = policy.inspect_limit
    timeout_s = receive_timeout_ms / 1000.0

    prefix = bytearray()
    events: list[dict] = []
    total = 0
    saw_end = False          # 是否已观测到 more_body=False / 非预期收尾事件
    split_tail = False       # 分片在检查边界被拆分，余量已进入重放队列

    while total < inspect_limit:
        try:
            message = await asyncio.wait_for(receive(), timeout=timeout_s)
        except TimeoutError as exc:
            raise BodyReceiveTimeout(receive_timeout_ms) from exc
        if message.get("type") != "http.request":
            # 非预期事件（如 http.disconnect）：结束预取，原样重放给下游
            events.append(message)
            saw_end = True
            break

        chunk: bytes = message.get("body", b"")
        more_body = bool(message.get("more_body", False))
        remaining = inspect_limit - total
        if len(chunk) <= remaining:
            prefix.extend(chunk)
            total += len(chunk)
            events.append({"type": "http.request", "body": chunk,
                           "more_body": more_body})
        else:
            # 单个 ASGI 分片跨过检查边界：拆成两段，保证检查前缀有界，
            # 剩余部分留待边界探测后决定如何重放（此处先不入队，避免双份）。
            head = chunk[:remaining]
            tail = chunk[remaining:]
            prefix.extend(head)
            total += len(head)
            events.append({"type": "http.request", "body": head,
                           "more_body": True})
            # tail 尚未被“再读一次”，先记录为待重放余量；它本身就是
            # “检查窗口之外还有数据”的证据，因此必然 exceeds。
            events.append({"type": "http.request", "body": tail,
                           "more_body": more_body})
            if not more_body:
                saw_end = True
            split_tail = True
            break
        if not more_body:
            saw_end = True
            break

    exceeds = False
    if not saw_end and total >= inspect_limit:
        # 缓冲恰好读满检查上限：可能是“正文恰好这么大”，也可能“还有后续”。
        # 再探测一个事件来区分；该事件必须进入重放队列，下游字节不丢不重。
        try:
            message = await asyncio.wait_for(receive(), timeout=timeout_s)
        except TimeoutError as exc:
            raise BodyReceiveTimeout(receive_timeout_ms) from exc
        if message.get("type") == "http.request":
            chunk = message.get("body", b"")
            more_body = bool(message.get("more_body", False))
            if len(chunk) == 0 and not more_body:
                # 空的收尾事件：正文恰好等于检查上限，不超限
                events.append(message)
            else:
                # 非空分片或仍有后续：正文确实超过检查上限。
                # 探测分片原样进入重放；其大小受 ASGI 服务器分片上限约束
                # （uvicorn 单分片约 64KiB，与默认 inspect_limit 同量级）。
                exceeds = True
                events.append({"type": "http.request", "body": chunk,
                               "more_body": more_body})
                total += len(chunk)
        else:
            events.append(message)
    elif split_tail:
        # 分片在检查边界被拆开且余量非空：正文超过检查上限
        exceeds = True

    return PrefetchResult(
        inspected=bytes(prefix),
        content_length=content_length,
        content_type=content_type,
        total_seen=total,
        exceeds_inspect=exceeds,
        events=tuple(events),
    )


def make_replay_receive(
    receive: Receive,
    events: tuple[dict, ...],
    policy: BodyPolicy,
    on_drained: Callable[[], None] | None = None,
) -> Receive:
    """构造下游使用的 receive：先原样重放预取事件，再透传真实 receive。

    透传阶段继续按 receive_limit 计量（覆盖无 Content-Length 的分块请求）；
    下游首次拉到预取窗口之外的数据时回调 on_drained（用于释放在途名额）。
    """
    queue: list[dict] = list(events)
    state = {"total": 0, "drained": False, "past": False}

    for event in events:
        if event.get("type") == "http.request":
            state["total"] += len(event.get("body", b""))

    async def replay_receive() -> dict:
        if queue:
            return queue.pop(0)
        message = await receive()
        if not state["past"]:
            state["past"] = True
            if on_drained is not None:
                on_drained()
        if message.get("type") == "http.request":
            state["total"] += len(message.get("body", b""))
            if state["total"] > policy.receive_limit:
                raise BodyTooLarge(state["total"], policy.receive_limit)
        return message

    return replay_receive
