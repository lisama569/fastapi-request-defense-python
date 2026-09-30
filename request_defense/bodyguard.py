"""有界正文接收：预取检查前缀 + 计量判定 + 下游原样重放。

设计目标（对应带正文入口的防护要求）：

1. **送达方式无关的一致判定**：无论客户端一次性发整包（带 Content-Length）、
   分多片发送，还是不带长度流式（分块）推送，防护层都会把正文事件读到
   “可以下确定结论”为止：
     - 读到结束事件且总字节数 ≤ inspect_limit：正文完整落在检查范围内；
     - 读到结束事件且 inspect_limit < 总字节数 ≤ receive_limit：
       ``exceeds_inspect=True``（正文确实比检查范围大，且已见到结束）；
     - 总字节数一旦超过 receive_limit：立刻 ``BodyTooLarge``，不再保留任何
       后续字节，业务侧绝不会被执行。
   因此不会再出现“某一片恰好填满检查上限、下一个事件是空收尾事件”就被误判
   成“正文恰好等于上限”的分片绕过——判定只依据**累计字节数与结束事实**，
   与 ASGI 事件如何切分无关。
2. **防护层不提前消费正文**：允许路径下，预取期间读到的 ASGI
   ``http.request`` 事件会**按原始事件边界原样重放**给下游（不拆事件、不
   改写 more_body），随后透传真实 receive；字节序、长度、内容与客户端发出
   的完全一致，下游 ``await request.body()/json()/form()`` 拿到的就是原始
   正文。
3. **内存有界**：为了能在“正文结束”这一确定事实上下结论，预取会持续读取
   直到结束或越过接收上限；读取在越界点立即停止，因此单请求缓冲
   **≤ receive_limit（硬天花板 16 MiB）**，在途名额（外层信号量，默认 32）
   再限制并发缓冲总量（最坏 ≈ inflight × receive_limit）。为下确定结论而
   读完整个（有界的）正文，是“判定与送达方式一致 + 超量绝不透传业务”的
   显式取舍。
4. **两类“太大”严格区分且都不进业务**：
   - 超过 ``receive_limit``（接收上限）：不接受，``BodyTooLarge``（413），
     带不带 Content-Length、分不分片结论完全一致；
   - 超过 ``inspect_limit``（检查上限）但在接收上限内：能收但无法对整体
     内容完成判定，由上层给出 ``content_inspection_incomplete``（403），
     写在检查范围之后的内容不可能靠“放在后面”绕过。
5. **耗时有界**：每次 receive 都有超时，慢发送不能无界占用连接/名额。
6. **运行时策略变更对在途分段请求即时生效**：每次 receive 后重新读取策略
   快照，新调大/调小的检查上限、接收上限对尚未读完的部分立即适用；
   判定结论使用的版本号就是最终适用的策略版本。
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass
from typing import Awaitable, Callable

from .policy import BodyPolicy

# 带正文的统一保护方法集合
BODY_METHODS = frozenset({"POST", "PUT", "PATCH"})

Receive = Callable[[], Awaitable[dict]]

# 策略快照提供者：返回 (policy_version, BodyPolicy)。
# 预取在每次 receive 后重新取快照，使运行时调整的上限对在途正文立即生效。
PolicyProvider = Callable[[], tuple[int, BodyPolicy]]


class BodyReceiveError(Exception):
    """正文接收阶段的防护异常基类。"""


class BodyTooLarge(BodyReceiveError):
    """正文超过接收上限（服务不接受）。"""

    def __init__(self, received: int, limit: int,
                 policy_version: int = 0) -> None:
        super().__init__(f"body too large: {received} > receive_limit {limit}")
        self.received = received
        self.limit = limit
        # 触发该结论时实际生效的策略版本（在途调小接收上限时可能是新版本）
        self.policy_version = policy_version


class BodyReceiveTimeout(BodyReceiveError):
    """正文接收超过单请求时间预算。"""

    def __init__(self, timeout_ms: int) -> None:
        super().__init__(f"body receive timed out after {timeout_ms}ms")
        self.timeout_ms = timeout_ms


@dataclass(frozen=True, slots=True)
class PrefetchResult:
    """预取结论：检查前缀 + 计量信息（不含任何判定，判定由上层做）。

    - ``inspected``：按最终生效 inspect_limit 从已读取字节序中截取的检查
      前缀（用于 body 规则匹配与审计摘要）；
    - ``events``：预取期间读到的**原始** ASGI 事件（边界/more_body 不改写），
      允许路径下原样重放给下游；
    - ``total_bytes``：截至结束/断开时已观测到的累计字节数（越过接收上限
      时函数直接抛 ``BodyTooLarge``，不会走到这里）；
    - ``exceeds_inspect``：累计字节数是否严格大于最终生效的 inspect_limit；
    - ``ended``：是否已观测到正文结束（more_body=False 的收尾事件）；
    - ``policy_version`` / ``policy``：判定时实际适用的策略快照。
    """

    inspected: bytes
    content_length: int | None
    content_type: str
    total_bytes: int
    total_seen: int  # 兼容旧字段：与 total_bytes 相同
    exceeds_inspect: bool
    ended: bool
    events: tuple[dict, ...]
    policy_version: int
    policy: BodyPolicy


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
    policy_provider: PolicyProvider | None = None,
) -> PrefetchResult:
    """有界预取 + 计量判定：读到“可以下确定结论”为止。

    结论与正文的送达方式（整包/分片/无长度流式）无关，只取决于累计字节数：

    - Content-Length 已知且超过**当前生效**的 receive_limit：不读取任何字节，
      直接 ``BodyTooLarge``；
    - 每次 receive 后重新取策略快照（``policy_provider``），运行时调整后的
      两个上限对在途正文尚未读到的部分立即适用；
    - 累计字节数超过当前 receive_limit：立刻 ``BodyTooLarge``（后续字节不读、
      不进业务），带不带长度、分不分片结论一致；
    - 见到正文结束（more_body=False 收尾）且总字节 > inspect_limit：
      ``exceeds_inspect=True``，由上层给 ``content_inspection_incomplete``；
    - 见到正文结束且总字节 ≤ inspect_limit：``exceeds_inspect=False``，
      正常进入内容判定；
    - receive 超时：``BodyReceiveTimeout``。

    缓冲策略：**所有已读取的 ASGI 事件原样保留**用于放行重放，但读取在
    “正文结束 / 越过 receive_limit”处立即停止，因此单请求缓冲恒有界
    （≤ receive_limit + 一个 ASGI 分片，receive_limit 另有 16 MiB 硬天花板），
    在途名额再约束并发缓冲总量。不做跨边界拆事件——原始事件边界、more_body
    标记、字节序在重放时与客户端发出的完全一致。
    """
    content_length = _parse_content_length(scope_headers)
    content_type = _header(scope_headers, b"content-type") or ""
    version, current = policy_provider() if policy_provider else (0, policy)
    if content_length is not None and content_length > current.receive_limit:
        raise BodyTooLarge(content_length, current.receive_limit, version)

    timeout_s = receive_timeout_ms / 1000.0

    replay_events: list[dict] = []  # 已读取事件，原样保留，允许路径下重放
    total = 0                      # 已观测累计字节数
    ended = False                  # 是否已见到正文结束

    while True:
        try:
            message = await asyncio.wait_for(receive(), timeout=timeout_s)
        except TimeoutError as exc:
            raise BodyReceiveTimeout(receive_timeout_ms) from exc

        # 运行时调整的上限对在途请求立即生效：每个事件后都重新取快照。
        if policy_provider is not None:
            version, current = policy_provider()

        if message.get("type") != "http.request":
            # http.disconnect 等非数据事件：正文未以正常收尾结束。
            # 原样保留给下游重放；累计是否越过检查上限仍由 total 判定。
            replay_events.append(message)
            break

        chunk: bytes = message.get("body", b"")
        more_body = bool(message.get("more_body", False))
        total += len(chunk)

        # 越过接收上限：立即拒绝。该事件不保留（绝不透传给业务），
        # 后续也不再读取；无论是否声明长度、分不分片，结论一致。
        if total > current.receive_limit:
            raise BodyTooLarge(total, current.receive_limit, version)

        replay_events.append({"type": "http.request", "body": chunk,
                              "more_body": more_body})

        if not more_body:
            ended = True
            break

    # 检查前缀：把已保留事件的字节序拼接后截到最终生效的 inspect_limit。
    # 只用于 body 规则匹配与审计摘要；重放仍使用原始事件（不拆不拼）。
    prefix = bytearray()
    for event in replay_events:
        if event.get("type") != "http.request":
            continue
        chunk = event.get("body", b"")
        room = current.inspect_limit - len(prefix)
        if room <= 0:
            break
        prefix.extend(chunk[:room])

    exceeds = total > current.inspect_limit
    return PrefetchResult(
        inspected=bytes(prefix),
        content_length=content_length,
        content_type=content_type,
        total_bytes=total,
        total_seen=total,
        exceeds_inspect=exceeds,
        ended=ended,
        events=tuple(replay_events),
        policy_version=version,
        policy=current,
    )


def make_replay_receive(
    receive: Receive,
    events: tuple[dict, ...],
    policy: BodyPolicy,
    on_drained: Callable[[], None] | None = None,
    policy_version: int = 0,
) -> Receive:
    """构造下游使用的 receive：先原样重放预取读取的全部事件，再透传真实 receive。

    透传阶段继续按 receive_limit 计量（纵深防御：覆盖预取后仍在途的数据，
    例如预取因 http.disconnect 结束而客户端实际仍有后续的异常形态）；下游
    首次拉到重放队列之外的真实事件时回调 on_drained（用于尽早释放在途名额）。
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
            if on_drained is not None and not state["drained"]:
                state["drained"] = True
                on_drained()
        if message.get("type") == "http.request":
            state["total"] += len(message.get("body", b""))
            if state["total"] > policy.receive_limit:
                raise BodyTooLarge(state["total"], policy.receive_limit,
                                   policy_version)
        return message

    return replay_receive
