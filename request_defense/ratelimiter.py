"""按来源标识的滑动时间窗限流器。

语义：
  - 每个来源独立维护一个单调推进的滑动窗口；
  - ``try_acquire`` 在窗口内追加 ``count`` 个请求时间戳并判定是否超限；
  - 配额耗尽时拒绝，返回 ``retry_after_ms``，且**本次请求不被计入**
    （被拒绝的请求不消耗配额，保证重复重试不会漏计/超发正常配额）；
  - 窗口通过锁保护，单调时钟（``time.monotonic_ns``）保证并发下
    不出现计数跳变或重复扣减。
"""

from __future__ import annotations

import threading
import time
from collections import deque
from dataclasses import dataclass
from typing import Callable

# 每个来源最多保留的时间戳数量（窗口内不可能超过 limit 个成功请求，
# 再留少量余量），防止异常来源无界占用内存。
_MAX_EV_PER_SOURCE_MARGIN = 8


@dataclass(frozen=True, slots=True)
class RateLimitResult:
    allowed: bool
    remaining: int
    limit: int
    window_ms: int
    retry_after_ms: int


Clock = Callable[[], int]  # 单调纳秒时钟


class SlidingWindowRateLimiter:
    """线程安全的滑动窗口限流器。"""

    __slots__ = ("limit", "window_ns", "_clock", "_lock", "_events", "_capacity")

    def __init__(self, limit: int, window_ms: int, clock: Clock | None = None) -> None:
        if limit <= 0:
            raise ValueError("limit must be positive")
        if window_ms <= 0:
            raise ValueError("window_ms must be positive")
        self.limit = limit
        self.window_ns = window_ms * 1_000_000
        self._clock = clock or time.monotonic_ns
        self._lock = threading.Lock()
        self._events: dict[str, deque[int]] = {}
        self._capacity = limit + _MAX_EV_PER_SOURCE_MARGIN

    def _evict(self, dq: deque[int], now_ns: int) -> None:
        boundary = now_ns - self.window_ns
        while dq and dq[0] <= boundary:
            dq.popleft()

    def try_acquire(self, source: str, count: int = 1) -> RateLimitResult:
        """尝试在 source 的窗口内占用 count 个配额。

        拒绝时窗口状态保持调用前的样子（不落时间戳）。
        """
        if count <= 0:
            raise ValueError("count must be positive")
        if count > self.limit:
            # 单次请求所需配额超过上限，永远无法放行
            return RateLimitResult(False, 0, self.limit, self.window_ns // 1_000_000, 0)

        with self._lock:
            now_ns = self._clock()
            dq = self._events.get(source)
            if dq is None:
                dq = deque()
                self._events[source] = dq
            self._evict(dq, now_ns)

            current = len(dq)
            if current + count > self.limit:
                oldest = dq[0]
                retry_ns = max(0, (oldest + self.window_ns) - now_ns)
                return RateLimitResult(
                    allowed=False,
                    remaining=max(0, self.limit - current),
                    limit=self.limit,
                    window_ms=self.window_ns // 1_000_000,
                    retry_after_ms=(retry_ns + 999_999) // 1_000_000,
                )

            for _ in range(count):
                dq.append(now_ns)
            # 防御性裁剪：任何情况下都不允许单来源内存无界增长
            if len(dq) > self._capacity:
                del dq[: len(dq) - self._capacity]
            return RateLimitResult(
                allowed=True,
                remaining=self.limit - len(dq),
                limit=self.limit,
                window_ms=self.window_ns // 1_000_000,
                retry_after_ms=0,
            )

    def reset(self, source: str | None = None) -> None:
        """清空计数（测试/管理用）。"""
        with self._lock:
            if source is None:
                self._events.clear()
            else:
                self._events.pop(source, None)

    def active_sources(self) -> int:
        with self._lock:
            return sum(1 for dq in self._events.values() if dq)
