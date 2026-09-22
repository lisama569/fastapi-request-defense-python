"""按来源标识的滑动时间窗限流器（sliding window log）。

语义：
- 每个来源维护窗口内的请求时间戳队列；窗口为 ``[now-window, now]``。
- 每次 ``check`` 恰好计数一次：放行才记入窗口，配额耗尽即拒绝，绝不超发。
- 时间戳按来源单调化（``max(now, last_seen)``）：时钟回拨不会让已过期槽位复活，
  相同时间戳的重复请求各自计数，不会漏计。
- 原因可区分：配额耗尽统一为 ``quota_exhausted``（有事件过期即必然放行，
  因此拒绝必然发生在当前窗口配额耗尽时）。
- 已空闲超过一个窗口的来源队列会被清理，避免内存无界增长。
"""

from __future__ import annotations

import threading
from collections import deque

from app.models import RateLimitReason


class SlidingWindowRateLimiter:
    def __init__(self, limit: int, window_seconds: float) -> None:
        if limit <= 0:
            raise ValueError("limit must be positive")
        if window_seconds <= 0:
            raise ValueError("window_seconds must be positive")
        self._limit = limit
        self._window = float(window_seconds)
        self._lock = threading.Lock()
        self._events: dict[str, deque[float]] = {}
        self._last_seen: dict[str, float] = {}

    @property
    def limit(self) -> int:
        return self._limit

    @property
    def window_seconds(self) -> float:
        return self._window

    def _prune_idle_locked(self, now: float) -> None:
        """清理已无窗口内事件且空闲超过一个窗口的来源。"""
        dead = [
            src
            for src, dq in self._events.items()
            if not dq and now - self._last_seen.get(src, now) >= self._window
        ]
        for src in dead:
            self._events.pop(src, None)
            self._last_seen.pop(src, None)

    def check(self, source: str, now: float) -> tuple[bool, int, str]:
        """返回 ``(是否放行, 剩余配额, 原因)``。

        拒绝时剩余配额为 0；原因见 :class:`RateLimitReason`。
        """
        with self._lock:
            # 单调化时间：同一来源不允许时钟回拨
            effective_now = max(float(now), self._last_seen.get(source, float(now)))
            self._last_seen[source] = effective_now

            dq = self._events.setdefault(source, deque())
            boundary = effective_now - self._window
            while dq and dq[0] <= boundary:
                dq.popleft()

            if len(dq) >= self._limit:
                self._prune_idle_locked(effective_now)
                return False, 0, RateLimitReason.QUOTA_EXHAUSTED.value

            # 放行：本次请求恰好计入一次
            dq.append(effective_now)
            remaining = self._limit - len(dq)
            self._prune_idle_locked(effective_now)
            return True, remaining, "within_quota"

    def remaining(self, source: str, now: float) -> int:
        with self._lock:
            effective_now = max(float(now), self._last_seen.get(source, float(now)))
            dq = self._events.get(source)
            if dq is None:
                return self._limit
            boundary = effective_now - self._window
            while dq and dq[0] <= boundary:
                dq.popleft()
            return self._limit - len(dq)

    def reset(self, source: str | None = None) -> None:
        with self._lock:
            if source is None:
                self._events.clear()
                self._last_seen.clear()
            else:
                self._events.pop(source, None)
                self._last_seen.pop(source, None)
