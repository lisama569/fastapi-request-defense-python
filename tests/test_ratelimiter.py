"""滑动窗口限流测试：语义、窗口推进、并发冲击下不漏计/不超发。"""

from __future__ import annotations

import threading

import pytest

from request_defense.ratelimiter import SlidingWindowRateLimiter


class FakeClock:
    """可控单调时钟（纳秒）。"""

    def __init__(self) -> None:
        self.ms = 0

    def __call__(self) -> int:
        return self.ms * 1_000_000

    def advance(self, ms: int) -> None:
        self.ms += ms


@pytest.fixture()
def clock():
    return FakeClock()


def test_allows_up_to_limit_then_rejects(clock):
    rl = SlidingWindowRateLimiter(limit=3, window_ms=1000, clock=clock)
    results = [rl.try_acquire("a") for _ in range(3)]
    assert all(r.allowed for r in results)
    assert results[-1].remaining == 0

    denied = rl.try_acquire("a")
    assert not denied.allowed
    assert denied.retry_after_ms > 0


def test_rejected_request_does_not_consume_quota(clock):
    rl = SlidingWindowRateLimiter(limit=2, window_ms=1000, clock=clock)
    rl.try_acquire("a")
    rl.try_acquire("a")
    d1 = rl.try_acquire("a")
    d2 = rl.try_acquire("a")
    assert not d1.allowed and not d2.allowed
    # 被拒绝不计数：retry_after 与 remaining 在时钟不动时保持一致
    assert d1.remaining == d2.remaining == 0


def test_window_slides_forward_monotonically(clock):
    rl = SlidingWindowRateLimiter(limit=2, window_ms=1000, clock=clock)
    assert rl.try_acquire("a").allowed
    clock.advance(600)
    assert rl.try_acquire("a").allowed
    clock.advance(600)  # 第一个时间戳（t=0）已滑出，t=600 的仍在窗内
    r = rl.try_acquire("a")
    assert r.allowed and r.remaining == 0  # 窗内 t=600 + 本次 = 2


def test_window_boundary_events_expire(clock):
    rl = SlidingWindowRateLimiter(limit=1, window_ms=1000, clock=clock)
    assert rl.try_acquire("a").allowed
    clock.advance(999)
    assert not rl.try_acquire("a").allowed
    clock.advance(1)  # t=0 的事件满足 ts <= now-window，被驱逐
    assert rl.try_acquire("a").allowed


def test_sources_are_isolated(clock):
    rl = SlidingWindowRateLimiter(limit=1, window_ms=1000, clock=clock)
    assert rl.try_acquire("a").allowed
    assert not rl.try_acquire("a").allowed
    assert rl.try_acquire("b").allowed


def test_concurrent_burst_no_overcount_no_overgrant():
    """50 线程 x 4 次请求，limit=100：恰好 100 放行、100 拒绝。"""
    rl = SlidingWindowRateLimiter(limit=100, window_ms=60_000)
    outcomes: list[bool] = []
    lock = threading.Lock()

    def worker() -> None:
        local = [rl.try_acquire("hot-source").allowed for _ in range(4)]
        with lock:
            outcomes.extend(local)

    threads = [threading.Thread(target=worker) for _ in range(50)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert len(outcomes) == 200
    assert sum(outcomes) == 100  # 无超发
    assert outcomes.count(False) == 100  # 无漏计（第 101 个起必拒）


def test_concurrent_distinct_sources_all_pass():
    rl = SlidingWindowRateLimiter(limit=1, window_ms=60_000)
    barrier = threading.Barrier(32)
    outcomes: list[bool] = []
    lock = threading.Lock()

    def worker(i: int) -> None:
        barrier.wait()
        ok = rl.try_acquire(f"src-{i}").allowed
        with lock:
            outcomes.append(ok)

    threads = [threading.Thread(target=worker, args=(i,)) for i in range(32)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert all(outcomes)
