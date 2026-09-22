"""滑动窗口限流测试：含并发冲击，断言不漏计、不超发、计数不跳变。"""

from __future__ import annotations

import threading

from app.models import RateLimitReason
from app.ratelimit import SlidingWindowRateLimiter


def test_quota_exhausted_is_distinguishable_and_no_overissue():
    rl = SlidingWindowRateLimiter(limit=5, window_seconds=1.0)
    results = [rl.check("a", 100.0) for _ in range(5)]
    assert all(ok for ok, _, _ in results)
    assert [rem for _, rem, _ in results] == [4, 3, 2, 1, 0]

    ok, remaining, reason = rl.check("a", 100.0)
    assert ok is False
    assert remaining == 0
    assert reason == RateLimitReason.QUOTA_EXHAUSTED.value


def test_duplicate_requests_same_timestamp_are_each_counted():
    """相同时间戳的重复请求不得漏计：每次都独立扣减配额。"""
    rl = SlidingWindowRateLimiter(limit=3, window_seconds=1.0)
    allowed = [rl.check("a", 50.0)[0] for _ in range(5)]
    assert allowed == [True, True, True, False, False]


def test_sliding_window_advances_monotonically_and_releases_quota():
    rl = SlidingWindowRateLimiter(limit=3, window_seconds=1.0)
    for t in (0.0, 0.1, 0.2):
        assert rl.check("a", t)[0]
    # 窗口内仍满 -> 拒绝
    assert rl.check("a", 0.9)[0] is False
    # 恰好滑过最早事件 (t=0.0) -> 释放 1 个配额
    ok, remaining, _ = rl.check("a", 1.0001)
    assert ok and remaining == 0
    # 再滑过 t=0.1 -> 又释放一个
    ok, remaining, _ = rl.check("a", 1.1001)
    assert ok and remaining == 0


def test_sources_are_counted_independently():
    rl = SlidingWindowRateLimiter(limit=2, window_seconds=1.0)
    assert rl.check("a", 0.0)[0]
    assert rl.check("a", 0.0)[0]
    assert rl.check("a", 0.0)[0] is False
    assert rl.check("b", 0.0)[0] is True


def test_concurrent_burst_admits_exactly_limit_no_more_no_less():
    """并发冲击：无论线程如何交错，放行数恰好等于配额，绝不超发。"""
    limit = 500
    rl = SlidingWindowRateLimiter(limit=limit, window_seconds=10.0)
    decisions: list[bool] = []
    lock = threading.Lock()

    def worker() -> None:
        ok, _, _ = rl.check("hot-source", 1000.0)  # 同一时间戳，强竞争
        with lock:
            decisions.append(ok)

    threads = [threading.Thread(target=worker) for _ in range(2000)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert len(decisions) == 2000
    assert sum(decisions) == limit  # 精确：不多不少
    assert rl.remaining("hot-source", 1000.0) == 0


def test_clock_going_backwards_does_not_revive_quota():
    rl = SlidingWindowRateLimiter(limit=2, window_seconds=1.0)
    assert rl.check("a", 100.0)[0]
    assert rl.check("a", 100.0)[0]
    # 时钟回拨到更早时刻，仍应被拒绝（时间单调化）
    assert rl.check("a", 99.0)[0] is False
    assert rl.check("a", 100.5)[0] is False


def test_reset_clears_state_without_affecting_other_sources():
    rl = SlidingWindowRateLimiter(limit=1, window_seconds=1.0)
    rl.check("a", 0.0)
    rl.check("b", 0.0)
    rl.reset("a")
    assert rl.check("a", 0.0)[0] is True
    assert rl.check("b", 0.0)[0] is False
