"""内容策略存储单测：整体校验、原子替换、版本单调、快照一致性。"""

from __future__ import annotations

import threading

import pytest

from request_defense.policy import (
    ContentPolicy,
    ContentPolicyStore,
    ContentPolicyValidationError,
)


def make(inspect=64, receive=256, enabled=True):
    return ContentPolicy(inspect, receive, enabled)


class TestContentPolicyValidation:
    def test_valid_policy(self):
        make().validate()

    @pytest.mark.parametrize(
        "kwargs",
        [
            {"inspect": 0, "receive": 10},
            {"inspect": -1, "receive": 10},
            {"inspect": 10, "receive": 0},
            {"inspect": 10, "receive": -1},
            {"inspect": 11, "receive": 10},  # inspect > receive
        ],
    )
    def test_invalid_limits_raise(self, kwargs):
        with pytest.raises(ContentPolicyValidationError):
            make(**kwargs).validate()

    def test_bool_not_accepted_as_int(self):
        with pytest.raises(ContentPolicyValidationError):
            ContentPolicy(True, 10, True).validate()  # type: ignore[arg-type]

    def test_store_rejects_bad_initial_policy(self):
        with pytest.raises(ContentPolicyValidationError):
            ContentPolicyStore(make(inspect=100, receive=10))


class TestAtomicReplace:
    def test_initial_version_is_one(self):
        store = ContentPolicyStore(make())
        version, policy = store.snapshot()
        assert version == 1
        assert policy == make()

    def test_replace_returns_monotonic_version(self):
        store = ContentPolicyStore(make())
        assert store.replace(make(inspect=32)) == 2
        assert store.replace(make(inspect=16)) == 3

    def test_invalid_replace_keeps_old_entirely(self):
        store = ContentPolicyStore(make(inspect=64, receive=256))
        before_v, before_p = store.snapshot()
        with pytest.raises(ContentPolicyValidationError) as exc:
            store.replace(make(inspect=512, receive=256))
        assert exc.value.field == "inspect_limit_bytes"
        after_v, after_p = store.snapshot()
        assert after_v == before_v
        assert after_p == before_p  # 无半更新

    def test_snapshot_is_stable_under_concurrent_replace(self):
        store = ContentPolicyStore(make(inspect=64, receive=1_000_000))
        stop = threading.Event()
        errors: list[Exception] = []
        seen: list[tuple[int, int]] = []
        lock = threading.Lock()

        def changer():
            i = 0
            while not stop.is_set():
                try:
                    store.replace(make(inspect=64 + (i % 100) * 64, receive=1_000_000))
                except Exception as exc:  # noqa: BLE001
                    with lock:
                        errors.append(exc)
                i += 1

        def reader():
            for _ in range(500):
                v, p = store.snapshot()
                # 任意时刻拿到的快照必须自洽：inspect <= receive
                if p.inspect_limit_bytes > p.receive_limit_bytes:
                    with lock:
                        errors.append(AssertionError("inconsistent snapshot"))
                with lock:
                    seen.append((v, p.inspect_limit_bytes))

        t = threading.Thread(target=changer)
        t.start()
        readers = [threading.Thread(target=reader) for _ in range(6)]
        for r in readers:
            r.start()
        for r in readers:
            r.join()
        stop.set()
        t.join()

        assert not errors
        # 所有版本号均为正（单个快照对象始终自洽；交错读取下版本集合必须合法）
        assert {v for v, _ in seen}
        assert min(v for v, _ in seen) >= 1
