"""带正文入口（POST/PUT/PATCH）端到端：字节一致、限流/拒绝不触达业务、
容量与降级语义、运行时内容策略切换。"""

from __future__ import annotations

import hashlib

import pytest
from fastapi.testclient import TestClient

from request_defense.app import create_app
from request_defense.config import DefenseConfig

AUTH = {"Authorization": "Bearer secret-admin-token"}


@pytest.fixture()
def client():
    # 小上限，便于稳定触发 413 / 422：检查 64B，接收 256B
    config = DefenseConfig(
        rate_limit=5,
        window_ms=60_000,
        max_rules=10,
        request_timeout_ms=200,
        admin_token="secret-admin-token",
        fail_open=False,
        inspect_limit_bytes=512,
        receive_limit_bytes=4096,
        content_check_enabled=True,
        body_timeout_ms=10_000,
        body_ingress_concurrency=8,
    )
    app = create_app(config)
    with TestClient(app) as c:
        yield c


def _h(src):
    return {"X-Forwarded-For": src}


class TestPassThroughFidelity:
    def test_json_body_preserved_byte_for_byte(self, client):
        payload = b'{"name":"\xe4\xb8\xad\xe6\x96\x87","payload":{"k":[1,2,3]}}'
        r = client.post(
            "/api/submit/json",
            content=payload,
            headers={**_h("198.51.100.11"), "Content-Type": "application/json"},
        )
        assert r.status_code == 200
        body = r.json()
        assert body["length"] == len(payload)
        assert body["content_type"] == "application/json"
        assert body["raw_sha256"] == hashlib.sha256(payload).hexdigest()
        assert body["name"] == "中文"

    def test_urlencoded_form_preserved(self, client):
        payload = b"name=alice&note=hello+world"
        r = client.post(
            "/api/submit/form",
            content=payload,
            headers={
                **_h("198.51.100.12"),
                "Content-Type": "application/x-www-form-urlencoded",
            },
        )
        assert r.status_code == 200
        body = r.json()
        assert body["length"] == len(payload)
        assert body["raw_sha256"] == hashlib.sha256(payload).hexdigest()
        assert body["fields"] == {"name": "alice", "note": "hello world"}

    def test_multipart_binary_preserved(self, client):
        payload = bytes(range(256))  # 全字节域，multipart 整体 < 检查上限
        r = client.put(
            "/api/upload/binary",
            files={"file": ("data.bin", payload, "application/octet-stream")},
            headers=_h("198.51.100.13"),
        )
        assert r.status_code == 200
        body = r.json()
        assert body["filename"] == "data.bin"
        assert body["file_length"] == len(payload)
        assert body["file_sha256"] == hashlib.sha256(payload).hexdigest()

    def test_patch_uses_same_pipeline(self, client):
        payload = b'{"name":"patch-me"}'
        r = client.patch(
            "/api/submit/json",
            content=payload,
            headers={**_h("198.51.100.14"), "Content-Type": "application/json"},
        )
        assert r.status_code == 200
        assert r.json()["raw_sha256"] == hashlib.sha256(payload).hexdigest()
        assert r.json()["name"] == "patch-me"


class TestBlockedNeverReachesBusiness:
    def test_rate_limited_post_does_not_run_business(self, client):
        # 用唯一来源连续打满 5 个配额，第 6 个 POST 必须 429
        for _ in range(5):
            r = client.post(
                "/api/submit/json",
                content=b'{"name":"ok"}',
                headers={**_h("203.0.113.50"), "Content-Type": "application/json"},
            )
            assert r.status_code == 200
        big = b'{"name":"sixth"}'
        r = client.post(
            "/api/submit/json",
            content=big,
            headers={**_h("203.0.113.50"), "Content-Type": "application/json"},
        )
        assert r.status_code == 429
        assert r.json()["error"] == "rate_limit_quota_exhausted"

    def test_rule_deny_on_body_blocks_business(self, client):
        # 内容规则：body 中含 blockme -> deny
        client.put(
            "/admin/rules",
            headers=AUTH,
            json={"rules": [{
                "rule_id": "deny-body-token",
                "priority": 0,
                "effect": "deny",
                "field_name": "body",
                "pattern": "blockme",
            }]},
        )
        r = client.post(
            "/api/submit/json",
            content=b'{"name":"abc blockme xyz"}',
            headers={**_h("203.0.113.51"), "Content-Type": "application/json"},
        )
        assert r.status_code == 403
        body = r.json()
        assert body["error"] == "rule_match_deny"

    def test_default_secret_area_rule_still_denies(self, client):
        r = client.post(
            "/secret-area/x",
            content=b"{}",
            headers={**_h("203.0.113.52"), "Content-Type": "application/json"},
        )
        assert r.status_code == 403
        assert r.json()["error"] == "rule_match_deny"


class TestCapacityAndDegradation:
    def test_declared_oversize_returns_413_and_no_business(self, client):
        # Content-Length 8192 > 接收上限 4096：不接受，且不读取正文
        r = client.post(
            "/api/submit/json",
            content=b"x" * 8192,
            headers={**_h("198.18.0.1"), "Content-Type": "application/json"},
        )
        assert r.status_code == 413
        assert r.json()["error"] == "body_too_large"
        assert r.json()["decision"] == "deny"

    def test_chunked_oversize_returns_413(self, client):
        # 无 Content-Length 分块发送，实际超过接收上限 4096
        def gen():
            for _ in range(80):
                yield b"y" * 60  # 4800 总计
        r = client.post(
            "/api/submit/json",
            content=gen(),
            headers={
                **_h("198.18.0.2"),
                "Content-Type": "application/json",
                "Transfer-Encoding": "chunked",
            },
        )
        assert r.status_code == 413
        assert r.json()["error"] == "body_too_large"

    def test_body_over_inspect_but_under_receive_is_422_incomplete(self, client):
        # 长度 >512 且 <=4096：能接收但无法完成内容判定 -> 422，业务不执行
        pad = b"a" * 1024
        payload = b'{"name":"n","pad":"' + pad + b'"}'
        r = client.post(
            "/api/submit/json",
            content=payload,
            headers={**_h("198.18.0.3"), "Content-Type": "application/json"},
        )
        assert r.status_code == 422
        assert r.json()["error"] == "body_inspection_incomplete"
        assert r.json()["decision"] == "deny"

    def test_413_and_422_are_distinct(self, client):
        r1 = client.post("/api/submit/json", content=b"x" * 8192,
                         headers={**_h("198.18.0.4"), "Content-Type": "application/json"})
        pad = b"a" * 1024
        r2 = client.post("/api/submit/json",
                         content=b'{"name":"n","pad":"' + pad + b'"}',
                         headers={**_h("198.18.0.5"), "Content-Type": "application/json"})
        assert (r1.status_code, r1.json()["error"]) == (413, "body_too_large")
        assert (r2.status_code, r2.json()["error"]) == (422, "body_inspection_incomplete")


class TestRuntimeContentPolicy:
    def _get(self, client):
        return client.get("/admin/content-policy", headers=AUTH).json()

    def test_policy_requires_auth(self, client):
        valid = {
            "inspect_limit_bytes": 32,
            "receive_limit_bytes": 4096,
            "content_check_enabled": True,
        }
        assert client.get("/admin/content-policy").status_code == 401
        # 即使请求体合法，未授权也必须在最外层被 401 拦截，不发生任何更新
        assert client.put("/admin/content-policy", json=valid).status_code == 401

    def test_read_initial_policy(self, client):
        p = self._get(client)
        assert p["version"] == 1
        assert p["inspect_limit_bytes"] == 512
        assert p["receive_limit_bytes"] == 4096
        assert p["content_check_enabled"] is True

    def test_replace_policy_takes_effect_without_restart(self, client):
        # 把检查上限降到 32：原本可放行的小 JSON 现在超过检查范围 -> 422
        r = client.put(
            "/admin/content-policy",
            headers=AUTH,
            json={
                "inspect_limit_bytes": 32,
                "receive_limit_bytes": 4096,
                "content_check_enabled": True,
            },
        )
        assert r.status_code == 200
        assert r.json()["version"] == 2

        payload = b'{"name":"this-is-a-rather-long-name-xxxxxxxx"}'  # > 32
        assert len(payload) > 32
        r2 = client.post(
            "/api/submit/json",
            content=payload,
            headers={**_h("198.19.0.1"), "Content-Type": "application/json"},
        )
        assert r2.status_code == 422
        assert r2.json()["error"] == "body_inspection_incomplete"

        # 调大检查上限后同一请求立即放行，无需重启
        client.put(
            "/admin/content-policy",
            headers=AUTH,
            json={
                "inspect_limit_bytes": 4096,
                "receive_limit_bytes": 4096,
                "content_check_enabled": True,
            },
        )
        r3 = client.post(
            "/api/submit/json",
            content=payload,
            headers={**_h("198.19.0.2"), "Content-Type": "application/json"},
        )
        assert r3.status_code == 200
        assert r3.json()["raw_sha256"] == hashlib.sha256(payload).hexdigest()

    def test_invalid_policy_rejected_entirely_keeps_old(self, client):
        before = self._get(client)
        # inspect > receive：非法，整体拒绝
        r = client.put(
            "/admin/content-policy",
            headers=AUTH,
            json={
                "inspect_limit_bytes": 8192,
                "receive_limit_bytes": 4096,
                "content_check_enabled": True,
            },
        )
        assert r.status_code == 422
        body = r.json()
        assert body["error"] == "invalid_content_policy"
        assert body["field"] == "inspect_limit_bytes"
        assert body["current_version"] == before["version"]
        after = self._get(client)
        assert after == before  # 旧策略完整保留，无半更新

    def test_non_positive_limits_rejected(self, client):
        for bad in (
            {"inspect_limit_bytes": 0, "receive_limit_bytes": 10, "content_check_enabled": True},
            {"inspect_limit_bytes": 5, "receive_limit_bytes": 0, "content_check_enabled": True},
            {"inspect_limit_bytes": -1, "receive_limit_bytes": 10, "content_check_enabled": True},
        ):
            r = client.put("/admin/content-policy", headers=AUTH, json=bad)
            assert r.status_code == 422

    def test_version_monotonic_under_repeated_updates(self, client):
        versions = []
        for i in range(3):
            r = client.put(
                "/admin/content-policy",
                headers=AUTH,
                json={
                    "inspect_limit_bytes": 100 + i,
                    "receive_limit_bytes": 4096,
                    "content_check_enabled": True,
                },
            )
            versions.append(r.json()["version"])
        assert versions == [2, 3, 4]

    def test_disable_content_check_allows_uninspected_large_body(self, client):
        # 关闭内容判定：超过检查上限的正文不再 422，完整转发业务
        client.put(
            "/admin/content-policy",
            headers=AUTH,
            json={
                "inspect_limit_bytes": 32,
                "receive_limit_bytes": 8192,
                "content_check_enabled": False,
            },
        )
        pad = b"b" * 1000
        payload = b'{"name":"big","pad":"' + pad + b'"}'
        r = client.post(
            "/api/submit/json",
            content=payload,
            headers={**_h("198.19.0.9"), "Content-Type": "application/json"},
        )
        assert r.status_code == 200
        assert r.json()["length"] == len(payload)
        assert r.json()["raw_sha256"] == hashlib.sha256(payload).hexdigest()

    def test_receive_limit_change_changes_413_boundary(self, client):
        client.put(
            "/admin/content-policy",
            headers=AUTH,
            json={
                "inspect_limit_bytes": 128,
                "receive_limit_bytes": 128,
                "content_check_enabled": True,
            },
        )
        r = client.post(
            "/api/submit/json",
            content=b"x" * 200,
            headers={**_h("198.19.0.10"), "Content-Type": "application/json"},
        )
        assert r.status_code == 413
        assert r.json()["error"] == "body_too_large"


class TestContentRuleOnPrefix:
    def test_body_rule_matches_within_inspect_range(self, client):
        client.put(
            "/admin/rules",
            headers=AUTH,
            json={"rules": [{
                "rule_id": "deny-evil-token",
                "priority": 0,
                "effect": "deny",
                "field_name": "body",
                "pattern": "EVIL",
            }]},
        )
        r = client.post(
            "/api/submit/json",
            content=b'{"x":"EVIL"}',
            headers={**_h("198.20.0.1"), "Content-Type": "application/json"},
        )
        assert r.status_code == 403
        assert r.json()["error"] == "rule_match_deny"

    def test_body_rule_not_fooled_when_token_only_after_inspect_range(self, client):
        # 命中串只出现在检查前缀之外：内容判定不可完成 -> 422（不会被静默放行），
        # 而不是按"未命中"放行，确保不被绕过。
        client.put(
            "/admin/rules",
            headers=AUTH,
            json={"rules": [{
                "rule_id": "deny-evil-token",
                "priority": 0,
                "effect": "deny",
                "field_name": "body",
                "pattern": "EVIL",
            }]},
        )
        prefix = b'{"pad":"' + b"p" * 600 + b'"'
        payload = prefix + b',"tail":"EVIL"}'
        assert len(payload) > 512
        r = client.post(
            "/api/submit/json",
            content=payload,
            headers={**_h("198.20.0.2"), "Content-Type": "application/json"},
        )
        assert r.status_code == 422
        assert r.json()["error"] == "body_inspection_incomplete"


class TestConcurrentLargeBodies:
    def test_many_concurrent_large_bodies_bounded_and_correct(self):
        # 独立 app：每来源高配额、并发容量小、检查/接收上限固定
        config = DefenseConfig(
            rate_limit=100_000,
            window_ms=60_000,
            max_rules=10,
            request_timeout_ms=500,
            admin_token="secret-admin-token",
            inspect_limit_bytes=256,
            receive_limit_bytes=16_384,
            content_check_enabled=True,
            body_timeout_ms=10_000,
            body_ingress_concurrency=4,
        )
        app = create_app(config)
        import hashlib as _h
        import threading

        outcomes: list[tuple[int, str, bool]] = []
        lock = threading.Lock()
        n_threads = 16
        barrier = threading.Barrier(n_threads)

        with TestClient(app) as client:
            def worker(i: int) -> None:
                barrier.wait()
                # 每线程发一个较大的合法 JSON（>检查上限、<接收上限）=> 422；
                # 以及一个小 JSON => 200，验证两类结论在并发下都正确。
                pad = b"q" * 500
                big = b'{"name":"big' + str(i).encode() + b'","pad":"' + pad + b'"}'
                small = ('{"name":"s%d"}' % i).encode()
                rb = client.post(
                    "/api/submit/json", content=big,
                    headers={"X-Forwarded-For": f"10.10.{i}.1",
                             "Content-Type": "application/json"},
                )
                rs = client.post(
                    "/api/submit/json", content=small,
                    headers={"X-Forwarded-For": f"10.10.{i}.2",
                             "Content-Type": "application/json"},
                )
                small_ok = (
                    rs.status_code == 200
                    and rs.json()["raw_sha256"] == _h.sha256(small).hexdigest()
                )
                with lock:
                    outcomes.append((rb.status_code, rb.json().get("error", ""), True))
                    outcomes.append((rs.status_code, "small", small_ok))

            threads = [threading.Thread(target=worker, args=(i,)) for i in range(n_threads)]
            for t in threads:
                t.start()
            for t in threads:
                t.join()

        assert len(outcomes) == 2 * n_threads
        # 不允许出现 5xx/500/408（容量足够、超时足够），只允许 200 / 422
        statuses = [o[0] for o in outcomes]
        assert set(statuses) <= {200, 422}, statuses
        # 大正文一律 422 且原因正确
        bigs = [o for o in outcomes if o[1] == "body_inspection_incomplete"]
        smalls = [o for o in outcomes if o[1] == "small"]
        assert len(bigs) == n_threads
        assert all(o[0] == 422 for o in bigs)
        assert len(smalls) == n_threads
        assert all(o[2] is True for o in smalls)  # 字节级一致全部成立

    def test_policy_switch_under_traffic_never_half_updates(self):
        config = DefenseConfig(
            rate_limit=100_000,
            window_ms=60_000,
            max_rules=10,
            request_timeout_ms=500,
            admin_token="secret-admin-token",
            inspect_limit_bytes=256,
            receive_limit_bytes=8192,
            content_check_enabled=True,
            body_timeout_ms=10_000,
            body_ingress_concurrency=8,
        )
        app = create_app(config)
        import threading

        statuses: list[int] = []
        lock = threading.Lock()
        stop = threading.Event()

        with TestClient(app) as client:
            def changer() -> None:
                i = 0
                while not stop.is_set():
                    # 在两套合法策略间整体原子切换（inspect 64 / 512）
                    insp = 64 if i % 2 == 0 else 512
                    r = client.put(
                        "/admin/content-policy",
                        headers=AUTH,
                        json={
                            "inspect_limit_bytes": insp,
                            "receive_limit_bytes": 8192,
                            "content_check_enabled": True,
                        },
                    )
                    assert r.status_code == 200
                    i += 1

            def requester() -> None:
                # 300B：inspect=64 时一定 422；inspect=512 时 200。
                # 任何时刻只可能是这两个结论之一，绝不允许 5xx。
                payload = b'{"name":"n","data":"' + b"d" * 280 + b'"}'
                for i in range(120):
                    r = client.post(
                        "/api/submit/json",
                        content=payload,
                        headers={"X-Forwarded-For": f"10.20.{i % 250}.{i % 5}",
                                 "Content-Type": "application/json"},
                    )
                    with lock:
                        statuses.append(r.status_code)

            ct = threading.Thread(target=changer)
            rt = threading.Thread(target=requester)
            ct.start(); rt.start()
            rt.join()
            stop.set(); ct.join()

        assert statuses
        assert set(statuses) <= {200, 422}, set(statuses)
        # 两套策略都应被实际观测到（证明切换生效且结论随版本整体变化）
        assert 200 in statuses and 422 in statuses
