"""Unit tests for plugin/hook.py. No network, no real herdr."""

import fcntl
import hashlib
import http.client
import json
import os
import tempfile
import time
import unittest
import unittest.mock

import hook

HOST_ID = "11111111-1111-4111-8111-111111111111"


def host_config(**overrides):
    host = {
        "socket_path": "/tmp/herdr-test.sock",
        "workspace_allowlist": [],
        "host_id": HOST_ID,
        "host_secret": "s" * 43,
        "host_expires_at": "2027-01-01T00:00:00.000Z",
    }
    host.update(overrides)
    return host


def event_json(pane_id="w9:p1", status="blocked", workspace_id="w9"):
    return json.dumps(
        {
            "event": "pane_agent_status_changed",
            "data": {
                "type": "pane_agent_status_changed",
                "pane_id": pane_id,
                "workspace_id": workspace_id,
                "agent_status": status,
                "agent": "claude",
            },
        }
    )


def ready_settings(**overrides):
    settings = {
        "enabled": True,
        "upload_state": "ready",
        "eligible_recipient_count": 1,
        "stream_id": None,
        "stream_expires_at": None,
        "settings_version": 1,
        "collection_epoch": "epoch-1",
        "collection_epoch_expires_at": "2099-01-01T00:00:00.000Z",
    }
    settings.update(overrides)
    return settings


class FakeRelay:
    # Relay と同じ。drain が retry 予算の計算で読む。
    timeout = 8

    def __init__(
        self, settings=None, handler=None, settings_status=200, service_info=None
    ):
        self.settings = settings or ready_settings()
        self.handler = handler
        self.settings_status = settings_status
        self.service_info = {"features": []} if service_info is None else service_info
        self.posts = []
        self.gets = []

    def url(self, path):
        return "https://relay.test" + path

    def get(self, path, timeout=None):
        self.gets.append(path)
        if path == "/v1/source-settings":
            return self.settings_status, dict(self.settings)
        if path == "/v1/service-info":
            return 200, dict(self.service_info)
        return 200, {}

    def post(self, path, body, idempotency_key=None, timeout=None):
        call = {"path": path, "body": body, "key": idempotency_key}
        self.posts.append(call)
        if self.handler:
            result = self.handler(call, len(self.posts))
            if result is not None:
                return result
        if path == "/v1/streams":
            return 201, {
                "stream_id": "stream-1",
                "last_sequence": 0,
                "expires_at": "2099-01-01T00:00:00.000Z",
            }
        if path == "/v1/events":
            return 202, {}
        return 200, {}

    def paths(self):
        return [post["path"] for post in self.posts]

    def events(self):
        return [post for post in self.posts if post["path"] == "/v1/events"]


class HookTestCase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.state_dir = os.path.join(self.tmp.name, "state")
        self.host_dir = os.path.join(self.state_dir, HOST_ID)
        self.logs = []
        self.clock = [1000.0]
        self.monotonic_clock = [1000.0]

    def make_hook(
        self, relay, blocked=None, pane=None, content_key=None, fetch_content=None,
        **host_overrides
    ):
        extra = {}
        if content_key is not None:
            extra["content_key"] = content_key
        if fetch_content is not None:
            extra["fetch_content"] = fetch_content
        return hook.Hook(
            host_config(**host_overrides),
            self.state_dir,
            relay,
            blocked or (lambda timeout: []),
            pane or (lambda pane_id, timeout: (True, {"terminal_id": "term-1"})),
            now=lambda: self.clock[0],
            sleep=lambda seconds: None,
            log_line=self.logs.append,
            monotonic=lambda: self.monotonic_clock[0],
            **extra
        )

    def with_features(self, hook_obj, features, version=None):
        state = hook_obj.load()
        state["features"] = list(features)
        state["features_version"] = version or hook.PLUGIN_VERSION
        hook_obj.save(state)


class FingerprintTests(unittest.TestCase):
    def test_matches_contract_formula(self):
        expected = hashlib.sha256(
            ("herdsight-pane-v1\x00" + HOST_ID + "\x00term_abc").encode("utf-8")
        ).hexdigest()
        self.assertEqual(hook.pane_fingerprint(HOST_ID, "term_abc"), expected)
        self.assertEqual(len(expected), 64)


class RelayHeaderTests(unittest.TestCase):
    class Response:
        status = 201

        def read(self):
            return b"{}"

        def close(self):
            pass

    def test_post_sends_auth_dev_access_and_generated_key(self):
        seen = []

        def opener(req, timeout=None):
            seen.append((req.method, {k.lower(): v for k, v in req.headers.items()}))
            return self.Response()

        relay = hook.Relay(
            "https://relay.test",
            {"host_id": "host-id", "host_secret": "secret"},
            "dev-access",
            opener=opener,
        )
        relay.post("/v1/streams", {})
        method, headers = seen[0]
        self.assertEqual(method, "POST")
        self.assertEqual(headers["authorization"], "Bearer host.host-id.secret")
        self.assertEqual(headers["x-relay-dev-access"], "dev-access")
        self.assertTrue(headers["idempotency-key"])

    def test_explicit_key_is_preserved_for_retries(self):
        seen = []

        def opener(req, timeout=None):
            seen.append({k.lower(): v for k, v in req.headers.items()})
            return self.Response()

        relay = hook.Relay(
            "https://relay.test", {"host_id": "h", "host_secret": "s"}, opener=opener
        )
        relay.post("/v1/events", {}, "fixed-key")
        self.assertEqual(seen[0]["idempotency-key"], "fixed-key")
        self.assertNotIn("x-relay-dev-access", seen[0])

    def test_incomplete_response_read_is_a_transport_failure(self):
        class IncompleteResponse(self.Response):
            def read(self):
                raise http.client.IncompleteRead(b"partial")

        relay = hook.Relay(
            "https://relay.test",
            {"host_id": "h", "host_secret": "s"},
            opener=lambda req, timeout=None: IncompleteResponse(),
        )

        self.assertEqual(relay.get("/v1/service-info"), (None, None))
        self.assertEqual(relay.last_transport_error, "IncompleteRead")


class StartupTests(HookTestCase):
    def test_fresh_baseline_skips_malformed_panes_and_non_string_terminal_ids(self):
        relay = FakeRelay()
        blocked = [
            None,
            {"pane_id": "w9:p0", "workspace_id": "w9", "terminal_id": 42},
            {"pane_id": "w9:p1", "workspace_id": "w9", "terminal_id": "term-1"},
        ]
        hook_obj = self.make_hook(relay, blocked=lambda timeout: blocked)

        self.assertEqual(hook_obj.run_startup(), 0)

        baseline = relay.posts[0]["body"]["baseline"]
        self.assertEqual([entry["pane_id"] for entry in baseline], ["w9:p0", "w9:p1"])
        self.assertIsNone(baseline[0]["pane_fingerprint"])
        self.assertEqual(
            baseline[1]["pane_fingerprint"], hook.pane_fingerprint(HOST_ID, "term-1")
        )

    def test_ready_posts_blocked_baseline_only(self):
        relay = FakeRelay()
        blocked = [
            {"pane_id": "w9:p1", "workspace_id": "w9", "terminal_id": "term-1"},
            {"pane_id": "w9:p2", "workspace_id": "w9", "terminal_id": "term-2"},
        ]
        hook_obj = self.make_hook(relay, blocked=lambda timeout: blocked)
        self.assertEqual(hook_obj.run_startup(), 0)

        streams = [post for post in relay.posts if post["path"] == "/v1/streams"]
        self.assertEqual(len(streams), 1)
        baseline = streams[0]["body"]["baseline"]
        self.assertEqual([entry["pane_id"] for entry in baseline], ["w9:p1", "w9:p2"])
        self.assertEqual(streams[0]["body"]["expected_stream_id"], None)
        self.assertEqual(streams[0]["body"]["expected_collection_epoch"], "epoch-1")
        self.assertFalse(relay.events())

        state_path = os.path.join(self.host_dir, "state.json")
        self.assertEqual(os.stat(state_path).st_mode & 0o777, 0o600)
        with open(state_path, encoding="utf-8") as handle:
            state = json.load(handle)
        self.assertEqual(state["stream_id"], "stream-1")
        self.assertEqual(state["panes"]["w9:p1"]["last_state"], "blocked")
        self.assertEqual(
            state["panes"]["w9:p1"]["pane_fingerprint"],
            hook.pane_fingerprint(HOST_ID, "term-1"),
        )
        lock_path = os.path.join(self.host_dir, "state.lock")
        self.assertEqual(os.stat(lock_path).st_mode & 0o777, 0o600)

    def test_workspace_allowlist_filters_baseline(self):
        relay = FakeRelay()
        blocked = [
            {"pane_id": "w9:p1", "workspace_id": "w9", "terminal_id": "t1"},
            {"pane_id": "w10:p1", "workspace_id": "w10", "terminal_id": "t2"},
        ]
        hook_obj = self.make_hook(
            relay, blocked=lambda timeout: blocked, workspace_allowlist=["w9"]
        )
        hook_obj.run_startup()
        baseline = relay.posts[0]["body"]["baseline"]
        self.assertEqual([entry["pane_id"] for entry in baseline], ["w9:p1"])

    def test_not_ready_sends_nothing(self):
        relay = FakeRelay(settings=ready_settings(upload_state="no_links"))
        hook_obj = self.make_hook(relay)
        state = hook_obj.load()
        hook_obj.enqueue(state, "w9:p1", "blocked", "generation-1", "fingerprint-1")
        hook_obj.save(state)
        self.assertEqual(hook_obj.run_startup(), 0)
        self.assertFalse(relay.posts)
        with open(os.path.join(self.host_dir, "state.json"), encoding="utf-8") as handle:
            state = json.load(handle)
        self.assertTrue(state["suspended"])
        self.assertFalse(state["pending"])

    def test_startup_network_failure_does_not_suspend(self):
        relay = FakeRelay()
        relay.get = lambda path, timeout=None: (None, None)  # Relay._send の OSError 相当
        hook_obj = self.make_hook(relay)
        self.assertEqual(hook_obj.run_startup(), 0)
        with open(os.path.join(self.host_dir, "state.json"), encoding="utf-8") as handle:
            state = json.load(handle)
        self.assertFalse(state["suspended"])
        self.assertIsNone(state["settings_checked_at"])

    def test_agent_list_failure_sends_nothing(self):
        def boom(timeout):
            raise hook.HerdrError("no server")

        relay = FakeRelay()
        hook_obj = self.make_hook(relay, blocked=boom)
        self.assertEqual(hook_obj.run_startup(), 0)
        self.assertFalse(relay.posts)

    def test_startup_rebuilds_baseline_even_with_valid_stream(self):
        relay = FakeRelay()
        hook_obj = self.make_hook(relay)
        state = hook_obj.load()
        state["stream_id"] = "old-stream"
        state["stream_expires_at"] = "2099-01-01T00:00:00.000Z"
        hook_obj.save(state)
        hook_obj.run_startup()
        self.assertIn("/v1/streams", relay.paths())

    def test_startup_discards_stale_blocked_pending_when_pane_is_idle(self):
        relay = FakeRelay()
        hook_obj = self.make_hook(relay, blocked=lambda timeout: [])
        state = hook_obj.load()
        hook_obj.enqueue(state, "w9:p1", "blocked", "generation-1", "fingerprint-1")
        state["panes"]["w9:p1"] = {
            "pane_generation": "generation-1",
            "pane_fingerprint": "fingerprint-1",
            "last_state": "blocked",
        }
        hook_obj.save(state)

        hook_obj.run_startup()
        hook_obj.run_event(event_json(pane_id="w9:p1", status="idle"))

        baseline = [post for post in relay.posts if post["path"] == "/v1/streams"][-1]["body"]["baseline"]
        self.assertFalse(baseline)
        self.assertFalse(relay.events())
        self.assertFalse(hook_obj.load()["pending"])

    def test_startup_baselines_current_blocked_pane_without_sending_pending(self):
        relay = FakeRelay()
        current = {"pane_id": "w9:p1", "workspace_id": "w9", "terminal_id": "term-1"}
        hook_obj = self.make_hook(relay, blocked=lambda timeout: [current])
        state = hook_obj.load()
        hook_obj.enqueue(state, "w9:p1", "blocked", "generation-1", "fingerprint-1")
        hook_obj.save(state)

        hook_obj.run_startup()

        baseline = relay.posts[-1]["body"]["baseline"]
        self.assertEqual([entry["pane_id"] for entry in baseline], ["w9:p1"])
        self.assertFalse(relay.events())
        self.assertFalse(hook_obj.load()["pending"])


class EventMappingTests(HookTestCase):
    def test_blocked_transition_posts_one_event(self):
        relay = FakeRelay()
        hook_obj = self.make_hook(relay)
        hook_obj.run_event(event_json())

        events = relay.events()
        self.assertEqual(len(events), 1)
        body = events[0]["body"]
        self.assertEqual(body["state"], "blocked")
        self.assertEqual(body["sequence"], 1)
        self.assertEqual(
            body["pane_fingerprint"], hook.pane_fingerprint(HOST_ID, "term-1")
        )
        self.assertTrue(events[0]["key"])

    def test_blocked_to_blocked_is_not_sent_twice(self):
        relay = FakeRelay()
        hook_obj = self.make_hook(relay)
        hook_obj.run_event(event_json())
        hook_obj.run_event(event_json())
        self.assertEqual(len(relay.events()), 1)

    def test_clear_only_after_blocked(self):
        relay = FakeRelay()
        hook_obj = self.make_hook(relay)
        hook_obj.run_event(event_json(status="idle"))
        self.assertFalse(relay.events())

        hook_obj.run_event(event_json(status="blocked"))
        hook_obj.run_event(event_json(status="idle"))
        states = [event["body"]["state"] for event in relay.events()]
        self.assertEqual(states, ["blocked", "clear"])

        hook_obj.run_event(event_json(status="idle"))
        self.assertEqual(len(relay.events()), 2)

    def test_non_blocked_without_prior_blocked_sends_nothing(self):
        relay = FakeRelay()
        hook_obj = self.make_hook(relay)
        for status in ("idle", "working", "done", "unknown"):
            hook_obj.run_event(event_json(status=status))
        self.assertFalse(relay.posts)

    def test_unknown_status_and_bad_json_are_ignored(self):
        relay = FakeRelay()
        hook_obj = self.make_hook(relay)
        hook_obj.run_event(event_json(status="sleeping"))
        hook_obj.run_event("not json")
        hook_obj.run_event(json.dumps({"data": {"agent_status": "blocked"}}))
        self.assertFalse(relay.posts)

    def test_workspace_allowlist_filters_events(self):
        relay = FakeRelay()
        hook_obj = self.make_hook(relay, workspace_allowlist=["w9"])
        hook_obj.run_event(event_json(pane_id="w10:p1", workspace_id="w10"))
        self.assertFalse(relay.posts)

    def test_pane_get_failure_skips_event(self):
        relay = FakeRelay()
        hook_obj = self.make_hook(relay, pane=lambda pane_id, timeout: (False, None))
        hook_obj.run_event(event_json())
        self.assertFalse(relay.posts)

    def test_missing_terminal_id_still_sends_null_fingerprint(self):
        relay = FakeRelay()
        hook_obj = self.make_hook(relay, pane=lambda pane_id, timeout: (True, {}))
        hook_obj.run_event(event_json())
        events = relay.events()
        self.assertEqual(len(events), 1)
        self.assertIsNone(events[0]["body"]["pane_fingerprint"])

    def test_non_string_terminal_id_still_sends_null_fingerprint(self):
        relay = FakeRelay()
        hook_obj = self.make_hook(
            relay, pane=lambda pane_id, timeout: (True, {"terminal_id": 123})
        )

        hook_obj.run_event(event_json())

        events = relay.events()
        self.assertEqual(len(events), 1)
        self.assertIsNone(events[0]["body"]["pane_fingerprint"])

    def test_first_blocked_excludes_itself_from_baseline(self):
        relay = FakeRelay()
        other = {"pane_id": "w9:p9", "workspace_id": "w9", "terminal_id": "term-9"}
        hook_obj = self.make_hook(relay, blocked=lambda timeout: [other])
        hook_obj.run_event(event_json(pane_id="w9:p1"))
        streams = [post for post in relay.posts if post["path"] == "/v1/streams"]
        self.assertEqual(len(streams), 1)
        self.assertEqual(
            [entry["pane_id"] for entry in streams[0]["body"]["baseline"]], ["w9:p9"]
        )
        self.assertEqual(len(relay.events()), 1)

    def test_recreated_stream_sends_current_stream_id(self):
        stream_id = "11111111-1111-4111-8111-111111111111"
        relay = FakeRelay(settings=ready_settings(stream_id=stream_id))
        hook_obj = self.make_hook(relay)
        hook_obj.run_event(event_json())
        streams = [post for post in relay.posts if post["path"] == "/v1/streams"]
        self.assertEqual(streams[0]["body"]["expected_stream_id"], stream_id)

    def test_suspended_recovery_excludes_current_pane_from_baseline(self):
        relay = FakeRelay()
        current = {"pane_id": "w9:p1", "workspace_id": "w9", "terminal_id": "term-1"}
        hook_obj = self.make_hook(relay, blocked=lambda timeout: [current])
        state = hook_obj.load()
        state["suspended"] = True
        state["settings_checked_at"] = "1970-01-01T00:00:00.000Z"
        hook_obj.save(state)

        hook_obj.run_event(event_json(pane_id="w9:p1"))

        streams = [post for post in relay.posts if post["path"] == "/v1/streams"]
        self.assertEqual(streams[-1]["body"]["baseline"], [])
        self.assertEqual(len(relay.events()), 1)

    def test_suspended_event_network_failure_does_not_update_check_time(self):
        relay = FakeRelay()
        hook_obj = self.make_hook(relay)
        state = hook_obj.load()
        state["suspended"] = True
        state["settings_checked_at"] = "1970-01-01T00:00:00.000Z"
        hook_obj.save(state)
        relay.get = lambda path, timeout=None: (None, None)  # Relay._send の OSError 相当

        hook_obj.run_event(event_json())

        self.assertFalse(relay.posts)
        state = hook_obj.load()
        self.assertTrue(state["suspended"])
        # 通信の失敗では checked_at を更新しない。次のイベントで settings を読み直す。
        self.assertEqual(state["settings_checked_at"], "1970-01-01T00:00:00.000Z")

        # upload_state が ready でない枝は従来どおり: 停止のまま checked_at を更新する。
        self.clock[0] += 16 * 60
        relay.get = lambda path, timeout=None: (
            200,
            dict(ready_settings(upload_state="no_links")),
        )
        hook_obj.run_event(event_json(status="idle"))
        state = hook_obj.load()
        self.assertTrue(state["suspended"])
        self.assertNotEqual(state["settings_checked_at"], "1970-01-01T00:00:00.000Z")

    def test_state_is_kept_per_host(self):
        relay = FakeRelay()
        hook_a = self.make_hook(relay)
        hook_a.run_event(event_json(pane_id="w9:p1"))
        hook_b = self.make_hook(
            relay, host_id="33333333-3333-4333-8333-333333333333"
        )
        hook_b.run_event(event_json(pane_id="w9:p2", status="idle"))
        self.assertIn("w9:p1", hook_a.load()["panes"])
        self.assertNotIn("w9:p1", hook_b.load()["panes"])

    def test_blocked_event_is_not_lost_when_pending_exists(self):
        relay = FakeRelay()
        current = {"pane_id": "w9:p1", "workspace_id": "w9", "terminal_id": "term-1"}
        hook_obj = self.make_hook(relay, blocked=lambda timeout: [current])
        state = hook_obj.load()
        hook_obj.enqueue(state, "w9:p2", "blocked", "generation-2", None)
        hook_obj.save(state)

        hook_obj.run_event(event_json(pane_id="w9:p1"))

        self.assertEqual(
            [event["body"]["pane_id"] for event in relay.events()], ["w9:p2", "w9:p1"]
        )


class PendingTests(HookTestCase):
    def test_pending_is_capped_at_sixteen(self):
        relay = FakeRelay()
        hook_obj = self.make_hook(relay)
        state = hook_obj.load()
        for index in range(20):
            hook_obj.enqueue(
                state, "w9:p%d" % index, "blocked", "generation", "fingerprint"
            )
        self.assertEqual(len(state["pending"]), hook.PENDING_MAX)
        self.assertEqual(state["pending"][0]["pane_id"], "w9:p4")

    def test_rate_limited_event_is_retried_with_same_key(self):
        attempts = {"events": 0}

        def handler(call, _count):
            if call["path"] == "/v1/events":
                attempts["events"] += 1
                if attempts["events"] == 1:
                    return 429, {"error": {"code": "rate_limited", "retry_after_seconds": 0}}
            return None

        relay = FakeRelay(handler=handler)
        hook_obj = self.make_hook(relay)
        hook_obj.run_event(event_json())

        events = relay.events()
        self.assertEqual(len(events), 2)
        self.assertEqual(events[0]["key"], events[1]["key"])
        self.assertEqual(events[0]["body"]["sequence"], 1)
        self.assertEqual(events[1]["body"]["sequence"], 1)
        state = hook_obj.load()
        self.assertEqual(state["sequence"], 1)
        self.assertFalse(state["pending"])

    def test_retry_budget_exhaustion_keeps_pending_without_resending(self):
        sleeps = []

        def handler(call, _count):
            if call["path"] == "/v1/events":
                return 429, {"error": {"code": "rate_limited", "retry_after_seconds": 44}}
            return None

        relay = FakeRelay(handler=handler)
        hook_obj = self.make_hook(relay)
        hook_obj.sleep = sleeps.append
        hook_obj.run_event(event_json())

        # 待ち時間と再試行の要求が 45 秒の予算に入らない。pending に残して次の hook へ。
        self.assertEqual(len(relay.events()), 1)
        self.assertFalse(sleeps)
        state = hook_obj.load()
        self.assertEqual(len(state["pending"]), 1)
        self.assertEqual(state["pending"][0]["idempotency_key"], relay.events()[0]["key"])

    def test_negative_retry_after_is_clamped_before_sleep(self):
        attempts = {"events": 0}

        def handler(call, _count):
            if call["path"] == "/v1/events":
                attempts["events"] += 1
                if attempts["events"] == 1:
                    return 429, {"error": {"retry_after_seconds": -2}}
            return None

        relay = FakeRelay(handler=handler)
        hook_obj = self.make_hook(relay)
        sleeps = []
        hook_obj.sleep = sleeps.append

        hook_obj.run_event(event_json())

        self.assertEqual(len(relay.events()), 2)
        self.assertEqual(len(sleeps), 1)
        self.assertGreaterEqual(sleeps[0], 0)

    def test_sequence_gap_resyncs_with_fresh_baseline(self):
        relay = FakeRelay()
        hook_obj = self.make_hook(relay)
        hook_obj.run_event(event_json(pane_id="w9:p1"))
        self.assertEqual(len(relay.events()), 1)

        def handler(call, _count):
            if call["path"] == "/v1/events":
                return 409, {"error": {"code": "sequence_gap", "expected_sequence": 5}}
            return None

        relay.handler = handler
        hook_obj.run_event(event_json(pane_id="w9:p2"))

        streams = [post for post in relay.posts if post["path"] == "/v1/streams"]
        self.assertEqual(len(streams), 2)
        self.assertIsNone(streams[-1]["body"]["expected_stream_id"])
        state = hook_obj.load()
        self.assertFalse(state["pending"])
        self.assertEqual(state["sequence"], 0)

    def test_invalid_event_resyncs_then_sends_remaining_pending_in_same_hook(self):
        attempts = {"events": 0}

        def handler(call, _count):
            if call["path"] == "/v1/events":
                attempts["events"] += 1
                if attempts["events"] == 1:
                    return 400, {"error": {"code": "invalid_request"}}
            return None

        relay = FakeRelay(handler=handler)
        hook_obj = self.make_hook(relay)
        state = hook_obj.load()
        hook_obj.enqueue(state, "w9:p1", "blocked", "generation-1", None)
        hook_obj.enqueue(state, "w9:p2", "blocked", "generation-2", None)
        hook_obj.save(state)

        hook_obj.run_event(event_json(pane_id="w9:p3"))

        events = relay.events()
        self.assertEqual(
            [event["body"]["pane_id"] for event in events], ["w9:p1", "w9:p2", "w9:p3"]
        )
        self.assertEqual([event["body"]["sequence"] for event in events], [1, 1, 2])
        self.assertFalse(hook_obj.load()["pending"])

    def test_resync_baseline_includes_blocked_panes_when_pending_is_dropped(self):
        def handler(call, _count):
            if call["path"] == "/v1/events":
                return 409, {"error": {"code": "sequence_gap"}}
            return None

        relay = FakeRelay(handler=handler)
        current = {"pane_id": "w9:p1", "workspace_id": "w9", "terminal_id": "term-1"}
        hook_obj = self.make_hook(relay, blocked=lambda timeout: [current])

        hook_obj.run_event(event_json(pane_id="w9:p1"))

        streams = [post for post in relay.posts if post["path"] == "/v1/streams"]
        self.assertEqual(len(streams), 2)
        self.assertEqual(
            [entry["pane_id"] for entry in streams[-1]["body"]["baseline"]],
            ["w9:p1"],
        )
        self.assertFalse(hook_obj.load()["pending"])

    def test_expired_clear_rebuilds_baseline_before_next_block(self):
        relay = FakeRelay()
        hook_obj = self.make_hook(relay, blocked=lambda timeout: [])
        state = hook_obj.load()
        state["stream_id"] = "old-stream"
        state["stream_expires_at"] = "2099-01-01T00:00:00.000Z"
        state["panes"]["w9:p1"] = {
            "pane_generation": "generation-1",
            "pane_fingerprint": "fingerprint-1",
            "last_state": "blocked",
        }
        hook_obj.enqueue(state, "w9:p1", "clear", "generation-1", "fingerprint-1")
        state["pending"][0]["expires_at"] = hook.iso_utc(self.clock[0] - 1)

        self.assertEqual(hook_obj.drain(state), "ok")
        self.assertFalse(relay.events())
        self.assertNotIn("w9:p1", state["panes"])

        hook_obj.map_event(state, "w9:p1", "blocked")
        self.assertEqual(hook_obj.drain(state), "ok")
        self.assertEqual([event["body"]["state"] for event in relay.events()], ["blocked"])

    def test_suspended_resume_drops_clear_for_pane_absent_from_baseline(self):
        def handler(call, _count):
            if call["path"] == "/v1/events":
                return 400, {"error": {"code": "invalid_request"}}
            return None

        relay = FakeRelay(handler=handler)
        hook_obj = self.make_hook(relay, blocked=lambda timeout: [])
        state = hook_obj.load()
        state["suspended"] = True
        state["settings_checked_at"] = "1970-01-01T00:00:00.000Z"
        state["panes"]["w9:p1"] = {
            "pane_generation": "generation-1",
            "pane_fingerprint": "fingerprint-1",
            "last_state": "blocked",
        }
        hook_obj.save(state)

        hook_obj.run_event(event_json(pane_id="w9:p1", status="idle"))

        self.assertFalse(relay.events())
        self.assertEqual(len([post for post in relay.posts if post["path"] == "/v1/streams"]), 1)
        self.assertFalse(hook_obj.load()["pending"])

    def test_source_settings_rejection_stops_event_retry_and_keeps_pending(self):
        relay = FakeRelay(settings_status=401)
        hook_obj = self.make_hook(relay)

        hook_obj.run_event(event_json())

        self.assertEqual(relay.gets, ["/v1/service-info", "/v1/source-settings"])
        self.assertFalse(relay.posts)
        self.assertEqual(len(hook_obj.load()["pending"]), 1)
        self.assertTrue(any("credential rejected" in line for line in self.logs))

    def test_nonready_settings_are_checked_only_once_per_event(self):
        relay = FakeRelay(settings=ready_settings(upload_state="no_links"))
        hook_obj = self.make_hook(relay)

        hook_obj.run_event(event_json())

        self.assertEqual(relay.gets, ["/v1/service-info", "/v1/source-settings"])
        self.assertEqual(len(hook_obj.load()["pending"]), 1)

    def test_upload_suspended_drops_pending_and_stops(self):
        def handler(call, _count):
            if call["path"] == "/v1/events":
                return 409, {"error": {"code": "upload_suspended"}}
            return None

        relay = FakeRelay(handler=handler)
        hook_obj = self.make_hook(relay)
        hook_obj.run_event(event_json())

        state = hook_obj.load()
        self.assertTrue(state["suspended"])
        self.assertFalse(state["pending"])

        # While suspended, the settings check is throttled to 15 minutes.
        relay.gets.clear()
        hook_obj.run_event(event_json(status="idle"))
        self.assertFalse(relay.gets)

    def test_invalid_request_drops_event_and_resyncs(self):
        def handler(call, _count):
            if call["path"] == "/v1/events":
                return 400, {"error": {"code": "invalid_request"}}
            return None

        relay = FakeRelay(handler=handler)
        hook_obj = self.make_hook(relay)
        hook_obj.run_event(event_json())

        state = hook_obj.load()
        self.assertFalse(state["pending"])
        self.assertEqual(
            len([post for post in relay.posts if post["path"] == "/v1/streams"]), 2
        )

    def test_expired_pending_is_dropped(self):
        relay = FakeRelay()
        hook_obj = self.make_hook(relay)
        state = hook_obj.load()
        state["pending"].append(
            {
                "event_id": "e",
                "idempotency_key": "k",
                "pane_id": "w9:p1",
                "state": "blocked",
                "observed_at": "1970-01-01T00:00:00.000Z",
                "expires_at": "1970-01-01T00:00:01.000Z",
                "pane_generation": "g",
                "pane_fingerprint": None,
            }
        )
        hook_obj.save(state)
        hook_obj.run_event(event_json(status="idle"))
        state = hook_obj.load()
        self.assertFalse(state["pending"])
        self.assertFalse(relay.events())


CONTENT_KEY = bytes(range(32))
CONTENT = {
    "agent": "claude",
    "workspace": "herdsight",
    "tab": "main",
    "title": "Fix the login flow",
    "prompt": "テストを直してよいですか？",
}


class ContentSealTests(HookTestCase):
    def test_blocked_event_is_sealed_only_when_the_relay_advertises_it(self):
        relay = FakeRelay()
        fetched = []

        def fetch(pane_id, kind, remaining, pane):
            fetched.append(pane_id)
            return dict(CONTENT)

        hook_obj = self.make_hook(
            relay, content_key=CONTENT_KEY, fetch_content=fetch
        )
        hook_obj.run_event(event_json())
        self.assertNotIn("sealed", relay.events()[0]["body"])
        self.assertEqual(fetched, [])

        self.with_features(hook_obj, ["sealed"])
        hook_obj.run_event(event_json(pane_id="w9:p2"))

        self.assertTrue(relay.events()[-1]["body"]["sealed"])
        self.assertEqual(fetched, ["w9:p2"])
        # 平文が stderr やログに出ない。
        self.assertFalse(
            any("claude" in line or "Fix the login flow" in line for line in self.logs)
        )

    def test_sealed_is_made_once_and_reused_on_retry(self):
        attempts = {"events": 0}

        def handler(call, _count):
            if call["path"] == "/v1/events":
                attempts["events"] += 1
                if attempts["events"] == 1:
                    return 429, {"error": {"retry_after_seconds": 0}}
            return None

        fetched = []
        relay = FakeRelay(handler=handler)
        hook_obj = self.make_hook(
            relay,
            content_key=CONTENT_KEY,
            fetch_content=lambda pane_id, kind, remaining, pane: fetched.append(pane_id)
            or dict(CONTENT),
        )
        self.with_features(hook_obj, ["sealed"])
        hook_obj.run_event(event_json())

        events = relay.events()
        self.assertEqual(len(events), 2)
        self.assertEqual(events[0]["body"]["sealed"], events[1]["body"]["sealed"])
        self.assertEqual(fetched, ["w9:p1"])

    def test_all_null_content_still_gets_a_seal(self):
        relay = FakeRelay()
        hook_obj = self.make_hook(
            relay,
            content_key=CONTENT_KEY,
            fetch_content=lambda pane_id, kind, remaining, pane: {
                "agent": None,
                "workspace": None,
                "tab": None,
                "title": None,
                "prompt": None,
            },
        )
        self.with_features(hook_obj, ["sealed"])
        hook_obj.run_event(event_json())
        self.assertTrue(relay.events()[0]["body"]["sealed"])

    def test_a_fetch_exception_skips_the_seal_without_dropping_the_event(self):
        def fetch(_pane_id, _kind, _remaining, _pane):
            raise OSError("herdr is gone")

        relay = FakeRelay()
        hook_obj = self.make_hook(relay, content_key=CONTENT_KEY, fetch_content=fetch)
        self.with_features(hook_obj, ["sealed"])
        hook_obj.run_event(event_json())
        self.assertEqual(len(relay.events()), 1)
        self.assertNotIn("sealed", relay.events()[0]["body"])

    def test_no_seal_without_the_content_key(self):
        relay = FakeRelay()
        fetched = []
        hook_obj = self.make_hook(
            relay, fetch_content=lambda pane_id, kind, remaining, pane: fetched.append(pane_id)
            or dict(CONTENT)
        )
        self.with_features(hook_obj, ["sealed"])
        hook_obj.run_event(event_json())
        self.assertNotIn("sealed", relay.events()[0]["body"])
        self.assertEqual(fetched, [])

    def test_unresolved_terminal_has_no_seal(self):
        relay = FakeRelay()
        fetched = []
        hook_obj = self.make_hook(
            relay,
            content_key=CONTENT_KEY,
            fetch_content=lambda pane_id, kind, remaining, pane: fetched.append(pane_id)
            or dict(CONTENT),
        )
        self.with_features(hook_obj, ["sealed"])
        state = hook_obj.load()
        hook_obj.map_event(state, "w9:p1", "blocked", resolve_terminal=False)
        hook_obj.drain(state)
        self.assertNotIn("sealed", relay.events()[0]["body"])
        self.assertEqual(fetched, [])

    def test_pending_finished_event_survives_a_reload(self):
        relay = FakeRelay()
        hook_obj = self.make_hook(relay)
        state = hook_obj.load()
        hook_obj.enqueue(state, "w9:p1", "finished", "generation-1", None, "sealed-1")
        hook_obj.save(state)
        reloaded = hook_obj.load()
        self.assertEqual(reloaded["pending"][0]["state"], "finished")
        self.assertEqual(reloaded["pending"][0]["sealed"], "sealed-1")


class FinishedTests(HookTestCase):
    def test_done_after_blocked_sends_clear_then_finished(self):
        relay = FakeRelay()
        hook_obj = self.make_hook(relay)
        self.with_features(hook_obj, ["finished"])
        hook_obj.run_event(event_json(status="blocked"))
        hook_obj.run_event(event_json(status="done"))

        self.assertEqual(
            [event["body"]["state"] for event in relay.events()],
            ["blocked", "clear", "finished"],
        )
        self.assertEqual(hook_obj.load()["panes"]["w9:p1"]["last_state"], "clear")

    def test_done_for_an_unregistered_pane_sends_finished_only(self):
        relay = FakeRelay()
        hook_obj = self.make_hook(relay)
        self.with_features(hook_obj, ["finished"])
        hook_obj.run_event(event_json(status="done"))

        self.assertEqual(
            [event["body"]["state"] for event in relay.events()], ["finished"]
        )
        self.assertNotIn("w9:p1", hook_obj.load()["panes"])

    def test_done_without_the_finished_feature_sends_nothing(self):
        relay = FakeRelay()
        hook_obj = self.make_hook(relay)
        hook_obj.run_event(event_json(status="done"))
        self.assertFalse(relay.posts)

    def test_done_after_blocked_without_the_feature_sends_only_clear(self):
        relay = FakeRelay()
        hook_obj = self.make_hook(relay)
        hook_obj.run_event(event_json(status="blocked"))
        hook_obj.run_event(event_json(status="done"))
        self.assertEqual(
            [event["body"]["state"] for event in relay.events()],
            ["blocked", "clear"],
        )

    def test_finished_is_sealed_with_the_finished_kind_and_a_null_prompt(self):
        captured = {}

        def fake_seal(key, kind, plaintext):
            captured["kind"] = kind
            captured["plaintext"] = plaintext
            return "sealed"

        relay = FakeRelay()
        fetched = []
        hook_obj = self.make_hook(
            relay,
            content_key=CONTENT_KEY,
            fetch_content=lambda pane_id, kind, remaining, pane: fetched.append(pane_id)
            or dict(CONTENT),
        )
        self.with_features(hook_obj, ["sealed", "finished"])
        with unittest.mock.patch("hook.seal_content", side_effect=fake_seal):
            hook_obj.run_event(event_json(status="done"))

        self.assertEqual(captured["kind"], "finished")
        self.assertIsNone(json.loads(captured["plaintext"])["prompt"])
        self.assertTrue(relay.events()[0]["body"]["sealed"])
        self.assertEqual(fetched, ["w9:p1"])


class FeatureDegradeTests(HookTestCase):
    def test_sealed_400_is_resent_without_sealed_and_without_a_new_stream(self):
        bodies = []

        def handler(call, _count):
            if call["path"] == "/v1/events":
                bodies.append(call)
                if len(bodies) == 1:
                    return 400, {"error": {"code": "invalid_request"}}
            return None

        relay = FakeRelay(handler=handler)
        hook_obj = self.make_hook(relay, content_key=CONTENT_KEY,
                                  fetch_content=lambda pane_id, kind, remaining, pane: dict(CONTENT))
        self.with_features(hook_obj, ["sealed"])
        hook_obj.run_event(event_json())

        self.assertEqual(len(bodies), 2)
        self.assertIn("sealed", bodies[0]["body"])
        self.assertNotIn("sealed", bodies[1]["body"])
        self.assertEqual(bodies[0]["body"]["event_id"], bodies[1]["body"]["event_id"])
        self.assertEqual(bodies[0]["body"]["sequence"], bodies[1]["body"]["sequence"])
        self.assertNotEqual(bodies[0]["key"], bodies[1]["key"])
        self.assertEqual(
            len([post for post in relay.posts if post["path"] == "/v1/streams"]), 1
        )
        self.assertEqual(hook_obj.load()["features"], [])
        self.assertFalse(hook_obj.load()["pending"])

    def test_finished_400_is_dropped_without_rebuilding_the_stream(self):
        relay = FakeRelay(handler=lambda call, _count:
                          (400, {"error": {"code": "invalid_request"}})
                          if call["path"] == "/v1/events" else None)
        hook_obj = self.make_hook(relay)
        self.with_features(hook_obj, ["finished"])
        hook_obj.run_event(event_json(status="done"))

        self.assertEqual(len(relay.events()), 1)
        self.assertEqual(
            len([post for post in relay.posts if post["path"] == "/v1/streams"]), 1
        )
        self.assertFalse(hook_obj.load()["pending"])
        self.assertEqual(hook_obj.load()["features"], [])

    def test_startup_saves_advertised_features(self):
        relay = FakeRelay(service_info={"features": ["sealed", "finished"]})
        hook_obj = self.make_hook(relay)
        hook_obj.run_startup()
        state = hook_obj.load()
        self.assertEqual(state["features"], ["sealed", "finished"])
        self.assertEqual(state["features_version"], hook.PLUGIN_VERSION)

    def test_startup_keeps_known_features_when_service_info_fails(self):
        relay = FakeRelay()
        hook_obj = self.make_hook(relay)
        self.with_features(hook_obj, ["sealed"])
        original = relay.get

        def get(path, timeout=None):
            if path == "/v1/service-info":
                return None, None
            return original(path)

        relay.get = get
        hook_obj.run_startup()
        self.assertEqual(hook_obj.load()["features"], ["sealed"])


class BudgetTests(HookTestCase):
    def test_no_content_or_fingerprint_when_the_budget_is_gone(self):
        relay = FakeRelay()
        pane_calls, fetch_calls = [], []
        hook_obj = self.make_hook(
            relay,
            pane=lambda pane_id, timeout: pane_calls.append(pane_id)
            or (True, {"terminal_id": "term-1"}),
            content_key=CONTENT_KEY,
            fetch_content=lambda pane_id, kind, remaining, pane: fetch_calls.append(
                pane_id
            )
            or dict(CONTENT),
        )
        self.with_features(hook_obj, ["sealed"])
        hook_obj.deadline = self.monotonic_clock[0]
        hook_obj.run_event(event_json())

        self.assertFalse(pane_calls)
        self.assertFalse(fetch_calls)
        self.assertFalse(relay.events())
        event = hook_obj.load()["pending"][0]
        self.assertNotIn("sealed", event)
        self.assertIsNone(event["pane_fingerprint"])

    def test_content_budget_is_capped_by_the_remaining_time(self):
        relay = FakeRelay()
        pane_calls, fetch_calls = [], []
        hook_obj = self.make_hook(
            relay,
            pane=lambda pane_id, timeout: pane_calls.append(timeout)
            or (True, {"terminal_id": "term-1"}),
            content_key=CONTENT_KEY,
            fetch_content=lambda pane_id, kind, remaining, pane: fetch_calls.append(
                remaining
            )
            or dict(CONTENT),
        )
        self.with_features(hook_obj, ["sealed"])
        hook_obj.deadline = self.monotonic_clock[0] + 2.5
        hook_obj.run_event(event_json())

        self.assertEqual(len(pane_calls), 1)
        self.assertGreater(pane_calls[0], 0)
        self.assertLessEqual(pane_calls[0], 2.5)
        self.assertEqual(len(fetch_calls), 1)
        self.assertGreater(fetch_calls[0], 0)
        self.assertLessEqual(fetch_calls[0], 2.5)
        self.assertIn("sealed", relay.events()[0]["body"])

    def test_spooled_events_take_no_content(self):
        relay = FakeRelay()
        pane_calls, fetch_calls = [], []
        hook_obj = self.make_hook(
            relay,
            pane=lambda pane_id, timeout: pane_calls.append(pane_id)
            or (True, {"terminal_id": "term-1"}),
            content_key=CONTENT_KEY,
            fetch_content=lambda pane_id, kind, remaining, pane: fetch_calls.append(
                pane_id
            )
            or dict(CONTENT),
        )
        self.with_features(hook_obj, ["sealed"])
        hook.spool_event(self.host_dir, event_json(pane_id="w9:p1"))
        hook_obj.run_event(event_json(pane_id="w9:p2"))

        self.assertNotIn("w9:p1", pane_calls)
        self.assertNotIn("w9:p1", fetch_calls)
        sealed = {
            event["body"]["pane_id"]: event["body"].get("sealed")
            for event in relay.events()
        }
        self.assertIsNone(sealed["w9:p1"])
        self.assertIsNotNone(sealed["w9:p2"])

    def test_startup_takes_no_content(self):
        relay = FakeRelay(service_info={"features": ["sealed", "finished"]})
        pane_calls, fetch_calls = [], []
        hook_obj = self.make_hook(
            relay,
            pane=lambda pane_id, timeout: pane_calls.append(pane_id)
            or (True, {"terminal_id": "term-1"}),
            content_key=CONTENT_KEY,
            fetch_content=lambda pane_id, kind, remaining, pane: fetch_calls.append(
                pane_id
            )
            or dict(CONTENT),
        )
        hook.spool_event(self.host_dir, event_json(pane_id="w9:p1"))
        hook_obj.run_startup()

        self.assertFalse(pane_calls)
        self.assertFalse(fetch_calls)

    def test_blocked_event_uses_one_pane_get_for_fingerprint_and_content(self):
        from tests.test_content import FakeHerdr

        herdr = FakeHerdr()
        relay = FakeRelay()
        hook_obj = self.make_hook(
            relay, pane=hook.herdr_pane, content_key=CONTENT_KEY
        )
        self.with_features(hook_obj, ["sealed"])
        with unittest.mock.patch("hook.subprocess.run", side_effect=herdr.run):
            hook_obj.run_event(event_json())

        self.assertEqual(
            sum(1 for args, _timeout in herdr.calls if args[:2] == ("pane", "get")), 1
        )
        body = relay.events()[0]["body"]
        self.assertIn("sealed", body)
        self.assertEqual(
            body["pane_fingerprint"], hook.pane_fingerprint(HOST_ID, "term-1")
        )

    def test_finished_event_does_not_call_pane_read(self):
        from tests.test_content import FakeHerdr

        herdr = FakeHerdr()
        relay = FakeRelay()
        hook_obj = self.make_hook(
            relay, pane=hook.herdr_pane, content_key=CONTENT_KEY
        )
        self.with_features(hook_obj, ["sealed", "finished"])
        with unittest.mock.patch("hook.subprocess.run", side_effect=herdr.run):
            hook_obj.run_event(event_json(status="done"))

        self.assertFalse(
            any(args[:2] == ("pane", "read") for args, _timeout in herdr.calls)
        )
        self.assertIn("sealed", relay.events()[0]["body"])

    def test_400_service_info_recheck_respects_the_budget(self):
        hook_obj = None

        def handler(call, _count):
            if call["path"] == "/v1/events":
                self.monotonic_clock[0] = hook_obj.deadline + 1
                return 400, {"error": {"code": "invalid_request"}}
            return None

        relay = FakeRelay(handler=handler)
        hook_obj = self.make_hook(
            relay, content_key=CONTENT_KEY,
            fetch_content=lambda pane_id, kind, remaining, pane: dict(CONTENT),
        )
        self.with_features(hook_obj, ["sealed"])
        hook_obj.run_event(event_json())

        self.assertNotIn("/v1/service-info", relay.gets)
        self.assertEqual(len(relay.events()), 1)
        self.assertFalse(hook_obj.load()["pending"][0].get("sealed"))

    def test_a_short_budget_pane_get_failure_keeps_the_event(self):
        relay = FakeRelay()
        hook_obj = self.make_hook(
            relay, pane=lambda pane_id, timeout: (False, None)
        )
        state = hook_obj.load()
        state["features_version"] = hook.PLUGIN_VERSION
        state["panes"]["w9:p1"] = {
            "pane_generation": "generation-1",
            "pane_fingerprint": "f" * 64,
            "last_state": "clear",
        }
        hook_obj.save(state)
        hook_obj.deadline = self.monotonic_clock[0] + 1

        hook_obj.run_event(event_json())

        events = relay.events()
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0]["body"]["pane_fingerprint"], "f" * 64)

    def test_a_streamless_event_never_starts_a_call_past_the_budget(self):
        deadline = self.monotonic_clock[0] + hook.HOOK_BUDGET_SECONDS
        calls = []
        relay = FakeRelay()

        def timed(kind, timeout, cost):
            calls.append((kind, timeout, self.monotonic_clock[0]))
            self.monotonic_clock[0] += cost if timeout is None else min(cost, timeout)

        def get(path, timeout=None):
            timed("get " + path, timeout, 8)
            if path == "/v1/service-info":
                return 200, {"features": ["sealed"]}
            return 200, dict(ready_settings())

        relay.get = get

        def post(path, body, idempotency_key=None, timeout=None):
            timed("post " + path, timeout, 5 if path == "/v1/streams" else 8)
            if path == "/v1/streams":
                return 201, {
                    "stream_id": "stream-1",
                    "last_sequence": 0,
                    "expires_at": "2099-01-01T00:00:00.000Z",
                }
            return 202, {}

        relay.post = post
        hook_obj = self.make_hook(
            relay,
            blocked=lambda timeout: timed("agent list", timeout, 10) or [],
            pane=lambda pane_id, timeout: timed("pane", timeout, 10)
            or (True, {"terminal_id": "term-1"}),
            content_key=CONTENT_KEY,
            fetch_content=lambda pane_id, kind, remaining, pane: timed(
                "content", remaining, 12
            )
            or dict(CONTENT),
        )
        hook_obj.deadline = deadline
        hook_obj.run_event(event_json())

        self.assertTrue(calls)
        for kind, timeout, at in calls:
            self.assertIsNotNone(timeout, kind)
            self.assertGreater(timeout, 0, kind)
            self.assertLessEqual(at + timeout, deadline + 1e-9, kind)
        self.assertLessEqual(self.monotonic_clock[0], deadline + 1e-9)
        self.assertTrue(hook_obj.load()["pending"])

    def test_stream_and_event_posts_are_capped(self):
        relay = FakeRelay()
        calls = []

        def get(path, timeout=None):
            calls.append(("get " + path, timeout, self.monotonic_clock[0]))
            self.monotonic_clock[0] += timeout if timeout is not None else 8
            return 200, dict(ready_settings())

        relay.get = get

        def post(path, body, idempotency_key=None, timeout=None):
            calls.append(("post " + path, timeout, self.monotonic_clock[0]))
            self.monotonic_clock[0] += timeout if timeout is not None else 8
            if path == "/v1/streams":
                return 201, {
                    "stream_id": "stream-1",
                    "last_sequence": 0,
                    "expires_at": "2099-01-01T00:00:00.000Z",
                }
            return 202, {}

        relay.post = post
        hook_obj = self.make_hook(
            relay,
            blocked=lambda timeout: [],
        )
        state = hook_obj.load()
        state["features_version"] = hook.PLUGIN_VERSION
        hook_obj.save(state)
        hook_obj.deadline = self.monotonic_clock[0] + 20
        hook_obj.run_event(event_json())

        by_name = {name: timeout for name, timeout, _at in calls}
        self.assertGreater(by_name["get /v1/source-settings"], 0)
        self.assertGreater(by_name["post /v1/streams"], 0)
        self.assertGreater(by_name["post /v1/events"], 0)
        self.assertEqual(hook_obj.load()["sequence"], 1)
        for name, timeout, at in calls:
            self.assertLessEqual(at + timeout, hook_obj.deadline + 1e-9, name)


class FeatureRefreshTests(HookTestCase):
    def test_old_state_reads_features_on_the_next_event(self):
        relay = FakeRelay(service_info={"features": ["sealed", "finished"]})
        hook_obj = self.make_hook(
            relay, content_key=CONTENT_KEY,
            fetch_content=lambda pane_id, kind, remaining, pane: dict(CONTENT),
        )
        hook_obj.run_event(event_json())

        state = hook_obj.load()
        self.assertEqual(state["features"], ["sealed", "finished"])
        self.assertEqual(state["features_version"], hook.PLUGIN_VERSION)
        self.assertIn("sealed", relay.events()[0]["body"])

    def test_version_mismatch_reads_features_once(self):
        relay = FakeRelay(service_info={"features": ["sealed"]})
        hook_obj = self.make_hook(
            relay, content_key=CONTENT_KEY,
            fetch_content=lambda pane_id, kind, remaining, pane: dict(CONTENT),
        )
        self.with_features(hook_obj, [], version="0.2.0")
        hook_obj.run_event(event_json(pane_id="w9:p1"))

        self.assertEqual(hook_obj.load()["features"], ["sealed"])
        self.assertEqual(relay.gets.count("/v1/service-info"), 1)
        hook_obj.run_event(event_json(pane_id="w9:p2"))
        self.assertEqual(relay.gets.count("/v1/service-info"), 1)

    def test_a_failed_startup_read_is_retried_on_the_next_event(self):
        relay = FakeRelay(service_info={"features": ["finished"]})
        hook_obj = self.make_hook(relay)
        original = relay.get

        def failing(path, timeout=None):
            if path == "/v1/service-info":
                return None, None
            return original(path, timeout)

        relay.get = failing
        hook_obj.run_startup()
        self.assertIsNone(hook_obj.load()["features_version"])

        relay.get = original
        hook_obj.run_event(event_json(status="done"))
        self.assertEqual(hook_obj.load()["features"], ["finished"])


class StreamErrorTests(HookTestCase):
    def check(self, status):
        def handler(call, _count):
            if call["path"] == "/v1/events" and call["body"]["state"] == "clear":
                code = "stale_stream" if status == 409 else "invalid_request"
                return status, {"error": {"code": code}}
            return None

        relay = FakeRelay(handler=handler)
        hook_obj = self.make_hook(relay)
        self.with_features(hook_obj, ["finished"])
        hook_obj.run_event(event_json(status="blocked"))
        hook_obj.run_event(event_json(status="done"))

        events = relay.events()
        self.assertEqual(
            [event["body"]["state"] for event in events],
            ["blocked", "clear", "finished"],
        )
        # resync で作った新しい stream の sequence で finished が送られる。
        self.assertEqual(events[-1]["body"]["sequence"], 1)
        self.assertFalse(hook_obj.load()["pending"])

    def test_clear_400_still_delivers_finished(self):
        self.check(400)

    def test_clear_409_still_delivers_finished(self):
        self.check(409)

    def test_clear_404_still_delivers_finished(self):
        self.check(404)

    def test_clear_410_drops_finished_without_another_stream(self):
        posts = {"events": 0}

        def handler(call, _count):
            if call["path"] != "/v1/events":
                return None
            posts["events"] += 1
            if posts["events"] > 10:
                return 500, {"error": {"code": "internal_error"}}
            if call["body"]["state"] in ("clear", "finished"):
                return 410, {"error": {"code": "expired"}}
            return None

        relay = FakeRelay(handler=handler)
        hook_obj = self.make_hook(relay)
        self.with_features(hook_obj, ["finished"])
        hook_obj.run_event(event_json(status="blocked"))
        hook_obj.run_event(event_json(status="done"))

        self.assertEqual(
            [event["body"]["state"] for event in relay.events()],
            ["blocked", "clear", "finished"],
        )
        self.assertEqual(
            len([post for post in relay.posts if post["path"] == "/v1/streams"]), 1
        )
        self.assertFalse(hook_obj.load()["pending"])


class FinishedFailureTests(HookTestCase):
    def test_finished_409_stale_stream_is_resent_once(self):
        attempts = {"finished": 0}

        def handler(call, _count):
            if call["path"] == "/v1/events" and call["body"]["state"] == "finished":
                attempts["finished"] += 1
                if attempts["finished"] == 1:
                    return 409, {"error": {"code": "stale_stream"}}
            return None

        relay = FakeRelay(handler=handler)
        hook_obj = self.make_hook(relay)
        self.with_features(hook_obj, ["finished"])
        hook_obj.run_event(event_json(status="done"))

        self.assertEqual(
            [event["body"]["state"] for event in relay.events()],
            ["finished", "finished"],
        )
        self.assertEqual(
            len([post for post in relay.posts if post["path"] == "/v1/streams"]), 2
        )
        self.assertFalse(hook_obj.load()["pending"])

    def test_finished_404_is_resent_once(self):
        attempts = {"finished": 0}

        def handler(call, _count):
            if call["path"] == "/v1/events" and call["body"]["state"] == "finished":
                attempts["finished"] += 1
                if attempts["finished"] == 1:
                    return 404, {"error": {"code": "not_found"}}
            return None

        relay = FakeRelay(handler=handler)
        hook_obj = self.make_hook(relay)
        self.with_features(hook_obj, ["finished"])
        hook_obj.run_event(event_json(status="done"))

        self.assertEqual(
            [event["body"]["state"] for event in relay.events()],
            ["finished", "finished"],
        )
        self.assertFalse(hook_obj.load()["pending"])

    def test_expired_finished_410_is_dropped_without_a_new_stream(self):
        posts = {"events": 0}

        def handler(call, _count):
            if call["path"] != "/v1/events":
                return None
            posts["events"] += 1
            if posts["events"] > 10:
                return 500, {"error": {"code": "internal_error"}}
            if call["body"]["state"] == "finished":
                return 410, {"error": {"code": "expired"}}
            return None

        relay = FakeRelay(handler=handler)
        hook_obj = self.make_hook(relay)
        self.with_features(hook_obj, ["finished"])
        hook_obj.run_event(event_json(status="done"))

        self.assertEqual(
            [event["body"]["state"] for event in relay.events()], ["finished"]
        )
        self.assertEqual(
            len([post for post in relay.posts if post["path"] == "/v1/streams"]), 1
        )
        self.assertFalse(hook_obj.load()["pending"])

    def test_finished_idempotency_conflict_is_treated_as_accepted(self):
        posts = {"events": 0}

        def handler(call, _count):
            if call["path"] != "/v1/events":
                return None
            posts["events"] += 1
            if posts["events"] > 10:
                return 500, {"error": {"code": "internal_error"}}
            if call["body"]["state"] == "finished":
                return 409, {"error": {"code": "idempotency_conflict"}}
            return None

        relay = FakeRelay(handler=handler)
        hook_obj = self.make_hook(relay)
        self.with_features(hook_obj, ["finished"])
        hook_obj.run_event(event_json(status="done"))

        self.assertEqual(
            [event["body"]["state"] for event in relay.events()], ["finished"]
        )
        self.assertEqual(
            len([post for post in relay.posts if post["path"] == "/v1/streams"]), 1
        )
        self.assertFalse(hook_obj.load()["pending"])

    def test_finished_survives_a_resync_while_upload_is_not_ready(self):
        def handler(call, _count):
            if call["path"] == "/v1/events" and call["body"]["state"] == "clear":
                return 409, {"error": {"code": "stale_stream"}}
            return None

        relay = FakeRelay(
            settings=ready_settings(upload_state="no_links"), handler=handler
        )
        hook_obj = self.make_hook(relay)
        state = hook_obj.load()
        state["features"] = ["finished"]
        state["features_version"] = hook.PLUGIN_VERSION
        state["stream_id"] = "stream-1"
        state["stream_expires_at"] = "2099-01-01T00:00:00.000Z"
        hook_obj.enqueue(state, "w9:p1", "clear", "generation-1", None)
        hook_obj.enqueue(state, "w9:p1", "finished", "generation-1", None)
        hook_obj.save(state)

        hook_obj.run_event(event_json(pane_id="w9:p2", status="idle"))

        state = hook_obj.load()
        self.assertTrue(state["suspended"])
        self.assertEqual([event["state"] for event in state["pending"]], ["finished"])

    def test_finished_survives_upload_suspended(self):
        relay = FakeRelay(
            handler=lambda call, _count: (409, {"error": {"code": "upload_suspended"}})
            if call["path"] == "/v1/events"
            else None
        )
        hook_obj = self.make_hook(relay)
        state = hook_obj.load()
        state["features"] = ["finished"]
        state["features_version"] = hook.PLUGIN_VERSION
        state["stream_id"] = "stream-1"
        state["stream_expires_at"] = "2099-01-01T00:00:00.000Z"
        hook_obj.enqueue(state, "w9:p1", "finished", "generation-1", None)
        hook_obj.save(state)

        hook_obj.run_event(event_json(pane_id="w9:p2", status="idle"))

        state = hook_obj.load()
        self.assertTrue(state["suspended"])
        self.assertEqual([event["state"] for event in state["pending"]], ["finished"])

    def test_multiple_finished_keep_their_order_after_resync(self):
        attempts = {"finished": 0}

        def handler(call, _count):
            if call["path"] == "/v1/events" and call["body"]["state"] == "finished":
                attempts["finished"] += 1
                if attempts["finished"] == 1:
                    return 409, {"error": {"code": "stale_stream"}}
            return None

        relay = FakeRelay(handler=handler)
        hook_obj = self.make_hook(relay)
        state = hook_obj.load()
        state["features"] = ["finished"]
        state["features_version"] = hook.PLUGIN_VERSION
        state["stream_id"] = "stream-1"
        state["stream_expires_at"] = "2099-01-01T00:00:00.000Z"
        hook_obj.enqueue(state, "w9:p1", "finished", "generation-1", None)
        hook_obj.enqueue(state, "w9:p2", "finished", "generation-2", None)
        hook_obj.save(state)

        hook_obj.run_event(event_json(pane_id="w9:p3", status="idle"))

        events = relay.events()
        self.assertEqual(
            [event["body"]["pane_id"] for event in events],
            ["w9:p1", "w9:p1", "w9:p2"],
        )
        self.assertEqual([event["body"]["sequence"] for event in events], [1, 1, 2])
        self.assertFalse(hook_obj.load()["pending"])


class SpoolFingerprintTests(HookTestCase):
    def test_spooled_blocked_reuses_the_previous_fingerprint(self):
        known = {}

        def handler(call, _count):
            if call["path"] != "/v1/events":
                return None
            body = call["body"]
            previous = known.get(body["pane_id"])
            if (
                previous is not None
                and previous[0] == body["pane_generation"]
                and previous[1] != body["pane_fingerprint"]
            ):
                return 409, {"error": {"code": "conflict"}}
            known[body["pane_id"]] = (
                body["pane_generation"],
                body["pane_fingerprint"],
            )
            return None

        relay = FakeRelay(handler=handler)
        hook_obj = self.make_hook(relay)
        hook_obj.run_event(event_json(status="blocked"))
        hook_obj.run_event(event_json(status="idle"))
        hook.spool_event(self.host_dir, event_json(status="blocked"))
        hook_obj.run_event(event_json(pane_id="w9:p2", status="idle"))

        self.assertEqual(
            [event["body"]["state"] for event in relay.events()],
            ["blocked", "clear", "blocked"],
        )
        self.assertEqual(
            relay.events()[-1]["body"]["pane_fingerprint"],
            hook.pane_fingerprint(HOST_ID, "term-1"),
        )
        self.assertEqual(
            len([post for post in relay.posts if post["path"] == "/v1/streams"]), 1
        )


class StateCompatTests(HookTestCase):
    def test_a_0_2_0_state_without_features_still_loads(self):
        state = hook._make_state(HOST_ID)
        state["stream_id"] = "stream-1"
        del state["features"]
        del state["features_version"]
        os.makedirs(self.host_dir)
        with open(os.path.join(self.host_dir, "state.json"), "w", encoding="utf-8") as handle:
            json.dump(state, handle)

        loaded = hook.load_state(self.host_dir, HOST_ID, now=1000)

        self.assertEqual(loaded["stream_id"], "stream-1")
        self.assertEqual(loaded["features"], [])
        self.assertIsNone(loaded["features_version"])


class VersionTests(unittest.TestCase):
    def test_plugin_version_matches_the_manifest(self):
        root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        with open(os.path.join(root, "herdr-plugin.toml"), encoding="utf-8") as handle:
            manifest = handle.read()
        self.assertIn('version = "%s"' % hook.PLUGIN_VERSION, manifest)


class LockTests(HookTestCase):
    def test_budgets_match_contract(self):
        # A hook gets 45 seconds in total; one lock wait gives up after 5.
        self.assertEqual(hook.HOOK_BUDGET_SECONDS, 45)
        self.assertEqual(hook.LOCK_TIMEOUT_SECONDS, 5)

    def test_spooled_event_is_ingested_and_removed(self):
        relay = FakeRelay()
        hook_obj = self.make_hook(relay)
        hook.spool_event(self.host_dir, event_json())
        directory = hook.spool_dir(self.host_dir)
        name = os.listdir(directory)[0]
        self.assertEqual(os.stat(os.path.join(directory, name)).st_mode & 0o777, 0o600)

        hook_obj.run_event(event_json(pane_id="w9:p2", status="idle"))

        self.assertEqual(len(relay.events()), 1)
        self.assertEqual(relay.events()[0]["body"]["pane_id"], "w9:p1")
        self.assertFalse(os.listdir(directory))

    def test_spooled_event_is_persisted_when_drain_exhausts_budget(self):
        relay = FakeRelay()
        pane_calls = []

        def pane(pane_id, timeout):
            pane_calls.append(pane_id)
            return True, {"terminal_id": "term-1"}

        hook_obj = self.make_hook(relay, pane=pane)

        def spool_during_retry(call, _index):
            if call["path"] != "/v1/events":
                return None
            hook.spool_event(hook_obj.state_dir, event_json(pane_id="w9:p2"))
            hook_obj.deadline = self.monotonic_clock[0] - 1
            return 429, {"error": {"retry_after_seconds": 60}}

        relay.handler = spool_during_retry
        hook_obj.run_event(event_json(pane_id="w9:p1"))

        self.assertFalse(os.listdir(hook.spool_dir(hook_obj.state_dir)))
        state = hook_obj.load()
        self.assertEqual([event["pane_id"] for event in state["pending"]], ["w9:p1", "w9:p2"])
        self.assertGreater(
            hook.parse_iso_utc(state["pending"][1]["expires_at"]), hook_obj.now()
        )
        self.assertEqual(pane_calls, ["w9:p1"])
        self.assertIsNone(state["pending"][1]["pane_fingerprint"])

    def test_ingest_does_not_remove_a_writing_temp_file(self):
        relay = FakeRelay()
        hook_obj = self.make_hook(relay)
        directory = hook.spool_dir(hook_obj.state_dir)
        os.makedirs(directory)
        tmp = os.path.join(directory, ".spool.writing.tmp")
        with open(tmp, "w", encoding="utf-8") as handle:
            handle.write("{partial")

        hook_obj.run_event(event_json(status="idle"))

        self.assertTrue(os.path.exists(tmp))

    def test_times_out_when_lock_is_held(self):
        os.makedirs(self.state_dir)
        fd = os.open(
            os.path.join(self.state_dir, "state.lock"), os.O_CREAT | os.O_RDWR, 0o600
        )
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            with self.assertRaises(hook.LockTimeout):
                with hook.state_lock(self.state_dir, timeout=0.2):
                    pass
        finally:
            fcntl.flock(fd, fcntl.LOCK_UN)
            os.close(fd)

    def test_corrupt_state_is_moved_aside(self):
        os.makedirs(self.state_dir)
        with open(os.path.join(self.state_dir, "state.json"), "w", encoding="utf-8") as fh:
            fh.write("{not json")
        state = hook.load_state(self.state_dir, HOST_ID)
        self.assertEqual(state["sequence"], 0)
        leftovers = [name for name in os.listdir(self.state_dir) if ".corrupt-" in name]
        self.assertEqual(len(leftovers), 1)

    def test_malformed_state_shapes_are_moved_aside(self):
        cases = []
        cases.append([])
        cases.append(hook._make_state("another-host"))
        missing_sequence = hook._make_state(HOST_ID)
        missing_sequence["sequence"] = None
        cases.append(missing_sequence)
        bad_pane = hook._make_state(HOST_ID)
        bad_pane["panes"]["w9:p1"] = None
        cases.append(bad_pane)
        bad_pending = hook._make_state(HOST_ID)
        bad_pending["pending"] = [None]
        cases.append(bad_pending)

        os.makedirs(self.state_dir)
        for index, data in enumerate(cases):
            with self.subTest(index=index):
                with open(os.path.join(self.state_dir, "state.json"), "w", encoding="utf-8") as fh:
                    json.dump(data, fh)
                state = hook.load_state(self.state_dir, HOST_ID, now=1000 + index)
                self.assertEqual(state, hook._make_state(HOST_ID))

        leftovers = [name for name in os.listdir(self.state_dir) if ".corrupt-" in name]
        self.assertEqual(len(leftovers), len(cases))


class EnvironmentConfigTests(unittest.TestCase):
    def test_environment_host_lookup_skips_malformed_entries(self):
        with tempfile.TemporaryDirectory() as config_dir:
            host = host_config()
            with open(os.path.join(config_dir, "config.json"), "w", encoding="utf-8") as handle:
                json.dump({"relay_url": "https://relay.test", "hosts": [None, "bad", host]}, handle)
            environment = {
                "HERDR_ENV": "1",
                "HERDR_PLUGIN_CONFIG_DIR": config_dir,
                "HERDR_SOCKET_PATH": host["socket_path"],
            }
            with unittest.mock.patch.dict(os.environ, environment, clear=True):
                config, selected = hook._config_for_environment()

        self.assertEqual(config["relay_url"], "https://relay.test")
        self.assertEqual(selected["host_id"], HOST_ID)


class MainLockTests(HookTestCase):
    def test_lock_timeout_spools_event_which_is_drained_later(self):
        import unittest.mock

        config_dir = os.path.join(self.tmp.name, "config")
        os.makedirs(config_dir)
        with open(os.path.join(config_dir, "config.json"), "w", encoding="utf-8") as fh:
            json.dump({"relay_url": "https://relay.test", "hosts": [host_config()]}, fh)
        os.makedirs(self.host_dir)
        lock_fd = os.open(
            os.path.join(self.host_dir, "state.lock"), os.O_CREAT | os.O_RDWR, 0o600
        )
        fcntl.flock(lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        real_state_lock = hook.state_lock

        def fast_lock(path):
            return real_state_lock(path, timeout=0.2)

        self.addCleanup(setattr, hook, "state_lock", real_state_lock)
        hook.state_lock = fast_lock
        try:
            with unittest.mock.patch.dict(
                os.environ,
                {
                    "HERDR_ENV": "1",
                    "HERDR_PLUGIN_CONFIG_DIR": config_dir,
                    "HERDR_SOCKET_PATH": "/tmp/herdr-test.sock",
                    "HERDR_PLUGIN_STATE_DIR": self.state_dir,
                    "HERDR_PLUGIN_EVENT_JSON": event_json(),
                },
            ):
                self.assertEqual(hook.main(["event"]), 0)
        finally:
            fcntl.flock(lock_fd, fcntl.LOCK_UN)
            os.close(lock_fd)

        spool_directory = hook.spool_dir(self.host_dir)
        self.assertEqual(len(os.listdir(spool_directory)), 1)

        # ロックを解いて再度 hook を動かすと、spool したイベントが消化される。
        relay = FakeRelay()
        hook_obj = self.make_hook(relay)
        hook_obj.run_event(event_json(pane_id="w9:p2", status="idle"))
        self.assertEqual(len(relay.events()), 1)
        self.assertEqual(relay.events()[0]["body"]["pane_id"], "w9:p1")
        self.assertFalse(os.listdir(spool_directory))


if __name__ == "__main__":
    unittest.main()
