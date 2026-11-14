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

    def __init__(self, settings=None, handler=None, settings_status=200):
        self.settings = settings or ready_settings()
        self.handler = handler
        self.settings_status = settings_status
        self.posts = []
        self.gets = []

    def url(self, path):
        return "https://relay.test" + path

    def get(self, path):
        self.gets.append(path)
        if path == "/v1/source-settings":
            return self.settings_status, dict(self.settings)
        return 200, {}

    def post(self, path, body, idempotency_key=None):
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

    def make_hook(self, relay, blocked=None, terminal=None, **host_overrides):
        return hook.Hook(
            host_config(**host_overrides),
            self.state_dir,
            relay,
            blocked or (lambda: []),
            terminal or (lambda pane_id: (True, "term-1")),
            now=lambda: self.clock[0],
            sleep=lambda seconds: None,
            log_line=self.logs.append,
        )


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
        hook_obj = self.make_hook(relay, blocked=lambda: blocked)

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
        hook_obj = self.make_hook(relay, blocked=lambda: blocked)
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
            relay, blocked=lambda: blocked, workspace_allowlist=["w9"]
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
        relay.get = lambda path: (None, None)  # Relay._send の OSError 相当
        hook_obj = self.make_hook(relay)
        self.assertEqual(hook_obj.run_startup(), 0)
        with open(os.path.join(self.host_dir, "state.json"), encoding="utf-8") as handle:
            state = json.load(handle)
        self.assertFalse(state["suspended"])
        self.assertIsNone(state["settings_checked_at"])

    def test_agent_list_failure_sends_nothing(self):
        def boom():
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
        hook_obj = self.make_hook(relay, blocked=lambda: [])
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
        hook_obj = self.make_hook(relay, blocked=lambda: [current])
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
        hook_obj = self.make_hook(relay, terminal=lambda pane_id: (False, None))
        hook_obj.run_event(event_json())
        self.assertFalse(relay.posts)

    def test_missing_terminal_id_still_sends_null_fingerprint(self):
        relay = FakeRelay()
        hook_obj = self.make_hook(relay, terminal=lambda pane_id: (True, None))
        hook_obj.run_event(event_json())
        events = relay.events()
        self.assertEqual(len(events), 1)
        self.assertIsNone(events[0]["body"]["pane_fingerprint"])

    def test_non_string_terminal_id_still_sends_null_fingerprint(self):
        relay = FakeRelay()
        hook_obj = self.make_hook(relay, terminal=lambda pane_id: (True, 123))

        hook_obj.run_event(event_json())

        events = relay.events()
        self.assertEqual(len(events), 1)
        self.assertIsNone(events[0]["body"]["pane_fingerprint"])

    def test_first_blocked_excludes_itself_from_baseline(self):
        relay = FakeRelay()
        other = {"pane_id": "w9:p9", "workspace_id": "w9", "terminal_id": "term-9"}
        hook_obj = self.make_hook(relay, blocked=lambda: [other])
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
        hook_obj = self.make_hook(relay, blocked=lambda: [current])
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
        relay.get = lambda path: (None, None)  # Relay._send の OSError 相当

        hook_obj.run_event(event_json())

        self.assertFalse(relay.posts)
        state = hook_obj.load()
        self.assertTrue(state["suspended"])
        # 通信の失敗では checked_at を更新しない。次のイベントで settings を読み直す。
        self.assertEqual(state["settings_checked_at"], "1970-01-01T00:00:00.000Z")

        # upload_state が ready でない枝は従来どおり: 停止のまま checked_at を更新する。
        self.clock[0] += 16 * 60
        relay.get = lambda path: (200, dict(ready_settings(upload_state="no_links")))
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
        hook_obj = self.make_hook(relay, blocked=lambda: [current])
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
        hook_obj = self.make_hook(relay, blocked=lambda: [current])

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
        hook_obj = self.make_hook(relay, blocked=lambda: [])
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
        hook_obj = self.make_hook(relay, blocked=lambda: [])
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

        self.assertEqual(relay.gets, ["/v1/source-settings"])
        self.assertFalse(relay.posts)
        self.assertEqual(len(hook_obj.load()["pending"]), 1)
        self.assertTrue(any("credential rejected" in line for line in self.logs))

    def test_nonready_settings_are_checked_only_once_per_event(self):
        relay = FakeRelay(settings=ready_settings(upload_state="no_links"))
        hook_obj = self.make_hook(relay)

        hook_obj.run_event(event_json())

        self.assertEqual(relay.gets, ["/v1/source-settings"])
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
        terminal_calls = []

        def terminal(pane_id):
            terminal_calls.append(pane_id)
            return True, "term-1"

        hook_obj = self.make_hook(relay, terminal=terminal)

        def spool_during_retry(call, _index):
            if call["path"] != "/v1/events":
                return None
            hook.spool_event(hook_obj.state_dir, event_json(pane_id="w9:p2"))
            hook_obj.deadline = time.monotonic() - 1
            return 429, {"error": {"retry_after_seconds": 60}}

        relay.handler = spool_during_retry
        hook_obj.run_event(event_json(pane_id="w9:p1"))

        self.assertFalse(os.listdir(hook.spool_dir(hook_obj.state_dir)))
        state = hook_obj.load()
        self.assertEqual([event["pane_id"] for event in state["pending"]], ["w9:p1", "w9:p2"])
        self.assertGreater(
            hook.parse_iso_utc(state["pending"][1]["expires_at"]), hook_obj.now()
        )
        self.assertEqual(terminal_calls, ["w9:p1"])
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
