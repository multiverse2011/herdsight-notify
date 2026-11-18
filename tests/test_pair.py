"""`setup.py pair`（アプリが SSH で動かす非対話のペアリング）のテスト。通信も herdr も使わない。"""

import io
import json
import os
import tempfile
import threading
import unittest
import unittest.mock

import setup

RELAY = "https://relay.test"
CODE = "12345678"
HOST_ID = "22222222-2222-4222-8222-222222222222"


class FakeRelay:
    """(method, path の先頭) ごとに応答を返す。リストは順に使い、最後の値を繰り返す。"""

    def __init__(self, **responses):
        self.responses = {
            "service": [(200, {"terms_version": "t", "privacy_notice_version": "p"})],
            "hosts": [(201, {"expires_at": "2027-01-01T00:00:00Z"})],
            "create": [(201, {"expires_at": "2026-11-14T00:05:00Z"})],
            "get": [(200, {"state": "pending"}), (200, {"state": "claimed", "verification_code": CODE})],
            "approve": [(201, {"link_id": "link-1", "host_id": HOST_ID})],
            "delete_pairing": [(204, None)],
            "delete_self": [(204, None)],
        }
        self.responses.update({key: list(value) for key, value in responses.items()})
        self.calls = []

    def key(self, method, path):
        if path == "/v1/service-info":
            return "service"
        if path == "/v1/hosts":
            return "hosts"
        if path == "/v1/self":
            return "delete_self"
        if path == "/v1/pairings":
            return "create"
        if path.endswith("/approve"):
            return "approve"
        return "delete_pairing" if method == "DELETE" else "get"

    def request(self, method, path, body=None, host=None, idempotency_key=None):
        key = self.key(method, path)
        self.calls.append((key, host and host.get("host_id")))
        queue = self.responses[key]
        response = queue.pop(0) if len(queue) > 1 else queue[0]
        if isinstance(response, BaseException):
            raise response
        return response

    def get(self, path, host=None):
        return self.request("GET", path, host=host)

    def keys(self):
        return [key for key, _host in self.calls]


class BlockingStdin:
    def __init__(self):
        self.release = threading.Event()

    def readline(self):
        self.release.wait(5)
        return ""


class PairTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.socket = os.path.join(self.tmp.name, "herdr.sock")
        open(self.socket, "w").close()
        self.config_path = os.path.join(self.tmp.name, "config", "config.json")
        env = unittest.mock.patch.dict(
            os.environ,
            {
                "HERDR_SOCKET_PATH": self.socket,
                "HERDR_PLUGIN_CONFIG_DIR": os.path.dirname(self.config_path),
            },
            clear=True,
        )
        env.start()
        self.addCleanup(env.stop)
        for name, value in (("POLL_INTERVAL_SECONDS", 0.01),):
            patcher = unittest.mock.patch.object(setup, name, value)
            patcher.start()
            self.addCleanup(patcher.stop)
        sleep = unittest.mock.patch("setup.time.sleep")
        sleep.start()
        self.addCleanup(sleep.stop)

    def write_config(self, config):
        setup.save_config(self.config_path, config)

    def raw_config(self):
        with open(self.config_path, encoding="utf-8") as handle:
            return handle.read()

    def read_config(self):
        return setup.load_config(self.config_path)

    def host(self, host_id=HOST_ID):
        return {
            "socket_path": self.socket,
            "workspace_allowlist": ["w1"],
            "host_id": host_id,
            "host_secret": "s" * 43,
            "host_expires_at": "2027-01-01T00:00:00Z",
        }

    def run_pair(self, relay, stdin_text=None, stdin=None, relay_url=RELAY, stdout=None):
        out = stdout or io.StringIO()
        stdin = stdin or io.StringIO(
            json.dumps({"verification_code": CODE}) + "\n" if stdin_text is None else stdin_text
        )
        with unittest.mock.patch("setup.RelayClient", return_value=relay):
            result = setup.run_pair(relay_url, stdin=stdin, stdout=out)
        lines = [json.loads(line) for line in out.getvalue().splitlines()] if stdout is None else []
        return result, lines

    def assert_error(self, lines, code):
        self.assertTrue(all(line["v"] == 1 for line in lines))
        self.assertEqual(lines[-1], {"v": 1, "error": code})

    def test_approved_creates_host_and_prints_json_lines_only(self):
        relay = FakeRelay()
        result, lines = self.run_pair(relay)
        self.assertEqual(result, 0)
        self.assertEqual(len(lines), 2)
        pair_id, _sep, secret = lines[0]["pair"].partition(".")
        setup.parse_pair_string(lines[0]["pair"])
        self.assertEqual(lines[0]["expires_at"], "2026-11-14T00:05:00Z")
        self.assertEqual(lines[1]["v"], 1)
        self.assertEqual(lines[1]["result"], "approved")
        self.assertEqual(lines[1]["link_id"], "link-1")
        self.assertEqual(lines[1]["host_id"], HOST_ID)
        self.assertRegex(lines[1]["content_key"], setup.BASE64URL)
        key_path = setup.content_key_path(os.path.dirname(self.config_path))
        self.assertEqual(os.stat(key_path).st_mode & 0o777, 0o600)
        with open(key_path, "rb") as handle:
            self.assertEqual(
                setup.content_key_encode(handle.read()), lines[1]["content_key"]
            )
        self.assertEqual(relay.keys(), ["service", "hosts", "create", "get", "get", "approve"])
        config = self.read_config()
        self.assertEqual(config["relay_url"], RELAY)
        self.assertEqual(config["hosts"][0]["socket_path"], self.socket)
        self.assertEqual(config["hosts"][0]["workspace_allowlist"], [])

    def test_existing_host_keeps_allowlist(self):
        self.write_config({"relay_url": RELAY, "hosts": [self.host()]})
        relay = FakeRelay()
        result, _lines = self.run_pair(relay)
        self.assertEqual(result, 0)
        self.assertNotIn("hosts", relay.keys())
        self.assertEqual(self.read_config()["hosts"][0]["workspace_allowlist"], ["w1"])

    def test_code_mismatch_cancels(self):
        relay = FakeRelay()
        result, lines = self.run_pair(relay, json.dumps({"verification_code": "87654321"}) + "\n")
        self.assertEqual(result, 1)
        self.assert_error(lines, "code_mismatch")
        self.assertNotIn("approve", relay.keys())
        self.assertEqual(relay.keys()[-1], "delete_pairing")

    def test_bad_input_cancels_without_waiting_for_claim(self):
        for text in ("", "not json\n", '{"verification_code":"1234"}\n', '{"code":"12345678"}\n'):
            with self.subTest(text=text):
                relay = FakeRelay(get=[(200, {"state": "pending"})])
                result, lines = self.run_pair(relay, text)
                self.assertEqual(result, 1)
                self.assert_error(lines, "bad_input")
                self.assertEqual(relay.keys()[-1], "delete_pairing")
                self.assertNotIn("approve", relay.keys())

    def test_expired_and_cancelled_do_not_delete(self):
        for response, code in (
            ((410, None), "expired"),
            ((200, {"state": "expired"}), "expired"),
            ((409, None), "cancelled"),
            ((200, {"state": "cancelled"}), "cancelled"),
        ):
            with self.subTest(code=code, response=response):
                relay = FakeRelay(get=[response])
                result, lines = self.run_pair(relay, stdin=BlockingStdin())
                self.assertEqual(result, 1)
                self.assert_error(lines, code)
                self.assertNotIn("delete_pairing", relay.keys())

    def test_timeout_cancels(self):
        stdin = BlockingStdin()
        self.addCleanup(stdin.release.set)
        relay = FakeRelay(get=[(200, {"state": "pending"})])
        with unittest.mock.patch.object(setup, "PAIRING_LIFETIME_SECONDS", 0.05):
            result, lines = self.run_pair(relay, stdin=stdin)
        self.assertEqual(result, 1)
        self.assert_error(lines, "timeout")
        self.assertEqual(relay.keys()[-1], "delete_pairing")

    def test_no_socket(self):
        os.unlink(self.socket)
        result, lines = self.run_pair(FakeRelay())
        self.assertEqual((result, lines), (1, [{"v": 1, "error": "no_socket"}]))

    def test_invalid_relay_url(self):
        for url in ("http://relay.test", "relay.test", ""):
            with self.subTest(url=url):
                relay = FakeRelay()
                result, lines = self.run_pair(relay, relay_url=url)
                self.assertEqual((result, lines), (1, [{"v": 1, "error": "invalid_relay_url"}]))
                self.assertEqual(relay.calls, [])

    def test_relay_mismatch_keeps_config(self):
        self.write_config({"relay_url": "https://other.test", "hosts": [self.host()]})
        before = self.raw_config()
        relay = FakeRelay()
        result, lines = self.run_pair(relay)
        self.assertEqual((result, lines), (1, [{"v": 1, "error": "relay_mismatch"}]))
        self.assertEqual(relay.calls, [])
        self.assertEqual(self.raw_config(), before)

    def test_trailing_slash_is_the_same_relay(self):
        self.write_config({"relay_url": RELAY + "/", "hosts": [self.host()]})
        result, _lines = self.run_pair(FakeRelay())
        self.assertEqual(result, 0)

    def test_service_unavailable(self):
        relay = FakeRelay(service=[(403, None)])
        result, lines = self.run_pair(relay)
        self.assertEqual((result, lines), (1, [{"v": 1, "error": "service_unavailable"}]))
        self.assertFalse(os.path.exists(self.config_path))

    def test_pairing_busy(self):
        self.write_config({"relay_url": RELAY, "hosts": [self.host()]})
        relay = FakeRelay(create=[(409, {"error": {"code": "capacity_exceeded"}})])
        result, lines = self.run_pair(relay)
        self.assertEqual((result, lines), (1, [{"v": 1, "error": "pairing_busy"}]))

    def test_already_paired(self):
        self.write_config({"relay_url": RELAY, "hosts": [self.host()]})
        relay = FakeRelay(approve=[(409, {"error": {"code": "conflict"}})])
        result, lines = self.run_pair(relay)
        self.assertEqual(result, 1)
        self.assert_error(lines, "already_paired")
        self.assertEqual(relay.keys()[-2:], ["get", "delete_pairing"])

    def test_rejected_host_is_replaced_once_without_delete_self(self):
        self.write_config({"relay_url": RELAY, "hosts": [self.host("old-host")]})
        key = setup.load_or_create_content_key(os.path.dirname(self.config_path))
        relay = FakeRelay(create=[(401, None), (201, {"expires_at": "x"})])
        result, _lines = self.run_pair(relay)
        self.assertEqual(result, 0)
        self.assertNotIn("delete_self", relay.keys())
        self.assertEqual(relay.keys()[:4], ["service", "create", "hosts", "create"])
        hosts = self.read_config()["hosts"]
        self.assertEqual(len(hosts), 1)
        self.assertNotEqual(hosts[0]["host_secret"], "s" * 43)
        self.assertEqual(hosts[0]["workspace_allowlist"], ["w1"])
        # 401 の回復で鍵を作り直さない。
        self.assertEqual(
            setup.load_or_create_content_key(os.path.dirname(self.config_path)), key
        )

    def test_host_rejected_after_recovery(self):
        self.write_config({"relay_url": RELAY, "hosts": [self.host("old-host")]})
        relay = FakeRelay(create=[(401, None)])
        result, lines = self.run_pair(relay)
        self.assertEqual((result, lines), (1, [{"v": 1, "error": "host_rejected"}]))
        self.assertEqual(relay.keys().count("hosts"), 1)

    def test_forbidden_is_not_treated_as_rejected_credentials(self):
        # 403 は relay ではなく Cloudflare などの拒否。有効な host を捨てない
        self.write_config({"relay_url": RELAY, "hosts": [self.host()]})
        relay = FakeRelay(create=[(403, None)])
        result, lines = self.run_pair(relay)
        self.assertEqual((result, lines), (1, [{"v": 1, "error": "relay_error"}]))
        self.assertNotIn("hosts", relay.keys())
        self.assertEqual(self.read_config()["hosts"], [self.host()])

    def test_lost_or_conflicting_approve_response_is_checked_with_get(self):
        approved = (200, {"state": "approved", "link_id": "link-9", "host_id": HOST_ID})
        for response in ((409, {"error": {"code": "conflict"}}), (None, None), (502, None)):
            with self.subTest(response=response):
                self.write_config({"relay_url": RELAY, "hosts": [self.host()]})
                relay = FakeRelay(
                    approve=[response],
                    get=[(200, {"state": "pending"}),
                         (200, {"state": "claimed", "verification_code": CODE}), approved],
                )
                result, lines = self.run_pair(relay)
                self.assertEqual(result, 0)
                self.assertEqual(lines[-1]["result"], "approved")
                self.assertEqual(lines[-1]["link_id"], "link-9")
                self.assertNotIn("delete_pairing", relay.keys())

    def test_config_dir_defaults_to_xdg_config_home_not_the_socket_dir(self):
        xdg = os.path.join(self.tmp.name, "xdg")
        socket = os.path.join(xdg, "herdr", "herdr.sock")
        os.makedirs(os.path.dirname(socket))
        open(socket, "w").close()
        with unittest.mock.patch.dict(
            os.environ, {"XDG_CONFIG_HOME": xdg, "HOME": self.tmp.name}, clear=True
        ):
            result, _lines = self.run_pair(FakeRelay())
        self.assertEqual(result, 0)
        expected = os.path.join(xdg, "herdr", "plugins", "config", setup.PLUGIN_ID, "config.json")
        self.assertEqual(setup.load_config(expected)["hosts"][0]["socket_path"], socket)

    def test_config_dir_without_xdg_is_under_home(self):
        with unittest.mock.patch.dict(os.environ, {"HOME": "/home/u"}, clear=True):
            self.assertEqual(
                setup.default_config_dir(),
                "/home/u/.config/herdr/plugins/config/" + setup.PLUGIN_ID,
            )
            self.assertEqual(setup.default_socket_path(), "/home/u/.config/herdr/herdr.sock")

    def test_unreadable_config_is_config_error(self):
        os.makedirs(self.config_path)  # config.json がディレクトリ
        result, lines = self.run_pair(FakeRelay())
        self.assertEqual((result, lines), (1, [{"v": 1, "error": "config_error"}]))

    def test_unexpected_exception_is_internal_and_cleans_up(self):
        self.write_config({"relay_url": RELAY, "hosts": [self.host()]})
        relay = FakeRelay(get=[RuntimeError("boom")])
        result, lines = self.run_pair(relay)
        self.assertEqual(result, 1)
        self.assert_error(lines, "internal")
        self.assertEqual(relay.keys()[-1], "delete_pairing")

    def test_broken_stdout_does_not_stop_cleanup(self):
        class BrokenStdout:
            def write(self, _text):
                raise BrokenPipeError()

            def flush(self):
                pass

            def fileno(self):
                raise ValueError("no fd")

        relay = FakeRelay()
        result, _lines = self.run_pair(relay, "", stdout=BrokenStdout())
        self.assertEqual(result, 1)
        self.assertEqual(relay.keys()[-1], "delete_pairing")

    def test_nothing_goes_to_stderr_or_plain_stdout(self):
        relay = FakeRelay()
        stderr = io.StringIO()
        with unittest.mock.patch("sys.stderr", stderr):
            result, lines = self.run_pair(relay)
        self.assertEqual(result, 0)
        self.assertEqual(stderr.getvalue(), "")
        self.assertEqual(len(lines), 2)


class BootstrapRecoveryTests(unittest.TestCase):
    def old_host(self):
        return {"socket_path": "/tmp/s.sock", "host_id": "old", "host_secret": "s" * 43}

    def test_rejected_old_credentials_are_treated_as_gone(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "config.json")
            config = {"hosts": [self.old_host()]}
            relay = FakeRelay(delete_self=[(401, None)])
            with unittest.mock.patch("sys.stdout", io.StringIO()):
                host = setup.bootstrap_host(relay, config, path, "/tmp/s.sock", {})
            self.assertEqual(relay.keys(), ["delete_self", "hosts"])
            self.assertEqual(config["hosts"], [host])

    def test_forbidden_delete_keeps_old_credentials(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "config.json")
            config = {"hosts": [self.old_host()]}
            relay = FakeRelay(delete_self=[(403, None)])
            with unittest.mock.patch("sys.stdout", io.StringIO()):
                with self.assertRaises(setup.SetupError):
                    setup.bootstrap_host(relay, config, path, "/tmp/s.sock", {})
            self.assertEqual(relay.keys(), ["delete_self"])
            self.assertEqual(config["hosts"], [self.old_host()])


if __name__ == "__main__":
    unittest.main()
