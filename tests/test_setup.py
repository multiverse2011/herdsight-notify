"""Unit tests for setup.py. No network, no real herdr, no clipboard."""

import contextlib
import http.client
import io
import json
import os
import subprocess
import sys
import tempfile
import threading
import types
import unittest
import unittest.mock
import uuid

import setup
from tests.test_pair import FakeRelay


class FakeResponse:
    def __init__(self, status, payload):
        self.status = status
        self._body = json.dumps(payload).encode("utf-8") if payload is not None else b""

    def read(self):
        return self._body

    def close(self):
        pass


class FakeOpener:
    def __init__(self, responses):
        self.responses = list(responses)
        self.calls = []

    def __call__(self, req, timeout=None):
        self.calls.append(req)
        if not self.responses:
            raise AssertionError("unexpected request: %s %s" % (req.get_method(), req.full_url))
        status, payload = self.responses.pop(0)
        return FakeResponse(status, payload)

    @staticmethod
    def headers(req):
        return {key.lower(): value for key, value in req.headers.items()}


HOST = {
    "socket_path": "/tmp/herdr-test.sock",
    "workspace_allowlist": [],
    "host_id": "22222222-2222-4222-8222-222222222222",
    "host_secret": "s" * 43,
    "host_expires_at": "2027-01-01T00:00:00.000Z",
}


class PairStringTests(unittest.TestCase):
    def test_round_trip(self):
        pair_id = str(uuid.uuid4())
        secret = "a" * 43
        self.assertEqual(setup.parse_pair_string("%s.%s" % (pair_id, secret)), (pair_id, secret))

    def test_rejects_malformed_strings(self):
        for value in (
            "no-separator",
            "not-a-uuid." + "a" * 43,
            str(uuid.uuid4()) + ".short",
            str(uuid.uuid4()) + "." + "a" * 42,
            str(uuid.uuid4()) + "." + "!" * 43,
        ):
            with self.assertRaises(ValueError):
                setup.parse_pair_string(value)

    def test_accepts_an_optional_content_key(self):
        pair_id = str(uuid.uuid4())
        secret = "a" * 43
        key = "b" * 43
        self.assertEqual(
            setup.parse_pair_string("%s.%s.%s" % (pair_id, secret, key)),
            (pair_id, secret),
        )
        with self.assertRaises(ValueError):
            setup.parse_pair_string("%s.%s.%s" % (pair_id, secret, "short"))
        with self.assertRaisesRegex(ValueError, "2 or 3 parts"):
            setup.parse_pair_string("a.b.c.d")

    def test_rejects_non_v4_uuid(self):
        with self.assertRaises(ValueError):
            setup.parse_pair_string("11111111-1111-1111-8111-111111111111." + "a" * 43)

    def test_pair_id_is_validated_as_canonical_uuid_v4(self):
        pair_id = str(uuid.uuid4())
        self.assertEqual(setup.parse_pair_id(pair_id), pair_id)
        for value in ("../self", "11111111-1111-1111-8111-111111111111", "{" + pair_id + "}"):
            with self.assertRaises(ValueError):
                setup.parse_pair_id(value)


class SecretTests(unittest.TestCase):
    def test_secret_is_43_base64url_characters(self):
        secret = setup.random_secret()
        self.assertEqual(len(secret), 43)
        self.assertRegex(secret, setup.BASE64URL)
        self.assertNotEqual(secret, setup.random_secret())


class ContentKeyTests(unittest.TestCase):
    def test_created_once_as_32_bytes_with_mode_0600(self):
        with tempfile.TemporaryDirectory() as tmp:
            directory = os.path.join(tmp, "config")
            key = setup.load_or_create_content_key(directory)
            self.assertEqual(len(key), 32)
            path = setup.content_key_path(directory)
            self.assertEqual(os.stat(path).st_mode & 0o777, 0o600)
            self.assertEqual(setup.load_or_create_content_key(directory), key)

    def test_concurrent_creation_returns_the_key_that_was_published(self):
        real_fdopen = os.fdopen
        created = threading.Event()
        release = threading.Event()
        lock = threading.Lock()
        first = [True]

        def fdopen(fd, mode="r", *args, **kwargs):
            with lock:
                take = first[0]
                first[0] = False
            if take:
                created.set()
                release.wait(5)
            return real_fdopen(fd, mode, *args, **kwargs)

        with tempfile.TemporaryDirectory() as tmp:
            results = []

            def create():
                results.append(setup.load_or_create_content_key(tmp))

            with unittest.mock.patch("setup.os.fdopen", side_effect=fdopen):
                a = threading.Thread(target=create)
                a.start()
                self.assertTrue(created.wait(5))
                b = threading.Thread(target=create)
                b.start()
                b.join(5)
                release.set()
                a.join(5)

            with open(setup.content_key_path(tmp), "rb") as handle:
                published = handle.read()
            self.assertEqual(len(results), 2)
            self.assertEqual(results, [published, published])

    def test_creating_a_key_removes_an_old_temp_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            stale = os.path.join(tmp, ".content-key.old.tmp")
            with open(stale, "wb") as handle:
                handle.write(b"partial")
            os.utime(stale, (0, 0))
            setup.load_or_create_content_key(tmp)
            self.assertFalse(os.path.exists(stale))

    def test_creating_a_key_leaves_a_fresh_temp_file_alone(self):
        with tempfile.TemporaryDirectory() as tmp:
            fresh = os.path.join(tmp, ".content-key.fresh.tmp")
            with open(fresh, "wb") as handle:
                handle.write(b"partial")
            setup.load_or_create_content_key(tmp)
            self.assertTrue(os.path.exists(fresh))

    def test_a_short_key_file_is_replaced(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = setup.content_key_path(tmp)
            with open(path, "wb") as handle:
                handle.write(b"short")
            key = setup.load_or_create_content_key(tmp)
            self.assertEqual(len(key), 32)
            with open(path, "rb") as handle:
                self.assertEqual(handle.read(), key)
            self.assertEqual(os.stat(path).st_mode & 0o777, 0o600)

    def test_content_key_command_prints_one_json_line_and_reuses_the_key(self):
        with tempfile.TemporaryDirectory() as tmp:
            with unittest.mock.patch.dict(
                os.environ, {"HERDR_PLUGIN_CONFIG_DIR": tmp}, clear=True
            ):
                first = io.StringIO()
                self.assertEqual(setup.run_content_key(first), 0)
                second = io.StringIO()
                self.assertEqual(setup.run_content_key(second), 0)
            line = json.loads(first.getvalue())
            self.assertEqual(line["v"], 1)
            self.assertRegex(line["content_key"], setup.BASE64URL)
            self.assertEqual(json.loads(second.getvalue()), line)
            self.assertEqual(len(first.getvalue().splitlines()), 1)

    def test_content_key_command_reports_a_missing_config_dir(self):
        with tempfile.TemporaryDirectory() as tmp, unittest.mock.patch.dict(
            os.environ, {"HERDR_PLUGIN_CONFIG_DIR": os.path.join(tmp, "none")}, clear=True
        ):
            output = io.StringIO()
            self.assertEqual(setup.run_content_key(output), 1)
        self.assertEqual(json.loads(output.getvalue()), {"v": 1, "error": "config_error"})


class ConfigFileTests(unittest.TestCase):
    def test_save_config_is_0600(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "config", "config.json")
            setup.save_config(path, {"relay_url": "https://relay.test", "hosts": [HOST]})
            self.assertEqual(os.stat(path).st_mode & 0o777, 0o600)
            with open(path, encoding="utf-8") as handle:
                self.assertEqual(json.load(handle)["hosts"][0]["host_id"], HOST["host_id"])

    def test_save_config_rewrites_existing_permissions(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "config.json")
            with open(path, "w", encoding="utf-8") as handle:
                handle.write("{}")
            os.chmod(path, 0o644)
            setup.save_config(path, {"relay_url": "https://relay.test"})
            self.assertEqual(os.stat(path).st_mode & 0o777, 0o600)

    def test_missing_config_is_empty(self):
        with tempfile.TemporaryDirectory() as tmp:
            self.assertEqual(setup.load_config(os.path.join(tmp, "config.json")), {})


class ConfigDirTests(unittest.TestCase):
    def test_command_output_must_be_nonempty_and_absolute(self):
        for output in (b"", b"relative/config\n"):
            with self.subTest(output=output):
                with unittest.mock.patch.dict(
                    os.environ,
                    {"HERDR_PLUGIN_CONFIG_DIR": "", "HERDR_BIN_PATH": "herdr"},
                    clear=True,
                ), unittest.mock.patch(
                    "setup.subprocess.run",
                    return_value=types.SimpleNamespace(stdout=output),
                ):
                    with self.assertRaises(setup.SetupError):
                        setup.config_dir()

    def test_environment_override_must_be_absolute(self):
        with unittest.mock.patch.dict(
            os.environ, {"HERDR_PLUGIN_CONFIG_DIR": "relative/config"}, clear=True
        ):
            with self.assertRaises(setup.SetupError):
                setup.config_dir()


class PairingPollingTests(unittest.TestCase):
    def test_temporary_poll_errors_keep_pairing_alive(self):
        class Client:
            def __init__(self):
                self.get_calls = 0

            def request(self, method, _path, body=None, host=None, idempotency_key=None):
                if method == "POST":
                    return 201, {}
                self.get_calls += 1
                if self.get_calls == 1:
                    return None, None
                if self.get_calls == 2:
                    return 503, None
                return 200, {"state": "approved"}

        client = Client()
        with contextlib.redirect_stdout(io.StringIO()), unittest.mock.patch(
            "setup.time.monotonic", return_value=0
        ), unittest.mock.patch("setup.time.sleep") as sleep, unittest.mock.patch(
            "setup.finish_approved", return_value=0
        ), unittest.mock.patch("setup.copy_to_clipboard", return_value=True):
            result = setup.run_pairing(client, {}, "/tmp/config.json", HOST)

        self.assertEqual(result, 0)
        self.assertEqual(client.get_calls, 3)
        self.assertEqual(sleep.call_count, 2)

    def test_invalid_pairing_string_returns_user_error_without_traceback(self):
        class Client:
            def request(self, *_args, **_kwargs):
                raise AssertionError("must not post an invalid pairing string")

        output = io.StringIO()
        pair_id = str(uuid.uuid4())
        with contextlib.redirect_stdout(output):
            result = setup.cmd_approve(Client(), {}, HOST, pair_id + ".short", "12345678")

        self.assertEqual(result, 1)
        self.assertIn("Invalid pairing string", output.getvalue())

    def test_approve_and_cancel_reject_invalid_pair_ids_before_request(self):
        class Client:
            def request(self, *_args, **_kwargs):
                raise AssertionError("must not delete an invalid pair ID")

        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            approve_result = setup.cmd_approve(Client(), {}, HOST, "../self", "12345678")
            cancel_result = setup.cmd_cancel(Client(), HOST, "../self")

        self.assertEqual(approve_result, 1)
        self.assertEqual(cancel_result, 1)
        self.assertIn("Invalid pair ID", output.getvalue())

    def test_cancel_uses_validated_uuid_in_relay_path(self):
        class Client:
            def __init__(self):
                self.path = None
                self.method = None

            def request(self, method, path, body=None, host=None, idempotency_key=None):
                self.method = method
                self.path = path
                return 204, None

        client = Client()
        pair_id = str(uuid.uuid4())
        with contextlib.redirect_stdout(io.StringIO()):
            result = setup.cmd_cancel(client, HOST, pair_id)

        self.assertEqual(result, 0)
        self.assertEqual(client.method, "DELETE")
        self.assertEqual(client.path, "/v1/pairings/%s" % pair_id)


class RelayClientTests(unittest.TestCase):
    def test_post_sends_host_auth_dev_access_and_idempotency_key(self):
        opener = FakeOpener([(201, {"id": HOST["host_id"]})])
        client = setup.RelayClient(
            "https://relay.test/", "dev-access", opener=opener
        )
        status, payload = client.request(
            "POST", "/v1/hosts", {"hello": "world"}, host=HOST
        )
        self.assertEqual(status, 201)
        self.assertEqual(payload, {"id": HOST["host_id"]})

        req = opener.calls[0]
        headers = opener.headers(req)
        self.assertEqual(req.get_method(), "POST")
        self.assertEqual(req.full_url, "https://relay.test/v1/hosts")
        self.assertEqual(
            headers["authorization"],
            "Bearer host.%s.%s" % (HOST["host_id"], HOST["host_secret"]),
        )
        self.assertEqual(headers["x-relay-dev-access"], "dev-access")
        self.assertEqual(json.loads(req.data), {"hello": "world"})
        uuid.UUID(headers["idempotency-key"])
        self.assertEqual(uuid.UUID(headers["idempotency-key"]).version, 4)

    def test_get_has_no_idempotency_key(self):
        opener = FakeOpener([(200, {"terms_version": "dev-1"})])
        client = setup.RelayClient("https://relay.test", opener=opener)
        client.get("/v1/service-info")
        headers = opener.headers(opener.calls[0])
        self.assertNotIn("idempotency-key", headers)
        self.assertNotIn("x-relay-dev-access", headers)

    def test_network_error_returns_no_status(self):
        def opener(req, timeout=None):
            raise OSError("offline")

        client = setup.RelayClient("https://relay.test", opener=opener)
        self.assertEqual(client.get("/v1/service-info"), (None, None))

    def test_incomplete_response_read_returns_no_status(self):
        class IncompleteResponse:
            status = 200

            def read(self):
                raise http.client.IncompleteRead(b"partial")

            def close(self):
                pass

        client = setup.RelayClient(
            "https://relay.test", opener=lambda req, timeout=None: IncompleteResponse()
        )
        self.assertEqual(client.get("/v1/service-info"), (None, None))


class RequestRetryTests(unittest.TestCase):
    def test_retries_rate_limit_with_same_idempotency_key(self):
        opener = FakeOpener(
            [
                (429, {"error": {"retry_after_seconds": 0}}),
                (201, {"id": HOST["host_id"]}),
            ]
        )
        client = setup.RelayClient("https://relay.test", opener=opener)
        key = str(uuid.uuid4())

        with unittest.mock.patch("setup.time.sleep") as sleep, unittest.mock.patch(
            "setup.random.uniform", return_value=0.25
        ):
            status, payload = setup.request_with_retry(
                client,
                "POST",
                "/v1/hosts",
                {"id": HOST["host_id"]},
                idempotency_key=key,
            )

        self.assertEqual(status, 201)
        self.assertEqual(payload, {"id": HOST["host_id"]})
        self.assertEqual(len(opener.calls), 2)
        headers = [FakeOpener.headers(call) for call in opener.calls]
        self.assertEqual([header["idempotency-key"] for header in headers], [key, key])
        sleep.assert_called_once_with(0.25)


class BootstrapTests(unittest.TestCase):
    def setUp(self):
        stdout = unittest.mock.patch("sys.stdout", io.StringIO())
        stdout.start()
        self.addCleanup(stdout.stop)

    def test_bootstrap_saves_host_credentials_0600(self):
        opener = FakeOpener(
            [(201, {"id": "unused", "expires_at": "2027-01-01T00:00:00.000Z"})]
        )
        client = setup.RelayClient("https://relay.test", opener=opener)
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "config.json")
            config = {}
            host = setup.bootstrap_host(
                client,
                config,
                path,
                "/tmp/herdr-test.sock",
                {"terms_version": "dev-1", "privacy_notice_version": "dev-1"},
            )
            self.assertEqual(len(host["host_secret"]), 43)
            self.assertEqual(
                config["hosts"][0]["host_id"], host["host_id"]
            )
            self.assertEqual(os.stat(path).st_mode & 0o777, 0o600)
            body = json.loads(opener.calls[0].data)
            self.assertEqual(body["id"], host["host_id"])
            self.assertEqual(body["secret"], host["host_secret"])
            self.assertEqual(body["terms_version"], "dev-1")

    def test_failed_replacement_post_removes_deleted_credentials_for_retry(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "config.json")
            config = {"relay_url": "https://relay.test", "hosts": [dict(HOST)]}
            setup.save_config(path, config)
            failed_opener = FakeOpener(
                [
                    (204, None),
                    (503, {"error": {"code": "unavailable"}}),
                ]
            )
            failed_client = setup.RelayClient("https://relay.test", opener=failed_opener)

            with unittest.mock.patch("setup.time.sleep"):
                with self.assertRaises(setup.SetupError):
                    setup.bootstrap_host(
                        failed_client, config, path, HOST["socket_path"],
                        {"terms_version": "dev-1", "privacy_notice_version": "dev-1"},
                    )

            with open(path, encoding="utf-8") as handle:
                self.assertEqual(json.load(handle)["hosts"], [])
            self.assertEqual(
                [call.get_method() for call in failed_opener.calls],
                ["DELETE", "POST"],
            )
            retry_opener = FakeOpener([(201, {"expires_at": "2027-01-01T00:00:00.000Z"})])
            retry_client = setup.RelayClient("https://relay.test", opener=retry_opener)
            setup.bootstrap_host(
                retry_client, config, path, HOST["socket_path"],
                {"terms_version": "dev-1", "privacy_notice_version": "dev-1"},
            )
            self.assertEqual([call.get_method() for call in retry_opener.calls], ["POST"])
            self.assertEqual(len(config["hosts"]), 1)


class RelayUrlTests(unittest.TestCase):
    def args(self, relay_url=None, dev_access=None):
        return types.SimpleNamespace(relay_url=relay_url, dev_access=dev_access)

    def test_requires_https(self):
        with self.assertRaises(setup.SetupError):
            setup.resolve_relay(self.args("http://relay.test"), {})

    def test_accepts_https(self):
        with unittest.mock.patch.dict(os.environ, {}, clear=True):
            self.assertEqual(
                setup.resolve_relay(self.args("https://relay.test"), {}),
                ("https://relay.test", None),
            )

    def test_defaults_to_production_relay(self):
        with unittest.mock.patch.dict(os.environ, {}, clear=True):
            self.assertEqual(
                setup.resolve_relay(self.args(), {}), (setup.DEFAULT_RELAY_URL, None)
            )

    def test_override_order_is_argument_env_config(self):
        env = {
            "HERDSIGHT_RELAY_URL": "https://env.test",
            "HERDSIGHT_RELAY_DEV_ACCESS": "from-env",
        }
        saved = {"relay_url": "https://config.test", "dev_access": "from-config"}
        with unittest.mock.patch.dict(os.environ, {}, clear=True):
            self.assertEqual(
                setup.resolve_relay(self.args(), saved),
                ("https://config.test", "from-config"),
            )
        with unittest.mock.patch.dict(os.environ, env, clear=True):
            self.assertEqual(
                setup.resolve_relay(self.args(), {}), ("https://env.test", "from-env")
            )
            self.assertEqual(
                setup.resolve_relay(self.args("https://arg.test", "from-arg"), {}),
                ("https://arg.test", "from-arg"),
            )

    def test_a_different_relay_than_the_saved_one_is_refused(self):
        saved = {"relay_url": "https://config.test"}
        with unittest.mock.patch.dict(os.environ, {}, clear=True):
            with self.assertRaises(setup.SetupError):
                setup.resolve_relay(self.args("https://other.test"), saved)
            self.assertEqual(
                setup.resolve_relay(self.args("https://config.test/"), saved)[0],
                "https://config.test/",
            )
        with unittest.mock.patch.dict(
            os.environ, {"HERDSIGHT_RELAY_URL": "https://other.test"}, clear=True
        ):
            with self.assertRaises(setup.SetupError):
                setup.resolve_relay(self.args(), saved)

    def test_uninstall_uses_the_saved_relay(self):
        saved = {"relay_url": "https://config.test"}
        with unittest.mock.patch.dict(os.environ, {}, clear=True):
            self.assertEqual(
                setup.resolve_relay(self.args("https://other.test"), saved, prefer_saved=True)[0],
                "https://config.test",
            )


class SocketPathTests(unittest.TestCase):
    def resolve(self, cli=None, env=None, default_exists=False, answer=None):
        with tempfile.TemporaryDirectory() as home:
            default = os.path.join(home, ".config", "herdr", "herdr.sock")
            if default_exists:
                os.makedirs(os.path.dirname(default))
                open(default, "w").close()
            environ = {"HOME": home}
            if env:
                environ["HERDR_SOCKET_PATH"] = env
            with unittest.mock.patch.dict(os.environ, environ, clear=True), \
                    unittest.mock.patch("builtins.input", return_value=answer) as prompt:
                return setup.socket_path(cli), default, prompt.called

    def test_argument_wins_over_environment(self):
        value, _default, asked = self.resolve(cli="/tmp/a.sock", env="/tmp/b.sock")
        self.assertEqual((value, asked), ("/tmp/a.sock", False))

    def test_environment_wins_over_default(self):
        value, _default, asked = self.resolve(env="/tmp/b.sock", default_exists=True)
        self.assertEqual((value, asked), ("/tmp/b.sock", False))

    def test_existing_default_socket_is_used_without_asking(self):
        value, default, asked = self.resolve(default_exists=True)
        self.assertEqual((value, asked), (default, False))

    def test_asks_only_when_nothing_is_found(self):
        value, _default, asked = self.resolve(answer="/tmp/c.sock")
        self.assertEqual((value, asked), ("/tmp/c.sock", True))
        with self.assertRaises(setup.SetupError):
            self.resolve(answer="relative.sock")


class ApproveFlowTests(unittest.TestCase):
    class Client:
        """応答を順に返し、最後の応答を繰り返す。"""

        def __init__(self, status=200, payload=None, responses=None):
            self.calls = []
            self.responses = list(responses or [(status, payload)])

        def request(self, method, path, body=None, host=None, idempotency_key=None):
            self.calls.append((method, path, body))
            return self.responses.pop(0) if len(self.responses) > 1 else self.responses[0]

    def run_flow(self, answer, client, code="12345678"):
        pair_id = str(uuid.uuid4())
        side_effect = answer if answer in (EOFError, KeyboardInterrupt) else None
        with contextlib.redirect_stdout(io.StringIO()) as output, unittest.mock.patch(
            "builtins.input", return_value=answer, side_effect=side_effect
        ), unittest.mock.patch("setup.finish_approved", return_value=0) as finish:
            result = setup.approve_flow(
                client, {}, "/tmp/config.json", HOST, pair_id, code
            )
        return result, pair_id, finish, output.getvalue()

    def test_yes_sends_the_relay_code(self):
        client = self.Client(200, {"link_id": "l"})
        result, pair_id, finish, output = self.run_flow("y", client)
        self.assertEqual(result, 0)
        self.assertIn("1234 5678", output)
        self.assertEqual(
            client.calls,
            [("POST", "/v1/pairings/%s/approve" % pair_id, {"verification_code": "12345678"})],
        )
        finish.assert_called_once()

    def test_default_no_and_eof_cancel_with_delete(self):
        for answer in ("", "n", EOFError, KeyboardInterrupt):
            with self.subTest(answer=answer):
                client = self.Client(204)
                result, pair_id, finish, _output = self.run_flow(answer, client)
                self.assertEqual(result, 1)
                self.assertEqual(client.calls, [("DELETE", "/v1/pairings/%s" % pair_id, None)])
                finish.assert_not_called()

    def test_invalid_relay_code_is_not_submitted(self):
        client = self.Client()
        result, _pair_id, _finish, _output = self.run_flow("y", client, code="1234")
        self.assertEqual(result, 1)
        self.assertEqual(client.calls, [])

    def test_rejected_approve_fails(self):
        client = self.Client(responses=[
            (400, {"error": {"code": "invalid_request"}}),
        ])
        result, _pair_id, finish, output = self.run_flow("y", client)
        self.assertEqual(result, 1)
        self.assertEqual([call[0] for call in client.calls], ["POST"])
        self.assertIn("invalid_request", output)
        finish.assert_not_called()

    def test_conflict_while_still_claimed_means_already_paired(self):
        client = self.Client(responses=[
            (409, {"error": {"code": "conflict"}}),
            (200, {"state": "claimed"}),
            (204, None),
        ])
        result, pair_id, finish, output = self.run_flow("y", client)
        self.assertEqual(result, 1)
        self.assertEqual([call[0] for call in client.calls], ["POST", "GET", "DELETE"])
        self.assertIn("already paired", output)
        finish.assert_not_called()

    def test_lost_approve_response_that_succeeded_is_success(self):
        approved = {"state": "approved", "link_id": "l", "host_id": HOST["host_id"]}
        for lost in ((None, None), (503, None), (409, {"error": {"code": "conflict"}})):
            with self.subTest(lost=lost):
                client = self.Client(responses=[lost, (200, approved)])
                result, _pair_id, finish, _output = self.run_flow("y", client)
                self.assertEqual(result, 0)
                self.assertEqual(finish.call_args[0][4], approved)


class PairingStringOutputTests(unittest.TestCase):
    def test_pairing_string_is_printed_and_copied(self):
        class Client:
            def request(self, method, _path, body=None, host=None, idempotency_key=None):
                if method == "POST":
                    self.body = body
                    return 201, {}
                return 410, None

        client = Client()
        with contextlib.redirect_stdout(io.StringIO()) as output, unittest.mock.patch(
            "setup.copy_to_clipboard", return_value=False
        ) as copy:
            self.assertEqual(setup.run_pairing(client, {}, "/tmp/config.json", HOST), 1)
        pair_string = "%s.%s" % (client.body["pair_id"], client.body["claim_secret"])
        copy.assert_called_once_with(pair_string)
        self.assertIn(pair_string, output.getvalue())

    def test_clipboard_failure_is_not_fatal(self):
        for error in (OSError("no pbcopy"), setup.subprocess.TimeoutExpired("pbcopy", 5)):
            with self.subTest(error=error), unittest.mock.patch(
                "setup.subprocess.run", side_effect=error
            ):
                self.assertFalse(setup.copy_to_clipboard("text"))


class FinishApprovedTests(unittest.TestCase):
    def finish(self, host, workspaces):
        config = {"hosts": [host]}
        with tempfile.TemporaryDirectory() as tmp, contextlib.redirect_stdout(io.StringIO()):
            setup.finish_approved(
                None, config, os.path.join(tmp, "config.json"), host,
                {"link_id": "l", "host_id": HOST["host_id"]}, workspaces,
            )
        return host["workspace_allowlist"]

    def test_allowlist_is_kept_unless_given(self):
        self.assertEqual(self.finish(dict(HOST), None), [])
        self.assertEqual(self.finish(dict(HOST, workspace_allowlist=["w1"]), None), ["w1"])
        self.assertEqual(self.finish(dict(HOST), ["w2"]), ["w2"])


class HostSelectionTests(unittest.TestCase):
    def test_setup_does_not_reuse_a_host_for_another_socket(self):
        other = dict(HOST, socket_path="/tmp/other.sock", host_id=str(uuid.uuid4()))
        config = {"hosts": [other]}
        self.assertIsNone(setup.host_for_socket(config, "/tmp/herdr-test.sock"))
        self.assertIs(setup.host_for_socket(config, "/tmp/other.sock"), other)

    def test_host_selection_skips_malformed_entries(self):
        config = {"hosts": [None, "bad", HOST]}
        self.assertIs(setup.host_for_socket(config, HOST["socket_path"]), HOST)


class RunPairingRecoveryTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.path = os.path.join(tmp.name, "config.json")
        for patcher in (
            unittest.mock.patch("setup.copy_to_clipboard", return_value=False),
            unittest.mock.patch("setup.time.sleep"),
            unittest.mock.patch("sys.stdout", io.StringIO()),
        ):
            patcher.start()
            self.addCleanup(patcher.stop)

    def test_rejected_host_is_recreated_once_and_keeps_allowlist(self):
        old = dict(HOST, workspace_allowlist=["w1"])
        config = {"relay_url": "https://relay.test", "hosts": [old]}
        relay = FakeRelay(
            create=[(401, None), (201, {})],
            get=[(200, {"state": "approved", "link_id": "l"})],
        )
        result = setup.run_pairing(relay, config, self.path, old, service_info={})
        self.assertEqual(result, 0)
        self.assertEqual(relay.keys(), ["create", "hosts", "create", "get"])
        self.assertEqual(len(config["hosts"]), 1)
        self.assertNotEqual(config["hosts"][0]["host_secret"], HOST["host_secret"])
        self.assertEqual(config["hosts"][0]["workspace_allowlist"], ["w1"])

    def test_forbidden_does_not_drop_the_host(self):
        config = {"relay_url": "https://relay.test", "hosts": [dict(HOST)]}
        relay = FakeRelay(create=[(403, None)])
        result = setup.run_pairing(relay, config, self.path, config["hosts"][0], service_info={})
        self.assertEqual(result, 1)
        self.assertEqual(relay.keys(), ["create"])
        self.assertEqual(config["hosts"], [HOST])

    def test_ctrl_c_while_waiting_cancels_the_pairing(self):
        relay = FakeRelay(get=[KeyboardInterrupt()])
        result = setup.run_pairing(relay, {}, self.path, dict(HOST))
        self.assertEqual(result, 1)
        self.assertEqual(relay.keys(), ["create", "get", "delete_pairing"])


class MainTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.dir = tmp.name
        self.socket = os.path.join(tmp.name, "herdr.sock")
        open(self.socket, "w").close()
        self.config_path = os.path.join(tmp.name, "config", "config.json")
        env = unittest.mock.patch.dict(os.environ, {
            "HOME": tmp.name,
            "HERDR_SOCKET_PATH": self.socket,
            "HERDR_PLUGIN_CONFIG_DIR": os.path.dirname(self.config_path),
            "HERDR_PLUGIN_STATE_DIR": os.path.join(tmp.name, "state"),
        }, clear=True)
        env.start()
        self.addCleanup(env.stop)
        for patcher in (
            unittest.mock.patch("setup.copy_to_clipboard", return_value=True),
            unittest.mock.patch("setup.time.sleep"),
        ):
            patcher.start()
            self.addCleanup(patcher.stop)

    def run_main(self, argv, relay, answers=("y",)):
        answers = list(answers)
        with contextlib.redirect_stdout(io.StringIO()) as output, unittest.mock.patch(
            "setup.RelayClient", return_value=relay
        ) as client_class, unittest.mock.patch(
            "builtins.input", side_effect=lambda _prompt="": answers.pop(0)
        ):
            result = setup.main(argv)
        return result, output.getvalue(), client_class

    def test_setup_flow_bootstraps_pairs_and_saves_config(self):
        relay = FakeRelay()
        result, output, client_class = self.run_main([], relay, answers=("y", "y"))
        self.assertEqual(result, 0)
        self.assertEqual(
            relay.keys(), ["service", "hosts", "create", "get", "get", "approve"]
        )
        client_class.assert_called_once_with(setup.DEFAULT_RELAY_URL, None)
        self.assertIn("Using herdr socket: %s" % self.socket, output)
        self.assertIn("Paired.", output)
        pair_line = next(
            line for line in output.splitlines() if line.startswith("Pairing code")
        )
        # 0.2.0 までのアプリは2つ目以降を claim secret として送るので、手動の文字列は2分割のまま。
        self.assertEqual(len(pair_line.rsplit(": ", 1)[1].split(".")), 2)
        self.assertEqual(
            os.stat(setup.content_key_path(os.path.dirname(self.config_path))).st_mode
            & 0o777,
            0o600,
        )
        config = setup.load_config(self.config_path)
        self.assertEqual(config["relay_url"], setup.DEFAULT_RELAY_URL)
        self.assertEqual(config["hosts"][0]["socket_path"], self.socket)
        self.assertEqual(config["hosts"][0]["workspace_allowlist"], [])
        self.assertEqual(os.stat(self.config_path).st_mode & 0o777, 0o600)

    def test_setup_declined_terms_preserves_local_state(self):
        relay = FakeRelay()
        result, output, _client = self.run_main([], relay, answers=("n",))
        self.assertEqual(result, 1)
        self.assertEqual(relay.keys(), ["service"])
        self.assertIn("https://relay.test/terms", output)
        self.assertIn("https://relay.test/privacy", output)
        self.assertFalse(os.path.exists(self.config_path))

    def test_setup_refuses_another_relay_before_any_request(self):
        setup.save_config(self.config_path, {"relay_url": "https://saved.test", "hosts": [HOST]})
        relay = FakeRelay()
        result, output, _client = self.run_main(["--relay-url", "https://other.test"], relay)
        self.assertEqual(result, 1)
        self.assertEqual(relay.keys(), [])
        self.assertIn("run uninstall first", output)
        self.assertEqual(setup.load_config(self.config_path)["relay_url"], "https://saved.test")

    def test_uninstall_asks_first_and_keeps_everything_on_no(self):
        setup.save_config(self.config_path, {"relay_url": "https://saved.test", "hosts": [HOST]})
        relay = FakeRelay()
        result, output, _client = self.run_main(["uninstall"], relay, answers=("",))
        self.assertEqual(result, 1)
        self.assertEqual(relay.keys(), [])
        self.assertIn("Nothing was removed", output)
        self.assertTrue(os.path.exists(self.config_path))

    def test_uninstall_yes_skips_the_question_and_uses_the_saved_relay(self):
        setup.save_config(self.config_path, {"relay_url": "https://saved.test", "hosts": [HOST]})
        relay = FakeRelay()
        with unittest.mock.patch.dict(os.environ, {"HERDSIGHT_RELAY_URL": "https://other.test"}):
            result, _output, client_class = self.run_main(["uninstall", "--yes"], relay, answers=())
        self.assertEqual(result, 0)
        client_class.assert_called_once_with("https://saved.test", None)
        self.assertEqual(relay.keys(), ["delete_self"])
        self.assertFalse(os.path.exists(self.config_path))


class PaneEntrypointTests(unittest.TestCase):
    """`python3 setup.py` を pane と同じ環境で動かし、閉じる前に Enter を待つことを確かめる。"""

    def run_script(self, config_dir):
        env = {
            "PATH": os.environ.get("PATH", ""),
            "HOME": config_dir,
            "HERDR_PLUGIN_ENTRYPOINT_ID": "setup",
            "HERDR_PLUGIN_CONFIG_DIR": config_dir,
        }
        return subprocess.run(
            [sys.executable, "-I", setup.__file__],
            input="\n",
            env=env,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            universal_newlines=True,
            timeout=30,
        )

    def test_waits_for_enter_after_a_setup_error(self):
        proc = self.run_script("relative/config")
        self.assertEqual(proc.returncode, 1)
        self.assertIn("plugin config dir must be absolute", proc.stdout)
        self.assertIn("Press Enter to close.", proc.stdout)

    def test_waits_for_enter_after_an_unexpected_exception(self):
        with tempfile.TemporaryDirectory() as tmp:
            os.makedirs(os.path.join(tmp, "config.json"))  # 読めない config
            proc = self.run_script(tmp)
        self.assertEqual(proc.returncode, 1)
        self.assertIn("Traceback", proc.stdout)
        self.assertIn("Press Enter to close.", proc.stdout)


class UninstallTests(unittest.TestCase):
    def setUp(self):
        stdout = unittest.mock.patch("sys.stdout", io.StringIO())
        stdout.start()
        self.addCleanup(stdout.stop)

    def test_removes_config_state_and_lock_and_calls_relay(self):
        opener = FakeOpener([(204, None)])
        client = setup.RelayClient("https://relay.test", opener=opener)
        config = {"relay_url": "https://relay.test", "hosts": [dict(HOST)]}
        with tempfile.TemporaryDirectory() as tmp:
            config_dir = os.path.join(tmp, "config")
            state_dir = os.path.join(tmp, "state")
            os.makedirs(config_dir)
            os.makedirs(state_dir)
            config_path = os.path.join(config_dir, "config.json")
            setup.save_config(config_path, config)
            key_path = setup.content_key_path(config_dir)
            setup.load_or_create_content_key(config_dir)
            temp_key = os.path.join(config_dir, ".content-key.stale.tmp")
            with open(temp_key, "wb") as handle:
                handle.write(b"partial")
            for name in ("state.json", "state.lock", "state.json.corrupt-123"):
                with open(os.path.join(state_dir, name), "w", encoding="utf-8") as handle:
                    handle.write("{}")
            spool = os.path.join(state_dir, "spool")
            os.makedirs(spool)
            with open(os.path.join(spool, "event.json"), "w", encoding="utf-8") as handle:
                handle.write("{}")

            self.assertEqual(
                setup.cmd_uninstall(client, config, config_path, state_directory=state_dir),
                0,
            )

            self.assertFalse(os.path.exists(config_path))
            self.assertFalse(os.path.exists(key_path))
            self.assertFalse(os.path.exists(temp_key))
            self.assertEqual(os.listdir(state_dir), [])
            req = opener.calls[0]
            self.assertEqual(req.get_method(), "DELETE")
            self.assertTrue(req.full_url.endswith("/v1/self"))

    def test_uninstall_removes_every_host(self):
        opener = FakeOpener([(204, None), (204, None)])
        client = setup.RelayClient("https://relay.test", opener=opener)
        other = dict(HOST, socket_path="/tmp/other.sock", host_id=str(uuid.uuid4()))
        config = {"relay_url": "https://relay.test", "hosts": [dict(HOST), other]}
        with tempfile.TemporaryDirectory() as tmp:
            config_path = os.path.join(tmp, "config.json")
            setup.save_config(config_path, config)
            self.assertEqual(
                setup.cmd_uninstall(
                    client, config, config_path, state_directory=os.path.join(tmp, "state")
                ),
                0,
            )
            self.assertEqual(len(opener.calls), 2)

    def test_uninstall_works_without_credentials(self):
        with tempfile.TemporaryDirectory() as tmp:
            config_path = os.path.join(tmp, "config.json")
            state_dir = os.path.join(tmp, "state")
            os.makedirs(state_dir)
            self.assertEqual(
                setup.cmd_uninstall(None, {}, config_path, state_directory=state_dir),
                0,
            )
            self.assertFalse(os.path.exists(config_path))


if __name__ == "__main__":
    unittest.main()
