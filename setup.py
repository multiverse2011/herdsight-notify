#!/usr/bin/env python3
"""Pairing and uninstall helper for the Herdsight herdr plugin.

Run it from herdr: herdr plugin pane open --plugin herdsight.notify --entrypoint setup
The Herdsight app runs `setup.py pair --relay-url <URL>` over SSH instead.

Standard library only (Python 3.9+). Credentials are written only to
HERDR_PLUGIN_CONFIG_DIR (or `herdr plugin config-dir`), never to the plugin root.
"""

import argparse
import base64
import contextlib
import glob
import hmac
import http.client
import json
import math
import os
import queue
import random
import re
import shutil
import subprocess
import sys
import tempfile
import threading
import time
import traceback
import uuid
from urllib import error, request
from urllib.parse import urlparse

PLUGIN_ID = "herdsight.notify"
PAIRING_LIFETIME_SECONDS = 5 * 60
POLL_INTERVAL_SECONDS = 2
DEFAULT_RELAY_URL = "https://relay.ayushio.com"
RETRY_WINDOW_SECONDS = PAIRING_LIFETIME_SECONDS
MAX_RETRY_DELAY_SECONDS = 60
BASE64URL = re.compile(r"^[A-Za-z0-9_-]{43}$")
CONTENT_KEY_BYTES = 32
CONTENT_KEY_TEMP_MAX_AGE_SECONDS = 60 * 60
SERVICE_PROFILE = "personal-self-use-v1"
DOCUMENT_VERSION = re.compile(r"[A-Za-z0-9.-]{1,64}")
VERIFICATION_CODE = re.compile(r"^[0-9]{8}$")
PAIR_ID = re.compile(
    r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-4[0-9a-fA-F]{3}-"
    r"[89aAbB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$"
)


class SetupError(Exception):
    code = "relay_error"


class RegistrationError(SetupError):
    def __init__(self, code, message):
        super().__init__(message)
        self.code = code


def registration_info(client):
    status, info = client.get("/v1/service-info")
    if (status != 200 or not isinstance(info, dict)
            or info.get("service_profile") != SERVICE_PROFILE
            or info.get("registrations_open") is not True
            or any(not isinstance(info.get(key), str) or not DOCUMENT_VERSION.fullmatch(info[key])
                   for key in ("terms_version", "privacy_notice_version"))):
        raise RegistrationError("service_unavailable", "The relay is unavailable for new registrations.")
    return info



def random_secret():
    """32 random bytes as unpadded base64url (43 characters)."""
    return base64.urlsafe_b64encode(os.urandom(32)).rstrip(b"=").decode("ascii")


def content_key_path(directory):
    return os.path.join(directory, "content-key")


def content_key_encode(key):
    return base64.urlsafe_b64encode(key).rstrip(b"=").decode("ascii")


def _write_temp_key(directory, key):
    """A complete 0600 key file that no reader can see under its final name yet."""
    fd, tmp = tempfile.mkstemp(dir=directory, prefix=".content-key.", suffix=".tmp")
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(key)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(tmp, 0o600)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise
    return tmp


def _remove_stale_temp_keys(directory):
    """A crash between the fsync and the link leaves a temp file; drop old ones."""
    now = time.time()
    for name in os.listdir(directory):
        if not (name.startswith(".content-key.") and name.endswith(".tmp")):
            continue
        path = os.path.join(directory, name)
        try:
            if now - os.path.getmtime(path) > CONTENT_KEY_TEMP_MAX_AGE_SECONDS:
                os.unlink(path)
        except OSError:
            pass


def load_or_create_content_key(directory):
    """The Mac's content key, created on first use. Raises OSError if it cannot be written.

    If two processes repair a corrupt (not 32-byte) file at the same time, one may return
    a key that the other has since replaced. New keys are published with link and do not race.
    """
    path = content_key_path(directory)
    os.makedirs(directory, mode=0o700, exist_ok=True)
    _remove_stale_temp_keys(directory)
    while True:
        try:
            with open(path, "rb") as handle:
                existing = handle.read()
        except FileNotFoundError:
            existing = None
        if existing is not None and len(existing) == CONTENT_KEY_BYTES:
            try:
                os.chmod(path, 0o600)
            except OSError:
                pass
            return existing
        key = os.urandom(CONTENT_KEY_BYTES)
        tmp = _write_temp_key(directory, key)
        try:
            if existing is None:
                try:
                    # 完成した一時ファイルだけを公開する。負けた側は公開された鍵を読み直す。
                    os.link(tmp, path)
                    return key
                except FileExistsError:
                    continue
            # 32 バイトでない既存ファイルは壊れている。書きかけは link 前なので見えない。
            os.replace(tmp, path)
            os.chmod(path, 0o600)
            return key
        finally:
            try:
                os.unlink(tmp)
            except FileNotFoundError:
                pass


def parse_pair_string(text):
    """Split `<pair_id>.<claim_secret>[.<content_key>]`; the third part is optional."""
    parts = text.strip().split(".")
    if len(parts) not in (2, 3):
        raise ValueError("pairing string must have 2 or 3 parts")
    pair_id = parse_pair_id(parts[0])
    if not BASE64URL.match(parts[1]):
        raise ValueError("claim_secret is not 43 base64url characters")
    if len(parts) == 3 and not BASE64URL.match(parts[2]):
        raise ValueError("content_key is not 43 base64url characters")
    return pair_id, parts[1]


def parse_pair_id(text):
    """Validate a canonical UUID v4 before placing it in a relay URL path."""
    if not isinstance(text, str) or not PAIR_ID.fullmatch(text):
        raise ValueError("pair_id is not a UUID v4")
    try:
        parsed = uuid.UUID(text)
    except ValueError as exc:
        raise ValueError("pair_id is not a UUID") from exc
    if parsed.version != 4:
        raise ValueError("pair_id is not a UUID v4")
    return str(parsed)


def default_state_dir():
    return os.path.join(
        os.path.expanduser("~"), ".local", "state", "herdr", "plugins", PLUGIN_ID
    )


def state_dir():
    return os.environ.get("HERDR_PLUGIN_STATE_DIR") or default_state_dir()


def config_dir():
    configured = os.environ.get("HERDR_PLUGIN_CONFIG_DIR")
    if configured is None or configured == "":
        binary = os.environ.get("HERDR_BIN_PATH") or "herdr"
        try:
            proc = subprocess.run(
                [binary, "plugin", "config-dir", PLUGIN_ID],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=True,
            )
        except (OSError, subprocess.SubprocessError) as exc:
            raise SetupError("cannot find the plugin config dir; set HERDR_PLUGIN_CONFIG_DIR") from exc
        configured = proc.stdout.decode("utf-8")
    value = configured.strip()
    if not value:
        raise SetupError("herdr plugin config-dir returned an empty path")
    if not os.path.isabs(value):
        raise SetupError("plugin config dir must be absolute: %s" % value)
    return value


def herdr_config_home():
    # herdr は socket と plugin の config を XDG_CONFIG_HOME（無ければ ~/.config）の herdr/ に置く
    base = os.environ.get("XDG_CONFIG_HOME") or ""
    if not os.path.isabs(base):
        base = os.path.join(os.path.expanduser("~"), ".config")
    return os.path.join(base, "herdr")


def default_socket_path():
    return os.path.join(herdr_config_home(), "herdr.sock")


def default_config_dir():
    """`herdr plugin config-dir` と同じ場所。herdr の CLI を呼べないとき（SSH）に使う。"""
    return os.path.join(herdr_config_home(), "plugins", "config", PLUGIN_ID)


def socket_path(cli_value=None):
    value = (cli_value or os.environ.get("HERDR_SOCKET_PATH") or "").strip()
    if not value and os.path.exists(default_socket_path()):
        value = default_socket_path()
    if not value:
        value = input("herdr socket path: ").strip()
    if not value:
        raise SetupError("herdr socket path is required; set HERDR_SOCKET_PATH")
    if not os.path.isabs(value):
        raise SetupError("herdr socket path must be absolute: %s" % value)
    return value


def load_config(path):
    try:
        with open(path, "r", encoding="utf-8") as handle:
            data = json.load(handle)
    except FileNotFoundError:
        return {}
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise SetupError(
            "config.json is not valid UTF-8 JSON; repair it before uninstalling relay credentials"
        ) from exc
    if not isinstance(data, dict):
        raise SetupError("config.json is not a JSON object")
    return data


def write_json(path, data):
    directory = os.path.dirname(path) or "."
    os.makedirs(directory, mode=0o700, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=directory, prefix=".config.", suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(data, handle, indent=2, sort_keys=True)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(tmp, 0o600)
        os.replace(tmp, path)
    finally:
        if os.path.exists(tmp):
            try:
                os.unlink(tmp)
            except OSError:
                pass


def save_config(path, config):
    write_json(path, config)


def error_code(payload):
    if isinstance(payload, dict):
        err = payload.get("error")
        if isinstance(err, dict):
            return err.get("code")
    return None


class RelayClient:
    """Relay v1 client. `opener` is injectable for tests."""

    def __init__(self, base_url, dev_access=None, opener=request.urlopen, timeout=15):
        self.base_url = base_url.rstrip("/")
        self.dev_access = dev_access
        self.opener = opener
        self.timeout = timeout

    def request(self, method, path, body=None, host=None, idempotency_key=None):
        # Cloudflare は urllib の既定の User-Agent を 403 で弾く
        headers = {"Accept": "application/json", "User-Agent": PLUGIN_ID}
        if host:
            headers["Authorization"] = "Bearer host.%s.%s" % (
                host["host_id"],
                host["host_secret"],
            )
        if self.dev_access:
            headers["X-Relay-Dev-Access"] = self.dev_access
        if method in ("POST", "PATCH"):
            headers["Idempotency-Key"] = idempotency_key or str(uuid.uuid4())
        data = None
        if body is not None:
            headers["Content-Type"] = "application/json"
            data = json.dumps(body, separators=(",", ":")).encode("utf-8")
        req = request.Request(
            self.base_url + path, data=data, headers=headers, method=method
        )
        try:
            resp = self.opener(req, timeout=self.timeout)
            try:
                status = getattr(resp, "status", None)
                if status is None:
                    status = resp.getcode()
                raw = resp.read()
            finally:
                close = getattr(resp, "close", None)
                if close:
                    close()
        except error.HTTPError as exc:
            status = exc.code
            try:
                raw = exc.read()
            except (OSError, http.client.HTTPException):
                return None, None
        except (OSError, http.client.HTTPException):
            return None, None
        try:
            payload = json.loads(raw.decode("utf-8")) if raw else None
        except (ValueError, UnicodeDecodeError):
            payload = None
        return status, payload

    def get(self, path, host=None):
        return self.request("GET", path, host=host)

    def post(self, path, body, host=None, idempotency_key=None):
        return self.request(
            "POST", path, body=body, host=host, idempotency_key=idempotency_key
        )

    def delete(self, path, host=None):
        return self.request("DELETE", path, host=host)


def retry_delay_seconds(payload):
    error_payload = payload.get("error") if isinstance(payload, dict) else None
    retry_after = (
        error_payload.get("retry_after_seconds")
        if isinstance(error_payload, dict)
        else None
    )
    if isinstance(retry_after, bool):
        retry_after = None
    try:
        base = float(retry_after)
    except (OverflowError, TypeError, ValueError):
        base = float(POLL_INTERVAL_SECONDS)
    if not math.isfinite(base) or base < 0:
        base = float(POLL_INTERVAL_SECONDS)
    base = min(base, MAX_RETRY_DELAY_SECONDS)
    return min(MAX_RETRY_DELAY_SECONDS, base + random.uniform(0.05, 1.0))


def request_with_retry(
    client, method, path, body=None, host=None, idempotency_key=None, retry_until=None,
    retry_unavailable=True,
):
    """Retry relay throttling with a stable key for writes and bounded jittered waits."""
    if method in ("POST", "PATCH") and not idempotency_key:
        idempotency_key = str(uuid.uuid4())
    if retry_until is None:
        retry_until = time.monotonic() + RETRY_WINDOW_SECONDS
    while True:
        status, payload = client.request(
            method, path, body=body, host=host, idempotency_key=idempotency_key
        )
        if status != 429 and (status != 503 or not retry_unavailable):
            return status, payload
        remaining = retry_until - time.monotonic()
        if remaining <= 0:
            return status, payload
        delay = retry_delay_seconds(payload)
        if delay >= remaining:
            time.sleep(remaining)
            return status, payload
        time.sleep(delay)


def host_for_socket(config, socket):
    """setup 用。別 socket の host を流用すると、そのセッションの hook が host を見つけられない。"""
    hosts = config.get("hosts")
    if not isinstance(hosts, list):
        return None
    return next(
        (host for host in hosts if isinstance(host, dict) and host.get("socket_path") == socket),
        None,
    )


def credentials_host(config, socket):
    """approve/cancel の宛先。host_for_socket に寄せ、別 socket の host を流用しない。

    socket 未指定で複数あるときは選べないので、socket path の一覧を出して選ばせる。
    """
    hosts = config.get("hosts") if isinstance(config.get("hosts"), list) else []
    hosts = [host for host in hosts if isinstance(host, dict)]
    if socket:
        host = host_for_socket(config, socket)
        if host is not None:
            return host
    if not socket and len(hosts) == 1:
        return hosts[0]
    if not hosts:
        print("No host credentials. Run setup first.")
    else:
        print(
            "Which herdr session? Pass --socket-path for one of these in config.json:"
            if socket
            else "Several hosts are configured. Pass --socket-path for one of:"
        )
        for entry in hosts:
            print("  %s" % (entry.get("socket_path") or "(no socket path)"))
    return None


def _host_entry(host_id, secret, socket, expires_at):
    return {
        "socket_path": socket,
        "workspace_allowlist": [],
        "host_id": host_id,
        "host_secret": secret,
        "host_expires_at": expires_at,
    }


def bootstrap_host(client, config, config_path, socket, service_info):
    # Delete old credentials before replacing them. Persist each successful deletion
    # so a failed POST can be retried with a fresh bootstrap on the next run.
    hosts = config.get("hosts")
    if not isinstance(hosts, list):
        hosts = []
    config["hosts"] = hosts
    for entry in list(hosts):
        if isinstance(entry, dict) and entry.get("socket_path") == socket and entry.get("host_id"):
            status, _payload = request_with_retry(
                client, "DELETE", "/v1/self", host=entry
            )
            # 401 は削除済みか拒否済みの資格（protocol §33）なので、消えたものとして進む。
            # 通るのは同じ socket の entry が config に残っているとき（重複など）だけ。
            if status not in (200, 204, 404, 401):
                print(
                    "Warning: DELETE /v1/self returned %s; the old credentials are"
                    " kept in config.json and the replacement was skipped." % status
                )
                raise SetupError("cannot delete the old host on the relay")
            config["hosts"] = [host for host in config["hosts"] if host is not entry]
            save_config(config_path, config)
    host_id = str(uuid.uuid4())
    secret = random_secret()
    body = {
        "id": host_id,
        "secret": secret,
        "service_profile": service_info.get("service_profile"),
        "terms_version": service_info.get("terms_version"),
        "privacy_notice_version": service_info.get("privacy_notice_version"),
    }
    status, payload = request_with_retry(
        client, "POST", "/v1/hosts", body, idempotency_key=str(uuid.uuid4()),
        retry_unavailable=False,
    )
    if status == 409 and error_code(payload) == "service_version_mismatch":
        raise RegistrationError("service_version_mismatch", "The relay documents changed. Review them and try again.")
    if status == 503:
        raise RegistrationError("service_unavailable", "The relay is unavailable for new registrations.")
    if status not in (200, 201):
        raise SetupError("POST /v1/hosts returned %s" % status)
    host = _host_entry(host_id, secret, socket, (payload or {}).get("expires_at"))
    config["hosts"] = [
        entry for entry in (config.get("hosts") or [])
        if not isinstance(entry, dict) or entry.get("socket_path") != socket
    ]
    config["hosts"].append(host)
    save_config(config_path, config)
    print("Created host credentials.")
    return host


def replace_rejected_host(client, config, config_path, host, service_info):
    """relay が 401 で拒否した host をローカルで捨てて作り直す。

    DELETE /v1/self は 401 になるだけなので送らない。workspace allowlist は引き継ぐ。
    """
    allowlist = host.get("workspace_allowlist")
    config["hosts"] = [entry for entry in config.get("hosts") or [] if entry is not host]
    save_config(config_path, config)
    replacement = bootstrap_host(client, config, config_path, host.get("socket_path"), service_info)
    if allowlist:
        replacement["workspace_allowlist"] = list(allowlist)
        save_config(config_path, config)
    return replacement


def create_pairing(client, host):
    pair_id = str(uuid.uuid4())
    claim_secret = random_secret()
    status, payload = request_with_retry(
        client,
        "POST",
        "/v1/pairings",
        {"pair_id": pair_id, "claim_secret": claim_secret},
        host=host,
        idempotency_key=str(uuid.uuid4()),
    )
    return pair_id, claim_secret, status, payload


def open_pairing(client, config, config_path, host, service_info):
    """POST /v1/pairings。401 なら1回だけ host を作り直す。403 は relay ではなく途中の拒否なので扱わない。"""
    pair_id, claim_secret, status, payload = create_pairing(client, host)
    if status == 401 and service_info is not None:
        host = replace_rejected_host(client, config, config_path, host, service_info)
        pair_id, claim_secret, status, payload = create_pairing(client, host)
    return host, pair_id, claim_secret, status, payload


def settle_approve(client, host, pair_id, status, payload):
    """approve の結果を approved / already_paired / expired / cancelled / failed に決める。

    409・通信断・5xx では link ができている場合があるので、GET の state で確かめる。
    """
    if status in (200, 201):
        return "approved", payload if isinstance(payload, dict) else {}
    if status == 410:
        return "expired", {}
    if status == 409 or status is None or (isinstance(status, int) and 500 <= status < 600):
        fetched_status, fetched = request_with_retry(
            client, "GET", "/v1/pairings/%s" % pair_id, host=host
        )
        state = fetched.get("state") if fetched_status == 200 and isinstance(fetched, dict) else None
        if state == "approved":
            return "approved", fetched
        # claimed のまま 409 なら、この host と device には既に有効な link がある（protocol §45）
        if state == "claimed" and status == 409:
            return "already_paired", {}
        if state in ("expired", "cancelled"):
            return state, {}
    return "failed", payload if isinstance(payload, dict) else {}


def copy_to_clipboard(text):
    """macOS のユニバーサルクリップボードで iPhone に渡す。失敗しても表示だけで続ける。"""
    try:
        subprocess.run(
            ["pbcopy"],
            input=text.encode("utf-8"),
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=True,
            timeout=5,
        )
    except (OSError, subprocess.SubprocessError):
        return False
    return True


def confirm(prompt):
    try:
        return input(prompt).strip().lower() in ("y", "yes")
    except (EOFError, KeyboardInterrupt):
        print()
        return False


def finish_approved(
    client, config, config_path, host, payload, workspace_allowlist=None
):
    link_id = (payload or {}).get("link_id")
    host_id = (payload or {}).get("host_id") or host.get("host_id")
    pair_id = (payload or {}).get("pair_id")
    if not link_id and pair_id:
        status, fetched = request_with_retry(
            client, "GET", "/v1/pairings/%s" % pair_id, host=host
        )
        if status == 200 and isinstance(fetched, dict):
            link_id = fetched.get("link_id")
    host["host_id"] = host_id
    # 未指定なら host の既存値（新規 host は [] = 全 workspace）を保つ
    if workspace_allowlist is not None:
        host["workspace_allowlist"] = list(workspace_allowlist)
    save_config(config_path, config)
    print("Paired.")
    print("link_id: %s" % link_id)
    print("host_id: %s" % host_id)
    return 0


def approve_flow(client, config, config_path, host, pair_id, code, workspace_allowlist=None):
    if not isinstance(code, str) or not VERIFICATION_CODE.fullmatch(code):
        print("Invalid relay verification code; expected 8 digits.")
        return 1
    print("Verification code: %s %s" % (code[:4], code[4:]))
    print("Answer N if your iPhone shows no code or a different one.")
    if not confirm("Is it the same code as on your iPhone? [y/N]: "):
        status, _payload = request_with_retry(
            client, "DELETE", "/v1/pairings/%s" % pair_id, host=host
        )
        if status in (200, 204, 404, 410):
            print("Cancelled.")
        else:
            print("Cancel failed: %s; the pairing expires in 5 minutes." % status)
        return 1
    status, payload = request_with_retry(
        client,
        "POST",
        "/v1/pairings/%s/approve" % pair_id,
        {"verification_code": code},
        host=host,
        idempotency_key=str(uuid.uuid4()),
    )
    outcome, settled = settle_approve(client, host, pair_id, status, payload)
    if outcome == "approved":
        return finish_approved(
            client, config, config_path, host, settled, workspace_allowlist
        )
    if outcome == "already_paired":
        request_with_retry(client, "DELETE", "/v1/pairings/%s" % pair_id, host=host)
        print(
            "This iPhone is already paired with this Mac. To pair again, unpair it in the"
            " app first, then run setup again."
        )
    elif outcome in ("expired", "cancelled"):
        print("The pairing is %s. Run setup again." % outcome)
    else:
        print("Approve failed: %s %s" % (status, error_code(payload) or ""))
    return 1


def run_pairing(client, config, config_path, host, workspace_allowlist=None, service_info=None):
    host, pair_id, claim_secret, status, payload = open_pairing(
        client, config, config_path, host, service_info
    )
    if status not in (200, 201):
        if status == 401:
            print("The relay rejected this Mac's credentials. Run uninstall, then setup again.")
        elif status == 409 and error_code(payload) == "capacity_exceeded":
            print("Another pairing is still open for this Mac. Wait 5 minutes and try again.")
        else:
            print("POST /v1/pairings returned %s" % status)
        return 1
    # 0.2.0 までのアプリは2つ目以降を claim secret として送るので、3つ目を足さない。
    pair_string = "%s.%s" % (pair_id, claim_secret)
    print("Pairing code (valid for 5 minutes): %s" % pair_string)
    if copy_to_clipboard(pair_string):
        print("Copied to the clipboard (replacing what was on it).")
    print("Paste it into the Herdsight app on your iPhone or iPad.")
    print("Waiting for the app...")
    sys.stdout.flush()
    try:
        return poll_pairing(client, config, config_path, host, pair_id, workspace_allowlist)
    except KeyboardInterrupt:
        # Ctrl-C でも relay 側の pairing を残さない
        request_with_retry(client, "DELETE", "/v1/pairings/%s" % pair_id, host=host)
        print("\nCancelled.")
        return 1


def poll_pairing(client, config, config_path, host, pair_id, workspace_allowlist):
    deadline = time.monotonic() + PAIRING_LIFETIME_SECONDS
    while time.monotonic() < deadline:
        status, payload = request_with_retry(
            client,
            "GET",
            "/v1/pairings/%s" % pair_id,
            host=host,
            retry_until=deadline,
        )
        if status in (429, 503):
            continue
        if status == 410 or status == 404:
            print("The pairing expired or was removed. Run setup again.")
            return 1
        if status == 409:
            print("The pairing was cancelled.")
            return 1
        if status is None or (isinstance(status, int) and 500 <= status < 600):
            # Wi-Fi 切替や relay 側の一時障害では pair_id を作り直さず期限まで待つ。
            time.sleep(POLL_INTERVAL_SECONDS)
            continue
        if status != 200 or not isinstance(payload, dict):
            print("GET /v1/pairings/%s returned %s" % (pair_id, status))
            return 1
        state = payload.get("state")
        if state == "claimed":
            code = payload.get("verification_code")
            if not isinstance(code, str) or not VERIFICATION_CODE.fullmatch(code):
                print("Relay returned an invalid verification code; approval was not submitted.")
                return 1
            return approve_flow(
                client, config, config_path, host, pair_id, code, workspace_allowlist
            )
        if state == "approved":
            return finish_approved(
                client, config, config_path, host, payload, workspace_allowlist
            )
        if state in ("cancelled", "expired"):
            print("The pairing is %s." % state)
            return 1
        time.sleep(POLL_INTERVAL_SECONDS)
    print("Timed out waiting for the app. Run setup again.")
    return 1


def cmd_approve(client, config, host, pair_id, code):
    try:
        if "." in pair_id:
            pair_id, _secret = parse_pair_string(pair_id)
        else:
            pair_id = parse_pair_id(pair_id)
    except ValueError as exc:
        description = "pairing string" if "." in pair_id else "pair ID"
        print("Invalid %s: %s" % (description, exc))
        return 1
    if not isinstance(code, str) or not VERIFICATION_CODE.fullmatch(code):
        print("Invalid verification code: expected 8 digits.")
        return 1
    status, payload = request_with_retry(
        client,
        "POST",
        "/v1/pairings/%s/approve" % pair_id,
        {"verification_code": code},
        host=host,
        idempotency_key=str(uuid.uuid4()),
    )
    if status in (200, 201):
        print("link_id: %s" % (payload or {}).get("link_id"))
        print("host_id: %s" % (payload or {}).get("host_id"))
        return 0
    print("Approve failed: %s %s" % (status, error_code(payload) or ""))
    return 1


def cmd_cancel(client, host, pair_id):
    try:
        pair_id = parse_pair_id(pair_id)
    except ValueError as exc:
        print("Invalid pair ID: %s" % exc)
        return 1
    status, _payload = request_with_retry(
        client, "DELETE", "/v1/pairings/%s" % pair_id, host=host
    )
    print("Cancelled." if status in (200, 204) else "Cancel failed: %s" % status)
    return 0 if status in (200, 204) else 1


class PairFailure(Exception):
    """`pair` の失敗。code はアプリに渡す固定の文字列。"""

    def __init__(self, code):
        super().__init__(code)
        self.code = code


def make_emitter(stream):
    """1行1つの JSON を書く。読み手が先に閉じても後片付けを止めない。"""

    def emit(fields):
        line = json.dumps(dict(fields, v=1), separators=(",", ":"))
        try:
            stream.write(line + "\n")
            stream.flush()
        except (OSError, ValueError):
            # 終了時の flush で BrokenPipe が stderr に出ないよう、以後は捨てる
            try:
                os.dup2(os.open(os.devnull, os.O_WRONLY), stream.fileno())
            except (OSError, ValueError, AttributeError):
                pass

    return emit


def read_code_line(stream, inbox):
    try:
        line = stream.readline()
    except (OSError, ValueError):
        line = ""
    inbox.put(line)


def parse_code_line(line):
    try:
        value = json.loads(line)
    except ValueError:
        return None
    code = value.get("verification_code") if isinstance(value, dict) else None
    return code if isinstance(code, str) and VERIFICATION_CODE.fullmatch(code) else None


def pair_bootstrap(client, config, config_path, socket, service_info):
    try:
        return bootstrap_host(client, config, config_path, socket, service_info)
    except SetupError as exc:
        raise PairFailure(exc.code) from exc


def approve_pairing(
    client, config, config_path, host, pair_id, code, relay_code, content_key, emit
):
    path = "/v1/pairings/%s" % pair_id
    if not hmac.compare_digest(code, relay_code):
        raise PairFailure("code_mismatch")
    status, payload = request_with_retry(
        client,
        "POST",
        path + "/approve",
        {"verification_code": relay_code},
        host=host,
        idempotency_key=str(uuid.uuid4()),
    )
    outcome, payload = settle_approve(client, host, pair_id, status, payload)
    if outcome != "approved":
        raise PairFailure("relay_error" if outcome == "failed" else outcome)
    host["host_id"] = payload.get("host_id") or host.get("host_id")
    save_config(config_path, config)
    emit(
        {
            "result": "approved",
            "link_id": payload.get("link_id"),
            "host_id": host["host_id"],
            "content_key": content_key_encode(content_key),
        }
    )
    return 0


def await_claim(client, config, config_path, host, pair_id, inbox, content_key, emit):
    path = "/v1/pairings/%s" % pair_id
    deadline = time.monotonic() + PAIRING_LIFETIME_SECONDS
    code = None
    while True:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise PairFailure("timeout")
        status, payload = request_with_retry(
            client, "GET", path, host=host, retry_until=deadline
        )
        state = payload.get("state") if status == 200 and isinstance(payload, dict) else None
        if status in (404, 410) or state == "expired":
            raise PairFailure("expired")
        if status == 409 or state == "cancelled":
            raise PairFailure("cancelled")
        transient = status in (None, 429, 503) or (isinstance(status, int) and 500 <= status < 600)
        if not transient and state not in ("pending", "claimed"):
            raise PairFailure("relay_error")
        if state == "claimed" and code is not None:
            relay_code = payload.get("verification_code")
            if not isinstance(relay_code, str) or not VERIFICATION_CODE.fullmatch(relay_code):
                raise PairFailure("relay_error")
            return approve_pairing(
                client, config, config_path, host, pair_id, code, relay_code,
                content_key, emit,
            )
        wait = max(0, min(POLL_INTERVAL_SECONDS, deadline - time.monotonic()))
        if code is not None:
            time.sleep(wait)
            continue
        try:
            line = inbox.get(timeout=wait)
        except queue.Empty:
            continue
        code = parse_code_line(line)
        if code is None:
            raise PairFailure("bad_input")


def cmd_pair(relay_url, accepted_terms_version, received_privacy_notice_version, stdin, emit):
    """アプリが SSH で動かす非対話のペアリング。コードは stdin で受け取り、機械で照合する。"""
    socket = os.environ.get("HERDR_SOCKET_PATH") or default_socket_path()
    if not os.path.isabs(socket) or not os.path.exists(socket):
        raise PairFailure("no_socket")
    parsed = urlparse(relay_url)
    if parsed.scheme != "https" or not parsed.netloc:
        raise PairFailure("invalid_relay_url")
    # herdr の CLI は SSH の PATH に無いので呼ばない
    directory = os.environ.get("HERDR_PLUGIN_CONFIG_DIR") or default_config_dir()
    if not os.path.isabs(directory):
        raise PairFailure("config_error")
    config_path = os.path.join(directory, "config.json")
    config = load_config(config_path)
    saved = config.get("relay_url")
    if saved and saved.rstrip("/") != relay_url.rstrip("/"):
        # 同じ config の他の host の通知先を変えない
        raise PairFailure("relay_mismatch")
    dev_access = os.environ.get("HERDSIGHT_RELAY_DEV_ACCESS") or config.get("dev_access")
    client = RelayClient(relay_url, dev_access)
    service_info = registration_info(client)
    if (service_info["terms_version"] != accepted_terms_version
            or service_info["privacy_notice_version"] != received_privacy_notice_version):
        raise PairFailure("service_version_mismatch")
    try:
        content_key = load_or_create_content_key(directory)
    except OSError as exc:
        raise PairFailure("config_error") from exc
    if not saved:
        config["relay_url"] = relay_url
        save_config(config_path, config)

    host = host_for_socket(config, socket)
    if host is None:
        host = pair_bootstrap(client, config, config_path, socket, service_info)
    try:
        host, pair_id, claim_secret, status, payload = open_pairing(
            client, config, config_path, host, service_info
        )
    except SetupError as exc:
        raise PairFailure(exc.code) from exc
    if status == 401:
        raise PairFailure("host_rejected")
    if status == 409 and error_code(payload) == "capacity_exceeded":
        raise PairFailure("pairing_busy")
    if status not in (200, 201):
        raise PairFailure("relay_error")

    expires_at = (payload or {}).get("expires_at") if isinstance(payload, dict) else None
    if not isinstance(expires_at, str):
        expires_at = time.strftime(
            "%Y-%m-%dT%H:%M:%SZ", time.gmtime(time.time() + PAIRING_LIFETIME_SECONDS)
        )
    emit({"pair": "%s.%s" % (pair_id, claim_secret), "expires_at": expires_at})
    inbox = queue.Queue()
    threading.Thread(target=read_code_line, args=(stdin, inbox), daemon=True).start()
    try:
        return await_claim(
            client, config, config_path, host, pair_id, inbox, content_key, emit
        )
    except BaseException as exc:
        if not (isinstance(exc, PairFailure) and exc.code in ("expired", "cancelled")):
            try:
                client.request("DELETE", "/v1/pairings/%s" % pair_id, host=host)
            except Exception:
                pass
        raise


def run_pair(relay_url, accepted_terms_version=None, received_privacy_notice_version=None, *, stdin=None, stdout=None):
    """stdout には JSON 行だけを書き、stderr には何も書かない。"""
    emit = make_emitter(stdout or sys.stdout)
    with open(os.devnull, "w") as sink, contextlib.redirect_stdout(sink), \
            contextlib.redirect_stderr(sink):
        try:
            return cmd_pair(relay_url, accepted_terms_version, received_privacy_notice_version,
                            stdin or sys.stdin, emit)
        except PairFailure as exc:
            code = exc.code
        except RegistrationError as exc:
            code = exc.code
        except (SetupError, OSError):
            code = "config_error"
        except (Exception, KeyboardInterrupt):
            code = "internal"
    emit({"error": code})
    return 1


def run_content_key(stdout=None):
    """`content-key`: one JSON line with the Mac's key, created if missing."""
    emit = make_emitter(stdout or sys.stdout)
    try:
        directory = os.environ.get("HERDR_PLUGIN_CONFIG_DIR") or default_config_dir()
        if not os.path.isabs(directory) or not os.path.isdir(directory):
            raise SetupError("config dir is missing")
        key = load_or_create_content_key(directory)
    except (OSError, SetupError):
        emit({"error": "config_error"})
        return 1
    emit({"content_key": content_key_encode(key)})
    return 0


def remove_content_key_files(directory):
    """The key and any temp file left by an interrupted creation."""
    paths = [content_key_path(directory)]
    paths += glob.glob(os.path.join(directory, ".content-key.*.tmp"))
    for path in paths:
        try:
            os.unlink(path)
        except FileNotFoundError:
            pass


def remove_state_files(directory):
    targets = [os.path.join(directory, "state.json"), os.path.join(directory, "state.lock")]
    targets += glob.glob(os.path.join(directory, "state.json.corrupt-*"))
    for path in targets:
        try:
            os.unlink(path)
        except FileNotFoundError:
            pass


def cmd_uninstall(client, config, config_path, state_directory=None):
    raw_hosts = config.get("hosts", [])
    hosts = raw_hosts if isinstance(raw_hosts, list) else []
    cleanup_failed = "hosts" in config and not isinstance(raw_hosts, list)
    if cleanup_failed:
        print("Warning: invalid host credentials; relay-side data may remain.")
    if hosts and client is not None:
        malformed = 0
        for host in hosts:
            if not isinstance(host, dict) or not all(
                isinstance(host.get(key), str) and host.get(key)
                for key in ("host_id", "host_secret")
            ):
                malformed += 1
                cleanup_failed = True
                continue
            status, _payload = request_with_retry(
                client, "DELETE", "/v1/self", host=host
            )
            if status not in (200, 204, 404):
                print("Warning: DELETE /v1/self returned %s; relay-side data may remain." % status)
                cleanup_failed = True
        if malformed:
            print(
                "Warning: skipped %d malformed host credential(s); relay-side data may remain."
                % malformed
            )
    elif hosts:
        print("Warning: no relay URL; relay-side data may remain.")
        cleanup_failed = True
    if cleanup_failed:
        print("Uninstall incomplete; local config and state were retained so you can retry.")
        return 1
    try:
        os.unlink(config_path)
    except FileNotFoundError:
        pass
    remove_content_key_files(os.path.dirname(config_path))
    directory = state_directory or state_dir()
    remove_state_files(directory)
    # host ごとの state ディレクトリ（旧 spool/ もここに入る）。
    for name in os.listdir(directory) if os.path.isdir(directory) else []:
        path = os.path.join(directory, name)
        if os.path.isdir(path):
            shutil.rmtree(path, ignore_errors=True)
    print("Removed local config and state.")
    print("Run: herdr plugin uninstall %s" % PLUGIN_ID)
    return 0


def resolve_relay(args, config, prefer_saved=False):
    """relay URL は 引数 → HERDSIGHT_RELAY_URL → config → 既定値。

    保存済みの URL と違う URL は拒む。config の host は保存済みの relay にしか登録されていない。
    uninstall（prefer_saved）は保存済みの relay から消す。
    """
    explicit = args.relay_url or os.environ.get("HERDSIGHT_RELAY_URL")
    saved = config.get("relay_url")
    if prefer_saved and saved:
        base_url = saved
    elif explicit and saved and explicit.rstrip("/") != saved.rstrip("/"):
        raise SetupError(
            "This Mac is set up for %s. To switch relays, run uninstall first." % saved
        )
    else:
        base_url = explicit or saved or DEFAULT_RELAY_URL
    parsed = urlparse(base_url)
    if parsed.scheme != "https" or not parsed.netloc:
        raise SetupError("relay URL must be https://host")
    dev_access = (
        args.dev_access
        or os.environ.get("HERDSIGHT_RELAY_DEV_ACCESS")
        or config.get("dev_access")
    )
    return base_url, dev_access


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--relay-url")
    parser.add_argument("--dev-access")
    parser.add_argument("--socket-path")
    parser.add_argument("--workspace", action="append", dest="workspaces")
    subparsers = parser.add_subparsers(dest="command")
    approve = subparsers.add_parser("approve")
    approve.add_argument("pair_id")
    approve.add_argument("code")
    cancel = subparsers.add_parser("cancel")
    cancel.add_argument("pair_id")
    uninstall = subparsers.add_parser("uninstall")
    uninstall.add_argument("-y", "--yes", action="store_true", help="do not ask for confirmation")
    pair = subparsers.add_parser("pair", help="non-interactive pairing for the Herdsight app")
    pair.add_argument("--relay-url", required=True)
    pair.add_argument("--accepted-terms-version")
    pair.add_argument("--received-privacy-notice-version")
    subparsers.add_parser("content-key", help="print the content key for the Herdsight app")
    args = parser.parse_args(argv)
    if args.command == "pair":
        return run_pair(args.relay_url, args.accepted_terms_version, args.received_privacy_notice_version)
    if args.command == "content-key":
        return run_content_key()

    try:
        config_path = os.path.join(config_dir(), "config.json")
        config = load_config(config_path)
        if args.command == "uninstall":
            if not args.yes and not confirm(
                "Remove this Mac from the Herdsight relay and delete the local config?"
                " Paired iPhones stop getting notifications. [y/N]: "
            ):
                print("Nothing was removed.")
                return 1
            try:
                base_url, dev_access = resolve_relay(args, config, prefer_saved=True)
            except SetupError:
                base_url, dev_access = None, None
            client = RelayClient(base_url, dev_access) if base_url else None
            return cmd_uninstall(client, config, config_path)

        base_url, dev_access = resolve_relay(args, config)
        client = RelayClient(base_url, dev_access)
        config["relay_url"] = base_url
        if dev_access:
            config["dev_access"] = dev_access

        if args.command in ("approve", "cancel"):
            host = credentials_host(
                config, args.socket_path or os.environ.get("HERDR_SOCKET_PATH")
            )
            if host is None:
                return 1
            if args.command == "approve":
                return cmd_approve(client, config, host, args.pair_id, args.code)
            return cmd_cancel(client, host, args.pair_id)

        # Setup can create a host, including when an existing credential is rejected.
        service_info = registration_info(client)
        operator = service_info.get("operator")
        name = operator.get("name") if isinstance(operator, dict) else None
        terms = service_info.get("terms_url")
        privacy = service_info.get("privacy_notice_url")
        if not isinstance(name, str) or not name.strip() or not name.isprintable():
            raise SetupError("The relay did not provide a valid operator name.")
        for url in (terms, privacy):
            if not isinstance(url, str) or not url.isprintable() or any(ch.isspace() for ch in url):
                raise SetupError("The relay did not provide valid document URLs.")
            try:
                parsed = urlparse(url)
                valid = parsed.scheme == "https" and parsed.hostname and not parsed.username and not parsed.password
            except ValueError:
                valid = False
            if not valid:
                raise SetupError("The relay did not provide valid document URLs.")
        print("Relay operator: %s" % name)
        print("Terms (%s): %s" % (service_info["terms_version"], terms))
        print("Privacy notice (%s): %s" % (service_info["privacy_notice_version"], privacy))
        if not confirm("Accept these terms and acknowledge receipt of this privacy notice? [y/N]: "):
            print("Relay setup cancelled.")
            return 1
        socket = socket_path(args.socket_path)
        print("Using herdr socket: %s" % socket)
        host = host_for_socket(config, socket)
        if host is None:
            host = bootstrap_host(client, config, config_path, socket, service_info)
        config["relay_url"] = base_url
        save_config(config_path, config)
        try:
            # 手動の文字列には載せない。鍵は SSH の pair か content-key で渡す。
            load_or_create_content_key(os.path.dirname(config_path))
        except OSError as exc:
            raise SetupError(
                "cannot write the content key: %s" % type(exc).__name__
            ) from exc
        return run_pairing(
            client,
            config,
            config_path,
            host,
            workspace_allowlist=args.workspaces,
            service_info=service_info,
        )
    except SetupError as exc:
        print(str(exc))
        return 1
    except (EOFError, KeyboardInterrupt):
        print("\nCancelled.")
        return 1


if __name__ == "__main__":
    try:
        exit_code = main()
    except Exception:
        # pane が閉じる前に原因を読めるようにする
        traceback.print_exc()
        exit_code = 1
    if os.environ.get("HERDR_PLUGIN_ENTRYPOINT_ID"):
        # plugin pane はコマンドの終了で閉じるので、結果を読めるよう待つ
        try:
            input("Press Enter to close.")
        except (EOFError, KeyboardInterrupt):
            pass
    sys.exit(exit_code)
