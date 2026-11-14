#!/usr/bin/env python3
"""Short-lived herdr plugin hook for Herdsight push notifications.

Runs once per herdr startup or pane.agent_status_changed event, then exits.
No listening socket, no loop, no polling, no authentication of its own.
Standard library only (Python 3.9+).
"""

import fcntl
import hashlib
import http.client
import json
import os
import random
import subprocess
import sys
import tempfile
import time
import uuid
from contextlib import contextmanager
from datetime import datetime, timezone
from urllib import error, request
from urllib.parse import urlparse

PLUGIN_ID = "herdsight.notify"
EVENT_STATES = {"blocked", "idle", "working", "done", "unknown"}
PENDING_MAX = 16
HOOK_BUDGET_SECONDS = 45
LOCK_TIMEOUT_SECONDS = 5
SETTINGS_MIN_INTERVAL_SECONDS = 15 * 60
EVENT_TTL_SECONDS = 5 * 60
EVENT_EXPIRY_SAFETY_SECONDS = 60
BASELINE_MAX = 256
PANE_SALT = "herdsight-pane-v1"


class HerdrError(Exception):
    pass


class LockTimeout(Exception):
    pass


def pane_fingerprint(host_id, terminal_id):
    """SHA-256("herdsight-pane-v1" NUL host_id NUL terminal_id), lowercase hex."""
    payload = "\x00".join((PANE_SALT, host_id, terminal_id)).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def iso_utc(timestamp):
    return (
        datetime.fromtimestamp(timestamp, timezone.utc)
        .isoformat(timespec="milliseconds")
        .replace("+00:00", "Z")
    )


def parse_iso_utc(value):
    return datetime.fromisoformat(value.replace("Z", "+00:00")).timestamp()


def log(message):
    sys.stderr.write("herdsight-notify: %s\n" % message)


def _error_field(payload, name, default=None):
    if isinstance(payload, dict):
        err = payload.get("error")
        if isinstance(err, dict):
            return err.get(name, default)
    return default


def retry_delay(payload):
    try:
        seconds = float(_error_field(payload, "retry_after_seconds", 1))
    except (OverflowError, TypeError, ValueError):
        seconds = 1.0
    return min(60.0, max(0.0, seconds) + random.uniform(0.0, 1.0))


class Relay:
    """Minimal relay v1 client. `opener` is injectable for tests."""

    def __init__(self, base_url, host, dev_access=None, opener=request.urlopen, timeout=8):
        if urlparse(base_url).scheme != "https":
            raise ValueError("relay URL must use https")
        self.base_url = base_url.rstrip("/")
        self.host = host
        self.dev_access = dev_access
        self.opener = opener
        self.timeout = timeout

    def url(self, path):
        return self.base_url + path

    def _headers(self, idempotency_key=None):
        headers = {
            "Accept": "application/json",
            # Cloudflare は urllib の既定の User-Agent を 403 で弾く
            "User-Agent": PLUGIN_ID,
            "Authorization": "Bearer host.%s.%s"
            % (self.host["host_id"], self.host["host_secret"]),
        }
        if self.dev_access:
            headers["X-Relay-Dev-Access"] = self.dev_access
        if idempotency_key:
            headers["Idempotency-Key"] = idempotency_key
        return headers

    def _send(self, req):
        self.last_transport_error = None
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
            except (OSError, http.client.HTTPException) as transport_error:
                self.last_transport_error = type(transport_error).__name__
                return None, None
        except (OSError, http.client.HTTPException) as exc:
            # 秘密は含まれない。診断に使うため型名だけ残す。
            self.last_transport_error = type(exc).__name__
            return None, None
        try:
            payload = json.loads(raw.decode("utf-8")) if raw else None
        except (ValueError, UnicodeDecodeError):
            payload = None
        return status, payload

    def get(self, path):
        req = request.Request(self.url(path), headers=self._headers(), method="GET")
        return self._send(req)

    def post(self, path, body, idempotency_key=None):
        headers = self._headers(idempotency_key or str(uuid.uuid4()))
        headers["Content-Type"] = "application/json"
        req = request.Request(
            self.url(path),
            data=json.dumps(body, separators=(",", ":")).encode("utf-8"),
            headers=headers,
            method="POST",
        )
        return self._send(req)


def state_path(state_dir):
    return os.path.join(state_dir, "state.json")


def _make_state(host_id):
    return {
        "host_id": host_id,
        "stream_id": None,
        "sequence": 0,
        "collection_epoch": None,
        "stream_expires_at": None,
        "suspended": False,
        "settings_checked_at": None,
        "panes": {},
        "pending": [],
    }


def _valid_timestamp(value):
    if not isinstance(value, str):
        return False
    try:
        parse_iso_utc(value)
        return True
    except (TypeError, ValueError):
        return False


def _valid_state_shape(data):
    if data.get("host_id") is not None and not isinstance(data.get("host_id"), str):
        return False
    if not isinstance(data.get("sequence"), int) or isinstance(data.get("sequence"), bool):
        return False
    if data["sequence"] < 0:
        return False
    for key in ("stream_id", "collection_epoch"):
        if data.get(key) is not None and not isinstance(data.get(key), str):
            return False
    for key in ("stream_expires_at", "settings_checked_at"):
        value = data.get(key)
        if value is not None and not _valid_timestamp(value):
            return False
    if not isinstance(data.get("suspended"), bool):
        return False
    panes = data.get("panes")
    if not isinstance(panes, dict):
        return False
    for pane_id, entry in panes.items():
        if not isinstance(pane_id, str) or not pane_id or not isinstance(entry, dict):
            return False
        if not isinstance(entry.get("pane_generation"), str) or not entry["pane_generation"]:
            return False
        if entry.get("pane_fingerprint") is not None and not isinstance(
            entry.get("pane_fingerprint"), str
        ):
            return False
        if entry.get("last_state") not in ("blocked", "clear"):
            return False
    pending = data.get("pending")
    if not isinstance(pending, list):
        return False
    for event in pending:
        if not isinstance(event, dict):
            return False
        if event.get("state") not in ("blocked", "clear"):
            return False
        for key in ("event_id", "idempotency_key", "pane_id", "pane_generation"):
            if not isinstance(event.get(key), str) or not event[key]:
                return False
        if event.get("pane_fingerprint") is not None and not isinstance(
            event.get("pane_fingerprint"), str
        ):
            return False
        if not _valid_timestamp(event.get("observed_at")) or not _valid_timestamp(
            event.get("expires_at")
        ):
            return False
    return True


def _move_corrupt_state(path, now, message):
    timestamp = time.time() if now is None else now
    stamp = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime(timestamp))
    try:
        os.replace(path, path + ".corrupt-" + stamp)
        log(message + "; moved aside")
    except OSError:
        log(message)


def load_state(state_dir, host_id, now=None):
    path = state_path(state_dir)
    try:
        with open(path, "r", encoding="utf-8") as handle:
            data = json.load(handle)
    except FileNotFoundError:
        return _make_state(host_id)
    except (ValueError, UnicodeDecodeError):
        _move_corrupt_state(path, now, "state.json unreadable")
        return _make_state(host_id)
    if not isinstance(data, dict):
        _move_corrupt_state(path, now, "state.json malformed")
        return _make_state(host_id)
    if data.get("host_id") not in (None, host_id):
        _move_corrupt_state(path, now, "state.json host mismatch")
        return _make_state(host_id)
    data.setdefault("stream_id", None)
    data.setdefault("sequence", 0)
    data.setdefault("collection_epoch", None)
    data.setdefault("stream_expires_at", None)
    data.setdefault("suspended", False)
    data.setdefault("settings_checked_at", None)
    if not _valid_state_shape(data):
        _move_corrupt_state(path, now, "state.json malformed")
        return _make_state(host_id)
    data["host_id"] = host_id
    return data


def save_state(state_dir, state):
    os.makedirs(state_dir, mode=0o700, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=state_dir, prefix=".state.", suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(state, handle, separators=(",", ":"), sort_keys=True)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(tmp, 0o600)
        os.replace(tmp, state_path(state_dir))
    finally:
        if os.path.exists(tmp):
            try:
                os.unlink(tmp)
            except OSError:
                pass


@contextmanager
def state_lock(state_dir, timeout=LOCK_TIMEOUT_SECONDS):
    """Exclusive flock on state.lock; gives up after `timeout` seconds."""
    os.makedirs(state_dir, mode=0o700, exist_ok=True)
    fd = os.open(os.path.join(state_dir, "state.lock"), os.O_CREAT | os.O_RDWR, 0o600)
    try:
        deadline = time.monotonic() + timeout
        while True:
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                break
            except OSError:
                if time.monotonic() >= deadline:
                    raise LockTimeout()
                time.sleep(0.05)
        yield
    finally:
        os.close(fd)


def spool_dir(state_dir):
    return os.path.join(state_dir, "spool")


def spool_event(state_dir, raw):
    """Write an event that arrived while another hook held the state lock."""
    directory = spool_dir(state_dir)
    os.makedirs(directory, mode=0o700, exist_ok=True)
    name = "%020d-%s.json" % (time.time_ns(), uuid.uuid4().hex)
    path = os.path.join(directory, name)
    # 読み手が書きかけを見ないよう、rename で置く。
    fd, tmp = tempfile.mkstemp(dir=directory, prefix=".spool.", suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(raw)
            handle.flush()
        os.replace(tmp, path)
    finally:
        if os.path.exists(tmp):
            try:
                os.unlink(tmp)
            except OSError:
                pass


def _herdr_bin():
    return os.environ.get("HERDR_BIN_PATH") or "herdr"


def _herdr_json(args):
    proc = subprocess.run(
        [_herdr_bin()] + args,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=10,
    )
    if proc.returncode != 0:
        raise HerdrError("herdr %s failed" % " ".join(args))
    try:
        return json.loads(proc.stdout.decode("utf-8"))
    except (ValueError, UnicodeDecodeError) as exc:
        raise HerdrError("herdr output unreadable") from exc


def herdr_blocked_panes():
    payload = _herdr_json(["agent", "list"])
    result = payload.get("result") if isinstance(payload, dict) else None
    agents = result.get("agents") if isinstance(result, dict) else None
    if not isinstance(agents, list):
        return []
    return [
        agent for agent in agents
        if isinstance(agent, dict) and agent.get("agent_status") == "blocked"
    ]


def herdr_terminal_id(pane_id):
    """Return (ok, terminal_id). ok=False means `pane get` failed."""
    try:
        payload = _herdr_json(["pane", "get", pane_id])
    except (HerdrError, OSError, subprocess.SubprocessError):
        return False, None
    result = payload.get("result") if isinstance(payload, dict) else None
    pane = result.get("pane") if isinstance(result, dict) else None
    if not isinstance(pane, dict):
        return True, None
    terminal = pane.get("terminal_id")
    return True, terminal if isinstance(terminal, str) and terminal else None


def parse_event(raw):
    try:
        payload = json.loads(raw)
    except (TypeError, ValueError):
        return None
    if not isinstance(payload, dict):
        return None
    data = payload.get("data")
    if not isinstance(data, dict):
        return None
    pane_id = data.get("pane_id")
    status = data.get("agent_status")
    if not isinstance(pane_id, str) or not pane_id:
        return None
    if not isinstance(status, str):
        return None
    workspace_id = data.get("workspace_id")
    if not isinstance(workspace_id, str) or not workspace_id:
        workspace_id = pane_id.split(":", 1)[0]
    return pane_id, status, workspace_id


class Hook:
    def __init__(
        self,
        host,
        state_dir,
        relay,
        blocked_panes,
        terminal_id,
        now=time.time,
        sleep=time.sleep,
        log_line=log,
    ):
        self.host = host
        # 同じ Mac で複数の herdr セッションが動いても、panes/pending を混ぜない。
        self.state_dir = os.path.join(state_dir, host.get("host_id") or "default")
        self.relay = relay
        self.blocked_panes = blocked_panes
        self.terminal_id = terminal_id
        self.now = now
        self.sleep = sleep
        self.log_line = log_line
        self.allowlist = host.get("workspace_allowlist") or []
        self.diagnostics = []
        self.settings_status = None
        # One hook process gets one 45-second budget, shared by both drains.
        self.deadline = time.monotonic() + HOOK_BUDGET_SECONDS

    def note(self, path, status=None, reason=None):
        parts = [self.relay.url(path)]
        if status is not None:
            parts.append(str(status))
        if reason:
            parts.append(reason)
        self.diagnostics.append(" ".join(parts))

    def finish(self):
        for line in self.diagnostics:
            self.log_line(line)
        self.diagnostics = []

    # --- state helpers -------------------------------------------------

    def load(self):
        return load_state(self.state_dir, self.host["host_id"], self.now())

    def save(self, state):
        save_state(self.state_dir, state)

    def in_scope(self, workspace_id):
        return not self.allowlist or workspace_id in self.allowlist

    def _stream_valid(self, state):
        if not state.get("stream_id"):
            return False
        expires = state.get("stream_expires_at")
        if not expires:
            return True
        try:
            return self.now() < parse_iso_utc(expires)
        except ValueError:
            return False

    def _suspension_elapsed(self, state):
        checked = state.get("settings_checked_at")
        if not checked:
            return True
        try:
            return self.now() - parse_iso_utc(checked) >= SETTINGS_MIN_INTERVAL_SECONDS
        except ValueError:
            return True

    def ingest_spooled(self, state, ignore_deadline=False):
        """Map events spooled while another hook held the lock, then remove them."""
        directory = spool_dir(self.state_dir)
        try:
            names = sorted(os.listdir(directory))
        except FileNotFoundError:
            return
        for name in names:
            if not ignore_deadline and time.monotonic() >= self.deadline:
                return
            path = os.path.join(directory, name)
            if name.startswith(".spool.") and name.endswith(".tmp"):
                # 書き手がまだ rename していない一時ファイルは触らない。
                try:
                    if self.now() - os.path.getmtime(path) > EVENT_TTL_SECONDS:
                        os.unlink(path)
                except OSError:
                    pass
                continue
            if len(name) != 58 or not name[:20].isdigit() or name[20] != "-" or not name.endswith(".json"):
                continue
            try:
                if self.now() - os.path.getmtime(path) > EVENT_TTL_SECONDS:
                    os.unlink(path)
                    continue
            except OSError:
                continue
            try:
                with open(path, "r", encoding="utf-8") as handle:
                    raw = handle.read()
            except OSError:
                continue
            event = parse_event(raw)
            if event:
                pane_id, status, workspace_id = event
                if status in EVENT_STATES and self.in_scope(workspace_id):
                    self.map_event(
                        state, pane_id, status, resolve_terminal=not ignore_deadline
                    )
            try:
                os.unlink(path)
            except OSError:
                pass

    def _drop_expired_pending(self, state):
        kept = []
        dropped = 0
        for event in state["pending"]:
            try:
                expired = parse_iso_utc(event.get("expires_at", "")) <= self.now()
            except (AttributeError, TypeError, ValueError):
                expired = True
            if expired:
                dropped += 1
            else:
                kept.append(event)
        state["pending"] = kept
        if dropped:
            self.note("/v1/events", reason="dropped %d expired" % dropped)
        return dropped

    def enqueue(self, state, pane_id, event_state, generation, fingerprint):
        observed = self.now()
        state["pending"].append(
            {
                "event_id": str(uuid.uuid4()),
                "idempotency_key": str(uuid.uuid4()),
                "pane_id": pane_id,
                "state": event_state,
                "observed_at": iso_utc(observed),
                # relay の300秒制限と端末・relay 間の時計ずれに60秒の余裕を取る。
                "expires_at": iso_utc(
                    observed + EVENT_TTL_SECONDS - EVENT_EXPIRY_SAFETY_SECONDS
                ),
                "pane_generation": generation,
                "pane_fingerprint": fingerprint,
            }
        )
        excess = len(state["pending"]) - PENDING_MAX
        if excess > 0:
            del state["pending"][:excess]
            self.note("/v1/events", reason="dropped %d pending" % excess)

    # --- relay calls ---------------------------------------------------

    def source_settings(self):
        status, payload = self.relay.get("/v1/source-settings")
        self.settings_status = status
        reason = None
        if status is None:
            reason = "network error (%s)" % self._oserror()
        elif status in (401, 403):
            reason = "credential rejected"
        self.note("/v1/source-settings", status, reason)
        if status == 200 and isinstance(payload, dict):
            return payload
        return None

    def _oserror(self):
        return getattr(self.relay, "last_transport_error", None) or "unknown"

    def _blocked_panes(self):
        try:
            return self.blocked_panes()
        except (HerdrError, OSError, subprocess.SubprocessError):
            self.note("/herdr/agent-list", reason="agent list failed")
            return None

    def fresh_baseline(self, state, settings, exclude=frozenset(), exclude_pending=True):
        """Create a new stream from the currently blocked panes."""
        blocked = self._blocked_panes()
        if blocked is None:
            return False
        # 送る予定の pane を baseline に入れると blocked→blocked になり、通知が作られない。
        exclude = set(exclude)
        if exclude_pending:
            exclude.update(
                event["pane_id"]
                for event in state["pending"]
                if event.get("state") == "blocked" and event.get("pane_id")
            )
        baseline = []
        panes = {}
        for pane in blocked:
            if not isinstance(pane, dict):
                continue
            pane_id = pane.get("pane_id")
            if not isinstance(pane_id, str) or not pane_id:
                continue
            workspace_id = pane.get("workspace_id") or str(pane_id).split(":", 1)[0]
            if not pane_id or pane_id in exclude or not self.in_scope(workspace_id):
                continue
            if len(baseline) >= BASELINE_MAX:
                continue
            previous = state["panes"].get(pane_id) or {}
            generation = previous.get("pane_generation") or str(uuid.uuid4())
            terminal = pane.get("terminal_id")
            if not isinstance(terminal, str) or not terminal:
                terminal = None
            fingerprint = (
                pane_fingerprint(self.host["host_id"], terminal) if terminal else None
            )
            baseline.append(
                {
                    "pane_id": pane_id,
                    "pane_generation": generation,
                    "pane_fingerprint": fingerprint,
                }
            )
            panes[pane_id] = {
                "pane_generation": generation,
                "pane_fingerprint": fingerprint,
                "last_state": "blocked",
            }
        # Pending events are not in the baseline, so keep their pane entries.
        for pane_id in exclude:
            if pane_id in state["panes"]:
                panes[pane_id] = state["panes"][pane_id]

        body = {
            # relay は現在の stream との CAS。古い id を送れば作り直せる。
            "expected_stream_id": settings.get("stream_id"),
            "expected_collection_epoch": settings.get("collection_epoch"),
            "baseline": baseline[:BASELINE_MAX],
        }
        status, payload = self.relay.post("/v1/streams", body)
        self.note("/v1/streams", status)
        if status in (200, 201) and isinstance(payload, dict):
            state["stream_id"] = payload.get("stream_id")
            state["sequence"] = payload.get("last_sequence") or 0
            state["collection_epoch"] = settings.get("collection_epoch")
            state["stream_expires_at"] = payload.get("expires_at")
            state["panes"] = panes
            state["suspended"] = False
            kept_pending = []
            dropped_clears = 0
            for event in state["pending"]:
                if event.get("state") == "clear" and event.get("pane_id") not in panes:
                    dropped_clears += 1
                else:
                    kept_pending.append(event)
            state["pending"] = kept_pending
            if dropped_clears:
                self.note(
                    "/v1/events", reason="dropped %d clears absent from baseline" % dropped_clears
                )
            return True
        return False

    def ensure_stream(self, state):
        if self._stream_valid(state):
            return True
        settings = self.source_settings()
        state["settings_checked_at"] = iso_utc(self.now())
        if not settings or settings.get("upload_state") != "ready":
            if settings is not None:
                state["suspended"] = True
            return False
        exclude = {
            event["pane_id"]
            for event in state["pending"]
            if event.get("state") == "blocked" and event.get("pane_id")
        }
        return self.fresh_baseline(state, settings, exclude)

    def _resync_after_stream_error(self, state, drop_pending):
        settings = self.source_settings()
        state["settings_checked_at"] = iso_utc(self.now())
        if settings is None:
            if self.settings_status in (401, 403):
                return "unauthorized"
            return "resync_failed"
        if settings.get("upload_state") != "ready":
            state["suspended"] = True
            if drop_pending:
                state["pending"] = []
            return "suspended"
        if not self.fresh_baseline(
            state, settings, exclude_pending=not drop_pending
        ):
            return "resync_failed"
        if drop_pending:
            state["pending"] = []
        return "resynced"

    def drain(self, state):
        dropped_expired = self._drop_expired_pending(state)
        if dropped_expired:
            outcome = self._resync_after_stream_error(state, drop_pending=False)
            if outcome != "resynced":
                return outcome
        deadline = self.deadline
        while state["pending"]:
            if time.monotonic() >= deadline:
                self.note("/v1/events", reason="hook budget exhausted")
                return "budget"
            event = state["pending"][0]
            if not self.ensure_stream(state):
                if self.settings_status in (401, 403):
                    return "unauthorized"
                return "no_stream"
            body = {
                "stream_id": state["stream_id"],
                "event_id": event["event_id"],
                "sequence": state["sequence"] + 1,
                "pane_id": event["pane_id"],
                "pane_generation": event["pane_generation"],
                "pane_fingerprint": event.get("pane_fingerprint"),
                "state": event["state"],
                "observed_at": event["observed_at"],
                "expires_at": event["expires_at"],
            }
            status, payload = self.relay.post(
                "/v1/events", body, event["idempotency_key"]
            )
            self.note("/v1/events", status)
            if status == 202:
                state["sequence"] += 1
                state["pending"].pop(0)
                continue
            if status == 409:
                code = _error_field(payload, "code")
                if code == "upload_suspended":
                    state["suspended"] = True
                    state["settings_checked_at"] = iso_utc(self.now())
                    state["pending"] = []
                    self.note("/v1/events", status, "upload_suspended")
                    return "suspended"
                self.note("/v1/events", status, code or "conflict")
                return self._resync_after_stream_error(state, drop_pending=True)
            if status in (404, 410):
                self.note("/v1/events", status, "stream gone")
                return self._resync_after_stream_error(state, drop_pending=True)
            if status == 400:
                state["pending"].pop(0)
                self.note("/v1/events", status, "invalid_request")
                outcome = self._resync_after_stream_error(state, drop_pending=False)
                if outcome != "resynced":
                    return outcome
                continue
            if status in (429, 503):
                delay = retry_delay(payload)
                # 再試行の要求自体が timeout 分を消す。それも予算に入れて超えそうなら pending に残す。
                if time.monotonic() + delay + getattr(self.relay, "timeout", 0) >= deadline:
                    self.note("/v1/events", status, "retry budget exhausted")
                    return "budget"
                self.note("/v1/events", status, "retrying")
                self.sleep(delay)
                continue
            if status in (401, 403):
                self.note("/v1/events", status, "credential rejected")
                return "unauthorized"
            if status is None:
                self.note("/v1/events", reason="network error (%s)" % self._oserror())
                return "network"
            self.note("/v1/events", status, "unexpected")
            return "error"
        return "ok"

    def map_event(self, state, pane_id, status, resolve_terminal=True):
        entry = state["panes"].get(pane_id) or {}
        last_state = entry.get("last_state")
        if status == "blocked":
            if last_state == "blocked":
                return
            if resolve_terminal:
                ok, terminal = self.terminal_id(pane_id)
                if not ok:
                    self.note("/v1/pane-get", reason="pane get failed")
                    return
                if not isinstance(terminal, str) or not terminal:
                    terminal = None
            else:
                # 予算切れ後は外部コマンドを待たずに遷移を保存する。
                # fingerprint が無い場合も app は pane 一覧へフォールバックできる。
                terminal = None
            generation = entry.get("pane_generation") or str(uuid.uuid4())
            fingerprint = (
                pane_fingerprint(self.host["host_id"], terminal) if terminal else None
            )
            state["panes"][pane_id] = {
                "pane_generation": generation,
                "pane_fingerprint": fingerprint,
                "last_state": "blocked",
            }
            self.enqueue(state, pane_id, "blocked", generation, fingerprint)
            return
        if last_state != "blocked":
            return
        generation = entry["pane_generation"]
        fingerprint = entry.get("pane_fingerprint")
        state["panes"][pane_id] = {
            "pane_generation": generation,
            "pane_fingerprint": fingerprint,
            "last_state": "clear",
        }
        self.enqueue(state, pane_id, "clear", generation, fingerprint)

    # --- entry points --------------------------------------------------

    def run_startup(self):
        with state_lock(self.state_dir):
            state = self.load()
            self.ingest_spooled(state)
            dropped = len(state["pending"])
            state["pending"] = []
            if dropped:
                self.note("/v1/events", reason="dropped %d pending on startup" % dropped)
            settings = self.source_settings()
            if settings is None:
                # 通信の断は停止にしない。次のイベントで再試行する。
                self.save(state)
                self.finish()
                return 0
            state["settings_checked_at"] = iso_utc(self.now())
            if settings.get("upload_state") != "ready":
                state["suspended"] = True
                self.save(state)
                self.note(
                    "/v1/source-settings", self.settings_status, "upload not ready"
                )
                self.finish()
                return 0
            state["suspended"] = False
            # herdr の再起動中に起きた遷移を取りこぼさない。起動ごとに作り直す。
            self.fresh_baseline(state, settings, exclude_pending=False)
            self.save(state)
        self.finish()
        return 0

    def run_event(self, raw):
        event = parse_event(raw)
        if event is None:
            return 0
        pane_id, status, workspace_id = event
        if status not in EVENT_STATES or not self.in_scope(workspace_id):
            return 0
        with state_lock(self.state_dir):
            state = self.load()
            self.ingest_spooled(state)
            if state.get("suspended"):
                if not self._suspension_elapsed(state):
                    self.save(state)
                    self.finish()
                    return 0
                settings = self.source_settings()
                if settings is None:
                    # 通信の断は停止にしない。次のイベントで再試行する。
                    self.save(state)
                    self.finish()
                    return 0
                state["settings_checked_at"] = iso_utc(self.now())
                if settings.get("upload_state") != "ready":
                    state["suspended"] = True
                    self.save(state)
                    self.finish()
                    return 0
                state["suspended"] = False
                # このイベントを先に pending へ入れる。baseline から除外させるため。
                self.map_event(state, pane_id, status)
                self.fresh_baseline(state, settings)
            else:
                self.map_event(state, pane_id, status)
            outcome = self.drain(state)
            if outcome != "ok":
                # 残り予算がなくても spool を state に移してから終了する。
                # drain 中に lock 待ちで spool した別 hook の遷移を取りこぼさない。
                self.ingest_spooled(state, ignore_deadline=True)
                self.save(state)
                self.finish()
                return 0
            # Pick up events spooled by hooks that lost the lock while we were sending.
            self.ingest_spooled(state)
            self.drain(state)
            self.save(state)
        self.finish()
        return 0


def _config_for_environment():
    """Return (config, host), or (None, reason) — the reason is safe to log."""
    if os.environ.get("HERDR_ENV") != "1":
        return None, "HERDR_ENV is not set to 1"
    config_dir = os.environ.get("HERDR_PLUGIN_CONFIG_DIR")
    if not config_dir:
        return None, "HERDR_PLUGIN_CONFIG_DIR is not set"
    try:
        with open(os.path.join(config_dir, "config.json"), "r", encoding="utf-8") as fh:
            config = json.load(fh)
    except FileNotFoundError:
        return None, "config.json not found in HERDR_PLUGIN_CONFIG_DIR"
    except (json.JSONDecodeError, UnicodeDecodeError):
        return None, "config.json is not valid UTF-8 JSON"
    if not isinstance(config, dict):
        return None, "config.json is not a JSON object"
    if config.get("paused"):
        return None, "plugin is paused in config.json"
    socket_path = os.environ.get("HERDR_SOCKET_PATH")
    hosts = config.get("hosts")
    if not isinstance(hosts, list):
        return None, "config.json has no host list"
    host = next(
        (h for h in hosts if isinstance(h, dict) and h.get("socket_path") == socket_path),
        None,
    )
    if not host or not host.get("host_id") or not host.get("host_secret"):
        return None, "no host credentials for HERDR_SOCKET_PATH in config.json"
    if not config.get("relay_url"):
        return None, "relay_url is missing in config.json"
    return config, host


def _default_state_dir():
    return os.path.join(
        os.path.expanduser("~"), ".local", "state", "herdr", "plugins", PLUGIN_ID
    )


def main(argv=None):
    argv = sys.argv[1:] if argv is None else argv
    mode = argv[0] if argv else None
    if mode not in ("startup", "event"):
        event_name = os.environ.get("HERDR_PLUGIN_EVENT")
        if event_name == "startup":
            mode = "startup"
        elif event_name == "pane_agent_status_changed":
            mode = "event"
        else:
            return 0
    state_dir = os.environ.get("HERDR_PLUGIN_STATE_DIR") or _default_state_dir()
    try:
        selected = _config_for_environment()
        if selected[0] is None:
            log(selected[1])
            return 0
        config, host = selected
        relay = Relay(config["relay_url"], host, config.get("dev_access"))
        hook = Hook(
            host,
            state_dir,
            relay,
            herdr_blocked_panes,
            herdr_terminal_id,
        )
        if mode == "startup":
            return hook.run_startup()
        return hook.run_event(os.environ.get("HERDR_PLUGIN_EVENT_JSON", ""))
    except LockTimeout:
        # The lock is held for a network drain. Keep the event instead of losing it.
        if mode == "event":
            try:
                spool_event(
                    os.path.join(state_dir, host["host_id"]),
                    os.environ.get("HERDR_PLUGIN_EVENT_JSON", ""),
                )
            except OSError as exc:
                log("state lock busy; spool failed: %s" % type(exc).__name__)
                return 1
            log("state lock busy; event spooled")
        else:
            log("state lock busy")
        return 0
    except Exception as exc:  # unexpected: never print secrets or payloads
        log("unexpected failure: %s" % type(exc).__name__)
        return 1


if __name__ == "__main__":
    sys.exit(main())
