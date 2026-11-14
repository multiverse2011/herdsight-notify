# Herdsight Notify (herdr plugin)

Sends a generic push notification through the Herdsight relay when an agent in this
herdr session needs input. The hook is a short-lived `python3` process (standard library
only, Python 3.9+), started by herdr for each `pane.agent_status_changed` event and once at
startup. macOS only (herdr 0.9.5 or later).

The notification carries no terminal content: the relay only learns that some pane is
blocked.

## Set up from the iPhone app

In the Herdsight app, open notification setup for a Mac whose host key you have approved and
tap **Set Up Notifications**. The app connects over SSH and, if the plugin is missing or older
than 0.2.0, asks before running `herdr plugin install` / `herdr plugin update` through your
login shell. It then runs:

```bash
cd <plugin root> && /usr/bin/python3 setup.py pair --relay-url <relay URL>
```

`pair` creates the pairing, prints it as one JSON line, reads the 8-digit code the app got
from the relay on stdin, compares it with the relay's code and approves it. There is no code to
compare by hand: the host key you approved stands in for that check. `pair` never prompts,
writes only JSON lines to stdout (`{"v":1,"pair":…}`, then `{"v":1,"result":"approved",…}` or
`{"v":1,"error":"<code>"}`), and cancels the pairing if stdin closes early. It refuses to
switch a Mac that is already set up for a different relay (`relay_mismatch`); run uninstall
first to switch relays.

The app needs `/usr/bin/python3` (Command Line Tools) on the Mac.

## Install and pair manually

Use this when the app can't reach the Mac over SSH (for example through a tunnel), or choose
**Set Up Manually** in the app. On the Mac that runs herdr:

```bash
herdr plugin install multiverse2011/herdsight-notify -y
herdr plugin pane open --plugin herdsight.notify --entrypoint setup
```

The second command opens the setup pane inside herdr. Then:

1. Setup prints a pairing string `<pair_id>.<claim_secret>` and copies it to the clipboard.
   With Universal Clipboard it is already on your iPhone.
2. In the Herdsight app, open notification setup and paste the string within 5 minutes.
3. The Mac and the app both show an 8-digit code. If they are the same, answer `y` on the
   Mac. Anything else (Enter, Ctrl-C) cancels the pairing. If the app shows no code, answer
   `N`: someone else may have claimed the pairing string.

Setup takes the herdr socket from `--socket-path`, `HERDR_SOCKET_PATH` (set inside herdr
panes), or `$XDG_CONFIG_HOME/herdr/herdr.sock` (default `~/.config/herdr/herdr.sock`), prints
the one it uses, and asks only when none of them exists.

Running setup again for the same socket reuses that host's credentials and adds another
iPhone or iPad. If the relay rejects the credentials (401), setup creates new ones once and
keeps the workspace allowlist. A device that is already paired with this Mac can't pair again
until you unpair it in the app.

### Options

`setup.py` also runs outside herdr (`python3 setup.py` from the install directory; the config
directory then comes from `herdr plugin config-dir herdsight.notify`).

| Option | Environment | Meaning |
|---|---|---|
| `--relay-url` | `HERDSIGHT_RELAY_URL` | Relay base URL (https). Default: the one saved in `config.json`, else `https://relay.ayushio.com`. A URL different from the saved one is refused; run uninstall first to switch relays. |
| `--dev-access` | `HERDSIGHT_RELAY_DEV_ACCESS` | Access value for a development relay. Never asked for. |
| `--socket-path` | `HERDR_SOCKET_PATH` | Absolute path of the herdr socket this host belongs to. |
| `--workspace <id>` (repeatable) | | Notify only for these workspaces. Default: all workspaces. |

If the app cannot finish the pairing, two manual commands remain (pass `--socket-path` when
`config.json` holds more than one host):

```bash
python3 setup.py approve <pair_id> <code>
python3 setup.py cancel <pair_id>
```

## Where the files live

- Config: `config.json` in `herdr plugin config-dir herdsight.notify`
  (or `HERDR_PLUGIN_CONFIG_DIR`). Contains the relay URL and the host credentials.
- State: `state.json` and `state.lock` in
  `~/.local/state/herdr/plugins/herdsight.notify/<host_id>/` (or
  `$HERDR_PLUGIN_STATE_DIR/<host_id>/`), one directory per paired host.

Both are written atomically with mode `0600`. Credentials are never written to the plugin
install directory.

## Uninstall

```bash
herdr plugin pane open --plugin herdsight.notify --entrypoint uninstall
herdr plugin uninstall herdsight.notify
```

The uninstall pane asks for confirmation first (`setup.py uninstall --yes` skips it).
`setup.py uninstall` calls `DELETE /v1/self` for every configured host on the saved relay, then
removes the local config, state, lock, and spool files. Run it **before**
`herdr plugin uninstall`, which only removes herdr's registration and leaves `config.json`
and the state files behind. If any relay deletion fails, the command exits nonzero and keeps
the local config and state so the cleanup can be retried.

## Tests

```bash
python3 -m unittest discover -s tests -t .
```

The tests use fake HTTP and fake herdr; they never touch the network, a live herdr, or the
clipboard.

## License

MIT. See [LICENSE](LICENSE).
