# Hisense TV for Omarchy

Control a Hisense **VIDAA** smart TV from the Omarchy bar: power, volume, mute,
D-pad/OK/back/home/menu, HDMI inputs and app launch — plus live state (channel,
app, volume) in the bar.

Everything runs on your LAN: the plugin talks to the TV's own MQTT broker on
port `36669`. No cloud, no account, no vendor app running.

```
bar:  Rai 4K 11        ← channel/app + volume, click for the remote
panel: power · mute · −/+ · D-pad · back/home/menu · inputs · apps
```

## Requirements

- Omarchy with the Quickshell shell (bar plugin support).
- The TV on the same network, with its **quick start / standby Wi-Fi** enabled
  (that is what lets the plugin wake it).
- A **VIDAA client certificate** (`CN=VidaaAppAndroidV01`) — see below.
- Python 3.11+ at `/usr/bin/python3`. No third-party packages.

## The client certificate

VIDAA firmware requires mutual TLS on the MQTT port and validates the client
certificate identity. That key pair is shipped inside the official VIDAA
smartphone app; it is **not** included in this repository, and it identifies the
vendor app — not you. Extract it from the app you already have a right to run:

```bash
unzip -l vidaa.apk | grep -iE '\.p12|client_mobile'
#  e.g. res/3R.p12  or  res/raw/client_mobile_android.p12

openssl pkcs12 -legacy -in <file>.p12 -clcerts -nokeys -out client.pem -passin pass:<p12-password>
openssl pkcs12 -legacy -in <file>.p12 -nocerts -nodes  -out client.key -passin pass:<p12-password>
chmod 600 client.pem client.key
```

The plugin copies them into its own config directory and refuses to run if they
are group/world readable, symlinked, hard-linked or outside that directory.

## Pairing (once)

```bash
/usr/bin/python3 ~/.config/omarchy/plugins/meviusisback.hisense-tv/scripts/vidaa.py \
  pair --cert /path/client.pem --key /path/client.key
```

The CLI prints the TV's certificate fingerprint and asks you to confirm it, then
triggers the on-screen pairing code: type the 4 digits and the TV authorizes this
client for good. Pairing only needs to be repeated if the firmware changes the
TV certificate (the bar shows `TV certificate changed`) or the authorization is
reset on the TV.

If the IP changes, run `vidaa.py discover` (SSDP + a scan of your /24 for the
MQTT port) and then `vidaa.py set-tv <ip>`. The address lives in `config.json`,
not in the shell settings, so there is a single source of truth; the panel shows
the failure code and the command to run.

## Usage

- Bar: live channel/app + volume. Click opens the remote; right-click refreshes.
- IPC: `omarchy-shell meviusisback.hisense-tv open|close|toggle|refresh` (bind it
  to a key if you want the remote without the mouse).
- Wheel over the bar icon: volume.
- Panel: power, mute, volume, D-pad, back/home/menu, inputs, app shortcuts.
- While the panel is open it owns the keyboard: arrow keys drive the TV's D-pad,
  Enter/space sends OK, Escape closes the panel.
- CLI (`scripts/vidaa.py`): `status`, `key <KEY>`, `vol up|down|set N|mute`,
  `source <TV|HDMI1|HDMI2|HDMI3|AVS|MusicSharing>`, `app <id|name>`, `power`,
  `refresh`, `discover`, `set-tv <ip>`, `pair`, `stop`.

## How it works

```
Panel.qml ──watches──> state.json   (written by the daemon, atomically)
    │
    └──one-shot──> vidaa.py <verb> ──unix socket──> daemon ──mTLS MQTT──> TV:36669
```

- Exactly **one** MQTT client exists: a per-user daemon holding a `flock`, a
  `0600` unix socket in `$XDG_RUNTIME_DIR/omarchy-hisense-tv/`, a keepalive and
  a capped backoff. Every bar press is a short-lived client of that daemon.
- Credentials are derived from the TV's own clock (UPnP `Date` header), so a
  skewed laptop clock cannot break the login.
- The TV's certificate is pinned at pairing (chain verified against the TV's
  `RemoteCA`, leaf SHA-256 stored). A different certificate is refused, never
  trusted silently.
- Presses use MQTT QoS 0: `delivered` means the daemon handed the key to the
  socket, not that the TV rendered it. Warm-path latency on the reference host:
  p95 ≈ 83 ms (measured over 15 warm presses on this host).

Files:

| Path | Contents |
|---|---|
| `~/.config/omarchy/hisense-tv/config.json` | `tvIp`, client id, pairing date (0600) |
| `~/.config/omarchy/hisense-tv/net.json` | pinned leaf fingerprint + RemoteCA anchor (0600) |
| `~/.config/omarchy/hisense-tv/client.pem`, `client.key` | client certificate pair (0600) |
| `$XDG_STATE_HOME/omarchy/hisense-tv/state.json` | last state document (0600) |
| `$XDG_RUNTIME_DIR/omarchy-hisense-tv/` | lock, socket, daemon status (0700) |

## Error codes

| Code | Meaning | Fix |
|---|---|---|
| `pairing_required` | TV refused the login (rc 5) or nothing is paired | run `pair` |
| `tv_identity_changed` | pinned certificate no longer matches | verify, then `pair` again |
| `cert_permissions` | cert/key not `0600` or foreign owner | `chmod 600`, check ownership |
| `cert_invalid` | not a cert/key pair, symlink, hard link, too large | re-extract from the app |
| `unsafe_dir` | config/state/runtime dir is world-writable, symlinked or foreign | fix the directory |
| `tv_unreachable` | TV off the network or wrong IP | `discover` / `set-tv` |
| `bad_request` | unknown key/source/app id | use the values from `status` |

## Not supported

- Power-on over Wi-Fi **without** standby networking: the TV must keep Wi-Fi
  alive in standby (VIDAA setting "Quick start").
- Text entry, voice, channel numbers beyond the digit keys.
- Firmware that changes the MQTT topics or requires an access token as password:
  the plugin reports `pairing_required` instead of guessing.
