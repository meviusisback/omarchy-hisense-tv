#!/usr/bin/python3
"""hisense-tv backend: VIDAA TV control over the TV's local MQTT bus.

Stdlib only. Two halves:

  * `daemon` — the single MQTT client. Owns a flock, a unix control socket and
    the state file. Reconnects on its own; exits on refusal with a coded status.
  * `ctl` verbs (key/vol/source/app/power/status/stop/set-tv/discover/pair) —
    short-lived clients that require the daemon (spawning it when absent).

Protocol notes (reverse engineered, verified against a 55A53FEVS, fw V0000.09.09G):
MQTT 3.1.1 over mutual TLS on :36669 with a client cert CN=VidaaAppAndroidV01;
username/password derived from the TV's own clock, read from the UPnP `Date`
header on :38400. Pairing is a 4-digit on-screen PIN. Keys are published to
.../remote_service/<client>/actions/sendkey as bare strings.
"""

from __future__ import annotations

import errno
import fcntl
import hashlib
import json
import os
import select
import selectors
import socket
import ssl
import stat
import struct
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request

VERSION = "0.1.0"
PLUGIN_ID = "meviusisback.hisense-tv"

TV_PORT = 36669
UPNP_PORT = 38400

# The TV authorizes this client id once (PIN pairing); it must never change,
# or the pairing is lost.
CLIENT_UUID = "02:11:22:33:44:55"
PATTERN = "38D65DC30F45109A369A86FCE866A85B"
TIME_XOR = 6239759785777146216
SALT = "h!i@s#$v%i^d&a*a"

MAX_CERT = 16 * 1024
MAX_PACKET = 64 * 1024
MAX_REPLY = 4096
MAX_REQUEST = 1024
MAX_STATE = 16 * 1024
STATE_REFRESH = 60
KEEPALIVE = 30
PING_EVERY = 20
SOCKET_TIMEOUT = 45

EXIT = {
    "tv_unreachable": 69,
    "tv_identity_changed": 70,
    "pairing_required": 71,
    "cert_permissions": 72,
    "cert_invalid": 73,
    "unsafe_dir": 74,
    "config": 78,
    "bad_request": 64,
    "busy": 75,
    "mqtt_refused": 71,
}

KEYS = {
    "KEY_POWER", "KEY_VOLUMEUP", "KEY_VOLUMEDOWN", "KEY_MUTE", "KEY_CHANNELUP",
    "KEY_CHANNELDOWN", "KEY_UP", "KEY_DOWN", "KEY_LEFT", "KEY_RIGHT", "KEY_OK",
    "KEY_RETURNS", "KEY_HOME", "KEY_MENU", "KEY_EXIT", "KEY_INFO", "KEY_PLAY",
    "KEY_PAUSE", "KEY_STOP", "KEY_FORWARDS", "KEY_BACK", "KEY_SUBTITLE",
    "KEY_MEDIA", "KEY_0", "KEY_1", "KEY_2", "KEY_3", "KEY_4", "KEY_5", "KEY_6",
    "KEY_7", "KEY_8", "KEY_9",
}

SOURCES = {"TV", "HDMI1", "HDMI2", "HDMI3", "HDMI4", "AVS", "MusicSharing"}

# Shown in the panel, in this order, when present in the TV's app list.
CURATED_APPS = ["Netflix", "YouTube", "Prime Video", "Rai Play", "DAZN", "NOW",
                "Disney+", "Spotify"]

TOPIC_STATE = "/remoteapp/mobile/broadcast/ui_service/state"
TOPIC_VOLUME = "/remoteapp/mobile/broadcast/platform_service/actions/volumechange"
TOPIC_SLEEP = "/remoteapp/mobile/broadcast/platform_service/actions/tvsleep"
TOPIC_AUTHS = "/remoteapp/mobile/{cid}/ui_service/data/authentication"
TOPIC_AUTHCODE = "/remoteapp/mobile/{cid}/ui_service/data/authenticationcode"


class Fail(Exception):
    def __init__(self, code: str, detail: str = ""):
        self.code = code
        self.detail = detail[:200]
        super().__init__(code)


# --------------------------------------------------------------------------
# paths and files
# --------------------------------------------------------------------------

def home_dir() -> str:
    home = os.environ.get("HOME", "")
    if not os.path.isabs(home):
        raise Fail("config", "HOME is not absolute")
    return home


def xdg_dir(var: str, fallback: str) -> str:
    value = os.environ.get(var, "")
    return value if os.path.isabs(value) else fallback


def config_root() -> str:
    return os.path.join(xdg_dir("XDG_CONFIG_HOME", os.path.join(home_dir(), ".config")),
                        "omarchy", "hisense-tv")


def state_root() -> str:
    return os.path.join(xdg_dir("XDG_STATE_HOME", os.path.join(home_dir(), ".local", "state")),
                        "omarchy", "hisense-tv")


def runtime_root() -> str:
    base = xdg_dir("XDG_RUNTIME_DIR", "/run/user/%d" % os.getuid())
    return os.path.join(base, "omarchy-hisense-tv")


def state_path() -> str:
    return os.path.join(state_root(), "state.json")


def config_path() -> str:
    return os.path.join(config_root(), "config.json")


def net_path() -> str:
    return os.path.join(config_root(), "net.json")


def lock_path() -> str:
    return os.path.join(runtime_root(), "lock")


def socket_path() -> str:
    return os.path.join(runtime_root(), "ctl.sock")


def daemon_status_path() -> str:
    return os.path.join(runtime_root(), "daemon.json")


def ensure_dir(path: str) -> str:
    """Create/validate a directory chain.

    Components inside the XDG base must be ours, single-linked and private;
    ancestors above it (/, /home, /run) are only checked for symlinks and
    group/world write access, which is what they can offer.
    """
    path = os.path.abspath(path)
    parts = path.split(os.sep)[1:]
    if parts[-2:] == ["omarchy", "hisense-tv"]:
        base_len = len(parts) - 2
    else:
        base_len = len(parts) - 1
    cur = os.sep
    for index, part in enumerate(parts):
        cur = os.path.join(cur, part)
        try:
            st = os.lstat(cur)
        except FileNotFoundError:
            try:
                os.mkdir(cur, 0o700)
            except OSError as exc:
                raise Fail("unsafe_dir", "mkdir %s: %s" % (cur, exc.errno))
            st = os.lstat(cur)
        if stat.S_ISLNK(st.st_mode):
            raise Fail("unsafe_dir", "symlink in path")
        if not stat.S_ISDIR(st.st_mode):
            raise Fail("unsafe_dir", "not a directory")
        if st.st_mode & 0o022:
            raise Fail("unsafe_dir", "group/world writable")
        if index >= base_len and st.st_uid != os.getuid():
            raise Fail("unsafe_dir", "foreign owner")
    return path


def sweep_temps(directory: str) -> None:
    try:
        names = os.listdir(directory)
    except OSError:
        return
    now = time.time()
    for name in names[:64]:
        if not name.startswith(".tmp."):
            continue
        full = os.path.join(directory, name)
        try:
            if now - os.lstat(full).st_mtime > 60:
                os.unlink(full)
        except OSError:
            pass


def atomic_write(path: str, data: bytes, mode: int = 0o600) -> None:
    ensure_dir(os.path.dirname(path))
    fd, tmp = tempfile.mkstemp(prefix=".tmp.", dir=os.path.dirname(path))
    try:
        os.fchmod(fd, mode)
        with os.fdopen(fd, "wb") as fh:
            fh.write(data)
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def read_bounded(path: str, limit: int) -> bytes:
    with open(path, "rb") as fh:
        return fh.read(limit + 1)[:limit]


def write_state_document(document: dict) -> None:
    """Write the state cache in place.

    Atomic replace would be the default choice, but the shell watches this file
    with inotify on the INODE: os.replace() swaps the inode and the watch never
    fires again, leaving the bar frozen on the first document. A state cache is
    not a secret and the widget keeps its last good value on a partial read, so
    truncate-and-write is the right trade here. Secrets/config still use
    atomic_write().
    """
    data = (json.dumps(document) + "\n").encode()
    if len(data) > 4 * MAX_STATE:
        data = (json.dumps({"available": False, "stale": True,
                            "code": "state_too_large"}) + "\n").encode()
    ensure_dir(state_root())
    fd = os.open(state_path(), os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_CLOEXEC, 0o600)
    try:
        os.write(fd, data)
    finally:
        os.close(fd)


def write_json(path: str, obj, mode: int = 0o600) -> None:
    atomic_write(path, (json.dumps(obj, separators=(",", ":")) + "\n").encode(), mode)


def read_json(path: str, limit: int = 16 * 1024):
    try:
        raw = read_bounded(path, limit)
    except FileNotFoundError:
        return None
    if len(raw) > limit:
        return None
    try:
        value = json.loads(raw.decode("utf-8", "replace"))
    except ValueError:
        return None
    return value if isinstance(value, dict) else None


# --------------------------------------------------------------------------
# config / net
# --------------------------------------------------------------------------

def valid_ip(value) -> str:
    if not isinstance(value, str) or len(value) > 15 or value.count(".") != 3:
        raise Fail("config", "bad address")
    try:
        packed = socket.inet_aton(value)
    except OSError:
        raise Fail("config", "bad address")
    if socket.inet_ntoa(packed) != value:
        raise Fail("config", "bad address")
    num = struct.unpack("!I", packed)[0]
    private = ((num >> 24) == 10
               or (num >> 20) == 0xAC1
               or (num >> 16) == 0xC0A8
               or (num >> 16) == 0xA9FE)
    if not private:
        raise Fail("config", "address outside private ranges")
    return value


def load_config(require_paired: bool = True) -> dict:
    ensure_dir(config_root())
    cfg = read_json(config_path())
    if not cfg:
        if require_paired:
            raise Fail("pairing_required", "config.json missing")
        return {}
    tv = valid_ip(cfg.get("tvIp"))
    return {"tvIp": tv,
            "clientId": str(cfg.get("clientId") or ""),
            "pairedAt": str(cfg.get("pairedAt") or "")}


def load_net() -> dict:
    net = read_json(net_path()) or {}
    pin = net.get("pin")
    anchor = net.get("anchor")
    if not isinstance(pin, str) or len(pin) != 64 or not isinstance(anchor, str) or "CERTIFICATE" not in anchor:
        raise Fail("cert_invalid", "net.json missing or malformed")
    return {"pin": pin, "anchor": anchor}


def read_secret(path: str) -> bytes:
    """Read a cert/key that must live inside the plugin config root."""
    if not os.path.isabs(path):
        raise Fail("cert_invalid", "relative path")
    root = os.path.realpath(config_root())
    if os.path.islink(os.path.abspath(path)):
        raise Fail("cert_invalid", "symlink")
    real = os.path.realpath(path)
    if real == root or os.path.commonpath([real, root]) != root:
        raise Fail("cert_invalid", "outside config root")
    try:
        fd = os.open(real, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
    except OSError as exc:
        raise Fail("cert_invalid", "open: %s" % exc.errno)
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode):
            raise Fail("cert_invalid", "not a regular file")
        if st.st_nlink != 1:
            raise Fail("cert_invalid", "hard linked")
        if st.st_uid != os.getuid():
            raise Fail("cert_permissions", "foreign owner")
        if st.st_mode & 0o077:
            raise Fail("cert_permissions", "mode %o" % (st.st_mode & 0o777))
        if st.st_size == 0 or st.st_size > MAX_CERT:
            raise Fail("cert_invalid", "bad size")
        data = os.read(fd, MAX_CERT + 1)
    finally:
        os.close(fd)
    if len(data) > MAX_CERT:
        raise Fail("cert_invalid", "too large")
    return data


def client_material() -> tuple[bytes, bytes]:
    return (read_secret(os.path.join(config_root(), "client.pem")),
            read_secret(os.path.join(config_root(), "client.key")))


# --------------------------------------------------------------------------
# TLS + credentials
# --------------------------------------------------------------------------

def _memfd(data: bytes) -> int:
    fd = os.memfd_create("hs", 0)
    os.write(fd, data)
    os.lseek(fd, 0, os.SEEK_SET)
    return fd


def tls_context(verify_anchor: str | None, cert: bytes, key: bytes) -> ssl.SSLContext:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    if verify_anchor:
        ctx.verify_mode = ssl.CERT_REQUIRED
        try:
            ctx.load_verify_locations(cadata=verify_anchor)
        except ssl.SSLError as exc:
            raise Fail("cert_invalid", "anchor: %s" % exc)
    else:
        ctx.verify_mode = ssl.CERT_NONE
    cf, kf = _memfd(cert), _memfd(key)
    try:
        ctx.load_cert_chain("/proc/self/fd/%d" % cf, "/proc/self/fd/%d" % kf)
    except ssl.SSLError as exc:
        raise Fail("cert_invalid", "pair: %s" % exc)
    finally:
        os.close(cf)
        os.close(kf)
    return ctx


def tv_timestamp(ip: str) -> int:
    """The TV's own clock (RFC1123 Date header). Credentials are derived from it."""
    class NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, *args, **kwargs):
            return None

    opener = urllib.request.build_opener(NoRedirect)
    url = "http://%s:%d/" % (ip, UPNP_PORT)
    try:
        with opener.open(url, timeout=3) as resp:
            date = resp.headers.get("Date")
            resp.read(4096)
    except urllib.error.HTTPError as exc:
        date = exc.headers.get("Date") if exc.headers else None
    except (urllib.error.URLError, OSError) as exc:
        raise Fail("tv_unreachable", "date: %s" % type(exc).__name__)
    if not date:
        raise Fail("tv_unreachable", "no Date header")
    try:
        ts = int(time.mktime(time.strptime(date, "%a, %d %b %Y %H:%M:%S %Z")))
    except ValueError:
        raise Fail("tv_unreachable", "bad Date")
    return ts


def credentials(ts: int) -> tuple[str, str, str]:
    md5 = lambda s: hashlib.md5(s.encode()).hexdigest().upper()
    cid = "%s$his$%s_vidaacommon_001" % (CLIENT_UUID, md5("%s$%s" % (PATTERN, CLIENT_UUID))[:6])
    username = "his$%d" % (ts ^ TIME_XOR)
    digitsum = sum(int(ch) for ch in str(ts)) % 10
    password = md5("%d$%s" % (ts, md5("his%d%s" % (digitsum, SALT))[:6]))
    return cid, username, password


# --------------------------------------------------------------------------
# MQTT codec
# --------------------------------------------------------------------------

def _varint(value: int) -> bytes:
    out = bytearray()
    while True:
        byte = value % 128
        value //= 128
        if value:
            out.append(byte | 0x80)
        else:
            out.append(byte)
            return bytes(out)


def _mstr(text: str) -> bytes:
    data = text.encode()
    return struct.pack("!H", len(data)) + data


def _recvn(sock, count: int) -> bytes:
    buf = bytearray()
    while len(buf) < count:
        chunk = sock.recv(count - len(buf))
        if not chunk:
            raise ConnectionError("eof")
        buf += chunk
    return bytes(buf)


class Mqtt:
    def __init__(self, sock):
        self.sock = sock

    def close(self):
        try:
            self.sock.close()
        except OSError:
            pass

    def publish(self, topic: str, payload: str) -> None:
        body = _mstr(topic) + payload.encode()
        if len(body) > MAX_PACKET:
            raise Fail("bad_request", "payload too large")
        self.sock.sendall(b"\x30" + _varint(len(body)) + body)

    def subscribe(self, topics) -> None:
        body = struct.pack("!H", 1) + b"".join(_mstr(t) + b"\x00" for t in topics)
        self.sock.sendall(b"\x82" + _varint(len(body)) + body)

    def ping(self) -> None:
        self.sock.sendall(b"\xc0\x00")

    def read(self, timeout: float):
        self.sock.settimeout(timeout)
        header = _recvn(self.sock, 1)[0]
        kind = header >> 4
        length = 0
        mult = 1
        for _ in range(4):
            byte = _recvn(self.sock, 1)[0]
            length += (byte & 0x7F) * mult
            if not byte & 0x80:
                break
            mult *= 128
        else:
            raise Fail("bad_request", "bad remaining length")
        if length > MAX_PACKET:
            raise Fail("bad_request", "packet too large")
        body = _recvn(self.sock, length) if length else b""
        return kind, body


def mqtt_open(ip: str, net: dict | None, timeout: float = 5.0) -> Mqtt:
    cert, key = client_material()
    anchor = net["anchor"] if net else None
    ctx = tls_context(anchor, cert, key)
    ts = tv_timestamp(ip)
    cid, user, password = credentials(ts)
    try:
        raw = socket.create_connection((ip, TV_PORT), timeout=timeout)
        sock = ctx.wrap_socket(raw)
    except ssl.SSLCertVerificationError as exc:
        raise Fail("cert_invalid", "server verify: %s" % exc)
    except (OSError, ssl.SSLError) as exc:
        raise Fail("tv_unreachable", "tls: %s" % type(exc).__name__)
    if net:
        der = sock.getpeercert(binary_form=True) or b""
        if hashlib.sha256(der).hexdigest() != net["pin"]:
            sock.close()
            raise Fail("tv_identity_changed", "leaf fingerprint mismatch")
    mqtt = Mqtt(sock)
    variable = _mstr("MQTT") + bytes([4, 0xC2]) + struct.pack("!H", KEEPALIVE)
    payload = _mstr(cid) + _mstr(user) + _mstr(password)
    try:
        sock.sendall(b"\x10" + _varint(len(variable) + len(payload)) + variable + payload)
        kind, body = mqtt.read(timeout)
    except (OSError, ConnectionError) as exc:
        mqtt.close()
        raise Fail("tv_unreachable", "connect: %s" % type(exc).__name__)
    if kind != 2 or len(body) < 2:
        mqtt.close()
        raise Fail("mqtt_refused", "no connack")
    rc = body[1]
    if rc != 0:
        mqtt.close()
        if rc == 5:
            raise Fail("pairing_required", "not authorized")
        raise Fail("mqtt_refused", "rc=%d" % rc)
    return mqtt


def sub_topics(cid: str):
    return [
        TOPIC_STATE,
        TOPIC_VOLUME,
        TOPIC_SLEEP,
        "/remoteapp/mobile/broadcast/ui_service/volume",
        "/remoteapp/mobile/%s/ui_service/data/state" % cid,
        "/remoteapp/mobile/%s/ui_service/data/applist" % cid,
        "/remoteapp/mobile/%s/ui_service/data/sourcelist" % cid,
        TOPIC_AUTHS.format(cid=cid),
        TOPIC_AUTHCODE.format(cid=cid),
    ]


# --------------------------------------------------------------------------
# state
# --------------------------------------------------------------------------

def boot_id() -> str:
    try:
        return read_bounded("/proc/sys/kernel/random/boot_id", 64).decode().strip()[:36]
    except OSError:
        return ""


def clean_text(value, limit: int = 64) -> str:
    if not isinstance(value, str):
        return ""
    out = []
    for ch in value[:limit * 2]:
        code = ord(ch)
        if code < 32 or 0x7F <= code <= 0x9F or 0x200E <= code <= 0x200F or code in (0x202A, 0x202B, 0x202C, 0x202D, 0x202E):
            continue
        out.append(ch)
    return "".join(out)[:limit]


class TvState:
    def __init__(self):
        self.power = "unknown"
        self.statetype = ""
        self.volume = None
        self.muted = None
        self.source = ""
        self.channel = ""
        self.app = ""
        self.apps = []
        self.sources = []
        self.raw_applist = []
        self.updated = 0.0
        self.dirty = False

    def summary(self) -> dict:
        return {
            "available": True,
            "power": self.power,
            "statetype": self.statetype,
            "volume": self.volume,
            "muted": self.muted,
            "source": self.source,
            "channel": self.channel,
            "app": self.app,
            "apps": self.apps,
            "sources": self.sources,
        }

    def document(self) -> dict:
        doc = self.summary()
        doc.update({"updated": int(self.updated or time.time()), "boot_id": boot_id(),
                    "pid": os.getpid(), "stale": False})
        if len(json.dumps(doc)) > MAX_STATE:
            doc["apps"] = []
            doc["appsTruncated"] = True
        return doc

    def set_statetype(self, payload: dict) -> None:
        st = payload.get("statetype")
        if not isinstance(st, str):
            return
        st = clean_text(st, 32)
        self.statetype = st
        self.updated = time.time()
        if st == "fake_sleep_0":
            self.power = "off"
            self.app = ""
        elif st == "fake_sleep_1":
            self.power = "on"
        else:
            self.power = "on"
            if st in ("livetv", "sourceswitch"):
                src = payload.get("sourceid") or payload.get("sourcename")
                if isinstance(src, str):
                    self.source = clean_text(src, 16)
                ch = payload.get("channel_name")
                if isinstance(ch, str):
                    self.channel = clean_text(ch, 40)
            elif st == "remote_launcher":
                self.app = ""
        self.dirty = True

    def set_volume(self, payload: dict) -> None:
        try:
            vtype = int(payload.get("volume_type"))
            value = int(payload.get("volume_value"))
        except (TypeError, ValueError):
            return
        if vtype == 0 and 0 <= value <= 100:
            self.volume = value
        elif vtype == 2:
            self.muted = value != 0
        self.updated = time.time()
        self.dirty = True

    def set_applist(self, payload) -> None:
        if not isinstance(payload, list):
            return
        raw = []
        resolved = []
        for entry in payload[:200]:
            if not isinstance(entry, dict):
                continue
            name = clean_text(entry.get("name"), 40)
            app_id = entry.get("appId")
            if not name or not isinstance(app_id, (str, int)):
                continue
            app_id = clean_text(str(app_id), 16)
            if not app_id or not all(c.isalnum() or c in "._-" for c in app_id):
                continue
            raw.append({"name": name, "appId": app_id,
                        "url": clean_text(entry.get("url"), 120)})
        for wanted in CURATED_APPS:
            for entry in raw:
                if entry["name"] == wanted or entry["name"].startswith(wanted):
                    resolved.append({"name": entry["name"], "appId": entry["appId"]})
                    break
        self.raw_applist = raw
        self.apps = resolved[:30]
        self.dirty = True

    def set_sourcelist(self, payload) -> None:
        if not isinstance(payload, list):
            return
        out = []
        for entry in payload[:32]:
            if not isinstance(entry, dict):
                continue
            sid = clean_text(entry.get("sourceid") or entry.get("sourcename"), 16)
            if not sid or not all(c.isalnum() or c in "._-" for c in sid):
                continue
            label = clean_text(entry.get("displayname") or entry.get("sourcename") or sid, 32)
            out.append({"id": sid, "label": label or sid})
        self.sources = out[:16]
        self.dirty = True


# --------------------------------------------------------------------------
# daemon
# --------------------------------------------------------------------------

def _notify(fd: int | None, payload: dict) -> None:
    if fd is None:
        return
    try:
        os.write(fd, (json.dumps(payload) + "\n").encode()[:512])
    except OSError:
        pass
    finally:
        try:
            os.close(fd)
        except OSError:
            pass


def write_daemon_status(state: str, code: str = "") -> None:
    try:
        write_json(daemon_status_path(), {"state": state, "code": code,
                                          "pid": os.getpid(), "updated": int(time.time())})
    except (Fail, OSError):
        pass


def daemon_main(lock_fd: int | None, status_fd: int | None) -> int:
    try:
        rt = ensure_dir(runtime_root())
    except Fail as exc:
        _notify(status_fd, {"state": "refused", "code": exc.code})
        return EXIT.get(exc.code, 78)
    sweep_temps(rt)

    if lock_fd is None:
        lock_fd = os.open(lock_path(), os.O_RDWR | os.O_CREAT | os.O_CLOEXEC | os.O_NOFOLLOW, 0o600)
        try:
            fcntl.flock(lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            _notify(status_fd, {"state": "refused", "code": "busy"})
            return 0

    try:
        cfg = load_config()
    except Fail as exc:
        write_daemon_status("refused", exc.code)
        _notify(status_fd, {"state": "refused", "code": exc.code})
        return EXIT.get(exc.code, 71)
    ip = cfg["tvIp"]
    cid = credentials(int(time.time()))[0]

    sock_path = socket_path()
    try:
        st = os.lstat(sock_path)
        if stat.S_ISSOCK(st.st_mode):
            os.unlink(sock_path)
        else:
            raise Fail("unsafe_dir", "ctl.sock is not a socket")
    except FileNotFoundError:
        pass
    except Fail as exc:
        _notify(status_fd, {"state": "refused", "code": exc.code})
        return EXIT.get(exc.code, 78)

    old = os.umask(0o077)
    try:
        listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        listener.bind(sock_path)
        listener.listen(4)
        listener.setblocking(False)
    finally:
        os.umask(old)

    state = TvState()
    state.updated = time.time()
    write_daemon_status("ready")
    _notify(status_fd, {"state": "ready"})
    write_state_document(state.document())

    sel = selectors.DefaultSelector()
    sel.register(listener, selectors.EVENT_READ)
    mqtt = None
    mqtt_fd = None
    next_attempt = 0.0
    next_ping = 0.0
    next_refresh = 0.0
    next_state_write = 0.0
    backoff = 1.0
    stopping = False

    def disconnect():
        nonlocal mqtt, mqtt_fd
        if mqtt:
            mqtt.close()
            try:
                sel.unregister(mqtt.sock)
            except (KeyError, ValueError):
                pass
        mqtt, mqtt_fd = None, None

    def write_state(force=False):
        nonlocal next_state_write
        now = time.time()
        if not force and now < next_state_write:
            return
        next_state_write = now + 0.5
        if not state.dirty and not force:
            return
        try:
            write_state_document(state.document())
            state.dirty = False
        except (OSError, Fail):
            pass

    def handle_publish(topic: str, payload: bytes):
        try:
            data = json.loads(payload.decode("utf-8", "replace")) if payload else None
        except ValueError:
            return
        if topic.endswith("/state") and "/ui_service/" in topic:
            if isinstance(data, dict):
                state.set_statetype(data)
        elif topic.endswith("/volumechange") or topic.endswith("/ui_service/volume"):
            if isinstance(data, dict):
                state.set_volume(data)
        elif topic.endswith("/actions/tvsleep"):
            state.power = "off"
            state.statetype = "fake_sleep_0"
            state.dirty = True
        elif topic.endswith("/data/applist"):
            state.set_applist(data)
        elif topic.endswith("/data/sourcelist"):
            state.set_sourcelist(data)

    def connect():
        nonlocal mqtt, mqtt_fd, next_ping, next_refresh, backoff
        mqtt = mqtt_open(ip, load_net(), timeout=4.0)
        mqtt.subscribe(sub_topics(cid))
        mqtt.publish("/remoteapp/tv/ui_service/%s/actions/gettvstate" % cid, "")
        mqtt.publish("/remoteapp/tv/platform_service/%s/actions/getvolume" % cid, "")
        mqtt.publish("/remoteapp/tv/ui_service/%s/actions/applist" % cid, "")
        mqtt.publish("/remoteapp/tv/ui_service/%s/actions/sourcelist" % cid, "")
        sel.register(mqtt.sock, selectors.EVENT_READ)
        mqtt_fd = mqtt.sock.fileno()
        next_ping = time.time() + PING_EVERY
        next_refresh = time.time() + STATE_REFRESH
        backoff = 1.0
        write_daemon_status("ready")
        state.dirty = True

    def reply(conn, payload: dict):
        try:
            data = (json.dumps(payload) + "\n").encode()
            if len(data) > MAX_REPLY:
                data = (json.dumps({"id": payload.get("id"), "ok": False,
                                    "code": "too_large"}) + "\n").encode()
            conn.sendall(data)
        except OSError:
            pass
        finally:
            try:
                conn.close()
            except OSError:
                pass

    def command(payload: dict) -> dict:
        nonlocal stopping, next_refresh
        rid = payload.get("id")
        cmd = payload.get("cmd")
        base = {"id": rid, "ok": True, "delivered": False}
        if mqtt is None:
            base.update({"ok": False, "code": "tv_unreachable"})
            return base
        ui = "/remoteapp/tv/ui_service/%s/actions/" % cid
        try:
            if cmd == "key":
                key = payload.get("key")
                if key not in KEYS:
                    return {"id": rid, "ok": False, "code": "bad_request"}
                mqtt.publish("/remoteapp/tv/remote_service/%s/actions/sendkey" % cid, key)
            elif cmd == "vol":
                action = payload.get("action")
                if action == "up":
                    mqtt.publish("/remoteapp/tv/remote_service/%s/actions/sendkey" % cid, "KEY_VOLUMEUP")
                elif action == "down":
                    mqtt.publish("/remoteapp/tv/remote_service/%s/actions/sendkey" % cid, "KEY_VOLUMEDOWN")
                elif action == "mute":
                    mqtt.publish("/remoteapp/tv/remote_service/%s/actions/sendkey" % cid, "KEY_MUTE")
                elif action == "set":
                    try:
                        level = int(payload.get("level"))
                    except (TypeError, ValueError):
                        return {"id": rid, "ok": False, "code": "bad_request"}
                    if not 0 <= level <= 100:
                        return {"id": rid, "ok": False, "code": "bad_request"}
                    mqtt.publish("/remoteapp/tv/platform_service/%s/actions/changevolume" % cid, str(level))
                else:
                    return {"id": rid, "ok": False, "code": "bad_request"}
            elif cmd == "source":
                src = payload.get("source")
                if src not in SOURCES:
                    return {"id": rid, "ok": False, "code": "bad_request"}
                mqtt.publish(ui + "changesource", json.dumps({"sourceid": src}))
            elif cmd == "app":
                target = payload.get("app")
                entry = None
                for item in state.raw_applist:
                    if item["appId"] == target or item["name"] == target:
                        entry = item
                        break
                if entry is None:
                    return {"id": rid, "ok": False, "code": "bad_request"}
                mqtt.publish(ui + "launchapp", json.dumps(
                    {"appId": entry["appId"], "name": entry["name"],
                     "url": entry.get("url") or entry["name"], "storeType": 99}))
            elif cmd == "power":
                mqtt.publish("/remoteapp/tv/remote_service/%s/actions/sendkey" % cid, "KEY_POWER")
            elif cmd == "refresh":
                mqtt.publish(ui + "gettvstate", "")
                mqtt.publish("/remoteapp/tv/platform_service/%s/actions/getvolume" % cid, "")
                mqtt.publish(ui + "applist", "")
                mqtt.publish(ui + "sourcelist", "")
                next_refresh = time.time() + STATE_REFRESH
            elif cmd == "status":
                base.update({"state": state.summary()})
                return base
            elif cmd == "shutdown":
                stopping = True
                base["delivered"] = True
                return base
            else:
                return {"id": rid, "ok": False, "code": "bad_request"}
            base["delivered"] = True
        except (OSError, Fail) as exc:
            disconnect()
            return {"id": rid, "ok": False, "code": getattr(exc, "code", "tv_unreachable")}
        return base

    try:
        while not stopping:
            now = time.time()
            if mqtt is None and now >= next_attempt:
                try:
                    connect()
                except Fail as exc:
                    if exc.code in ("pairing_required", "cert_invalid", "cert_permissions",
                                    "tv_identity_changed", "unsafe_dir", "config"):
                        write_daemon_status("refused", exc.code)
                        write_state_document({"available": False, "stale": True,
                                              "code": exc.code, "updated": int(time.time())})
                        return EXIT.get(exc.code, 78)
                    next_attempt = now + backoff
                    backoff = min(backoff * 2, 30.0) * (1 + os.urandom(1)[0] / 2550.0)

            try:
                events = sel.select(0.5)
            except InterruptedError:
                events = []

            for key, _mask in events:
                if mqtt and key.fileobj is mqtt.sock:
                    try:
                        kind, body = mqtt.read(1.0)
                    except socket.timeout:
                        disconnect()
                        next_attempt = time.time() + 1.0
                        continue
                    except (OSError, ConnectionError, ssl.SSLError, Fail):
                        disconnect()
                        next_attempt = time.time() + 1.0
                        continue
                    if kind == 3 and len(body) >= 2:
                        tlen = struct.unpack("!H", body[:2])[0]
                        if 2 + tlen <= len(body):
                            topic = body[2:2 + tlen].decode("utf-8", "replace")
                            handle_publish(topic, body[2 + tlen:])
                elif key.fileobj is listener:
                    try:
                        conn, _ = listener.accept()
                    except OSError:
                        continue
                    conn.settimeout(2.0)
                    try:
                        raw = b""
                        while b"\n" not in raw and len(raw) <= MAX_REQUEST:
                            chunk = conn.recv(MAX_REQUEST)
                            if not chunk:
                                break
                            raw += chunk
                        if len(raw) > MAX_REQUEST:
                            reply(conn, {"ok": False, "code": "bad_request"})
                            continue
                        request = json.loads(raw.decode("utf-8", "replace") or "{}")
                        if not isinstance(request, dict):
                            reply(conn, {"ok": False, "code": "bad_request"})
                            continue
                        reply(conn, command(request))
                    except (OSError, ValueError, socket.timeout):
                        reply(conn, {"ok": False, "code": "bad_request"})

            if mqtt is not None:
                now = time.time()
                if now >= next_ping:
                    try:
                        mqtt.ping()
                        next_ping = now + PING_EVERY
                    except OSError:
                        disconnect()
                if now >= next_refresh:
                    try:
                        ui = "/remoteapp/tv/ui_service/%s/actions/" % cid
                        mqtt.publish(ui + "gettvstate", "")
                        mqtt.publish("/remoteapp/tv/platform_service/%s/actions/getvolume" % cid, "")
                    except (OSError, Fail):
                        disconnect()
                    next_refresh = now + STATE_REFRESH
                write_state()

        # shutdown: remove state so a dead daemon is never shown as live
        try:
            os.unlink(state_path())
        except OSError:
            pass
        write_daemon_status("stopped")
        return 0
    finally:
        for fd in (listener,):
            try:
                fd.close()
            except OSError:
                pass
        try:
            os.unlink(sock_path)
        except OSError:
            pass
        sel.close()
        if mqtt:
            mqtt.close()


# --------------------------------------------------------------------------
# client side
# --------------------------------------------------------------------------

def open_lock(readonly=False) -> int:
    flags = os.O_RDONLY if readonly else (os.O_RDWR | os.O_CREAT)
    return os.open(lock_path(), flags | os.O_CLOEXEC | os.O_NOFOLLOW, 0o600)


def connect_socket(deadline: float):
    end = time.time() + deadline
    while True:
        try:
            sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            sock.settimeout(1.0)
            sock.connect(socket_path())
            return sock
        except OSError:
            try:
                sock.close()
            except OSError:
                pass
            if time.time() >= end:
                return None
            time.sleep(0.05)


def daemon_code() -> str:
    doc = read_json(daemon_status_path(), 4096) or {}
    code = doc.get("code")
    return code if isinstance(code, str) and code else ""


def run_command(request: dict, spawn: bool = True, timeout: float = 3.0) -> dict:
    ensure_dir(runtime_root())
    spawned = False
    lock_fd = None
    if spawn:
        lock_fd = open_lock()
        try:
            fcntl.flock(lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            spawned = True
        except BlockingIOError:
            spawned = False
    status_fd = None
    if spawned:
        status_r, status_w = os.pipe()
        env = {"HOME": home_dir(), "PATH": "/usr/bin:/bin"}
        for name in ("XDG_RUNTIME_DIR", "XDG_STATE_HOME", "XDG_CONFIG_HOME"):
            value = os.environ.get(name)
            if value:
                env[name] = value
        env["VIDAA_LOCK_FD"] = str(lock_fd)
        env["VIDAA_STATUS_FD"] = str(status_w)
        python = sys.executable if os.path.isabs(sys.executable) else "/usr/bin/python3"
        try:
            subprocess.Popen([python, "-I", "-u", os.path.abspath(__file__), "daemon"],
                             stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                             stderr=subprocess.DEVNULL, pass_fds=(lock_fd, status_w),
                             start_new_session=True, env=env, close_fds=True)
        except OSError as exc:
            os.close(status_r)
            os.close(status_w)
            raise Fail("config", "spawn: %s" % exc)
        os.close(status_w)
        ready, _, _ = select.select([status_r], [], [], 3.0)
        line = b""
        if ready:
            try:
                line = os.read(status_r, 512)
            except OSError:
                line = b""
        os.close(status_r)
        if line:
            try:
                msg = json.loads(line.decode("utf-8", "replace"))
            except ValueError:
                msg = {}
            if msg.get("state") != "ready":
                raise Fail(msg.get("code") or "config")

    try:
        return _run_command_finish(request, timeout, spawned)
    finally:
        try:
            os.close(lock_fd)
        except (OSError, TypeError):
            pass


def _run_command_finish(request: dict, timeout: float, spawned: bool) -> dict:
    sock = connect_socket(3.0 if spawned else 2.0)
    if sock is None:
        code = daemon_code()
        if code:
            raise Fail(code)
        raise Fail("tv_unreachable", "daemon did not answer")
    try:
        sock.settimeout(timeout)
        sock.sendall((json.dumps(request) + "\n").encode()[:MAX_REQUEST])
        raw = b""
        while b"\n" not in raw and len(raw) <= MAX_REPLY:
            chunk = sock.recv(MAX_REPLY)
            if not chunk:
                break
            raw += chunk
        if not raw:
            raise Fail(daemon_code() or "tv_unreachable", "no reply")
        reply = json.loads(raw.decode("utf-8", "replace"))
        if not isinstance(reply, dict):
            raise Fail("bad_request", "bad reply")
        return reply
    except (OSError, ValueError) as exc:
        # A daemon that died mid-request (refused config, TV identity change,
        # ...) leaves its reason in daemon.json: report that, not "unreachable".
        raise Fail(daemon_code() or "tv_unreachable", "ctl: %s" % type(exc).__name__)
    finally:
        try:
            sock.close()
        except OSError:
            pass


def cli_verb(verb: str, extra: dict | None = None) -> dict:
    request = {"id": 1, "cmd": verb}
    if extra:
        request.update(extra)
    reply = run_command(request)
    if not reply.get("ok"):
        raise Fail(reply.get("code") or "config")
    return reply


# --------------------------------------------------------------------------
# pairing / discovery
# --------------------------------------------------------------------------

def import_material(path: str, target: str) -> None:
    if not os.path.isabs(path):
        raise Fail("cert_invalid", "absolute path required")
    try:
        fd = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
    except OSError as exc:
        raise Fail("cert_invalid", "open: %s" % exc.errno)
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode) or st.st_size == 0 or st.st_size > MAX_CERT:
            raise Fail("cert_invalid", "not a usable file")
        data = os.read(fd, MAX_CERT + 1)
    finally:
        os.close(fd)
    if b"PRIVATE KEY" in data and target.endswith(".pem"):
        raise Fail("cert_invalid", "that is a key, not a certificate")
    atomic_write(target, data, 0o600)


def stop_daemon(timeout: float = 12.0) -> None:
    """Ask a running daemon to exit and wait for the lock to be released."""
    ensure_dir(runtime_root())
    try:
        reply = run_command({"id": 1, "cmd": "shutdown"}, spawn=False, timeout=2.0)
        if not reply.get("ok"):
            raise Fail(reply.get("code") or "config")
    except Fail:
        pass
    end = time.time() + timeout
    while time.time() < end:
        fd = open_lock()
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            os.close(fd)
            return
        except BlockingIOError:
            os.close(fd)
            time.sleep(0.1)
    raise Fail("busy", "daemon did not stop")


def cmd_pair(args) -> dict:
    ip = valid_ip(args.tv or (load_config(require_paired=False).get("tvIp") or ""))
    ensure_dir(config_root())
    cert_path = os.path.join(config_root(), "client.pem")
    key_path = os.path.join(config_root(), "client.key")
    import_material(os.path.expanduser(args.cert), cert_path)
    import_material(os.path.expanduser(args.key), key_path)
    os.chmod(cert_path, 0o600)
    os.chmod(key_path, 0o600)
    stop_daemon()

    cert, key = client_material()
    mqtt = None
    try:
        # first contact: capture the TV's chain, then prove it verifies against
        # that anchor before trusting it.
        ctx = tls_context(None, cert, key)
        try:
            raw = socket.create_connection((ip, TV_PORT), timeout=5)
            probe = ctx.wrap_socket(raw)
        except (OSError, ssl.SSLError) as exc:
            raise Fail("tv_unreachable", "tls: %s" % type(exc).__name__)
        chain = probe.get_unverified_chain() or []
        der = probe.getpeercert(binary_form=True) or b""
        probe.close()
        if not der:
            raise Fail("cert_invalid", "no server certificate")
        anchor_der = chain[1] if len(chain) > 1 else der
        anchor = ssl.DER_cert_to_PEM_cert(anchor_der)
        pin = hashlib.sha256(der).hexdigest()
        verified = tls_context(anchor, cert, key)
        try:
            raw = socket.create_connection((ip, TV_PORT), timeout=5)
            check = verified.wrap_socket(raw)
            check.close()
        except (OSError, ssl.SSLError) as exc:
            raise Fail("cert_invalid", "anchor does not verify the TV: %s" % type(exc).__name__)
        print("TV certificate sha256: %s" % pin)
        if not args.yes:
            answer = input("Trust this TV? [y/N] ").strip().lower()
            if answer not in ("y", "yes"):
                raise Fail("config", "aborted")

        write_json(net_path(), {"pin": pin, "anchor": anchor})
        mqtt = mqtt_open(ip, {"pin": pin, "anchor": anchor}, timeout=6.0)
        cid = credentials(int(time.time()))[0]
        mqtt.subscribe([TOPIC_AUTHS.format(cid=cid), TOPIC_AUTHCODE.format(cid=cid)])
        mqtt.publish("/remoteapp/tv/ui_service/%s/actions/vidaa_app_connect" % cid,
                     json.dumps({"app_version": 2, "connect_result": 0, "device_type": "Mobile App"}))
        print("Look at the TV: a 4-digit pairing code should be on screen.")
        got_prompt = False
        end = time.time() + 25
        while time.time() < end:
            try:
                kind, body = mqtt.read(1.0)
            except socket.timeout:
                continue
            if kind == 3:
                tlen = struct.unpack("!H", body[:2])[0]
                topic = body[2:2 + tlen].decode("utf-8", "replace")
                if topic.endswith("/data/authentication"):
                    got_prompt = True
                    break
        if not got_prompt:
            print("(no prompt seen, sending the code anyway)")

        pin_code = os.environ.get("VIDAA_PIN") or ""
        try:
            import getpass
            pin_code = getpass.getpass("Pairing code: ").strip() or pin_code
        except (EOFError, OSError):
            pass
        if len(pin_code) != 4 or not pin_code.isdigit():
            raise Fail("bad_request", "4 digits required")
        mqtt.publish("/remoteapp/tv/ui_service/%s/actions/authenticationcode" % cid,
                     json.dumps({"authNum": int(pin_code)}))
        ok = False
        end = time.time() + 10
        while time.time() < end:
            try:
                kind, body = mqtt.read(1.0)
            except socket.timeout:
                continue
            if kind != 3:
                continue
            tlen = struct.unpack("!H", body[:2])[0]
            topic = body[2:2 + tlen].decode("utf-8", "replace")
            if topic.endswith("/data/authenticationcode"):
                try:
                    payload = json.loads(body[2 + tlen:].decode())
                except ValueError:
                    continue
                if payload.get("result") == 1:
                    ok = True
                    break
                raise Fail("pairing_required", "code rejected")
        if not ok:
            raise Fail("pairing_required", "no confirmation")
        mqtt.publish("/remoteapp/tv/ui_service/%s/actions/authenticationcodeclose" % cid, "")
        write_json(config_path(), {"tvIp": ip, "clientId": cid,
                                   "pairedAt": time.strftime("%Y-%m-%dT%H:%M:%S")})
        print("Paired with %s (%s)" % (ip, cid))
        return {"ok": True, "tvIp": ip}
    finally:
        if mqtt:
            mqtt.close()


def discover(timeout: float = 2.0) -> list:
    """Find candidate TVs: SSDP M-SEARCH plus a :36669 scan of the local /24."""
    candidates = set()
    message = ("\r\n".join([
        "M-SEARCH * HTTP/1.1", "HOST: 239.255.255.250:1900", 'MAN: "ssdp:discover"',
        "MX: 2", "ST: ssdp:all", "", ""])).encode()
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 2)
        sock.settimeout(0.6)
        sock.sendto(message, ("239.255.255.250", 1900))
        end = time.time() + timeout
        while time.time() < end:
            try:
                data, addr = sock.recvfrom(4096)
            except socket.timeout:
                break
            text = data[:4096].decode("utf-8", "replace").lower()
            if "hisense" in text or "vidaa" in text or "media" in text:
                try:
                    candidates.add(valid_ip(addr[0]))
                except Fail:
                    pass
        sock.close()
    except OSError:
        pass

    # Local /24 probe for the MQTT port.
    try:
        src = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        src.connect(("192.168.1.1", 9))
        local = src.getsockname()[0]
        src.close()
    except OSError:
        local = ""
    if local:
        prefix = local.rsplit(".", 1)[0]
        import concurrent.futures
        def probe(last):
            host = "%s.%s" % (prefix, last)
            sock = socket.socket()
            sock.settimeout(0.3)
            try:
                sock.connect((host, TV_PORT))
                return host
            except OSError:
                return None
            finally:
                sock.close()
        with concurrent.futures.ThreadPoolExecutor(max_workers=64) as pool:
            for host in pool.map(probe, range(1, 255)):
                if host:
                    try:
                        candidates.add(valid_ip(host))
                    except Fail:
                        pass
    return sorted(candidates)


# --------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------

def emit(obj, code: int = 0) -> int:
    sys.stdout.write(json.dumps(obj, separators=(",", ":")) + "\n")
    sys.stdout.flush()
    return code


def main(argv) -> int:
    import argparse
    parser = argparse.ArgumentParser(prog="vidaa", description="Hisense VIDAA TV control")
    sub = parser.add_subparsers(dest="verb")

    p = sub.add_parser("daemon", help="run the singleton MQTT daemon")
    p.add_argument("--lock-fd", type=int, default=None)
    p.add_argument("--status-fd", type=int, default=None)

    sub.add_parser("state-path")
    sub.add_parser("status")
    sub.add_parser("stop")
    sub.add_parser("discover")

    p = sub.add_parser("key")
    p.add_argument("key")
    p = sub.add_parser("vol")
    p.add_argument("action", choices=["up", "down", "mute", "set"])
    p.add_argument("level", nargs="?", default="")
    p = sub.add_parser("source")
    p.add_argument("source")
    p = sub.add_parser("app")
    p.add_argument("app")
    sub.add_parser("power")
    sub.add_parser("refresh")

    p = sub.add_parser("set-tv")
    p.add_argument("ip")

    p = sub.add_parser("pair")
    p.add_argument("--tv", default="")
    p.add_argument("--cert", required=True)
    p.add_argument("--key", required=True)
    p.add_argument("--yes", action="store_true")

    args = parser.parse_args(argv[1:])
    verb = args.verb or "status"

    try:
        if verb == "daemon":
            lock_fd = args.lock_fd
            if lock_fd is None:
                lock_fd = os.environ.get("VIDAA_LOCK_FD")
                lock_fd = int(lock_fd) if lock_fd and lock_fd.isdigit() else None
            status_fd = args.status_fd
            if status_fd is None:
                status_fd = os.environ.get("VIDAA_STATUS_FD")
                status_fd = int(status_fd) if status_fd and status_fd.isdigit() else None
            return daemon_main(lock_fd, status_fd)
        if verb == "state-path":
            ensure_dir(state_root())
            return emit({"ok": True, "path": state_path()})
        if verb == "discover":
            found = discover()
            return emit({"ok": True, "candidates": found})
        if verb == "set-tv":
            ip = valid_ip(args.ip)
            cfg = load_config(require_paired=False)
            cfg["tvIp"] = ip
            cfg.setdefault("clientId", "")
            cfg.setdefault("pairedAt", "")
            write_json(config_path(), cfg)
            try:
                run_command({"id": 1, "cmd": "shutdown"}, spawn=False, timeout=2.0)
            except Fail:
                pass
            return emit({"ok": True, "tvIp": ip})
        if verb == "pair":
            return emit(cmd_pair(args))
        if verb == "status":
            reply = run_command({"id": 1, "cmd": "status"})
            if reply.get("ok"):
                return emit({"ok": True, "state": reply.get("state", {})})
            cfg = load_config(require_paired=False)
            code = reply.get("code") or daemon_code() or "pairing_required"
            if not cfg:
                code = "pairing_required"
            return emit({"ok": False, "code": code}, EXIT.get(code, 69))
        if verb == "stop":
            try:
                reply = run_command({"id": 1, "cmd": "shutdown"}, timeout=2.0)
            except Fail as exc:
                if exc.code in ("tv_unreachable", "config"):
                    return emit({"ok": True, "stopped": True})
                raise
            return emit({"ok": bool(reply.get("ok")), "stopped": True})
        if verb == "key":
            if args.key not in KEYS:
                raise Fail("bad_request", "unknown key")
            return emit(cli_verb("key", {"key": args.key}))
        if verb == "vol":
            extra = {"action": args.action}
            if args.action == "set":
                if not args.level.isdigit():
                    raise Fail("bad_request", "level required")
                extra["level"] = int(args.level)
            return emit(cli_verb("vol", extra))
        if verb == "source":
            if args.source not in SOURCES:
                raise Fail("bad_request", "unknown source")
            return emit(cli_verb("source", {"source": args.source}))
        if verb == "app":
            return emit(cli_verb("app", {"app": args.app}))
        if verb == "power":
            return emit(cli_verb("power"))
        if verb == "refresh":
            return emit(cli_verb("refresh"))
        raise Fail("bad_request", "unknown verb")
    except Fail as exc:
        sys.stderr.write("vidaa: %s%s\n" % (exc.code, (": " + exc.detail) if exc.detail else ""))
        return emit({"ok": False, "code": exc.code}, EXIT.get(exc.code, 1))
    except (KeyboardInterrupt, EOFError):
        return 130


if __name__ == "__main__":
    try:
        sys.exit(main(sys.argv))
    except Fail as exc:
        sys.stderr.write("vidaa: %s\n" % exc.code)
        sys.exit(EXIT.get(exc.code, 1))
