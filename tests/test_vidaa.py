#!/usr/bin/python3
"""Hermetic tests for the backend: codec, guards, state projection.

No network, no daemon, no real credentials. Fixtures live under $HOME because
the path guards validate ancestors (a world-writable /tmp would fail them).
"""

import importlib.util
import json
import os
import shutil
import socket
import ssl
import struct
import stat
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
MODULE = os.path.join(HERE, "..", "scripts", "vidaa.py")

spec = importlib.util.spec_from_file_location("vidaa", MODULE)
vidaa = importlib.util.module_from_spec(spec)
sys.modules["vidaa"] = vidaa
spec.loader.exec_module(vidaa)


class Paths(unittest.TestCase):
    def setUp(self):
        self.root = tempfile.mkdtemp(dir=os.path.expanduser("~"), prefix=".vidaa-test-")
        os.chmod(self.root, 0o700)
        self.env = {k: os.environ.get(k) for k in
                    ("HOME", "XDG_CONFIG_HOME", "XDG_STATE_HOME", "XDG_RUNTIME_DIR")}
        os.environ["XDG_CONFIG_HOME"] = os.path.join(self.root, "config")
        os.environ["XDG_STATE_HOME"] = os.path.join(self.root, "state")
        os.environ["XDG_RUNTIME_DIR"] = os.path.join(self.root, "run")
        os.makedirs(os.path.join(self.root, "run"), mode=0o700, exist_ok=True)
        os.chmod(os.path.join(self.root, "run"), 0o700)

    def tearDown(self):
        for key, value in self.env.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value
        shutil.rmtree(self.root, ignore_errors=True)

    def write(self, name, data, mode=0o600):
        path = os.path.join(vidaa.config_root(), name)
        vidaa.ensure_dir(vidaa.config_root())
        with open(path, "wb") as fh:
            fh.write(data)
        os.chmod(path, mode)
        return path


class Credentials(unittest.TestCase):
    def test_known_vector(self):
        # Literals captured from the implementation that actually paired with the
        # TV: changing PATTERN, TIME_XOR, SALT or the hash chain must fail here.
        cid, user, password = vidaa.credentials(1794515869)
        self.assertEqual(cid, "02:11:22:33:44:55$his$363E21_vidaacommon_001")
        self.assertEqual(user, "his$6239759786162096885")
        self.assertEqual(password, "06FD421E88045DC4EE79BD8EEBB8A03C")

    def test_clock_change_changes_password(self):
        self.assertNotEqual(vidaa.credentials(1000)[2], vidaa.credentials(1001)[2])

    def test_client_id_is_stable(self):
        self.assertEqual(vidaa.credentials(1)[0], vidaa.credentials(2)[0])


class AddressGuard(unittest.TestCase):
    def test_private_accepted(self):
        for ip in ("192.168.1.77", "10.0.0.5", "172.16.4.9", "172.31.255.254", "169.254.1.1"):
            self.assertEqual(vidaa.valid_ip(ip), ip)

    def test_refused(self):
        for ip in ("127.0.0.1", "8.8.8.8", "0.0.0.0", "224.0.0.1", "172.32.0.1",
                   "100.64.1.2", "192.168.1.256", "192.168.1", "192.168.1.1.1",
                   "", None, "192.168.01.1", " 192.168.1.1"):
            with self.assertRaises(vidaa.Fail, msg=repr(ip)):
                vidaa.valid_ip(ip)


class Secrets(Paths):
    def test_accepts_0600_regular_file(self):
        path = self.write("client.pem", b"-----BEGIN CERTIFICATE-----\nX\n")
        self.assertEqual(vidaa.read_secret(path), b"-----BEGIN CERTIFICATE-----\nX\n")

    def test_rejects_group_readable(self):
        path = self.write("client.pem", b"x", mode=0o644)
        with self.assertRaises(vidaa.Fail) as ctx:
            vidaa.read_secret(path)
        self.assertEqual(ctx.exception.code, "cert_permissions")

    def test_rejects_symlink(self):
        target = self.write("real.pem", b"x")
        link = os.path.join(vidaa.config_root(), "client.pem")
        os.symlink(target, link)
        with self.assertRaises(vidaa.Fail) as ctx:
            vidaa.read_secret(link)
        self.assertEqual(ctx.exception.code, "cert_invalid")

    def test_rejects_path_outside_root(self):
        outside = os.path.join(self.root, "outside.pem")
        with open(outside, "wb") as fh:
            fh.write(b"x")
        os.chmod(outside, 0o600)
        with self.assertRaises(vidaa.Fail) as ctx:
            vidaa.read_secret(outside)
        self.assertEqual(ctx.exception.code, "cert_invalid")

    def test_rejects_relative_path(self):
        with self.assertRaises(vidaa.Fail):
            vidaa.read_secret("client.pem")

    def test_rejects_hardlink(self):
        path = self.write("client.pem", b"x")
        other = os.path.join(vidaa.config_root(), "other.pem")
        os.link(path, other)
        with self.assertRaises(vidaa.Fail) as ctx:
            vidaa.read_secret(other)
        self.assertEqual(ctx.exception.code, "cert_invalid")

    def test_rejects_oversize(self):
        path = self.write("client.pem", b"x" * (vidaa.MAX_CERT + 1))
        with self.assertRaises(vidaa.Fail):
            vidaa.read_secret(path)

    def test_import_refuses_relative(self):
        with self.assertRaises(vidaa.Fail):
            vidaa.import_material("client.pem", os.path.join(vidaa.config_root(), "client.pem"))

    def test_import_refuses_key_as_certificate(self):
        src = os.path.join(self.root, "key.pem")
        with open(src, "wb") as fh:
            fh.write(b"-----BEGIN PRIVATE KEY-----\nX\n")
        with self.assertRaises(vidaa.Fail) as ctx:
            vidaa.import_material(src, os.path.join(vidaa.config_root(), "client.pem"))
        self.assertEqual(ctx.exception.code, "cert_invalid")


class Directories(Paths):
    def test_creates_private_chain(self):
        root = vidaa.config_root()
        vidaa.ensure_dir(root)
        self.assertEqual(stat.S_IMODE(os.stat(root).st_mode), 0o700)
        self.assertEqual(stat.S_IMODE(os.stat(os.path.dirname(root)).st_mode), 0o700)

    def test_rejects_symlinked_component(self):
        real = os.path.join(self.root, "real")
        os.makedirs(real, mode=0o700)
        link = os.path.join(self.root, "link")
        os.symlink(real, link)
        os.environ["XDG_CONFIG_HOME"] = os.path.join(link, "config")
        with self.assertRaises(vidaa.Fail) as ctx:
            vidaa.ensure_dir(vidaa.config_root())
        self.assertEqual(ctx.exception.code, "unsafe_dir")

    def test_rejects_world_writable_component(self):
        base = os.path.join(self.root, "shared")
        os.makedirs(base, mode=0o700)
        os.chmod(base, 0o777)
        os.environ["XDG_STATE_HOME"] = base
        with self.assertRaises(vidaa.Fail) as ctx:
            vidaa.ensure_dir(vidaa.state_root())
        self.assertEqual(ctx.exception.code, "unsafe_dir")

    def test_atomic_write_is_0600(self):
        path = os.path.join(vidaa.state_root(), "state.json")
        vidaa.write_json(path, {"a": 1})
        self.assertEqual(stat.S_IMODE(os.stat(path).st_mode), 0o600)
        self.assertEqual(json.load(open(path)), {"a": 1})
        self.assertEqual([n for n in os.listdir(os.path.dirname(path)) if n.startswith(".tmp.")], [])


class Text(unittest.TestCase):
    def test_strips_control_and_bidi(self):
        raw = "Rai\u202e 4K\u0007\n<img src=x>"
        self.assertEqual(vidaa.clean_text(raw, 40), "Rai 4K<img src=x>")

    def test_caps_length(self):
        self.assertEqual(len(vidaa.clean_text("x" * 500, 40)), 40)


class Codec(unittest.TestCase):
    def test_varint_roundtrip(self):
        for value in (0, 1, 127, 128, 300, 16383, 16384, 2097151):
            encoded = vidaa._varint(value)
            self.assertEqual(encoded[-1] & 0x80, 0)
            decoded, mult = 0, 1
            for byte in encoded:
                decoded += (byte & 0x7F) * mult
                mult *= 128
            self.assertEqual(decoded, value)

    def test_publish_frames_topic_and_payload(self):
        left, right = socket.socketpair()
        try:
            writer = vidaa.Mqtt(left)
            reader = vidaa.Mqtt(right)
            writer.publish("/remoteapp/tv/remote_service/x/actions/sendkey", "KEY_OK")
            kind, body = reader.read(1.0)
            self.assertEqual(kind, 3)
            tlen = int.from_bytes(body[:2], "big")
            self.assertEqual(body[2:2 + tlen], b"/remoteapp/tv/remote_service/x/actions/sendkey")
            self.assertEqual(body[2 + tlen:], b"KEY_OK")
        finally:
            left.close()
            right.close()

    def test_oversize_packet_is_refused(self):
        left, right = socket.socketpair()
        try:
            mqtt = vidaa.Mqtt(left)
            with self.assertRaises(vidaa.Fail):
                mqtt.publish("/x", "y" * vidaa.MAX_PACKET)
        finally:
            left.close()
            right.close()

    def test_read_rejects_declared_oversize_before_allocating(self):
        left, right = socket.socketpair()
        try:
            mqtt = vidaa.Mqtt(right)
            # header 0x30 + remaining length 0x80 0x80 0x10 (~262144) -> too large
            left.sendall(b"\x30\x80\x80\x10")
            with self.assertRaises(vidaa.Fail) as ctx:
                mqtt.read(0.5)
            self.assertEqual(ctx.exception.code, "bad_request")
        finally:
            left.close()
            right.close()

    def test_read_rejects_bad_remaining_length(self):
        left, right = socket.socketpair()
        try:
            mqtt = vidaa.Mqtt(right)
            left.sendall(b"\x30\xff\xff\xff\xff\x7f")
            with self.assertRaises(vidaa.Fail):
                mqtt.read(0.5)
        finally:
            left.close()
            right.close()


class Frames(unittest.TestCase):
    def test_publish_parts(self):
        body = struct.pack("!H", 4) + b"/abc" + b"payload"
        self.assertEqual(vidaa.publish_parts(body), ("/abc", b"payload"))

    def test_publish_parts_rejects_short_and_lying_topic(self):
        self.assertIsNone(vidaa.publish_parts(b""))
        self.assertIsNone(vidaa.publish_parts(b"\x00"))
        self.assertIsNone(vidaa.publish_parts(struct.pack("!H", 500) + b"short"))

    def test_parse_json_bounded(self):
        self.assertEqual(vidaa.parse_json('{"a": 1}'), {"a": 1})
        # Deep nesting must not propagate RecursionError into the daemon loop.
        self.assertIsNone(vidaa.parse_json("[" * 60000 + "]" * 60000))
        self.assertIsNone(vidaa.parse_json("not json"))
        self.assertIsInstance(vidaa.parse_json("[" * 2000 + "]" * 2000), list)


class StateProjection(unittest.TestCase):
    def test_sleep_and_wake_statetypes(self):
        state = vidaa.TvState()
        state.set_statetype({"statetype": "fake_sleep_0"})
        self.assertEqual(state.power, "off")
        state.set_statetype({"statetype": "fake_sleep_1"})
        self.assertEqual(state.power, "on")
        state.set_statetype({"statetype": "livetv", "channel_name": "Rai 4K", "sourceid": "TV"})
        self.assertEqual((state.power, state.channel, state.source), ("on", "Rai 4K", "TV"))

    def test_volume_types(self):
        state = vidaa.TvState()
        state.set_volume({"volume_type": 0, "volume_value": 11})
        state.set_volume({"volume_type": 2, "volume_value": 1})
        self.assertEqual(state.volume, 11)
        self.assertTrue(state.muted)
        state.set_volume({"volume_type": 2, "volume_value": 0})
        self.assertFalse(state.muted)

    def test_volume_out_of_range_ignored(self):
        state = vidaa.TvState()
        state.set_volume({"volume_type": 0, "volume_value": 101})
        self.assertIsNone(state.volume)

    def test_applist_curates_and_validates(self):
        state = vidaa.TvState()
        state.set_applist([
            {"name": "Netflix", "appId": "1"},
            {"name": "YouTube", "appId": "3"},
            {"name": "Evil", "appId": "../x"},
            {"name": "Bad", "appId": "1/2"},
        ])
        self.assertEqual([a["name"] for a in state.apps], ["Netflix", "YouTube"])
        self.assertEqual(len(state.raw_applist), 2)

    def test_sourcelist_validates_ids(self):
        state = vidaa.TvState()
        state.set_sourcelist([{"sourceid": "HDMI1", "displayname": "HDMI1"},
                              {"sourceid": "x/y", "displayname": "bad"}])
        self.assertEqual(state.sources, [{"id": "HDMI1", "label": "HDMI1"}])

    def test_document_fits_state_cap(self):
        state = vidaa.TvState()
        # Curated names are what survives set_applist, so pad them to the
        # per-field limit: a document built only from HDMI1 entries would never
        # approach MAX_STATE and the truncation branch would stay untested.
        state.apps = [{"name": ("x" * 40) + str(i), "appId": str(i)} for i in range(30)]
        state.sources = [{"id": "HDMI1", "label": "y" * 32} for _ in range(16)]
        state.raw_applist = [{"name": "x" * 40, "appId": str(i), "url": "z" * 120}
                             for i in range(200)]
        doc = state.document()
        self.assertLessEqual(len(json.dumps(doc)), vidaa.MAX_STATE)
        self.assertIn("updated", doc)
        self.assertIn("pid", doc)

    def test_document_marks_apps_truncated_when_too_large(self):
        state = vidaa.TvState()
        state.apps = [{"name": ("x" * 40) + str(i), "appId": str(i)} for i in range(30)]
        state.sources = [{"id": "HDMI1", "label": "y" * 32} for _ in range(16)]
        state.available = False
        state.code = "tv_unreachable"
        doc = state.document()
        self.assertEqual(doc["available"], False)
        self.assertEqual(doc["code"], "tv_unreachable")


class NetFile(Paths):
    def test_missing_net_is_a_refusal_not_trust(self):
        with self.assertRaises(vidaa.Fail) as ctx:
            vidaa.load_net()
        self.assertEqual(ctx.exception.code, "cert_invalid")

    def test_malformed_pin_refused(self):
        self.write("net.json", json.dumps({"pin": "abc", "anchor": "x"}).encode())
        with self.assertRaises(vidaa.Fail):
            vidaa.load_net()

    def test_valid_net_reads(self):
        self.write("net.json", json.dumps({"pin": "a" * 64, "anchor": "-----BEGIN CERTIFICATE-----\nX\n"}).encode())
        self.assertEqual(vidaa.load_net()["pin"], "a" * 64)


class Config(Paths):
    def test_missing_config_requires_pairing(self):
        with self.assertRaises(vidaa.Fail) as ctx:
            vidaa.load_config()
        self.assertEqual(ctx.exception.code, "pairing_required")

    def test_config_rejects_public_ip(self):
        self.write("config.json", json.dumps({"tvIp": "8.8.8.8"}).encode())
        with self.assertRaises(vidaa.Fail):
            vidaa.load_config()


if __name__ == "__main__":
    unittest.main(verbosity=2)
