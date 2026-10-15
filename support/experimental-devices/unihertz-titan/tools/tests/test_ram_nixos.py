"""Synthetic tests of the RAM NixOS push helper; no phone, port or network."""

import contextlib
import hashlib
import importlib.util
import io
import os
from pathlib import Path
import socket
import tempfile
import threading
import unittest
from unittest import mock


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


HERE = Path(__file__).resolve().parent
tool = load("titan_ram_nixos_test", HERE.parent / "ram-nixos.py")


def device(port, product="Titan RAM NixOS", serial="TITAN-RAM-NIXOS-0001", vendor="Titan rescue experiment"):
    return (f'+-o {product}@01100000  <class IOUSBHostDevice, id 0x1>\n'
            f'    "idVendor" = 4617\n    "idProduct" = 5\n'
            f'    "USB Vendor Name" = "{vendor}"\n    "USB Product Name" = "{product}"\n'
            f'    "USB Serial Number" = "{serial}"\n'
            f'  +-o AppleUSBACMData  <class AppleUSBACMData, id 0x2>\n'
            f'      "IOCalloutDevice" = "{port}"\n')


class StageZero(threading.Thread):
    """Accepts one connection and reads at most the pinned size, like stage 0."""

    def __init__(self, size):
        super().__init__(daemon=True)
        self.server = socket.create_server(("127.0.0.1", 0))
        self.port, self.size, self.received = self.server.getsockname()[1], size, b""

    def run(self):
        connection, _ = self.server.accept()
        with connection:
            while len(self.received) < self.size:
                chunk = connection.recv(min(65536, self.size - len(self.received)))
                if not chunk:
                    break
                self.received += chunk
        self.server.close()


class ClockedTests(unittest.TestCase):
    def test_connect_retries_until_accepted_and_respects_the_deadline(self):
        now = [0.0]
        attempts = []

        def opener(address, timeout, source_address):
            attempts.append((address, source_address))
            if len(attempts) < 3:
                raise ConnectionRefusedError
            return "connection"

        result = tool.connect("172.16.42.1", 7000, "172.16.42.2", 10, opener=opener, clock=lambda: now[0],
                              sleep=lambda seconds: now.__setitem__(0, now[0] + seconds))
        self.assertEqual((result, len(attempts)), ("connection", 3))
        # Every attempt is bound to the USB link's leased address.
        self.assertEqual(set(attempts), {(("172.16.42.1", 7000), ("172.16.42.2", 0))})
        now[0] = 0.0
        with self.assertRaisesRegex(tool.PushError, "did not accept"):
            tool.connect("172.16.42.1", 7000, "172.16.42.2", 5,
                         opener=lambda *a, **k: (_ for _ in ()).throw(OSError()),
                         clock=lambda: now[0], sleep=lambda seconds: now.__setitem__(0, now[0] + seconds))

    def test_ssh_wait_needs_the_banner(self):
        class Fake:
            def __init__(self, banner):
                self.banner = banner
            def __enter__(self):
                return self
            def __exit__(self, *exc):
                return False
            def settimeout(self, value):
                pass
            def recv(self, size):
                return self.banner

        banners = [b"HTTP/1.1", b"SSH-2.0-OpenSSH_10.0"]
        tool.wait_ssh("172.16.42.1", "172.16.42.2", 10, opener=lambda *a, **k: Fake(banners.pop(0)),
                      clock=lambda: 0.0, sleep=lambda seconds: None)
        self.assertEqual(banners, [])


class PushTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name).resolve()
        self.system = self.root / "system.squashfs"
        self.data = os.urandom(300000)
        self.system.write_bytes(self.data)
        self.sha256 = hashlib.sha256(self.data).hexdigest()

    def tearDown(self):
        self.temporary.cleanup()

    def test_verify_refuses_a_different_file(self):
        tool.verify(self.system, self.sha256, len(self.data))
        with self.assertRaisesRegex(tool.PushError, "nothing was sent"):
            tool.verify(self.system, self.sha256, len(self.data) + 1)
        with self.assertRaisesRegex(tool.PushError, "nothing was sent"):
            tool.verify(self.system, "0" * 64, len(self.data))

    def test_push_sends_exactly_the_verified_bytes(self):
        stage = StageZero(len(self.data))
        stage.start()
        arguments = ["--system", str(self.system), "--sha256", self.sha256, "--bytes", str(len(self.data)),
                     "--output", str(self.root / "session"), "--key", "/private/key", "--host", "127.0.0.1",
                     "--source", "127.0.0.1", "--wait", "10", "--ssh-wait", "10", "--no-status"]
        with mock.patch.object(tool, "PORT", stage.port), mock.patch.object(tool, "wait_ssh") as ssh, \
                contextlib.redirect_stdout(io.StringIO()) as stdout:
            self.assertEqual(tool.main(arguments), 0)
        stage.join(5)
        self.assertEqual(stage.received, self.data)
        ssh.assert_called_once()
        self.assertIn("ssh -i /private/key -o IdentitiesOnly=yes -o BindAddress=127.0.0.1", stdout.getvalue())
        self.assertEqual(oct((self.root / "session").stat().st_mode & 0o777), "0o700")

    def test_a_wrong_local_file_sends_nothing_and_creates_nothing(self):
        arguments = ["--system", str(self.system), "--sha256", "0" * 64, "--bytes", str(len(self.data)),
                     "--output", str(self.root / "session"), "--key", "k", "--host", "127.0.0.1"]
        with mock.patch.object(tool, "connect") as connect, contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(tool.main(arguments), 1)
        connect.assert_not_called()
        self.assertFalse((self.root / "session").exists())
        # With the correct hash, so that only the bad option can refuse.
        options = dict(zip(arguments[0::2], arguments[1::2]), **{"--sha256": self.sha256})
        for option, value in (("--sha256", "XYZ"), ("--wait", "901"), ("--ssh-wait", "0"), ("--bytes", "0")):
            with self.subTest(option=option), contextlib.redirect_stderr(io.StringIO()):
                changed = dict(options, **{option: value})
                flat = [item for pair in changed.items() for item in pair if item is not None]
                self.assertEqual(tool.main(flat), 1)
                self.assertFalse((self.root / "session").exists())


class IdentityTests(unittest.TestCase):
    def test_only_the_ram_gadget_is_matched(self):
        listener = tool.load_listener()
        text = (device("/dev/cu.usbmodem101", product="Titan", serial="TITA0000", vendor="A-gold")
                + device("/dev/cu.usbmodem102", product="Titan read-only acquisition",
                         serial="TITAN-RESCUE-EXPERIMENT-0001")
                + device("/dev/cu.usbmodem103"))
        self.assertEqual(listener.probe_ports(text), [["/dev/cu.usbmodem103"]])
        # The reviewed listener itself still matches only the probe.
        original = load("titan_probe_listener_check", HERE.parent / "read-probe-report.py")
        self.assertEqual(original.probe_ports(text), [["/dev/cu.usbmodem102"]])


if __name__ == "__main__":
    unittest.main()
