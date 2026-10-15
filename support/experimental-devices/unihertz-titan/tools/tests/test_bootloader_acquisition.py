"""Synthetic lk/lk2 acquisition and remote-guard tests; never contact a phone."""

import contextlib
import copy
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import shlex
import stat
import struct
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock


SCRIPT = Path(__file__).resolve().parents[1] / "acquire-bootloaders.py"
SPEC = importlib.util.spec_from_file_location("titan_bootloader_acquisition_test", SCRIPT)
tool = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(tool)


def encoded(value):
    return (json.dumps(value, sort_keys=True) + "\n").encode("ascii")


def evidence(permission_only=False):
    """Independent complete synthetic map; no private phone metadata is used."""
    anchors = {1: ("boot_para", 64, 512), 2: ("recovery", 1024, 65536),
               26: ("lk", 960512, 2048), 27: ("lk2", 962560, 2048),
               28: ("boot", 1000000, 65536), 29: ("logo", 1070000, 512),
               30: ("dtbo", 1100000, 16384),
               36: ("userdata", 10027008, 234137536),
               37: ("otp", 244164544, 65536), 38: ("flashinfo", 244230080, 55296)}
    parts = []
    for number in range(1, 39):
        name, start, size = anchors.get(number, (f"fixture{number}",
            100000 + number * 4096 if number < 26 else 1200000 + number * 2048, 512))
        parts.append({"number": number, "name": name, "start": start,
                      "sectors": size, "device_number": f"179:{number}"})
    return {"format": "titan-bootloader-guard-v1", "disk": {
        "node": "/dev/mmcblk0", "type": "MMC", "removable": 0,
        "sectors": 244285440, "bytes": 125074145280,
        "logical_sector_bytes": 512, "physical_sector_bytes": 512,
        "device_number": "179:0", "sysfs": "/sys/devices/fixture/mmcblk0"},
        "partitions": parts,
        "targets": {label: {"node": f"/dev/mmcblk0p{number}", "bytes": 1048576,
                             **parts[number - 1]} for label, number in (("lk", 26), ("lk2", 27))},
        "permissions": {name: True for name in ("mmcblk0", "mmcblk0p26", "mmcblk0p27")},
        "checks": {"self_mounts": True, "pid1_mounts": True,
                   "holders_and_slaves_empty": True, "ioctl_geometry": not permission_only}}


class FakeRemote:
    def __init__(self):
        self.data = {"lk": bytes(range(256)) * 4096, "lk2": bytes(reversed(range(256))) * 4096}
        self.calls, self.probes = [], 0
        self.maps, self.read_data, self.hashes = {}, {}, {}
        self.fail_probe = self.fail_read = self.corrupt_saved = None
        self.bad_read_count = self.bad_read_digest = self.bad_hash_count = None
        self.permissions = evidence(True)
        self.password = None
        self.checked = False
        self.after_read = None

    def check_protocol(self):
        self.checked = True

    def run(self, script, limit=16384, *, sink=None, expected_exit=0):
        known = {(mode, label): tool.remote_script(mode, label)
                 for mode, labels in (("permissions", ("",)), ("probe", ("",)),
                                      ("read", ("lk", "lk2")), ("hash", ("lk", "lk2")))
                 for label in labels}
        selected = [key for key, command in known.items() if command == script]
        if len(selected) != 1:
            raise AssertionError("Unexpected remote command")
        mode, label = selected[0]
        self.calls.append((mode, label))
        if mode in ("permissions", "probe"):
            if limit != 32768 or sink is not None:
                raise AssertionError("Metadata channel lost its bound or separation")
            if mode == "permissions":
                data = encoded(self.permissions)
            else:
                self.probes += 1
                if self.probes == self.fail_probe:
                    raise tool.AcquisitionError("Synthetic guard refused.")
                value = self.maps.get(self.probes, evidence())
                data = value if isinstance(value, bytes) else encoded(value)
        elif mode == "read":
            if limit != 1048576 or sink is None:
                raise AssertionError("Content read escaped its fixed 1 MiB stream")
            data = self.read_data.get(label, self.data[label])
            if self.fail_read == label:
                sink.write(data[:17])
                raise tool.AcquisitionError("Synthetic framed transport failed.")
            sink.write(data if self.corrupt_saved != label else bytes([data[0] ^ 1]) + data[1:])
            if self.after_read is not None:
                self.after_read(label)
        else:
            if limit != 256 or sink is not None:
                raise AssertionError("Repeat hash channel lost its fixed bound")
            value = self.hashes.get(label, {"label": label, "bytes": 1048576,
                                          "sha256": hashlib.sha256(self.data[label]).hexdigest()})
            data = value if isinstance(value, bytes) else encoded(value)
        count, digest = len(data), hashlib.sha256(data).hexdigest()
        if mode == "read" and self.bad_read_count == label:
            count -= 1
        if mode == "read" and self.bad_read_digest == label:
            digest = "0" * 64
        if mode == "hash" and self.bad_hash_count == label:
            count -= 1
        return b"" if sink is not None else data, count, digest


class AcquisitionTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="titan-bootloaders-test-", dir="/tmp")
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name).resolve()
        self.output = self.base / "capture"

    def assert_unpublished(self):
        self.assertFalse((self.output / "manifest.json").exists())
        self.assertFalse((self.output / "lk.img").exists())
        self.assertFalse((self.output / "lk2.img").exists())
        if self.output.exists():
            self.assertEqual(stat.S_IMODE(self.output.stat().st_mode), 0o700)
            for path in self.output.iterdir():
                self.assertTrue(path.name.endswith(".part"))
                self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)

    def test_success_preserves_both_exact_images_with_three_hashes_and_private_modes(self):
        remote = FakeRemote()
        output, report = tool.acquire(remote, self.output)
        self.assertEqual(output, self.output)
        self.assertEqual(remote.probes, 8)
        self.assertEqual([call for call in remote.calls if call[0] in ("read", "hash")],
                         [("read", "lk"), ("hash", "lk"), ("read", "lk2"), ("hash", "lk2")])
        self.assertEqual(report["status"], "complete")
        self.assertEqual(report["bytes_preserved"], 2097152)
        self.assertFalse(any(report["validation"].values()))
        self.assertEqual(json.loads((output / "manifest.json").read_text()), report)
        self.assertEqual(stat.S_IMODE(output.stat().st_mode), 0o700)
        self.assertEqual(sorted(path.name for path in output.iterdir()), ["lk.img", "lk2.img", "manifest.json"])
        for label, data in remote.data.items():
            self.assertEqual((output / f"{label}.img").read_bytes(), data)
            for key in ("sha256", "transfer_sha256", "readback_sha256", "phone_repeat_sha256"):
                self.assertEqual(report["partitions"][label][key], hashlib.sha256(data).hexdigest())
        for path in output.iterdir():
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
            self.assertEqual(path.stat().st_nlink, 1)

    def test_initial_guard_denial_precedes_private_output_creation(self):
        remote = FakeRemote(); remote.fail_probe = 1
        with self.assertRaises(tool.AcquisitionError):
            tool.acquire(remote, self.output)
        self.assertFalse(self.output.exists())
        self.assertEqual(remote.calls, [("probe", "")])

    def test_every_followup_guard_failure_prevents_publication(self):
        for index in range(2, 9):
            with self.subTest(probe=index):
                self.output = self.base / str(index)
                remote = FakeRemote(); remote.fail_probe = index
                with self.assertRaises(tool.AcquisitionError):
                    tool.acquire(remote, self.output)
                self.assert_unpublished()

    def test_changed_other_partition_or_final_map_is_not_ignored(self):
        for index in (3, 4, 5, 8):
            self.output = self.base / str(index)
            remote = FakeRemote()
            changed = evidence(); changed["partitions"][3]["name"] = "changed"
            remote.maps[index] = changed
            with self.subTest(probe=index), self.assertRaisesRegex(tool.AcquisitionError, "changed"):
                tool.acquire(remote, self.output)
            self.assert_unpublished()

    def test_short_extra_corrupt_saved_or_mismatched_stream_metadata_fails(self):
        for fault in ("short", "extra", "corrupt_saved", "bad_read_count", "bad_read_digest", "fail_read"):
            self.output = self.base / fault
            remote = FakeRemote()
            if fault == "short": remote.read_data["lk"] = remote.data["lk"][:-1]
            elif fault == "extra": remote.read_data["lk"] = remote.data["lk"] + b"x"
            else: setattr(remote, fault, "lk")
            with self.subTest(fault=fault), self.assertRaises(tool.AcquisitionError):
                tool.acquire(remote, self.output)
            self.assert_unpublished()
            self.assertTrue((self.output / "lk.img.part").exists())
            self.assertNotIn(("read", "lk2"), remote.calls)

    def test_independent_second_read_and_hash_framing_must_agree(self):
        for fault in ("different", "wrong_label", "wrong_size", "extra_field", "bad_json", "duplicate", "count"):
            self.output = self.base / fault
            remote = FakeRemote()
            value = {"label": "lk2", "bytes": 1048576, "sha256": hashlib.sha256(remote.data["lk2"]).hexdigest()}
            if fault == "different": value["sha256"] = "0" * 64
            elif fault == "wrong_label": value["label"] = "lk"
            elif fault == "wrong_size": value["bytes"] -= 1
            elif fault == "extra_field": value["unexpected"] = 1
            elif fault == "bad_json": value = b"private stderr contamination\n"
            elif fault == "duplicate": value = b'{"label":"lk2","label":"lk2"}\n'
            else: remote.bad_hash_count = "lk2"
            remote.hashes["lk2"] = value
            with self.subTest(fault=fault), self.assertRaises(tool.AcquisitionError):
                tool.acquire(remote, self.output)
            self.assert_unpublished()

    def test_existing_output_and_repository_markers_are_preserved(self):
        self.output.mkdir(); (self.output / "sentinel").write_bytes(b"existing")
        with self.assertRaises(tool.AcquisitionError):
            tool.acquire(FakeRemote(), self.output)
        self.assertEqual((self.output / "sentinel").read_bytes(), b"existing")
        for marker in (".git", ".jj"):
            parent = self.base / marker[1:]; parent.mkdir(); (parent / marker).write_text("marker")
            with self.subTest(marker=marker), self.assertRaises(tool.AcquisitionError):
                tool.acquire(FakeRemote(), parent / "new")
            self.assertFalse((parent / "new").exists())
        with mock.patch.object(tool.Path, "resolve", return_value=Path("/nix")):
            with self.assertRaisesRegex(tool.AcquisitionError, "outside /nix"):
                tool.private_path("/nix/titan-synthetic-never-created")

    def test_insecure_parent_or_insufficient_free_space_fails_before_reads(self):
        self.base.chmod(0o777)
        remote = FakeRemote()
        with self.assertRaisesRegex(tool.AcquisitionError, "parent"):
            tool.acquire(remote, self.output)
        self.base.chmod(0o700)
        self.assertNotIn(("read", "lk"), remote.calls)
        with mock.patch.object(tool.os, "fstatvfs", return_value=SimpleNamespace(f_bavail=0, f_frsize=4096)):
            with self.assertRaisesRegex(tool.AcquisitionError, "space"):
                tool.acquire(FakeRemote(), self.output)
        self.assertFalse(self.output.exists())

    def test_second_publication_link_failure_rolls_back_first_without_losing_parts(self):
        original = os.link
        def fail_second(source, target, **kwargs):
            if target == "lk2.img": raise OSError("synthetic publication failure")
            return original(source, target, **kwargs)
        with mock.patch.object(tool.os, "link", side_effect=fail_second):
            with self.assertRaises(OSError):
                tool.acquire(FakeRemote(), self.output)
        self.assert_unpublished()
        self.assertEqual((self.output / "lk.img.part").stat().st_size, 1048576)
        self.assertEqual((self.output / "lk2.img.part").stat().st_size, 1048576)

    def test_directory_replacement_is_detected_without_touching_replacement(self):
        displaced = self.base / "displaced"
        remote = FakeRemote()
        def swap(label):
            if label == "lk2":
                self.output.rename(displaced)
                self.output.mkdir(mode=0o700)
                (self.output / "sentinel").write_bytes(b"replacement")
        remote.after_read = swap
        with self.assertRaisesRegex(tool.AcquisitionError, "identity changed"):
            tool.acquire(remote, self.output)
        self.assertEqual(list(path.name for path in self.output.iterdir()), ["sentinel"])
        self.assertEqual((self.output / "sentinel").read_bytes(), b"replacement")
        self.assertFalse((displaced / "manifest.json").exists())


class MetadataTests(unittest.TestCase):
    def test_fixed_geometry_and_no_arbitrary_remote_path_or_mode(self):
        self.assertEqual(tool.TARGETS, {"lk": (26, 960512), "lk2": (27, 962560)})
        self.assertEqual(tool.validate_evidence(encoded(evidence())), evidence())
        for mode, label in (("read", "userdata"), ("read", "lk; reboot"), ("probe", "lk"), ("flash", "lk")):
            with self.subTest(mode=mode, label=label), self.assertRaises(ValueError):
                tool.remote_script(mode, label)
        command = shlex.split(tool.remote_script("read", "lk"))
        self.assertEqual(command[:5], ["/usr/bin/python3", "-I", "-S", "-B", "-c"])
        self.assertEqual(len(command), 6)
        compile(command[-1], "synthetic-remote", "exec")

    def test_duplicate_missing_wrong_geometry_or_device_identity_is_rejected(self):
        mutations = [lambda r: r["partitions"].pop(),
            lambda r: r["partitions"][0].update(number=2),
            lambda r: r["partitions"][3].update(name="lk"),
            lambda r: r["partitions"][3].update(device_number="179:0"),
            lambda r: r["partitions"][3].update(start=True),
            lambda r: r["partitions"][3].update(start=64),
            lambda r: r["targets"]["lk"].update(bytes=1048575),
            lambda r: r["disk"].update(type="SD"),
            lambda r: r["disk"].update(logical_sector_bytes=4096),
            lambda r: r["checks"].update(pid1_mounts=False),
            lambda r: r["permissions"].update(mmcblk0p26=False)]
        for mutate in mutations:
            report = evidence(); mutate(report)
            with self.subTest(mutation=mutate), self.assertRaises(tool.AcquisitionError):
                tool.validate_evidence(encoded(report))
        for data in (b'{"format":1,"format":1}\n', b"[]\n", b"{}", b"\xff\n", b"x" * 32769 + b"\n"):
            with self.subTest(data=data[:20]), self.assertRaises(tool.AcquisitionError):
                tool.validate_evidence(data)

    def test_permission_probe_allows_only_explicit_unavailable_privileged_checks(self):
        report = evidence(True)
        report["permissions"]["mmcblk0"] = False
        report["checks"]["pid1_mounts"] = False
        self.assertEqual(tool.validate_evidence(encoded(report), True), report)
        for field in ("self_mounts", "holders_and_slaves_empty"):
            bad = copy.deepcopy(report); bad["checks"][field] = False
            with self.subTest(field=field), self.assertRaises(tool.AcquisitionError):
                tool.validate_evidence(encoded(bad), True)


class RemoteProgramTests(unittest.TestCase):
    def namespace(self):
        namespace = {}
        exec(compile(tool.REMOTE_CODE, "synthetic-remote-guard", "exec"), namespace)
        namespace["sys"] = SimpleNamespace(platform="linux", byteorder="little", maxsize=2**63 - 1,
                                            stdout=SimpleNamespace(buffer=io.BytesIO()))
        return namespace

    def guard_fixture(self, unreadable=False, pid1_denied=False):
        ns = self.namespace(); report = evidence()
        disk, parent = "/sys/class/block/mmcblk0", report["disk"]["sysfs"]
        metadata = {disk + "/device/type": "MMC", disk + "/removable": "0",
                    disk + "/size": "244285440", disk + "/dev": "179:0",
                    disk + "/queue/logical_block_size": "512",
                    disk + "/queue/physical_block_size": "512"}
        def text(path, limit=4096):
            if path == "/proc/1/mountinfo" and pid1_denied:
                raise PermissionError
            if path in ("/proc/self/mountinfo", "/proc/1/mountinfo"):
                return "1 1 0:1 / / rw - tmpfs tmpfs rw"
            return metadata[path]
        def number(name):
            return 0 if name == "mmcblk0" else int(name.removeprefix("mmcblk0p"))
        def node(name, device):
            value = number(name)
            self.assertEqual(device, f"179:{value}")
            return 1, 100 + value, os.makedev(179, value)
        def canonical(path):
            if path == disk: return parent
            return {"/dev/disk/by-partlabel/lk": "/dev/mmcblk0p26",
                    "/dev/disk/by-partlabel/lk2": "/dev/mmcblk0p27"}[path]
        descriptors = {"/dev/mmcblk0": 7, "/dev/mmcblk0p26": 8, "/dev/mmcblk0p27": 9}
        nodes = {fd: SimpleNamespace(st_mode=stat.S_IFBLK | 0o600, st_dev=1,
                                    st_ino=100 + number(path.removeprefix("/dev/")),
                                    st_rdev=os.makedev(179, number(path.removeprefix("/dev/"))))
                 for path, fd in descriptors.items()}
        opened, closed, ioctls = [], [], []
        def open_block(path, flags):
            self.assertEqual(flags & os.O_ACCMODE, os.O_RDONLY)
            self.assertTrue(flags & os.O_NOFOLLOW)
            self.assertFalse(flags & os.O_EXCL)
            opened.append(path)
            return descriptors[path]
        def ioctl(fd, request, zeroes):
            ioctls.append(request)
            if request == 0x80081272:
                return struct.pack("<Q", 125074145280 if fd == 7 else 1048576)
            self.assertIn(request, (0x1268, 0x127b))
            return struct.pack("<I", 512)
        ns["text"], ns["node"] = text, node
        ns["partition"] = lambda directory, expected_parent: copy.deepcopy(
            report["partitions"][int(directory.rsplit("mmcblk0p", 1)[1]) - 1])
        ns["empty_directory"] = mock.Mock()
        ns["fcntl"] = SimpleNamespace(ioctl=ioctl)
        ns["os"] = SimpleNamespace(uname=lambda: SimpleNamespace(machine="aarch64"),
            path=SimpleNamespace(realpath=canonical),
            scandir=lambda path: contextlib.nullcontext(iter(SimpleNamespace(name=f"mmcblk0p{i}") for i in range(1, 39))),
            access=lambda path, mode: not unreadable, R_OK=os.R_OK, open=open_block,
            fstat=lambda fd: nodes[fd], close=closed.append,
            **{name: getattr(os, name) for name in ("O_RDONLY", "O_NONBLOCK", "O_NOFOLLOW", "O_CLOEXEC")})
        return ns, nodes, opened, closed, ioctls

    def test_actual_permissions_snapshot_never_opens_blocks_and_requires_full_probe_access(self):
        ns, _, opened, closed, ioctls = self.guard_fixture(unreadable=True, pid1_denied=True)
        ns["execute"]("permissions", "")
        report = json.loads(ns["sys"].stdout.buffer.getvalue())
        self.assertFalse(any(report["permissions"].values()))
        self.assertFalse(report["checks"]["pid1_mounts"])
        self.assertFalse(report["checks"]["ioctl_geometry"])
        self.assertEqual(opened, []); self.assertEqual(ioctls, []); self.assertEqual(closed, [])
        ns["sys"].stdout.buffer = io.BytesIO()
        with self.assertRaises(ValueError):
            ns["execute"]("probe", "")
        self.assertEqual(ns["sys"].stdout.buffer.getvalue(), b"")
        self.assertEqual(opened, [])

    def test_actual_full_snapshot_checks_held_block_identity_and_ioctl_before_output(self):
        for fault in ("none", "regular", "replaced", "geometry"):
            ns, nodes, opened, closed, ioctls = self.guard_fixture()
            if fault == "regular": nodes[8].st_mode = stat.S_IFREG | 0o600
            elif fault == "replaced": nodes[8].st_ino += 1
            elif fault == "geometry":
                original = ns["fcntl"].ioctl
                ns["fcntl"].ioctl = lambda fd, request, zeroes: (
                    struct.pack("<Q", 1048575) if fd == 8 and request == 0x80081272 else
                    original(fd, request, zeroes))
            with self.subTest(fault=fault):
                if fault == "none":
                    ns["execute"]("probe", "")
                    self.assertTrue(json.loads(ns["sys"].stdout.buffer.getvalue())["checks"]["ioctl_geometry"])
                    self.assertEqual(opened, ["/dev/mmcblk0", "/dev/mmcblk0p26", "/dev/mmcblk0p27"])
                    self.assertEqual(closed, [7, 8, 9])
                    self.assertEqual(len(ioctls), 9)
                else:
                    with self.assertRaises(ValueError):
                        ns["execute"]("probe", "")
                    self.assertEqual(ns["sys"].stdout.buffer.getvalue(), b"")
                    self.assertEqual(closed, [7, 8])

    def test_actual_execute_reads_exactly_one_mib_and_checks_after_read_before_output(self):
        for mode in ("read", "hash"):
            ns = self.namespace(); content = bytes(range(256)) * 4096
            descriptors = {"mmcblk0": 7, "mmcblk0p26": 8, "mmcblk0p27": 9}
            source, sizes, events = io.BytesIO(content + b"MUST NOT READ"), [], []
            def snapshot(permission_only=False, descriptors=None):
                events.append("post" if descriptors is not None else "pre")
                return evidence(), descriptors or {"mmcblk0": 7, "mmcblk0p26": 8, "mmcblk0p27": 9}
            def read(fd, size):
                self.assertEqual(fd, 8); sizes.append(size); events.append("read")
                return source.read(size)
            closed = []
            ns["snapshot"] = snapshot
            ns["os"] = SimpleNamespace(lseek=lambda *args: 0, SEEK_CUR=os.SEEK_CUR, read=read, close=closed.append)
            ns["execute"](mode, "lk")
            self.assertEqual(source.tell(), 1048576)
            self.assertEqual(sum(sizes), 1048576)
            self.assertEqual(events[0], "pre"); self.assertEqual(events[-1], "post")
            self.assertEqual(sorted(closed), list(descriptors.values()))
            output = ns["sys"].stdout.buffer.getvalue()
            if mode == "read": self.assertEqual(output, content)
            else: self.assertEqual(json.loads(output), {"label": "lk", "bytes": 1048576,
                                                      "sha256": hashlib.sha256(content).hexdigest()})

    def test_actual_execute_short_read_or_changed_postguard_emits_no_payload(self):
        for fault in ("short", "changed"):
            ns = self.namespace(); closed = []
            def snapshot(permission_only=False, descriptors=None):
                report = evidence()
                if descriptors is not None and fault == "changed":
                    report["partitions"][3]["name"] = "changed"
                return report, {"mmcblk0p26": 8}
            source = io.BytesIO(b"x" * (17 if fault == "short" else 1048576))
            ns["snapshot"] = snapshot
            ns["os"] = SimpleNamespace(lseek=lambda *args: 0, SEEK_CUR=os.SEEK_CUR,
                                        read=lambda fd, size: source.read(size), close=closed.append)
            with self.subTest(fault=fault), self.assertRaises(ValueError):
                ns["execute"]("read", "lk")
            self.assertEqual(ns["sys"].stdout.buffer.getvalue(), b"")
            self.assertEqual(closed, [8])

    def test_actual_node_guard_rejects_regular_and_symlink_identity(self):
        for mode, canonical in ((stat.S_IFREG | 0o600, "/dev/mmcblk0p26"),
                                 (stat.S_IFBLK | 0o600, "/dev/other")):
            ns = self.namespace()
            ns["os"] = SimpleNamespace(stat=lambda *args, **kwargs: SimpleNamespace(st_mode=mode),
                                        path=SimpleNamespace(realpath=lambda path: canonical))
            with self.subTest(mode=mode), self.assertRaises(ValueError):
                ns["node"]("mmcblk0p26", "179:26")

    def test_actual_mount_guard_rejects_target_and_permission_policy(self):
        ns = self.namespace()
        ns["text"] = lambda *args: "1 1 179:26 / /fixture ro - ext4 /dev/fixture ro"
        with self.assertRaises(ValueError):
            ns["unmounted"]("fixture", {"179:26"}, False)
        ns["text"] = mock.Mock(side_effect=PermissionError)
        self.assertFalse(ns["unmounted"]("fixture", set(), True))
        with self.assertRaises(ValueError):
            ns["unmounted"]("fixture", set(), False)


class CLITests(unittest.TestCase):
    def test_credentials_follow_protocol_and_permission_probe_only_when_needed(self):
        for readable, sudo in ((True, True), (False, False), (False, True)):
            with tempfile.TemporaryDirectory(dir="/tmp") as temporary:
                output = Path(temporary).resolve() / "new"
                remote = FakeRemote()
                remote.permissions["permissions"]["mmcblk0"] = readable
                def prompt():
                    self.assertTrue(remote.checked)
                    self.assertEqual(remote.calls, [("permissions", "")])
                    self.assertFalse(output.exists())
                    return b"fixture-secret"
                args = ["--output", str(output)] + (["--sudo"] if sudo else [])
                with mock.patch.object(tool.transport, "Remote", return_value=remote), \
                     mock.patch.object(tool.transport, "run_bounded", return_value=(b"List of devices attached\nprivate-selector\tdevice\n", 0, "")), \
                     mock.patch.object(tool.transport, "prompt_password", side_effect=prompt) as password, \
                     contextlib.redirect_stdout(io.StringIO()) as stdout, contextlib.redirect_stderr(io.StringIO()) as stderr:
                    code = tool.main(args)
                self.assertEqual(code, 0 if readable or sudo else 1)
                self.assertEqual(password.call_count, int(not readable and sudo))
                self.assertIsNone(remote.password)
                self.assertNotIn("fixture-secret", stdout.getvalue() + stderr.getvalue())
                self.assertNotIn("private-selector", stdout.getvalue() + stderr.getvalue())
                if not readable and not sudo: self.assertFalse(output.exists())


if __name__ == "__main__":
    unittest.main()
