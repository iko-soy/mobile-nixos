"""Synthetic fixed firmware/eMMC boot-area tests; never contact a phone."""

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


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


HERE = Path(__file__).resolve().parent
tool = load("titan_firmware_acquisition_test", HERE.parent / "acquire-firmware.py")
os_tests = load("titan_firmware_os_fixtures", HERE / "test_os_partition_acquisition.py")

# Independent fixed geometry; no private GUIDs, serials or captured image data.
FIRMWARE = {
    "md1img": (14, 436224, 204800, 104857600),
    "spmfw": (15, 641024, 2048, 1048576),
    "scp1": (16, 643072, 12288, 6291456),
    "scp2": (17, 655360, 12288, 6291456),
    "sspm_1": (18, 667648, 2048, 1048576),
    "sspm_2": (19, 669696, 2048, 1048576),
    "cam_vpu1": (20, 671744, 30720, 15728640),
    "cam_vpu2": (21, 702464, 30720, 15728640),
    "cam_vpu3": (22, 733184, 30720, 15728640),
    "gz1": (23, 763904, 32768, 16777216),
    "gz2": (24, 796672, 32768, 16777216),
    "logo": (29, 1030144, 16384, 8388608),
    "tee1": (31, 1062912, 10240, 5242880),
    "tee2": (32, 1073152, 24576, 12582912),
}
LABELS = (*FIRMWARE, "boot0", "boot1")


def encoded(value):
    return (json.dumps(value, sort_keys=True) + "\n").encode("ascii")


def base_evidence(permission_only=False):
    result = os_tests.evidence(permission_only)
    for label, (number, start, sectors, _) in FIRMWARE.items():
        result["partitions"][number - 1].update(name=label, start=start, sectors=sectors)
    result["partitions"][27]["start"] = 964608
    result["partitions"][29]["start"] = 1046528
    return result


def evidence(permission_only=False):
    base = base_evidence(permission_only)
    targets = {label: {"node": f"/dev/mmcblk0p{number}", "bytes": size,
                       **base["partitions"][number - 1]}
               for label, (number, _, _, size) in FIRMWARE.items()}
    for index in (0, 1):
        name = f"mmcblk0boot{index}"
        targets[f"boot{index}"] = {"node": "/dev/" + name, "name": name,
            "sectors": 8192, "bytes": 4194304, "device_number": f"179:{32 * (index + 1)}",
            "sysfs": base["disk"]["sysfs"] + "/" + name, "parent": base["disk"]["sysfs"],
            "logical_sector_bytes": 512, "physical_sector_bytes": 512, "ro": 1, "force_ro": 1}
    return {"format": "titan-firmware-guard-v1", "base": base, "targets": targets,
            "permissions": {item["node"].removeprefix("/dev/"): True for item in targets.values()},
            "checks": {"self_mounts": True, "pid1_mounts": True, "android_mounts": True,
                       "holders_and_slaves_empty": True, "ioctl_geometry": not permission_only,
                       "boot_area_read_only": True}}


class FakeRemote:
    def __init__(self):
        self.data = {label: b"\0" * 4096 + bytes(range(256)) * (index + 1) + b"\0" * 17
                     for index, label in enumerate(LABELS)}
        self.calls, self.probes = [], 0
        self.changed_probe = self.fail_probe = self.fail_read = self.bad_digest = None
        self.repeat_mismatch = None
        self.extra = self.short = False
        self.permission = evidence(True)
        self.password, self.protocol_checked = None, False

    def check_protocol(self): self.protocol_checked = True

    def run(self, script, limit=16384, *, sink=None, expected_exit=0):
        commands = {(mode, label): tool.remote_script(mode, label)
                    for mode, labels in (("probe", ("",)), ("permissions", ("",)),
                                         ("read", LABELS), ("hash", LABELS)) for label in labels}
        selected = [key for key, value in commands.items() if value == script]
        if len(selected) != 1: raise AssertionError("Unexpected remote command")
        mode, label = selected[0]; self.calls.append((mode, label))
        if mode in ("probe", "permissions"):
            if sink is not None or limit != tool.METADATA_LIMIT: raise AssertionError("Unbounded metadata channel")
            if mode == "permissions": value = self.permission
            else:
                self.probes += 1
                if self.probes == self.fail_probe: raise tool.AcquisitionError("Synthetic guard failed.")
                value = evidence()
                if self.probes == self.changed_probe: value["base"]["android_init"]["start_time"] += 1
            data = encoded(value)
        elif mode == "read":
            if sink is None or limit != len(self.data[label]): raise AssertionError("Unbounded image channel")
            data = self.data[label]
            if label == "md1img":
                if self.short: data = data[:-1]
                if self.extra: data += b"x"
            for start in range(0, len(data), 4096):
                sink.write(data[start:start + 4096])
            if self.fail_read == label: raise tool.AcquisitionError("Synthetic failed remote exit status after full payload.")
        else:
            if sink is not None or limit != 256: raise AssertionError("Unbounded hash channel")
            data = encoded({"label": label, "bytes": len(self.data[label]), "sha256": "0" * 64
                if self.repeat_mismatch == label else hashlib.sha256(self.data[label]).hexdigest()})
        count, digest = len(data), hashlib.sha256(data).hexdigest()
        if mode == "read" and self.bad_digest == label: digest = "0" * 64
        return b"" if sink is not None else data, count, digest


class WorkflowTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="titan-firmware-test-", dir="/tmp")
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name).resolve(); self.output = self.base / "capture"
        self.remote = FakeRemote()
        sizes = mock.patch.object(tool, "target_bytes", side_effect=lambda label: len(self.remote.data[label]))
        sizes.start(); self.addCleanup(sizes.stop)
        progress = mock.patch.object(tool, "progress"); progress.start(); self.addCleanup(progress.stop)

    def assert_unpublished(self):
        self.assertFalse((self.output / "manifest.json").exists())
        for label in LABELS: self.assertFalse((self.output / (label + ".img")).exists())
        if self.output.exists():
            self.assertEqual(stat.S_IMODE(self.output.stat().st_mode), 0o700)
            for path in self.output.iterdir():
                self.assertTrue(path.name.endswith(".part"))
                self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)

    def test_all_sixteen_images_require_complete_hash_agreement_before_publication(self):
        output, report = tool.acquire(self.remote, self.output)
        self.assertEqual(report["status"], "complete"); self.assertEqual(output, self.output)
        self.assertEqual(report["bytes_preserved"], sum(map(len, self.remote.data.values())))
        self.assertEqual(self.remote.probes, 50)
        self.assertEqual(set(report["partitions"]), set(LABELS))
        self.assertFalse(any(report["validation"].values()))
        self.assertEqual(json.loads((output / "manifest.json").read_text()), report)
        self.assertEqual(len(list(output.iterdir())), 17)
        for label, data in self.remote.data.items():
            image = output / (label + ".img")
            self.assertEqual(image.read_bytes(), data)
            self.assertEqual(image.stat().st_size, len(data)); self.assertEqual(stat.S_IMODE(image.stat().st_mode), 0o600)
            for key in ("sha256", "transfer_sha256", "readback_sha256", "phone_repeat_sha256"):
                self.assertEqual(report["partitions"][label][key], hashlib.sha256(data).hexdigest())

    def test_failed_remote_status_short_extra_saved_or_repeat_hash_never_publishes(self):
        for fault in ("short", "extra", "status", "transfer_hash", "repeat_hash"):
            self.remote = FakeRemote(); self.output = self.base / fault
            if fault in ("short", "extra"): setattr(self.remote, fault, True)
            elif fault == "status": self.remote.fail_read = "boot1"
            elif fault == "transfer_hash": self.remote.bad_digest = "logo"
            else: self.remote.repeat_mismatch = "boot0"
            with self.subTest(fault=fault), self.assertRaises(tool.AcquisitionError):
                tool.acquire(self.remote, self.output)
            self.assert_unpublished()

    def test_initial_and_late_guard_changes_refuse_any_completed_set(self):
        for probe in (1, 2, 3, 4, 47, 48, 49, 50):
            self.remote = FakeRemote(); self.output = self.base / str(probe)
            if probe == 1: self.remote.fail_probe = probe
            else: self.remote.changed_probe = probe
            with self.subTest(probe=probe), self.assertRaises(tool.AcquisitionError):
                tool.acquire(self.remote, self.output)
            self.assert_unpublished()
            if probe == 1: self.assertFalse(self.output.exists())

    def test_existing_output_is_preserved_and_late_link_failure_rolls_back_set(self):
        self.output.mkdir(); (self.output / "sentinel").write_bytes(b"existing")
        with self.assertRaises(tool.AcquisitionError): tool.acquire(self.remote, self.output)
        self.assertEqual((self.output / "sentinel").read_bytes(), b"existing")
        self.output = self.base / "new"
        original = os.link
        def fail_last(source, target, **kwargs):
            if target == "boot1.img": raise OSError("Synthetic final link failure")
            return original(source, target, **kwargs)
        with mock.patch.object(tool.os, "link", side_effect=fail_last), self.assertRaises(OSError):
            tool.acquire(self.remote, self.output)
        self.assert_unpublished()
        for label, data in self.remote.data.items():
            self.assertEqual((self.output / (label + ".img.part")).read_bytes(), data)


class ProfileTests(unittest.TestCase):
    def test_exact_225_mib_profile_and_command_whitelist(self):
        self.assertEqual(set(tool.TARGETS), set(LABELS))
        for label, (_, _, _, size) in FIRMWARE.items(): self.assertEqual(tool.target_bytes(label), size)
        self.assertEqual(tool.target_bytes("boot0"), 4194304); self.assertEqual(tool.target_bytes("boot1"), 4194304)
        self.assertEqual(sum(tool.target_bytes(label) for label in LABELS), 235929600)
        self.assertEqual(tool.validate_evidence(encoded(evidence())), evidence())
        for mode, label in (("read", "nvram"), ("read", "rpmb"), ("read", "userdata"),
                            ("read", "mmcblk0boot0"), ("read", "/dev/mmcblk0"),
                            ("probe", "boot0"), ("write", "boot1")):
            with self.subTest(mode=mode, label=label), self.assertRaises(ValueError): tool.remote_script(mode, label)
        command = shlex.split(tool.remote_script("read", "boot0"))
        self.assertEqual(command[:5], ["/usr/bin/python3", "-I", "-S", "-B", "-c"])
        self.assertEqual(len(command), 6); compile(command[-1], "synthetic-firmware-remote", "exec")

    def test_geometry_boot_write_protection_identity_and_mount_checks_fail_closed(self):
        mutations = [lambda r: r["targets"].pop("boot1"),
            lambda r: r["targets"]["md1img"].update(start=436225),
            lambda r: r["targets"]["tee2"].update(bytes=5242880),
            lambda r: r["targets"]["scp1"].update(device_number="179:17"),
            lambda r: r["targets"]["boot0"].update(ro=0),
            lambda r: r["targets"]["boot1"].update(force_ro=0),
            lambda r: r["targets"]["boot0"].update(sectors=8193),
            lambda r: r["targets"]["boot1"].update(logical_sector_bytes=4096),
            lambda r: r["targets"]["boot1"].update(physical_sector_bytes=4096),
            lambda r: r["targets"]["boot1"].update(parent="/sys/devices/other/mmcblk0"),
            lambda r: r["targets"]["boot0"].update(sysfs=r["targets"]["boot1"]["sysfs"]),
            lambda r: r["targets"]["boot0"].update(device_number=r["targets"]["boot1"]["device_number"]),
            lambda r: r["checks"].update(self_mounts=False),
            lambda r: r["checks"].update(pid1_mounts=False),
            lambda r: r["checks"].update(android_mounts=False),
            lambda r: r["checks"].update(boot_area_read_only=False),
            lambda r: r["permissions"].update(mmcblk0boot0=False)]
        for mutate in mutations:
            value = evidence(); mutate(value)
            with self.subTest(mutation=mutate), self.assertRaises(tool.AcquisitionError): tool.validate_evidence(encoded(value))

    def test_missing_read_permissions_can_only_be_reported_by_preflight(self):
        value = evidence(True); value["permissions"]["mmcblk0boot1"] = False
        self.assertEqual(tool.validate_evidence(encoded(value), True), value)
        value["checks"]["boot_area_read_only"] = False
        with self.assertRaises(tool.AcquisitionError): tool.validate_evidence(encoded(value), True)

    def test_full_225_mib_space_requirement_and_copied_size_map_are_retained(self):
        sizes = {label: tool.target_bytes(label) for label in LABELS}
        required = 235929600 + 64 * 1048576
        with tempfile.TemporaryDirectory(prefix="titan-firmware-space-", dir="/tmp") as temporary:
            base = Path(temporary).resolve()
            with mock.patch.object(tool.os, "fstatvfs", return_value=SimpleNamespace(f_bavail=required - 1, f_frsize=1)):
                with self.assertRaisesRegex(tool.AcquisitionError, "space"):
                    tool.PrivateOutput(base / "insufficient", size_mapping=sizes)
            self.assertFalse(any((base / "insufficient").glob("*.img*")))
            with mock.patch.object(tool.os, "fstatvfs", return_value=SimpleNamespace(f_bavail=required, f_frsize=1)):
                output = tool.PrivateOutput(base / "enough", size_mapping=sizes)
            try:
                sizes["boot0"] = 1
                self.assertEqual(output.image_sizes["boot0"], 4194304)
                self.assertEqual(output.budget.remaining, 235929600)
            finally: output.close()


class CredentialTests(unittest.TestCase):
    def test_credentials_follow_binary_status_and_permission_checks_and_are_cleared(self):
        for missing, sudo in ((None, True), ("target", False), ("target", True), ("base", True), ("android", True)):
            with tempfile.TemporaryDirectory(prefix="titan-firmware-cli-", dir="/tmp") as temporary:
                output = Path(temporary).resolve() / "new"
                remote = FakeRemote()
                if missing == "target": remote.permission["permissions"]["mmcblk0boot1"] = False
                elif missing == "base": remote.permission["base"]["permissions"]["mmcblk0"] = False
                elif missing == "android":
                    remote.permission["base"]["checks"]["android_mounts"] = False
                    remote.permission["base"]["vendor_mounts"]["android"] = None
                    remote.permission["base"]["android_init"] = None
                    remote.permission["checks"]["android_mounts"] = False
                def prompt():
                    self.assertTrue(remote.protocol_checked)
                    self.assertEqual(remote.calls, [("permissions", "")])
                    self.assertFalse(output.exists())
                    return b"synthetic-secret"
                def acquire(selected, requested):
                    self.assertIs(selected, remote); self.assertEqual(requested, output)
                    self.assertEqual(remote.password, b"synthetic-secret" if missing else None)
                    return output, {"bytes_preserved": 235929600}
                with mock.patch.object(tool.transport, "Remote", return_value=remote), \
                     mock.patch.object(tool.transport, "run_bounded", return_value=(b"List of devices attached\nsynthetic-selector\tdevice\n", 0, "")), \
                     mock.patch.object(tool.transport, "prompt_password", side_effect=prompt) as password, \
                     mock.patch.object(tool, "acquire", side_effect=acquire) as acquisition, \
                     contextlib.redirect_stdout(io.StringIO()) as stdout, contextlib.redirect_stderr(io.StringIO()) as stderr:
                    code = tool.main(["--output", str(output)] + (["--sudo"] if sudo else []))
                with self.subTest(missing=missing, sudo=sudo):
                    self.assertEqual(code, 1 if missing and not sudo else 0)
                    self.assertEqual(password.call_count, int(bool(missing) and sudo))
                    self.assertEqual(acquisition.call_count, int(not missing or sudo))
                    self.assertIsNone(remote.password); self.assertFalse(output.exists())
                    self.assertNotIn("synthetic-secret", stdout.getvalue() + stderr.getvalue())
                    self.assertNotIn("synthetic-selector", stdout.getvalue() + stderr.getvalue())


class RemoteWrapperTests(unittest.TestCase):
    def fixture(self, permission_only=False, unreadable=False):
        ns = {}; exec(compile(tool.REMOTE_CODE, "synthetic-firmware-wrapper", "exec"), ns)
        report = evidence(permission_only); base = report["base"]
        base_fds = {"mmcblk0": 7, "mmcblk0p33": 8, "mmcblk0p34": 9,
                    "android_proc": 100, "monitor_proc": 101, "android_namespace": 102, "monitor_namespace": 103}
        # The unchanged OS base has its own actual-guard tests. Exercise the
        # entire added wrapper against an independently prepared base result.
        ns["base_snapshot"] = lambda optional=False, descriptors=None: (
            copy.deepcopy(base), descriptors if descriptors is not None else {} if optional else dict(base_fds))
        opened, closed, ioctls = [], [], []
        paths = {item["node"]: 20 + index for index, item in enumerate(report["targets"].values())}
        nodes = {path: SimpleNamespace(st_mode=stat.S_IFBLK | 0o600, st_dev=1,
            st_ino=1000 + index, st_rdev=2000 + index) for index, path in enumerate(paths)}
        devices = {nodes[item["node"]].st_rdev: tuple(map(int, item["device_number"].split(":")))
                   for item in report["targets"].values()}
        canonical = {path: path for path in paths}
        for label, item in report["targets"].items():
            name = item["node"].removeprefix("/dev/")
            canonical["/sys/class/block/" + name] = base["disk"]["sysfs"] + "/" + name
            if label in FIRMWARE: canonical["/dev/disk/by-partlabel/" + label] = item["node"]
        fields = {}
        for label in ("boot0", "boot1"):
            item = report["targets"][label]; prefix = "/sys/class/block/" + item["name"] + "/"
            fields.update({prefix + key: str(value) for key, value in {
                "dev": item["device_number"], "size": 8192, "ro": 1, "force_ro": 1,
                "queue/logical_block_size": 512, "queue/physical_block_size": 512}.items()})
        mounts = "\n".join(f"{index} 1 259:1 / {row['mountpoint']} ro,noatime - ext4 /dev/vendor ro"
                           for index, row in enumerate(base["vendor_mounts"]["self"], 1))
        fields.update({path: mounts for path in ("/proc/self/mountinfo", "/proc/1/mountinfo", "android-view")})
        def open_block(path, flags):
            self.assertEqual(flags & os.O_ACCMODE, os.O_RDONLY)
            self.assertTrue(flags & os.O_NOFOLLOW); self.assertFalse(flags & os.O_EXCL)
            opened.append(path); return paths[path]
        def ioctl(fd, request, zeroes):
            ioctls.append((fd, request))
            path = next(path for path, value in paths.items() if value == fd)
            label = next(label for label, value in report["targets"].items() if value["node"] == path)
            if request == 0x80081272: return struct.pack("<Q", report["targets"][label]["bytes"])
            self.assertIn(request, (0x1268, 0x127b, 0x125e))
            if request == 0x125e: self.assertIn(label, ("boot0", "boot1"))
            return struct.pack("<I", 1 if request == 0x125e else 512)
        ns["text"] = lambda path, limit=4096: fields[path]
        ns["empty_directory"] = mock.Mock()
        ns["android_view"] = lambda optional, vendor, forbidden, descriptors=None: (
            copy.deepcopy(base["android_init"]), ns["mount_rows"]("android-view", vendor, forbidden), descriptors or {})
        ns["fcntl"] = SimpleNamespace(ioctl=ioctl)
        ns["os"] = SimpleNamespace(path=SimpleNamespace(realpath=lambda path: canonical[path]),
            stat=lambda path, **kwargs: nodes[path], major=lambda dev: devices[dev][0], minor=lambda dev: devices[dev][1],
            access=lambda *args: not unreadable, R_OK=os.R_OK, open=open_block,
            fstat=lambda fd: nodes[next(path for path, number in paths.items() if number == fd)], close=closed.append,
            **{name: getattr(os, name) for name in ("O_RDONLY", "O_NONBLOCK", "O_NOFOLLOW", "O_CLOEXEC")})
        return ns, report, fields, canonical, nodes, opened, closed, ioctls, base_fds

    def test_permission_wrapper_opens_no_targets_and_full_wrapper_holds_exact_ro_fds(self):
        ns, _, _, _, _, opened, closed, ioctls, _ = self.fixture(True, unreadable=True)
        report, held = ns["snapshot"](True)
        self.assertEqual(tool.validate_evidence(encoded(report), True), report)
        self.assertFalse(any(report["permissions"].values())); self.assertEqual(held, {})
        self.assertEqual((opened, closed, ioctls), ([], [], []))
        ns, expected, _, _, _, opened, closed, ioctls, _ = self.fixture()
        report, held = ns["snapshot"]()
        self.assertEqual(report, expected); self.assertEqual(len(held), 23)
        self.assertEqual(len(opened), 16); self.assertEqual(len(ioctls), 50)
        again, retained = ns["snapshot"](False, held)
        self.assertEqual((again, retained), (report, held)); self.assertEqual(len(opened), 16)
        self.assertEqual(closed, [])

    def test_all_sixteen_targets_must_be_unmounted_in_each_of_three_views(self):
        for label in LABELS:
            for view in ("/proc/self/mountinfo", "/proc/1/mountinfo", "android-view"):
                ns, report, fields, _, _, opened, closed, _, base_fds = self.fixture()
                fields[view] += f"\n3 1 {report['targets'][label]['device_number']} / /unexpected ro - ext4 /dev/fixture ro"
                with self.subTest(label=label, view=view), self.assertRaises(ValueError): ns["snapshot"]()
                self.assertEqual(opened, []); self.assertEqual(sorted(closed), sorted(base_fds.values()))

    def test_boot_sysfs_identity_flags_and_held_fd_get_ioctl_geometry_cannot_be_bypassed(self):
        for fault in ("force_ro", "ro", "size", "canonical", "symlink", "inode", "ioctl_size", "ioctl_ro"):
            ns, report, fields, canonical, nodes, opened, closed, _, base_fds = self.fixture()
            prefix = "/sys/class/block/mmcblk0boot0/"
            if fault in ("force_ro", "ro", "size"): fields[prefix + fault] = "0"
            elif fault == "canonical": canonical[prefix[:-1]] = "/sys/devices/other/mmcblk0/mmcblk0boot0"
            elif fault == "symlink": nodes["/dev/mmcblk0boot0"].st_mode = stat.S_IFLNK | 0o600
            elif fault == "inode":
                original = ns["os"].fstat
                def changed(fd):
                    value = copy.copy(original(fd))
                    if fd == 34: value.st_ino += 1
                    return value
                ns["os"].fstat = changed
            else:
                original_ioctl = ns["fcntl"].ioctl
                ns["fcntl"].ioctl = lambda fd, request, data: (
                    struct.pack("<Q", 4194303) if fault == "ioctl_size" and fd == 34 and request == 0x80081272 else
                    struct.pack("<I", 0) if fault == "ioctl_ro" and fd == 34 and request == 0x125e else original_ioctl(fd, request, data))
            with self.subTest(fault=fault), self.assertRaises(ValueError): ns["snapshot"]()
            self.assertEqual(len(closed), len(base_fds) + len(opened))
        ns, _, fields, _, _, opened, closed, _, _ = self.fixture()
        _, held = ns["snapshot"]()
        fields["/sys/class/block/mmcblk0boot1/force_ro"] = "0"
        with self.assertRaises(ValueError): ns["snapshot"](False, held)
        self.assertEqual(len(opened), 16); self.assertEqual(closed, [])

    def test_execute_selects_boot_area_or_gpt_fd_and_never_reads_past_fixed_length(self):
        for label in ("md1img", "boot1"):
            for mode in ("read", "hash"):
                ns = {}; exec(compile(tool.REMOTE_CODE, "synthetic-firmware-stream", "exec"), ns)
                ns["FIRMWARE_ALL"] = copy.deepcopy(ns["FIRMWARE_ALL"])
                size = 65536 + 19; ns["FIRMWARE_ALL"][label]["bytes"] = size
                name = "mmcblk0p14" if label == "md1img" else "mmcblk0boot1"
                content = bytes(range(256)) * 256 + bytes(range(19))
                source, output, sizes, closed = io.BytesIO(content + b"DO NOT READ"), io.BytesIO(), [], []
                ns["snapshot"] = mock.Mock(return_value=(evidence(), {name: 123}))
                def read(fd, count):
                    self.assertEqual(fd, 123); self.assertLessEqual(count, 65536); sizes.append(count)
                    return source.read(count)
                ns["os"] = SimpleNamespace(lseek=lambda *args: 0, SEEK_CUR=os.SEEK_CUR, read=read, close=closed.append)
                ns["sys"] = SimpleNamespace(stdout=SimpleNamespace(buffer=output))
                ns["execute"](mode, label)
                self.assertEqual(source.tell(), size); self.assertEqual(sizes, [65536, 19]); self.assertEqual(closed, [123])
                self.assertEqual(ns["snapshot"].call_args_list, [mock.call(False), mock.call(False, {name: 123})])
                if mode == "read": self.assertEqual(output.getvalue(), content)
                else: self.assertEqual(json.loads(output.getvalue()), {"label": label, "bytes": size, "sha256": hashlib.sha256(content).hexdigest()})


if __name__ == "__main__":
    unittest.main()
