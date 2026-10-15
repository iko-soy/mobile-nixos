"""Synthetic fixed control/calibration-region tests; never contact a phone."""

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
tool = load("titan_control_region_acquisition_test", HERE.parent / "acquire-control-regions.py")
os_tests = load("titan_control_os_fixtures", HERE / "test_os_partition_acquisition.py")
catalog = load("titan_control_catalog_layout", HERE.parent / "verify-backup-catalog.py")

# Independent copy of the measured geometry; no private GUIDs, serials or data.
CONTROL = {
    "boot_para": (1, 64, 2048, 1048576), "para": (3, 67648, 1024, 524288),
    "expdb": (4, 68672, 40960, 20971520), "frp": (5, 109632, 2048, 1048576),
    "metadata": (8, 308288, 65536, 33554432), "seccfg": (11, 409600, 16384, 8388608),
    "sec1": (12, 425984, 4096, 2097152), "proinfo": (13, 430080, 6144, 3145728),
    "nvram": (25, 829440, 131072, 67108864), "cache": (35, 9142272, 884736, 452984832),
    "otp": (37, 244164544, 88064, 45088768), "flashinfo": (38, 244252608, 32768, 16777216),
}
LABELS = tuple(CONTROL)


def encoded(value):
    return (json.dumps(value, sort_keys=True) + "\n").encode("ascii")


def base_evidence(permission_only=False):
    """The OS guard result over the complete measured 38-entry layout."""
    result = os_tests.evidence(permission_only)
    result["partitions"] = [
        {"number": number, "name": name, "start": start, "sectors": sectors,
         "device_number": f"179:{number}" if number < 32 else f"259:{number - 32}"}
        for number, name, start, sectors in catalog.EXPECTED_LAYOUT]
    for label, number, size in (("vendor", 33, 897581056), ("system", 34, 3221225472)):
        result["targets"][label] = {"node": f"/dev/mmcblk0p{number}", "bytes": size,
                                    **result["partitions"][number - 1]}
    return result


def evidence(permission_only=False):
    base = base_evidence(permission_only)
    targets = {label: {"node": f"/dev/mmcblk0p{number}", "bytes": size, **base["partitions"][number - 1]}
               for label, (number, _, _, size) in CONTROL.items()}
    return {"format": "titan-control-region-guard-v1", "base": base, "targets": targets,
            "permissions": {item["node"].removeprefix("/dev/"): True for item in targets.values()},
            "checks": {"self_mounts": True, "pid1_mounts": True, "android_mounts": True,
                       "holders_and_slaves_empty": True, "ioctl_geometry": not permission_only}}


class FakeRemote:
    def __init__(self):
        self.data = {label: b"\0" * 4096 + bytes(range(256)) * (index + 1) + b"\0" * 17
                     for index, label in enumerate(LABELS)}
        self.calls, self.probes = [], 0
        self.changed_probe = self.fail_probe = self.fail_read = self.bad_digest = None
        self.repeat_mismatch = self.corrupt_saved = None
        self.repeat_records = {}
        self.extra = self.short = self.fail_permission = False
        self.permission = evidence(True)
        self.password, self.protocol_checked = None, False

    def check_protocol(self):
        self.protocol_checked = True

    def run(self, script, limit=16384, *, sink=None, expected_exit=0):
        commands = {(mode, label): tool.remote_script(mode, label)
                    for mode, labels in (("probe", ("",)), ("permissions", ("",)),
                                         ("read", LABELS), ("hash", LABELS)) for label in labels}
        selected = [key for key, value in commands.items() if value == script]
        if len(selected) != 1:
            raise AssertionError("Unexpected remote command")
        mode, label = selected[0]
        self.calls.append((mode, label))
        if mode in ("probe", "permissions"):
            if sink is not None or limit != tool.METADATA_LIMIT:
                raise AssertionError("Unbounded metadata channel")
            if mode == "permissions":
                if self.fail_permission:
                    raise tool.AcquisitionError("Synthetic unprivileged guard refused.")
                value = self.permission
            else:
                self.probes += 1
                if self.probes == self.fail_probe:
                    raise tool.AcquisitionError("Synthetic guard failed.")
                value = evidence()
                if self.probes == self.changed_probe:
                    value["base"]["android_init"]["start_time"] += 1
            data = encoded(value)
        elif mode == "read":
            if sink is None or limit != len(self.data[label]):
                raise AssertionError("Unbounded image channel")
            data = self.data[label]
            if label == "nvram":
                if self.short:
                    data = data[:-1]
                if self.extra:
                    data += b"x"
            for start in range(0, len(data), 4096):
                chunk = data[start:start + 4096]
                # The saved bytes then differ from those the transfer digest covers.
                sink.write(bytes([chunk[0] ^ 1]) + chunk[1:]
                           if self.corrupt_saved == label and start == 4096 else chunk)
            if self.fail_read == label:
                raise tool.AcquisitionError("Synthetic failed remote exit status after full payload.")
        else:
            if sink is not None or limit != 256:
                raise AssertionError("Unbounded hash channel")
            value = self.repeat_records.get(label, {"label": label, "bytes": len(self.data[label]), "sha256": "0" * 64
                            if self.repeat_mismatch == label else hashlib.sha256(self.data[label]).hexdigest()})
            data = value if isinstance(value, bytes) else encoded(value)
        count, digest = len(data), hashlib.sha256(data).hexdigest()
        if mode == "read" and self.bad_digest == label:
            digest = "0" * 64
        return b"" if sink is not None else data, count, digest


class WorkflowTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="titan-control-test-", dir="/tmp")
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name).resolve()
        self.output = self.base / "capture"
        self.remote = FakeRemote()
        sizes = mock.patch.object(tool, "target_bytes", side_effect=lambda label: len(self.remote.data[label]))
        sizes.start()
        self.addCleanup(sizes.stop)
        progress = mock.patch.object(tool, "progress")
        progress.start()
        self.addCleanup(progress.stop)

    def assert_unpublished(self):
        self.assertFalse((self.output / "manifest.json").exists())
        for label in LABELS:
            self.assertFalse((self.output / (label + ".img")).exists())
        if self.output.exists():
            self.assertEqual(stat.S_IMODE(self.output.stat().st_mode), 0o700)
            for path in self.output.iterdir():
                self.assertTrue(path.name.endswith(".part"))
                self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)

    def test_all_twelve_regions_require_complete_hash_agreement_before_publication(self):
        output, report = tool.acquire(self.remote, self.output)
        self.assertEqual((report["status"], output), ("complete", self.output))
        self.assertEqual(report["format"], "titan-private-control-regions-v1")
        self.assertEqual(report["bytes_preserved"], sum(map(len, self.remote.data.values())))
        self.assertEqual(self.remote.probes, 38)
        self.assertEqual(set(report["partitions"]), set(LABELS))
        self.assertFalse(any(report["validation"].values()))
        self.assertIn("not a consistent copy", report["scope"])
        self.assertEqual(json.loads((output / "manifest.json").read_text()), report)
        self.assertEqual(report["helper_sources"]["acquire-control-regions.py"],
                         hashlib.sha256((HERE.parent / "acquire-control-regions.py").read_bytes()).hexdigest())
        self.assertEqual(len(list(output.iterdir())), 13)
        for label, data in self.remote.data.items():
            image = output / (label + ".img")
            self.assertEqual(image.read_bytes(), data)
            self.assertEqual(stat.S_IMODE(image.stat().st_mode), 0o600)
            for key in ("sha256", "transfer_sha256", "readback_sha256", "phone_repeat_sha256"):
                self.assertEqual(report["partitions"][label][key], hashlib.sha256(data).hexdigest())
        reads = [label for mode, label in self.remote.calls if mode == "read"]
        self.assertEqual(reads, list(LABELS))

    def test_failed_status_short_extra_saved_or_repeat_hash_never_publishes(self):
        for fault in ("short", "extra", "status", "transfer_hash", "saved_hash", "repeat_hash"):
            self.remote = FakeRemote()
            self.output = self.base / fault
            if fault in ("short", "extra"):
                setattr(self.remote, fault, True)
            elif fault == "status":
                self.remote.fail_read = "flashinfo"
            elif fault == "transfer_hash":
                self.remote.bad_digest = "proinfo"
            elif fault == "saved_hash":
                # Only the saved-file readback can notice: transfer and phone
                # repeat digests both cover the true bytes.
                self.remote.corrupt_saved = "nvram"
            else:
                # A writer changing the region between transfer and reread.
                self.remote.repeat_mismatch = "nvram"
            message = {"saved_hash": "Saved-file SHA-256", "repeat_hash": "Independent bounded phone SHA-256"}
            with self.subTest(fault=fault), self.assertRaisesRegex(tool.AcquisitionError, message.get(fault, "")):
                tool.acquire(self.remote, self.output)
            self.assert_unpublished()

    def test_independent_repeat_record_and_framing_must_match(self):
        for fault in ("label", "bytes", "extra", "json", "duplicate"):
            self.remote = FakeRemote()
            self.output = self.base / ("repeat-" + fault)
            value = {"label": "nvram", "bytes": len(self.remote.data["nvram"]),
                     "sha256": hashlib.sha256(self.remote.data["nvram"]).hexdigest()}
            if fault == "label":
                value["label"] = "proinfo"
            elif fault == "bytes":
                value["bytes"] -= 1
            elif fault == "extra":
                value["unexpected"] = True
            elif fault == "json":
                value = b"private remote diagnostics\n"
            else:
                value = b'{"label":"nvram","label":"nvram"}\n'
            self.remote.repeat_records["nvram"] = value
            with self.subTest(fault=fault), self.assertRaises(tool.AcquisitionError):
                tool.acquire(self.remote, self.output)
            self.assert_unpublished()

    def test_failure_after_publication_commit_keeps_the_verified_files(self):
        for failing_name in ("boot_para.img.part", "manifest.json.part"):
            self.remote = FakeRemote()
            self.output = self.base / ("after-" + failing_name)
            original, failed = os.unlink, []

            def unlink(path, *args, **kwargs):
                result = original(path, *args, **kwargs)
                if path == failing_name and not failed:
                    failed.append(path)
                    raise OSError("Synthetic failure after the commit point")
                return result

            with self.subTest(after=failing_name), mock.patch.object(tool.os, "unlink", side_effect=unlink), \
                    self.assertRaises(tool.PublicationRetained):
                tool.acquire(self.remote, self.output)
            self.assertEqual(failed, [failing_name])
            for label, data in self.remote.data.items():
                kept = [path for path in (self.output / f"{label}.img", self.output / f"{label}.img.part")
                        if path.exists()]
                self.assertTrue(kept, label)
                for path in kept:
                    self.assertEqual(path.read_bytes(), data)
            # The retained set must not look complete.
            self.assertFalse((self.output / "manifest.json").exists())
            self.assertTrue((self.output / "manifest.json.part").is_file())

    def test_initial_and_late_guard_changes_refuse_any_completed_set(self):
        for probe in (1, 2, 3, 4, 35, 36, 37, 38):
            self.remote = FakeRemote()
            self.output = self.base / str(probe)
            if probe == 1:
                self.remote.fail_probe = probe
            else:
                self.remote.changed_probe = probe
            with self.subTest(probe=probe), self.assertRaises(tool.AcquisitionError):
                tool.acquire(self.remote, self.output)
            self.assert_unpublished()
            if probe == 1:
                self.assertFalse(self.output.exists())

    def test_existing_output_is_preserved_and_late_link_failure_keeps_parts(self):
        self.output.mkdir()
        (self.output / "sentinel").write_bytes(b"existing")
        with self.assertRaises(tool.AcquisitionError):
            tool.acquire(self.remote, self.output)
        self.assertEqual((self.output / "sentinel").read_bytes(), b"existing")
        self.output = self.base / "new"
        original = os.link

        def fail_last(source, target, **kwargs):
            if target == "flashinfo.img":
                raise OSError("Synthetic final link failure")
            return original(source, target, **kwargs)

        with mock.patch.object(tool.os, "link", side_effect=fail_last), self.assertRaises(OSError):
            tool.acquire(self.remote, self.output)
        self.assert_unpublished()
        for label, data in self.remote.data.items():
            self.assertEqual((self.output / (label + ".img.part")).read_bytes(), data)


class ProfileTests(unittest.TestCase):
    def test_exact_profile_matches_the_independent_catalog_layout(self):
        self.assertEqual(set(tool.TARGETS), set(LABELS))
        layout = {name: (number, start, sectors) for number, name, start, sectors in catalog.EXPECTED_LAYOUT}
        for label, (number, start, sectors, size) in CONTROL.items():
            self.assertEqual(layout[label], (number, start, sectors))
            self.assertEqual(tool.TARGETS[label], {"number": number, "start": start, "sectors": sectors,
                                                   "bytes": size})
            self.assertEqual(size, sectors * 512)
        self.assertEqual(sum(tool.target_bytes(label) for label in LABELS), tool.TOTAL_BYTES)
        self.assertEqual(tool.TOTAL_BYTES, 652738560)
        # Exactly the uncovered GPT regions that no host mount covered.
        self.assertEqual(set(LABELS), set(catalog.REMAINING_GPT) - {
            "nvcfg", "nvdata", "protect1", "protect2", "userdata"})
        self.assertEqual(tool.validate_evidence(encoded(evidence())), evidence())

    def test_only_fixed_labels_and_modes_build_remote_commands(self):
        for mode, label in (("read", "nvcfg"), ("read", "nvdata"), ("read", "protect1"), ("read", "protect2"),
                            ("read", "userdata"), ("read", "rpmb"), ("read", "mmcblk0rpmb"), ("read", "boot0"),
                            ("read", "vendor"), ("read", "/dev/mmcblk0p25"), ("hash", "lk"),
                            ("probe", "nvram"), ("write", "nvram"), ("erase", "frp")):
            with self.subTest(mode=mode, label=label), self.assertRaises(ValueError):
                tool.remote_script(mode, label)
        command = shlex.split(tool.remote_script("read", "nvram"))
        self.assertEqual(command[:5], ["/usr/bin/python3", "-I", "-S", "-B", "-c"])
        self.assertEqual(len(command), 6)
        compile(command[-1], "synthetic-control-remote", "exec")
        for forbidden in ("BLKROSET", "0x125d", "O_WRONLY", "O_RDWR", "mount(", "setns", "unshare", "rpmb"):
            self.assertNotIn(forbidden, tool.REMOTE_CODE.split("base_snapshot = snapshot", 1)[1])

    def test_geometry_identity_and_mount_checks_fail_closed(self):
        mutations = [lambda r: r["targets"].pop("nvram"),
            lambda r: r["targets"]["para"].update(start=67649),
            lambda r: r["targets"]["cache"].update(bytes=452984831),
            lambda r: r["targets"]["otp"].update(device_number="259:6"),
            lambda r: r["targets"]["proinfo"].update(node="/dev/mmcblk0p14"),
            lambda r: r["targets"].update(nvcfg=copy.deepcopy(r["targets"]["frp"])),
            lambda r: r["checks"].update(self_mounts=False),
            lambda r: r["checks"].update(pid1_mounts=False),
            lambda r: r["checks"].update(android_mounts=False),
            lambda r: r["checks"].update(holders_and_slaves_empty=False),
            lambda r: r["checks"].update(boot_area_read_only=True),
            lambda r: r["permissions"].update(mmcblk0p25=False),
            lambda r: r["permissions"].update(mmcblk0p6=True),
            lambda r: r.update(format="titan-firmware-guard-v1")]
        for mutate in mutations:
            value = evidence()
            mutate(value)
            with self.subTest(mutation=mutate), self.assertRaises(tool.AcquisitionError):
                tool.validate_evidence(encoded(value))

    def test_consistent_map_and_target_geometry_changes_are_refused(self):
        # A different layout reported consistently in the map and the targets
        # passes the unchanged OS guard; only the fixed profile can refuse it.
        changes = {"cache": {"sectors": -1}, "otp": {"sectors": -8},
                   "flashinfo": {"start": 8, "sectors": -8}, "para": {"name": "parb"}}
        for permission_only in (False, True):
            for label, change in changes.items():
                value = evidence(permission_only)
                number = tool.TARGETS[label]["number"]
                for record in (value["base"]["partitions"][number - 1], value["targets"][label]):
                    for key, delta in change.items():
                        record[key] = delta if key == "name" else record[key] + delta
                tool.os_partitions.validate_evidence(encoded(value["base"]), permission_only)
                with self.subTest(label=label, permission_only=permission_only), \
                        self.assertRaises(tool.AcquisitionError):
                    tool.validate_evidence(encoded(value), permission_only)

    def test_missing_read_permissions_can_only_be_reported_by_preflight(self):
        value = evidence(True)
        value["permissions"]["mmcblk0p13"] = False
        self.assertEqual(tool.validate_evidence(encoded(value), True), value)
        with self.assertRaises(tool.AcquisitionError):
            tool.validate_evidence(encoded(dict(value, checks=dict(value["checks"], ioctl_geometry=True))), True)
        # A wrapper mount-view result must agree with the base guard's.
        for scope in ("pid1", "android"):
            with self.subTest(scope=scope), self.assertRaises(tool.AcquisitionError):
                tool.validate_evidence(encoded(dict(value, checks=dict(value["checks"], **{scope + "_mounts": False}))), True)

    def test_full_space_requirement_is_checked_before_any_image(self):
        sizes = {label: tool.target_bytes(label) for label in LABELS}
        required = 652738560 + 64 * 1048576
        with tempfile.TemporaryDirectory(prefix="titan-control-space-", dir="/tmp") as temporary:
            base = Path(temporary).resolve()
            with mock.patch.object(tool.os, "fstatvfs", return_value=SimpleNamespace(f_bavail=required - 1, f_frsize=1)):
                with self.assertRaisesRegex(tool.AcquisitionError, "space"):
                    tool.PrivateOutput(base / "insufficient", size_mapping=sizes)
            self.assertFalse(any((base / "insufficient").glob("*.img*")))
            with mock.patch.object(tool.os, "fstatvfs", return_value=SimpleNamespace(f_bavail=required, f_frsize=1)):
                output = tool.PrivateOutput(base / "enough", size_mapping=sizes)
            try:
                self.assertEqual(output.budget.remaining, 652738560)
            finally:
                output.close()


class CredentialTests(unittest.TestCase):
    def test_credentials_follow_binary_status_and_permission_checks_and_are_cleared(self):
        for missing, sudo in ((None, True), ("target", False), ("target", True), ("base", True), ("pid1", True),
                              ("android", True)):
            with tempfile.TemporaryDirectory(prefix="titan-control-cli-", dir="/tmp") as temporary:
                output = Path(temporary).resolve() / "new"
                remote = FakeRemote()
                if missing == "target":
                    remote.permission["permissions"]["mmcblk0p25"] = False
                elif missing == "base":
                    remote.permission["base"]["permissions"]["mmcblk0"] = False
                elif missing == "pid1":
                    remote.permission["base"]["checks"]["pid1_mounts"] = False
                    remote.permission["base"]["vendor_mounts"]["pid1"] = None
                    remote.permission["checks"]["pid1_mounts"] = False
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
                    self.assertIs(selected, remote)
                    self.assertEqual(requested, output)
                    self.assertEqual(remote.password, b"synthetic-secret" if missing else None)
                    return output, {"bytes_preserved": 652738560}

                listing = b"List of devices attached\nsynthetic-selector\tdevice usb:1-1 transport_id:1\n"
                with mock.patch.object(tool.transport, "Remote", return_value=remote), \
                        mock.patch.object(tool.transport, "run_bounded", return_value=(listing, 0, "")), \
                        mock.patch.object(tool.transport, "prompt_password", side_effect=prompt) as password, \
                        mock.patch.object(tool, "acquire", side_effect=acquire) as acquisition, \
                        contextlib.redirect_stdout(io.StringIO()) as stdout, \
                        contextlib.redirect_stderr(io.StringIO()) as stderr:
                    code = tool.main(["--output", str(output)] + (["--sudo"] if sudo else []))
                with self.subTest(missing=missing, sudo=sudo):
                    self.assertEqual(code, 1 if missing and not sudo else 0)
                    self.assertEqual(password.call_count, int(bool(missing) and sudo))
                    self.assertEqual(acquisition.call_count, int(not missing or sudo))
                    self.assertIsNone(remote.password)
                    self.assertFalse(output.exists())
                    self.assertNotIn("synthetic-secret", stdout.getvalue() + stderr.getvalue())
                    self.assertNotIn("synthetic-selector", stdout.getvalue() + stderr.getvalue())

    def test_refused_or_inconsistent_preflight_never_prompts(self):
        cases = {"refused": None,
                 "format": lambda r: r.update(format="titan-firmware-guard-v1"),
                 "extra_target": lambda r: r["targets"].update(nvcfg=copy.deepcopy(r["targets"]["frp"])),
                 "inconsistent_start": lambda r: r["targets"]["para"].update(start=67649),
                 "consistent_size": lambda r: [item.update(sectors=88056)
                                               for item in (r["base"]["partitions"][36], r["targets"]["otp"])]}
        listing = b"List of devices attached\nsynthetic-selector\tdevice usb:1-1 transport_id:1\n"
        for name, mutate in cases.items():
            with tempfile.TemporaryDirectory(prefix="titan-control-cli-", dir="/tmp") as temporary:
                output = Path(temporary).resolve() / "new"
                remote = FakeRemote()
                # Missing read access would otherwise lead to the password prompt.
                remote.permission["permissions"]["mmcblk0p25"] = False
                if mutate is None:
                    remote.fail_permission = True
                else:
                    mutate(remote.permission)
                with mock.patch.object(tool.transport, "Remote", return_value=remote), \
                        mock.patch.object(tool.transport, "run_bounded", return_value=(listing, 0, "")), \
                        mock.patch.object(tool.transport, "prompt_password", return_value=b"synthetic-secret") as password, \
                        mock.patch.object(tool, "acquire") as acquisition, \
                        contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
                    code = tool.main(["--sudo", "--output", str(output)])
                with self.subTest(case=name):
                    self.assertEqual(code, 1)
                    password.assert_not_called()
                    acquisition.assert_not_called()
                    self.assertIsNone(remote.password)
                    self.assertEqual(remote.calls, [("permissions", "")])
                    self.assertFalse(output.exists())

    def test_failure_after_publication_commit_is_reported_as_retained(self):
        listing = b"List of devices attached\nsynthetic-selector\tdevice usb:1-1 transport_id:1\n"
        with tempfile.TemporaryDirectory(prefix="titan-control-cli-", dir="/tmp") as temporary:
            output = Path(temporary).resolve() / "new"
            remote = FakeRemote()
            original, failed = os.unlink, []

            def unlink(path, *args, **kwargs):
                result = original(path, *args, **kwargs)
                if path == "manifest.json.part" and not failed:
                    failed.append(path)
                    raise OSError("Synthetic failure after the commit point")
                return result

            with mock.patch.object(tool.transport, "Remote", return_value=remote), \
                    mock.patch.object(tool.transport, "run_bounded", return_value=(listing, 0, "")), \
                    mock.patch.object(tool.transport, "prompt_password") as password, \
                    mock.patch.object(tool, "target_bytes", side_effect=lambda label: len(remote.data[label])), \
                    mock.patch.object(tool, "progress"), mock.patch.object(tool.os, "unlink", side_effect=unlink), \
                    contextlib.redirect_stdout(io.StringIO()) as stdout, \
                    contextlib.redirect_stderr(io.StringIO()) as stderr:
                code = tool.main(["--output", str(output)])
            self.assertEqual((code, failed), (1, ["manifest.json.part"]))
            password.assert_not_called()
            self.assertEqual(stdout.getvalue(), "")
            self.assertIn("stopped after publication", stderr.getvalue())
            self.assertNotIn("incomplete private evidence", stderr.getvalue())
            self.assertFalse((output / "manifest.json").exists())
            self.assertTrue((output / "manifest.json.part").is_file())
            for label, data in remote.data.items():
                kept = [path for path in (output / f"{label}.img", output / f"{label}.img.part") if path.exists()]
                self.assertTrue(kept, label)
                for path in kept:
                    self.assertEqual(path.read_bytes(), data)

    def test_existing_output_is_refused_before_any_transport(self):
        with tempfile.TemporaryDirectory(prefix="titan-control-cli-", dir="/tmp") as temporary:
            output = Path(temporary).resolve() / "existing"
            output.mkdir()
            with mock.patch.object(tool.transport, "Remote") as constructed, \
                    mock.patch.object(tool.transport, "run_bounded") as listing, \
                    contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
                code = tool.main(["--sudo", "--output", str(output)])
            self.assertEqual(code, 1)
            listing.assert_not_called()
            constructed.assert_not_called()
            self.assertEqual(list(output.iterdir()), [])

    def test_network_transport_is_refused_before_any_remote_command(self):
        with tempfile.TemporaryDirectory(prefix="titan-control-cli-", dir="/tmp") as temporary:
            remote = FakeRemote()
            listing = b"List of devices attached\n192.0.2.10:5555\tdevice product:titan transport_id:2\n"
            with mock.patch.object(tool.transport, "Remote", return_value=remote) as constructed, \
                    mock.patch.object(tool.transport, "run_bounded", return_value=(listing, 0, "")), \
                    mock.patch.object(tool.transport, "prompt_password") as password, \
                    contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
                code = tool.main(["--sudo", "--output", str(Path(temporary).resolve() / "new")])
            self.assertEqual(code, 1)
            constructed.assert_not_called()
            password.assert_not_called()
            self.assertEqual(remote.calls, [])


class RemoteWrapperTests(unittest.TestCase):
    def fixture(self, permission_only=False, unreadable=False):
        ns = {}
        exec(compile(tool.REMOTE_CODE, "synthetic-control-wrapper", "exec"), ns)
        report = evidence(permission_only)
        base = report["base"]
        base_fds = {"mmcblk0": 7, "mmcblk0p33": 8, "mmcblk0p34": 9,
                    "android_proc": 100, "monitor_proc": 101, "android_namespace": 102, "monitor_namespace": 103}
        # The unchanged OS base has its own guard tests. Exercise the whole added
        # wrapper against an independently prepared base result.
        ns["base_snapshot"] = lambda optional=False, descriptors=None: (
            copy.deepcopy(base), descriptors if descriptors is not None else {} if optional else dict(base_fds))
        opened, closed, ioctls = [], [], []
        paths = {item["node"]: 20 + index for index, item in enumerate(report["targets"].values())}
        nodes = {path: SimpleNamespace(st_mode=stat.S_IFBLK | 0o600, st_dev=1, st_ino=1000 + index,
                                       st_rdev=2000 + index) for index, path in enumerate(paths)}
        devices = {nodes[item["node"]].st_rdev: tuple(map(int, item["device_number"].split(":")))
                   for item in report["targets"].values()}
        canonical = {path: path for path in paths}
        for label, item in report["targets"].items():
            name = item["node"].removeprefix("/dev/")
            canonical["/sys/class/block/" + name] = base["disk"]["sysfs"] + "/" + name
            canonical["/dev/disk/by-partlabel/" + label] = item["node"]
        mounts = "\n".join(f"{index} 1 259:1 / {row['mountpoint']} ro,noatime - ext4 /dev/vendor ro"
                           for index, row in enumerate(base["vendor_mounts"]["self"], 1))
        fields = {path: mounts for path in ("/proc/self/mountinfo", "/proc/1/mountinfo", "android-view")}

        def open_block(path, flags):
            self.assertEqual(flags & os.O_ACCMODE, os.O_RDONLY)
            self.assertTrue(flags & os.O_NOFOLLOW)
            self.assertFalse(flags & os.O_EXCL)
            opened.append(path)
            return paths[path]

        def ioctl(fd, request, zeroes):
            ioctls.append((fd, request))
            path = next(path for path, value in paths.items() if value == fd)
            label = next(label for label, value in report["targets"].items() if value["node"] == path)
            if request == 0x80081272:
                return struct.pack("<Q", report["targets"][label]["bytes"])
            # Only size/sector GET requests: never BLKROSET or other setters.
            self.assertIn(request, (0x1268, 0x127b))
            return struct.pack("<I", 512)

        ns["text"] = lambda path, limit=4096: fields[path]
        ns["empty_directory"] = mock.Mock()
        ns["android_view"] = lambda optional, vendor, forbidden, descriptors=None: (
            copy.deepcopy(base["android_init"]), ns["mount_rows"]("android-view", vendor, forbidden), descriptors or {})
        ns["fcntl"] = SimpleNamespace(ioctl=ioctl)
        ns["os"] = SimpleNamespace(path=SimpleNamespace(realpath=lambda path: canonical[path]),
            stat=lambda path, **kwargs: nodes[path], major=lambda dev: devices[dev][0],
            minor=lambda dev: devices[dev][1], access=lambda *args: not unreadable, R_OK=os.R_OK,
            open=open_block, fstat=lambda fd: nodes[next(path for path, number in paths.items() if number == fd)],
            close=closed.append,
            **{name: getattr(os, name) for name in ("O_RDONLY", "O_NONBLOCK", "O_NOFOLLOW", "O_CLOEXEC")})
        return ns, report, fields, canonical, nodes, opened, closed, ioctls, base_fds

    def test_permission_wrapper_opens_no_targets_and_full_wrapper_holds_exact_ro_fds(self):
        ns, _, _, _, _, opened, closed, ioctls, _ = self.fixture(True, unreadable=True)
        report, held = ns["snapshot"](True)
        self.assertEqual(tool.validate_evidence(encoded(report), True), report)
        self.assertFalse(any(report["permissions"].values()))
        self.assertEqual(held, {})
        self.assertEqual((opened, closed, ioctls), ([], [], []))
        ns, expected, _, _, _, opened, closed, ioctls, base_fds = self.fixture()
        report, held = ns["snapshot"]()
        self.assertEqual(report, expected)
        self.assertEqual(len(held), len(base_fds) + 12)
        self.assertEqual(len(opened), 12)
        self.assertEqual(len(ioctls), 36)
        again, retained = ns["snapshot"](False, held)
        self.assertEqual((again, retained), (report, held))
        self.assertEqual(len(opened), 12)
        self.assertEqual(closed, [])

    def test_all_twelve_targets_must_be_unmounted_in_each_of_three_views(self):
        for label in LABELS:
            for view in ("/proc/self/mountinfo", "/proc/1/mountinfo", "android-view"):
                ns, report, fields, _, _, opened, closed, _, base_fds = self.fixture()
                fields[view] += f"\n3 1 {report['targets'][label]['device_number']} / /unexpected ro - ext4 /dev/fixture ro"
                with self.subTest(label=label, view=view), self.assertRaises(ValueError):
                    ns["snapshot"]()
                self.assertEqual(opened, [])
                self.assertEqual(sorted(closed), sorted(base_fds.values()))

    def test_identity_label_and_held_fd_geometry_cannot_be_bypassed(self):
        for fault in ("map_sectors", "map_name", "label", "canonical", "symlink", "inode", "ioctl_size",
                      "ioctl_sector"):
            ns, report, fields, canonical, nodes, opened, closed, _, base_fds = self.fixture()
            target = "/dev/mmcblk0p25"
            if fault == "map_sectors":
                # The base guard's own map, not a disagreeing target record.
                report["base"]["partitions"][34]["sectors"] -= 1
            elif fault == "map_name":
                report["base"]["partitions"][2]["name"] = "parb"
            elif fault == "label":
                canonical["/dev/disk/by-partlabel/nvram"] = "/dev/mmcblk0p24"
            elif fault == "canonical":
                canonical["/sys/class/block/mmcblk0p25"] = "/sys/devices/other/mmcblk0/mmcblk0p25"
            elif fault == "symlink":
                nodes[target].st_mode = stat.S_IFLNK | 0o600
            elif fault == "inode":
                original = ns["os"].fstat

                def changed(fd):
                    value = copy.copy(original(fd))
                    if fd == 28:
                        value.st_ino += 1
                    return value

                ns["os"].fstat = changed
            else:
                original_ioctl = ns["fcntl"].ioctl
                ns["fcntl"].ioctl = lambda fd, request, data: (
                    struct.pack("<Q", 67108863) if fault == "ioctl_size" and fd == 28 and request == 0x80081272 else
                    struct.pack("<I", 4096) if fault == "ioctl_sector" and fd == 28 and request == 0x1268 else
                    original_ioctl(fd, request, data))
            with self.subTest(fault=fault), self.assertRaises(ValueError):
                ns["snapshot"]()
            self.assertEqual(len(closed), len(base_fds) + len(opened))

    def test_execute_reads_only_the_fixed_length_of_the_selected_region(self):
        for mode in ("read", "hash"):
            ns = {}
            exec(compile(tool.REMOTE_CODE, "synthetic-control-stream", "exec"), ns)
            ns["CONTROL_TARGETS"] = copy.deepcopy(ns["CONTROL_TARGETS"])
            size = 65536 + 19
            ns["CONTROL_TARGETS"]["nvram"]["bytes"] = size
            content = bytes(range(256)) * 256 + bytes(range(19))
            source, output, sizes, closed = io.BytesIO(content + b"DO NOT READ"), io.BytesIO(), [], []
            ns["snapshot"] = mock.Mock(return_value=(evidence(), {"mmcblk0p25": 123}))

            def read(fd, count):
                self.assertEqual(fd, 123)
                self.assertLessEqual(count, 65536)
                sizes.append(count)
                return source.read(count)

            ns["os"] = SimpleNamespace(lseek=lambda *args: 0, SEEK_CUR=os.SEEK_CUR, read=read, close=closed.append)
            ns["sys"] = SimpleNamespace(stdout=SimpleNamespace(buffer=output))
            ns["execute"](mode, "nvram")
            self.assertEqual(source.tell(), size)
            self.assertEqual(sizes, [65536, 19])
            self.assertEqual(closed, [123])
            self.assertEqual(ns["snapshot"].call_args_list, [mock.call(False), mock.call(False, {"mmcblk0p25": 123})])
            if mode == "read":
                self.assertEqual(output.getvalue(), content)
            else:
                self.assertEqual(json.loads(output.getvalue()),
                                 {"label": "nvram", "bytes": size, "sha256": hashlib.sha256(content).hexdigest()})


if __name__ == "__main__":
    unittest.main()
