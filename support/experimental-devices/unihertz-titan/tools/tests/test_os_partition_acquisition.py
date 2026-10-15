"""Host-only synthetic vendor/system acquisition tests; no phone is contacted."""

import contextlib
import copy
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import shlex
import shutil
import stat
import struct
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock


SCRIPT = Path(__file__).resolve().parents[1] / "acquire-os-partitions.py"
SPEC = importlib.util.spec_from_file_location("titan_os_acquisition_test", SCRIPT)
tool = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(tool)


def encoded(value):
    return (json.dumps(value, sort_keys=True) + "\n").encode("ascii")


def evidence(permission_only=False):
    """Complete independent map: fixed target geometry, synthetic other labels."""
    anchors = {1: ("boot_para", 64, 512), 2: ("recovery", 1024, 65536),
        28: ("boot", 1000000, 65536), 29: ("logo", 1066000, 512),
        30: ("dtbo", 1070000, 16384), 31: ("fixture31", 1086400, 512),
        32: ("fixture32", 1087000, 512), 33: ("vendor", 1097728, 1753088),
        34: ("system", 2850816, 6291456), 35: ("cache", 9200000, 512),
        36: ("userdata", 10027008, 234137536),
        37: ("otp", 244164544, 65536), 38: ("flashinfo", 244230080, 55296)}
    parts = []
    for number in range(1, 39):
        name, start, size = anchors.get(number, (f"fixture{number}", 100000 + number * 4096, 512))
        device = f"179:{number}" if number < 32 else f"259:{number - 32}"
        parts.append({"number": number, "name": name, "start": start,
                      "sectors": size, "device_number": device})
    rows = [{"root": "/", "mountpoint": path, "filesystem": "ext4",
             "mount_options": ["noatime", "ro"], "super_options": ["ro"]}
            for path in ("/android/vendor", "/var/lib/lxc/android/rootfs/vendor")]
    return {"format": "titan-os-partition-guard-v1", "disk": {
        "node": "/dev/mmcblk0", "type": "MMC", "removable": 0,
        "sectors": 244285440, "bytes": 125074145280,
        "logical_sector_bytes": 512, "physical_sector_bytes": 512,
        "device_number": "179:0", "sysfs": "/sys/devices/fixture/mmcblk0"},
        "partitions": parts,
        "targets": {label: {"node": f"/dev/mmcblk0p{number}", "bytes": size,
                             **parts[number - 1]}
                    for label, number, size in (("vendor", 33, 897581056), ("system", 34, 3221225472))},
        "permissions": {name: True for name in ("mmcblk0", "mmcblk0p33", "mmcblk0p34")},
        "vendor_mounts": {scope: copy.deepcopy(rows) for scope in ("self", "pid1", "android")},
        "android_init": {"pid": 42, "start_time": 100, "parent_pid": 40, "parent_start_time": 90,
                         "parent_ppid": 1, "namespace": [9, 10], "parent_namespace": [9, 11]},
        "checks": {"self_mounts": True, "pid1_mounts": True, "android_mounts": True,
                   "holders_and_slaves_empty": True, "ioctl_geometry": not permission_only}}


class FakeRemote:
    """Small streams exercise the complete host workflow, not its fixed profile."""
    def __init__(self):
        self.data = {"vendor": b"\0" * 65536 + bytes(range(256)) * 256 + b"\0" * 65536,
                     "system": bytes(reversed(range(256))) * 256 + b"\0" * 65536 + b"end\0" * 257}
        self.calls, self.probes = [], 0
        self.maps, self.read_data, self.hashes = {}, {}, {}
        self.fail_probe = self.fail_read = self.corrupt_saved = None
        self.bad_read_count = self.bad_read_digest = None
        self.after_read = None

    def run(self, script, limit=16384, *, sink=None, expected_exit=0):
        known = {(mode, label): tool.remote_script(mode, label)
                 for mode, labels in (("probe", ("",)), ("permissions", ("",)),
                                      ("read", ("vendor", "system")), ("hash", ("vendor", "system")))
                 for label in labels}
        selected = [key for key, command in known.items() if command == script]
        if len(selected) != 1: raise AssertionError("Unexpected remote command")
        mode, label = selected[0]; self.calls.append((mode, label))
        if mode in ("probe", "permissions"):
            if limit != 65536 or sink is not None: raise AssertionError("Metadata stream lost its bound")
            self.probes += 1
            if self.probes == self.fail_probe: raise tool.AcquisitionError("Synthetic guard refused.")
            data = encoded(self.maps.get(self.probes, evidence(mode == "permissions")))
        elif mode == "read":
            if limit != len(self.data[label]) or sink is None: raise AssertionError("Image stream bound changed")
            data = self.read_data.get(label, self.data[label])
            for start in range(0, len(data), 65536):
                chunk = data[start:start + 65536]
                sink.write(bytes([chunk[0] ^ 1]) + chunk[1:] if self.corrupt_saved == label and start == 0 else chunk)
                if self.fail_read == label: raise tool.AcquisitionError("Synthetic remote read or postguard failed.")
            if self.after_read is not None: self.after_read(label)
        else:
            if limit != 256 or sink is not None: raise AssertionError("Repeat hash stream lost its bound")
            value = self.hashes.get(label, {"label": label, "bytes": len(self.data[label]),
                                           "sha256": hashlib.sha256(self.data[label]).hexdigest()})
            data = value if isinstance(value, bytes) else encoded(value)
        count, digest = len(data), hashlib.sha256(data).hexdigest()
        if mode == "read" and self.bad_read_count == label: count -= 1
        if mode == "read" and self.bad_read_digest == label: digest = "0" * 64
        return b"" if sink is not None else data, count, digest


class AcquisitionTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="titan-os-test-", dir="/tmp")
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name).resolve(); self.output = self.base / "capture"
        self.remote = FakeRemote()
        # Only workflow payload sizes shrink. validate_evidence still checks the
        # immutable production geometry in every baseline and repeat probe.
        patcher = mock.patch.object(tool, "target_bytes", side_effect=lambda label: len(self.remote.data[label]))
        patcher.start(); self.addCleanup(patcher.stop)
        progress = mock.patch.object(tool, "progress"); progress.start(); self.addCleanup(progress.stop)

    def assert_unpublished(self):
        for name in ("manifest.json", "vendor.img", "system.img"):
            self.assertFalse((self.output / name).exists())
        if self.output.exists():
            self.assertEqual(stat.S_IMODE(self.output.stat().st_mode), 0o700)
            for path in self.output.iterdir():
                self.assertTrue(path.name.endswith(".part"))
                self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)

    def test_success_preserves_full_logical_bytes_zero_runs_and_all_hashes(self):
        output, report = tool.acquire(self.remote, self.output)
        self.assertEqual(output, self.output); self.assertEqual(report["status"], "complete")
        self.assertEqual(report["bytes_preserved"], sum(map(len, self.remote.data.values())))
        self.assertFalse(any(report["validation"].values()))
        self.assertEqual(self.remote.probes, 8)
        self.assertEqual([call for call in self.remote.calls if call[0] in ("read", "hash")],
                         [("read", "vendor"), ("hash", "vendor"), ("read", "system"), ("hash", "system")])
        self.assertEqual(json.loads((output / "manifest.json").read_text()), report)
        self.assertEqual(sorted(path.name for path in output.iterdir()), ["manifest.json", "system.img", "vendor.img"])
        self.assertEqual(stat.S_IMODE(output.stat().st_mode), 0o700)
        for label, data in self.remote.data.items():
            path = output / (label + ".img")
            self.assertEqual(path.read_bytes(), data); self.assertEqual(path.stat().st_size, len(data))
            for field in ("sha256", "transfer_sha256", "readback_sha256", "phone_repeat_sha256"):
                self.assertEqual(report["partitions"][label][field], hashlib.sha256(data).hexdigest())
        for path in output.iterdir():
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600); self.assertEqual(path.stat().st_nlink, 1)

    def test_initial_and_every_followup_guard_failure_never_publishes(self):
        for index in range(1, 9):
            self.output = self.base / str(index); self.remote = FakeRemote(); self.remote.fail_probe = index
            with self.subTest(probe=index), self.assertRaises(tool.AcquisitionError):
                tool.acquire(self.remote, self.output)
            self.assert_unpublished()
            if index == 1: self.assertFalse(self.output.exists())

    def test_mount_alias_or_final_map_change_refuses_completion(self):
        for index, fault in ((3, "mount"), (4, "mount"), (5, "map"), (7, "android"), (8, "map")):
            self.output = self.base / str(index); self.remote = FakeRemote(); changed = evidence()
            if fault == "mount": changed["vendor_mounts"]["pid1"][0]["mountpoint"] = "/different"
            elif fault == "android": changed["android_init"]["start_time"] += 1
            else: changed["partitions"][3]["name"] = "changed"
            self.remote.maps[index] = changed
            with self.subTest(probe=index), self.assertRaises(tool.AcquisitionError):
                tool.acquire(self.remote, self.output)
            self.assert_unpublished()

    def test_short_extra_corrupt_stream_and_failed_remote_status_preserve_only_parts(self):
        for fault in ("short", "extra", "corrupt_saved", "bad_read_count", "bad_read_digest", "fail_read"):
            self.output = self.base / fault; self.remote = FakeRemote()
            if fault == "short": self.remote.read_data["vendor"] = self.remote.data["vendor"][:-1]
            elif fault == "extra": self.remote.read_data["vendor"] = self.remote.data["vendor"] + b"x"
            else: setattr(self.remote, fault, "vendor")
            with self.subTest(fault=fault), self.assertRaises(tool.AcquisitionError):
                tool.acquire(self.remote, self.output)
            self.assert_unpublished(); self.assertNotIn(("read", "system"), self.remote.calls)

    def test_independent_repeat_digest_and_metadata_framing_must_match(self):
        for fault in ("digest", "label", "bytes", "extra", "json", "duplicate"):
            self.output = self.base / fault; self.remote = FakeRemote()
            value = {"label": "system", "bytes": len(self.remote.data["system"]),
                     "sha256": hashlib.sha256(self.remote.data["system"]).hexdigest()}
            if fault == "digest": value["sha256"] = "0" * 64
            elif fault == "label": value["label"] = "vendor"
            elif fault == "bytes": value["bytes"] -= 1
            elif fault == "extra": value["unexpected"] = True
            elif fault == "json": value = b"private remote diagnostics\n"
            else: value = b'{"label":"system","label":"system"}\n'
            self.remote.hashes["system"] = value
            with self.subTest(fault=fault), self.assertRaises(tool.AcquisitionError):
                tool.acquire(self.remote, self.output)
            self.assert_unpublished()

    def test_existing_output_and_private_path_policy_are_not_bypassed(self):
        self.output.mkdir(); (self.output / "sentinel").write_bytes(b"existing")
        with self.assertRaises(tool.AcquisitionError): tool.acquire(self.remote, self.output)
        self.assertEqual((self.output / "sentinel").read_bytes(), b"existing")
        for marker in (".git", ".jj"):
            parent = self.base / marker[1:]; parent.mkdir(); (parent / marker).write_text("marker")
            with self.subTest(marker=marker), self.assertRaises(tool.AcquisitionError):
                tool.acquire(self.remote, parent / "new")
            self.assertFalse((parent / "new").exists())

    def test_publication_failure_rolls_back_first_name_and_retains_private_parts(self):
        original = os.link
        def fail_second(source, target, **kwargs):
            if target == "system.img": raise OSError("Synthetic publication failure")
            return original(source, target, **kwargs)
        with mock.patch.object(tool.os, "link", side_effect=fail_second), self.assertRaises(OSError):
            tool.acquire(self.remote, self.output)
        self.assert_unpublished()
        for label in self.remote.data:
            self.assertEqual((self.output / f"{label}.img.part").read_bytes(), self.remote.data[label])

    def test_failure_after_publication_commit_keeps_the_verified_files(self):
        for failing_name in ("vendor.img.part", "manifest.json.part"):
            with self.subTest(after=failing_name):
                if self.output.exists():
                    shutil.rmtree(self.output)
                original, failed = os.unlink, []

                def unlink(path, *args, **kwargs):
                    result = original(path, *args, **kwargs)
                    if path == failing_name and not failed:
                        failed.append(path)
                        raise OSError("Synthetic failure after the commit point")
                    return result

                with mock.patch.object(tool.os, "unlink", side_effect=unlink), \
                        self.assertRaises(tool.PublicationRetained):
                    tool.acquire(self.remote, self.output)
                self.assertEqual(failed, [failing_name])
                for label in self.remote.data:
                    names = [self.output / f"{label}.img", self.output / f"{label}.img.part"]
                    kept = [path for path in names if path.exists()]
                    self.assertTrue(kept, label)
                    for path in kept:
                        self.assertEqual(path.read_bytes(), self.remote.data[label])
                # The retained set must not look complete: only the .part name
                # of the manifest remains.
                self.assertFalse((self.output / "manifest.json").exists())
                self.assertTrue((self.output / "manifest.json.part").is_file())

    def test_rollback_keeps_bytes_when_a_part_name_vanished(self):
        original = tool.PrivateOutput.check_published

        def remove_part_then_check(output, links):
            if links == 2:
                os.unlink("vendor.img.part", dir_fd=output.fd)
            return original(output, links)

        with mock.patch.object(tool.PrivateOutput, "check_published", autospec=True,
                               side_effect=remove_part_then_check), self.assertRaises(tool.AcquisitionError):
            tool.acquire(self.remote, self.output)
        for label in self.remote.data:
            kept = [path for path in (self.output / f"{label}.img", self.output / f"{label}.img.part") if path.exists()]
            self.assertTrue(kept, label)
            for path in kept:
                self.assertEqual(path.read_bytes(), self.remote.data[label])
        self.assertFalse((self.output / "manifest.json").exists())

    def test_checks_before_the_commit_point_roll_back_but_keep_parts(self):
        original = tool.PrivateOutput.check_published

        def fail_first_check(output, links):
            if links == 2:
                raise tool.AcquisitionError("Synthetic pre-commit check failure")
            return original(output, links)

        with mock.patch.object(tool.PrivateOutput, "check_published", autospec=True, side_effect=fail_first_check), \
                self.assertRaisesRegex(tool.AcquisitionError, "pre-commit"):
            tool.acquire(self.remote, self.output)
        self.assert_unpublished()
        for label in self.remote.data:
            self.assertEqual((self.output / f"{label}.img.part").read_bytes(), self.remote.data[label])

    def test_incremental_space_loss_stops_before_another_chunk_or_publication(self):
        calls = []
        def space(fd):
            calls.append(fd)
            return SimpleNamespace(f_bavail=10**12 if len(calls) <= 2 else 0, f_frsize=1)
        with mock.patch.object(tool, "SPACE_INTERVAL", 65536), \
             mock.patch.object(tool.os, "fstatvfs", side_effect=space), self.assertRaisesRegex(tool.AcquisitionError, "space"):
            tool.acquire(self.remote, self.output)
        self.assertGreaterEqual(len(calls), 3); self.assert_unpublished()
        self.assertNotIn(("read", "system"), self.remote.calls)

    def test_transport_deadline_retains_only_an_incomplete_partial_stream(self):
        original = self.remote.run
        def timeout(script, limit=16384, *, sink=None, expected_exit=0):
            if script == tool.remote_script("read", "vendor"):
                return tool.transport.run_bounded([sys.executable, "-I", "-S", "-c",
                    "import os,time; os.write(1,b'fixture'); time.sleep(2)"], limit, 0.2, sink=sink)
            return original(script, limit, sink=sink, expected_exit=expected_exit)
        self.remote.run = timeout
        with self.assertRaisesRegex(tool.AcquisitionError, "timed out"):
            tool.acquire(self.remote, self.output)
        self.assert_unpublished()
        self.assertLessEqual((self.output / "vendor.img.part").stat().st_size, 7)


class PrivateStorageTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="titan-os-storage-test-", dir="/tmp")
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name).resolve()

    def test_sparse_sink_preserves_all_zero_mixed_boundary_and_trailing_hole_bytes(self):
        cases = [(b"\0" * 65536, b"\0" * 19),
                 (b"\0" * 3, b"x\0\0", bytes(range(256)), b"\0" * 65537),
                 (b"\0" * 65535 + b"x", b"\0" * 65536)]
        for index, chunks in enumerate(cases):
            path = self.base / str(index); expected = b"".join(chunks)
            budget = mock.Mock(); budget.remaining = len(expected)
            with path.open("wb") as stream:
                sink = tool.SparseSink(stream, len(expected), budget)
                for chunk in chunks: self.assertEqual(sink.write(chunk), len(chunk))
                sink.finish()
            self.assertEqual(path.read_bytes(), expected)
            self.assertEqual(path.stat().st_size, len(expected))
            self.assertEqual(sink.zero_bytes, sum(len(chunk) for chunk in chunks if not any(chunk)))
            self.assertEqual(budget.before_write.call_args_list, [mock.call(len(chunk)) for chunk in chunks])
            self.assertEqual(budget.consumed.call_args_list, [mock.call(len(chunk)) for chunk in chunks])

    def test_sparse_sink_refuses_short_extra_and_partial_local_writes(self):
        for fault in ("short", "extra", "write"):
            with (self.base / fault).open("wb") as stream:
                sink = tool.SparseSink(stream, 4, mock.Mock())
                with self.subTest(fault=fault), self.assertRaises(tool.AcquisitionError):
                    if fault == "short": sink.write(b"\0" * 3); sink.finish()
                    elif fault == "extra": sink.write(b"\0" * 5)
                    else:
                        sink.stream = mock.Mock(); sink.stream.write.return_value = 1
                        sink.write(b"data")

    def test_space_budget_reserves_full_pair_not_estimated_sparse_allocation(self):
        required = 4118806528 + 64 * 1048576
        with mock.patch.object(tool.os, "fstatvfs", return_value=SimpleNamespace(f_bavail=required - 1, f_frsize=1)):
            with self.assertRaisesRegex(tool.AcquisitionError, "space"):
                tool.SpaceBudget(123, 4118806528)
        with mock.patch.object(tool.os, "fstatvfs", return_value=SimpleNamespace(f_bavail=required, f_frsize=1)):
            budget = tool.SpaceBudget(123, 4118806528)
        budget.consumed(4118806528)
        with mock.patch.object(tool.os, "fstatvfs", return_value=SimpleNamespace(f_bavail=64 * 1048576 - 1, f_frsize=1)):
            with self.assertRaisesRegex(tool.AcquisitionError, "space"): budget.check()
        with self.assertRaises(tool.AcquisitionError): budget.before_write(1)

    def test_saved_hash_updates_incrementally_and_rejects_substituted_fifo_before_open(self):
        output = tool.PrivateOutput(self.base / "capture"); self.addCleanup(output.close)
        data = bytes(range(256)) * (3 * 4096) + b"tail"
        with os.fdopen(output.create("fixture.part"), "wb") as stream: stream.write(data)
        original_read, original_sha = os.read, hashlib.sha256
        requested, waiting = [], [False]
        class Digest:
            def __init__(self): self.inner = original_sha()
            def update(self, chunk):
                waiting[0] = False; self.inner.update(chunk)
            def hexdigest(self): return self.inner.hexdigest()
        def read(fd, size):
            self.assertFalse(waiting[0], "Readback buffered a prior chunk without hashing it")
            self.assertLessEqual(size, 1048576); requested.append(size)
            chunk = original_read(fd, size); waiting[0] = bool(chunk)
            return chunk
        with mock.patch.object(tool.os, "read", side_effect=read), mock.patch.object(tool.hashlib, "sha256", Digest):
            self.assertEqual(output.saved_hash("fixture.part", len(data)), original_sha(data).hexdigest())
        self.assertGreaterEqual(len(requested), 5)
        path = output.path / "fixture.part"; path.unlink(); os.mkfifo(path, 0o600)
        with mock.patch.object(tool.os, "open", side_effect=AssertionError("FIFO must not be opened")):
            with self.assertRaises(tool.AcquisitionError): output.saved_hash("fixture.part", len(data))


class MetadataTests(unittest.TestCase):
    def test_fixed_geometry_is_exact_and_remote_commands_have_no_path_overrides(self):
        self.assertEqual(tool.TARGETS, {
            "vendor": {"number": 33, "start": 1097728, "sectors": 1753088, "bytes": 897581056},
            "system": {"number": 34, "start": 2850816, "sectors": 6291456, "bytes": 3221225472}})
        self.assertEqual(tool.TOTAL_BYTES, 4118806528)
        for label, expected in tool.TARGETS.items():
            self.assertEqual(tool.target_bytes(label), expected["sectors"] * 512)
        self.assertEqual(tool.validate_evidence(encoded(evidence())), evidence())
        for mode, label in (("read", "userdata"), ("read", "/dev/mmcblk0p33"),
                            ("read", "vendor; reboot"), ("probe", "vendor"), ("flash", "system")):
            with self.subTest(mode=mode, label=label), self.assertRaises(ValueError):
                tool.remote_script(mode, label)
        command = shlex.split(tool.remote_script("read", "system"))
        self.assertEqual(command[:5], ["/usr/bin/python3", "-I", "-S", "-B", "-c"])
        self.assertEqual(len(command), 6); compile(command[-1], "synthetic-remote", "exec")

    def test_wrong_geometry_map_shape_identity_permissions_or_mount_flags_are_refused(self):
        mutations = [lambda r: r["partitions"].pop(),
            lambda r: r["partitions"][0].update(number=2),
            lambda r: r["partitions"][3].update(name="vendor"),
            lambda r: r["partitions"][3].update(device_number="259:1"),
            lambda r: r["partitions"][3].update(start=True),
            lambda r: r["partitions"][3].update(start=64),
            lambda r: r["partitions"][32].update(start=1097729),
            lambda r: r["partitions"][33].update(sectors=6291455),
            lambda r: r["targets"]["vendor"].update(bytes=897581055),
            lambda r: r["targets"]["system"].update(node="/dev/mmcblk0p35"),
            lambda r: r["disk"].update(type="SD"),
            lambda r: r["disk"].update(physical_sector_bytes=4096),
            lambda r: r["checks"].update(pid1_mounts=False),
            lambda r: r["checks"].update(android_mounts=False),
            lambda r: r.update(android_init=None),
            lambda r: r["android_init"].update(pid=True),
            lambda r: r["android_init"].update(namespace=[9, 0]),
            lambda r: r["permissions"].update(mmcblk0p34=False),
            lambda r: r["vendor_mounts"]["self"][0].update(mount_options=["rw"]),
            lambda r: r["vendor_mounts"].update(self=[]),
            lambda r: r["vendor_mounts"]["pid1"][1].update(super_options=["ro", "rw"])]
        for mutate in mutations:
            value = evidence(); mutate(value)
            with self.subTest(mutation=mutate), self.assertRaises(tool.AcquisitionError):
                tool.validate_evidence(encoded(value))
        for data in (b'{"format":1,"format":1}\n', b"[]\n", b"{}", b"\xff\n", b"x" * 65537 + b"\n"):
            with self.subTest(data=data[:20]), self.assertRaises(tool.AcquisitionError):
                tool.validate_evidence(data)

    def test_unavailable_pid1_android_or_block_access_is_only_valid_in_permission_preflight(self):
        value = evidence(True)
        value["vendor_mounts"]["pid1"] = value["vendor_mounts"]["android"] = None
        value["checks"]["pid1_mounts"] = value["checks"]["android_mounts"] = False
        value["android_init"] = None; value["permissions"]["mmcblk0p33"] = False
        self.assertEqual(tool.validate_evidence(encoded(value), True), value)
        value["checks"]["ioctl_geometry"] = True
        with self.assertRaises(tool.AcquisitionError): tool.validate_evidence(encoded(value))


class MetadataStreamTests(unittest.TestCase):
    class ShortFile:
        """Model procfs FileIO returning a newline-terminated page before EOF."""
        def __init__(self, chunks, limit):
            self.chunks, self.limit = list(chunks), limit
            self.total, self.eof, self.closed = 0, False, False

        def __enter__(self): return self
        def __exit__(self, *args): self.closed = True

        def read(self, size):
            if not 0 < size <= min(65536, self.limit + 1 - self.total):
                raise AssertionError("Metadata read escaped its remaining byte bound")
            if not self.chunks:
                self.eof = True
                return b""
            chunk = self.chunks.pop(0)
            if len(chunk) > size:
                self.chunks.insert(0, chunk[size:]); chunk = chunk[:size]
            self.total += len(chunk)
            return chunk

    def reader(self, kind, chunks, limit):
        ns = {}
        source = tool.bootloaders.REMOTE_CODE if kind == "lk" else tool.REMOTE_CODE
        exec(compile(source, "synthetic-metadata-reader", "exec"), ns)
        stream = self.ShortFile(chunks, limit)
        ns["open"] = lambda *args, **kwargs: stream
        if kind == "dirfd":
            ns["os"] = SimpleNamespace(open=lambda *args, **kwargs: 123,
                fdopen=lambda *args, **kwargs: stream,
                **{name: getattr(os, name) for name in ("O_RDONLY", "O_NOFOLLOW", "O_CLOEXEC")})
            read = lambda: ns["text_at"](99, "mountinfo", limit)
        else:
            read = lambda: ns["text"]("synthetic-proc-metadata", limit)
        return ns, stream, read

    def test_path_and_dirfd_metadata_readers_require_actual_eof_and_enforce_total_limit(self):
        for kind in ("path", "dirfd", "lk"):
            for fault in ("valid", "exact", "extra", "nul", "newline", "ascii"):
                chunks, limit = [b"a\n", b"b\n"], 8
                if fault in ("exact", "extra"): limit = 4
                if fault == "extra": chunks.append(b"c\n")
                elif fault == "nul": chunks.append(b"\0\n")
                elif fault == "newline": chunks[-1] = b"b"
                elif fault == "ascii": chunks.append(b"\xff\n")
                _, stream, read = self.reader(kind, chunks, limit)
                with self.subTest(kind=kind, fault=fault):
                    if fault in ("valid", "exact"):
                        self.assertEqual(read(), "a\nb"); self.assertTrue(stream.eof)
                    else:
                        with self.assertRaises(ValueError): read()
                    self.assertTrue(stream.closed); self.assertLessEqual(stream.total, limit + 1)

    def test_short_mountinfo_pages_cannot_hide_later_vendor_or_forbidden_aliases(self):
        ordinary = b"1 1 0:1 / / rw - tmpfs tmpfs rw\n"
        vendor = b"2 1 259:1 / /vendor ro - ext4 /dev/vendor ro\n"
        for kind in ("path", "dirfd"):
            for fault in ("valid", "rw", "system"):
                chunks = [ordinary, vendor]
                if fault == "rw": chunks.append(b"3 1 259:1 / /alias ro - ext4 /dev/vendor rw\n")
                elif fault == "system": chunks.append(b"3 1 259:2 / /system ro - ext4 /dev/system ro\n")
                ns, stream, _ = self.reader(kind, chunks, 262144)
                kwargs = {"directory_fd": 99} if kind == "dirfd" else {}
                with self.subTest(kind=kind, fault=fault):
                    if fault == "valid":
                        rows = ns["mount_rows"]("fixture", "259:1", {"179:0", "259:2"}, **kwargs)
                        self.assertEqual(len(rows), 1); self.assertEqual(rows[0]["mountpoint"], "/vendor")
                    else:
                        with self.assertRaises(ValueError):
                            ns["mount_rows"]("fixture", "259:1", {"179:0", "259:2"}, **kwargs)
                    self.assertTrue(stream.eof); self.assertTrue(stream.closed)
        ns, stream, _ = self.reader("lk", [ordinary, b"2 1 179:26 / /lk ro - ext4 /dev/lk ro\n"], 262144)
        with self.assertRaises(ValueError): ns["unmounted"]("fixture", {"179:26"}, False)
        self.assertTrue(stream.eof); self.assertTrue(stream.closed)


class RemoteProgramTests(unittest.TestCase):
    def namespace(self):
        namespace = {}
        exec(compile(tool.REMOTE_CODE, "synthetic-os-guard", "exec"), namespace)
        namespace["sys"] = SimpleNamespace(platform="linux", byteorder="little", maxsize=2**63 - 1,
                                            stdout=SimpleNamespace(buffer=io.BytesIO()))
        return namespace

    def guard_fixture(self, unreadable=False, pid1_denied=False):
        ns, report = self.namespace(), evidence()
        disk, parent = "/sys/class/block/mmcblk0", report["disk"]["sysfs"]
        metadata = {disk + "/device/type": "MMC", disk + "/removable": "0",
                    disk + "/size": "244285440", disk + "/dev": "179:0",
                    disk + "/queue/logical_block_size": "512", disk + "/queue/physical_block_size": "512"}
        def text(path, limit=4096):
            if path == "/proc/1/mountinfo" and pid1_denied: raise PermissionError
            if path in ("/proc/self/mountinfo", "/proc/1/mountinfo"):
                return "1 1 0:1 / / rw - tmpfs tmpfs rw\n2 1 259:1 / /vendor ro - ext4 /dev/vendor ro"
            return metadata[path]
        def number(name): return 0 if name == "mmcblk0" else int(name.removeprefix("mmcblk0p"))
        def node(name, device):
            index = number(name)
            self.assertEqual(device, "179:0" if index == 0 else report["partitions"][index - 1]["device_number"])
            return 1, 100 + index, 1000 + index
        def canonical(path):
            if path == disk: return parent
            return {"/dev/disk/by-partlabel/vendor": "/dev/mmcblk0p33",
                    "/dev/disk/by-partlabel/system": "/dev/mmcblk0p34"}[path]
        descriptors = {"/dev/mmcblk0": 7, "/dev/mmcblk0p33": 8, "/dev/mmcblk0p34": 9}
        nodes = {fd: SimpleNamespace(st_mode=stat.S_IFBLK | 0o600, st_dev=1,
            st_ino=100 + number(path.removeprefix("/dev/")), st_rdev=1000 + number(path.removeprefix("/dev/")))
            for path, fd in descriptors.items()}
        opened, closed, ioctls = [], [], []
        def open_block(path, flags):
            self.assertEqual(flags & os.O_ACCMODE, os.O_RDONLY)
            self.assertTrue(flags & os.O_NOFOLLOW); self.assertFalse(flags & os.O_EXCL)
            opened.append(path); return descriptors[path]
        def ioctl(fd, request, zeroes):
            ioctls.append((fd, request))
            if request == 0x80081272: return struct.pack("<Q", {7: 125074145280, 8: 897581056, 9: 3221225472}[fd])
            self.assertIn(request, (0x1268, 0x127b)); return struct.pack("<I", 512)
        ns["text"], ns["node"] = text, node
        ns["partition"] = lambda directory, expected_parent: copy.deepcopy(
            report["partitions"][int(directory.rsplit("mmcblk0p", 1)[1]) - 1])
        ns["empty_directory"] = mock.Mock()
        ns["android_view"] = mock.Mock(return_value=(report["android_init"], report["vendor_mounts"]["android"], {}))
        ns["fcntl"] = SimpleNamespace(ioctl=ioctl)
        ns["os"] = SimpleNamespace(uname=lambda: SimpleNamespace(machine="aarch64"),
            path=SimpleNamespace(realpath=canonical),
            scandir=lambda path: contextlib.nullcontext(iter(SimpleNamespace(name=f"mmcblk0p{i}") for i in range(1, 39))),
            access=lambda path, mode: not unreadable, R_OK=os.R_OK, open=open_block,
            fstat=lambda fd: nodes[fd], close=closed.append,
            **{name: getattr(os, name) for name in ("O_RDONLY", "O_NONBLOCK", "O_NOFOLLOW", "O_CLOEXEC")})
        return ns, nodes, opened, closed, ioctls

    def test_actual_permission_snapshot_opens_no_blocks_and_full_probe_requires_access(self):
        ns, _, opened, closed, ioctls = self.guard_fixture(unreadable=True, pid1_denied=True)
        ns["execute"]("permissions", "")
        value = json.loads(ns["sys"].stdout.buffer.getvalue())
        self.assertEqual(tool.validate_evidence(encoded(value), True), value)
        self.assertFalse(any(value["permissions"].values())); self.assertFalse(value["checks"]["pid1_mounts"])
        self.assertEqual(opened, []); self.assertEqual(closed, []); self.assertEqual(ioctls, [])
        ns["sys"].stdout.buffer = io.BytesIO()
        with self.assertRaises(ValueError): ns["execute"]("probe", "")
        self.assertEqual(ns["sys"].stdout.buffer.getvalue(), b""); self.assertEqual(opened, [])

    def test_actual_snapshot_checks_fixed_geometry_and_held_block_identity_before_output(self):
        for fault in ("none", "regular", "replaced", "geometry", "vendor_missing"):
            ns, nodes, opened, closed, ioctls = self.guard_fixture()
            if fault == "regular": nodes[8].st_mode = stat.S_IFREG | 0o600
            elif fault == "replaced": nodes[8].st_ino += 1
            elif fault == "geometry":
                original = ns["fcntl"].ioctl
                ns["fcntl"].ioctl = lambda fd, request, zeroes: (struct.pack("<Q", 897581055)
                    if fd == 8 and request == 0x80081272 else original(fd, request, zeroes))
            elif fault == "vendor_missing":
                original_text = ns["text"]
                ns["text"] = lambda path, limit=4096: ("1 1 0:1 / / rw - tmpfs tmpfs rw"
                    if path.endswith("/mountinfo") else original_text(path, limit))
            with self.subTest(fault=fault):
                if fault == "none":
                    ns["execute"]("probe", "")
                    value = json.loads(ns["sys"].stdout.buffer.getvalue())
                    self.assertEqual(tool.validate_evidence(encoded(value)), value)
                    self.assertEqual(opened, ["/dev/mmcblk0", "/dev/mmcblk0p33", "/dev/mmcblk0p34"])
                    self.assertEqual(closed, [7, 8, 9]); self.assertEqual(len(ioctls), 9)
                else:
                    with self.assertRaises(ValueError): ns["execute"]("probe", "")
                    self.assertEqual(ns["sys"].stdout.buffer.getvalue(), b"")
                    self.assertEqual(closed, [] if fault == "vendor_missing" else [7, 8])

    def android_fixture(self):
        ns = self.namespace()
        def record(pid, comm, ppid, start):
            return f"{pid} ({comm}) S {ppid} " + "0 " * 17 + str(start)
        processes = {
            40: {"comm": "lxc-start", "cgroup": "0::/lxc.monitor.android", "stat": record(40, "lxc-start", 1, 90)},
            42: {"comm": "init", "cgroup": "0::/lxc.payload.android", "stat": record(42, "init", 40, 100)},
            43: {"comm": "init", "cgroup": "0::/lxc.payload.android", "stat": record(43, "init", 42, 110)}}
        def text(path, limit=4096):
            _, _, pid, field = path.split("/"); return processes[int(pid)][field]
        opened, closed = [], []
        proc_fds = {100: 42, 101: 40}
        def open_fd(path, flags, dir_fd=None):
            self.assertEqual(flags & os.O_ACCMODE, os.O_RDONLY)
            opened.append((path, dir_fd))
            return {"/proc/42": 100, "/proc/40": 101}.get(path, {100: 102, 101: 103}.get(dir_fd))
        def stat_ns(path, dir_fd=None):
            self.assertEqual(path, "ns/mnt"); return SimpleNamespace(st_dev=9, st_ino=10 if dir_fd == 100 else 11)
        def text_at(fd, name, limit=4096):
            if name == "mountinfo": return "1 1 259:1 / /vendor ro - ext4 /dev/vendor ro"
            return processes[proc_fds[fd]][name]
        ns["text"], ns["text_at"] = text, text_at
        ns["os"] = SimpleNamespace(scandir=lambda path: contextlib.nullcontext(iter(
            SimpleNamespace(name=str(pid)) for pid in processes)), open=open_fd, close=closed.append,
            fstat=lambda fd: SimpleNamespace(st_dev=9, st_ino=10 if fd == 102 else 11), stat=stat_ns,
            **{name: getattr(os, name) for name in ("O_RDONLY", "O_DIRECTORY", "O_NOFOLLOW", "O_CLOEXEC")})
        return ns, processes, opened, closed

    def test_actual_android_discovery_requires_unique_payload_init_with_monitor_parent(self):
        ns, processes, _, _ = self.android_fixture()
        child, parent = ns["discover_android"]()
        self.assertEqual((child["pid"], parent["pid"]), (42, 40))
        for fault in ("missing", "ambiguous", "wrong_parent"):
            ns, processes, _, _ = self.android_fixture()
            if fault == "missing": processes[42]["cgroup"] = "0::/other"
            elif fault == "ambiguous":
                processes[45] = copy.deepcopy(processes[42]); processes[45]["stat"] = processes[45]["stat"].replace("42 (", "45 (", 1)
            else: processes[40]["cgroup"] = "0::/lxc.payload.android"
            with self.subTest(fault=fault), self.assertRaises(ValueError): ns["discover_android"]()

    def test_actual_android_view_holds_identity_and_refuses_pid_namespace_or_mount_changes(self):
        ns, _, opened, closed = self.android_fixture()
        report, rows, held = ns["android_view"](False, "259:1", {"179:0", "259:2"})
        self.assertEqual(report, evidence()["android_init"]); self.assertEqual(len(held), 4)
        again, same_rows, same_held = ns["android_view"](False, "259:1", {"179:0", "259:2"}, held)
        self.assertEqual((again, same_rows, same_held), (report, rows, held))
        self.assertEqual(len(opened), 4); self.assertEqual(closed, [])
        ns["os"].stat = lambda *args, **kwargs: SimpleNamespace(st_dev=9, st_ino=99)
        with self.assertRaises(ValueError): ns["android_view"](False, "259:1", {"179:0", "259:2"}, held)
        self.assertEqual(len(opened), 4); self.assertEqual(closed, [])
        for fault in ("pid", "namespace", "rw", "permission", "permission_full"):
            ns, processes, _, closed = self.android_fixture()
            original = ns["text_at"]; calls = [0]
            def changed_text(fd, name, limit=4096):
                if fd == 100 and name == "stat":
                    calls[0] += 1
                    if fault == "pid" and calls[0] == 2: return original(fd, name, limit)[:-3] + "101"
                if name == "mountinfo":
                    if fault == "rw": return "1 1 259:1 / /vendor ro - ext4 /dev/vendor rw"
                    if fault.startswith("permission"): raise PermissionError
                return original(fd, name, limit)
            ns["text_at"] = changed_text
            if fault == "namespace": ns["os"].stat = lambda *args, **kwargs: SimpleNamespace(st_dev=9, st_ino=99)
            with self.subTest(fault=fault):
                if fault == "permission":
                    self.assertEqual(ns["android_view"](True, "259:1", {"179:0", "259:2"}), (None, None, {}))
                else:
                    with self.assertRaises(ValueError): ns["android_view"](False, "259:1", {"179:0", "259:2"})
                self.assertEqual(sorted(closed), [100, 101, 102] if fault == "namespace" else [100, 101, 102, 103])

    def test_mount_policy_accepts_both_ro_views_and_preserves_aliases(self):
        ns = self.namespace()
        ns["text"] = lambda *args: (
            "1 1 0:1 / / rw - tmpfs tmpfs rw\n"
            "2 1 259:1 / /android/vendor ro,noatime shared:1 - ext4 /dev/vendor ro\n"
            "3 1 259:1 / /var/lib/lxc/android/rootfs/vendor noatime,ro - ext4 /dev/vendor ro")
        rows = ns["mount_rows"]("fixture", "259:1", {"179:0", "259:2"})
        self.assertEqual(rows, evidence()["vendor_mounts"]["self"])

    def test_mount_policy_rejects_any_rw_alias_and_mounted_system_or_whole_disk(self):
        base = "2 1 {device} / /fixture {vfs} - {fs} /dev/fixture {super}"
        cases = [("259:1", "rw", "ro", "ext4"), ("259:1", "ro", "rw", "ext4"),
            ("259:1", "ro,rw", "ro", "ext4"), ("259:1", "ro", "ro,rw", "ext4"),
            ("259:1", "ro,ro", "ro", "ext4"), ("259:1", "ro", "ro,ro", "ext4"),
            ("259:1", "noatime", "ro", "ext4"), ("259:1", "ro", "ro", "f2fs"),
            ("259:2", "ro", "ro", "ext4"), ("179:0", "ro", "ro", "ext4")]
        for device, vfs, super_options, filesystem in cases:
            ns = self.namespace()
            ns["text"] = lambda *args: ("1 1 259:1 / /valid ro - ext4 /dev/vendor ro\n" +
                base.format(device=device, vfs=vfs, super=super_options, fs=filesystem))
            with self.subTest(device=device, vfs=vfs, super_options=super_options, fs=filesystem), self.assertRaises(ValueError):
                ns["mount_rows"]("fixture", "259:1", {"179:0", "259:2"})
        for value in ("", "broken", "1 1 259:1 / /vendor ro - ext4 source ro extra",
                      "1 1 0259:1 / /vendor ro - ext4 source ro"):
            ns["text"] = lambda *args: value
            with self.subTest(malformed=value), self.assertRaises(ValueError):
                ns["mount_rows"]("fixture", "259:1", {"179:0", "259:2"})

    def test_mount_permission_exception_is_only_an_explicit_preflight_result(self):
        ns = self.namespace(); ns["text"] = mock.Mock(side_effect=PermissionError)
        self.assertIsNone(ns["mount_rows"]("fixture", "259:1", set(), optional=True))
        with self.assertRaises(ValueError):
            ns["mount_rows"]("fixture", "259:1", set())
        ns["text"] = mock.Mock(side_effect=FileNotFoundError)
        with self.assertRaises(FileNotFoundError):
            ns["mount_rows"]("fixture", "259:1", set(), optional=True)

    def stream_fixture(self, label="vendor", size=4 * 65536 + 31, fault=None):
        ns = self.namespace(); ns["TARGETS"] = copy.deepcopy(ns["TARGETS"])
        ns["TARGETS"][label]["bytes"] = size
        position, calls, closed, events = [0], [], [], []
        source_fd = 8 if label == "vendor" else 9
        pattern = bytes(range(256)) * 256
        def read(fd, requested):
            self.assertEqual(fd, source_fd); self.assertLessEqual(requested, 65536)
            self.assertLessEqual(position[0] + requested, size)
            calls.append(requested); events.append("read")
            if fault == "short" and position[0] >= 65536: return b""
            result = pattern[:requested]; position[0] += len(result)
            return result
        def snapshot(permission_only=False, descriptors=None):
            events.append("post" if descriptors is not None else "pre")
            value = evidence()
            if descriptors is not None and fault == "changed":
                value["vendor_mounts"]["self"][0]["mountpoint"] = "/changed"
            return value, {"mmcblk0": 7, "mmcblk0p33": 8, "mmcblk0p34": 9}
        class Sink:
            def __init__(self):
                self.count, self.digest, self.maximum = 0, hashlib.sha256(), 0
            def write(self, data):
                events.append("write")
                self.maximum = max(self.maximum, len(data))
                self.count += len(data); self.digest.update(data)
                return len(data)
            def flush(self): events.append("flush")
        sink = Sink()
        ns["snapshot"] = snapshot
        ns["os"] = SimpleNamespace(read=read, lseek=lambda *args: 0, SEEK_CUR=os.SEEK_CUR, close=closed.append)
        ns["sys"].stdout.buffer = sink
        return ns, sink, position, calls, closed, events

    def test_remote_read_streams_before_exhaustion_with_fixed_chunk_bound(self):
        for label in ("vendor", "system"):
            ns, sink, position, calls, closed, events = self.stream_fixture(label)
            ns["execute"]("read", label)
            self.assertEqual(position[0], 4 * 65536 + 31)
            self.assertEqual(sink.count, position[0]); self.assertEqual(sink.maximum, 65536)
            self.assertEqual(calls, [65536] * 4 + [31])
            self.assertEqual(events[:3], ["pre", "read", "write"])
            self.assertEqual(events[-2:], ["post", "flush"])
            self.assertEqual(sorted(closed), [7, 8, 9])
            expected = hashlib.sha256(bytes(range(256)) * 1024 + bytes(range(31))).hexdigest()
            self.assertEqual(sink.digest.hexdigest(), expected)

    def test_remote_repeat_hash_streams_and_emits_only_after_postguard(self):
        ns, _, position, calls, closed, events = self.stream_fixture()
        output = io.BytesIO(); ns["sys"].stdout.buffer = output
        ns["execute"]("hash", "vendor")
        self.assertEqual(json.loads(output.getvalue()), {"label": "vendor", "bytes": 4 * 65536 + 31,
            "sha256": hashlib.sha256(bytes(range(256)) * 1024 + bytes(range(31))).hexdigest()})
        self.assertEqual(max(calls), 65536); self.assertEqual(events[-1], "post")
        self.assertEqual(position[0], 4 * 65536 + 31); self.assertEqual(sorted(closed), [7, 8, 9])

    def test_stream_failure_or_postguard_change_is_not_success_even_after_payload(self):
        for mode in ("read", "hash"):
            for fault in ("short", "changed"):
                ns, sink, _, _, closed, _ = self.stream_fixture(fault=fault)
                with self.subTest(mode=mode, fault=fault), self.assertRaises(ValueError):
                    ns["execute"](mode, "vendor")
                self.assertEqual(sorted(closed), [7, 8, 9])
                self.assertEqual(sink.count, (65536 if fault == "short" else 4 * 65536 + 31) if mode == "read" else 0)


if __name__ == "__main__":
    unittest.main()
