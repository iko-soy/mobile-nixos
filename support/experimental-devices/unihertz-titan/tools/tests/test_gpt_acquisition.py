"""Host-only fixed-window GPT acquisition regressions; no phone or huge disk."""

import contextlib
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import stat
import struct
import subprocess
import sys
import tempfile
import unittest
from unittest import mock
import uuid
import zlib


SCRIPT = Path(__file__).resolve().parents[1] / "acquire-gpt.py"
SPEC = importlib.util.spec_from_file_location("titan_gpt_acquisition_test", SCRIPT)
tool = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(tool)


class Fixture:
    """Independent 38-partition GPT, allocating only the fixed 64 KiB edges."""

    def __init__(self):
        self.partitions = []
        start = 64
        for number in range(1, 36):
            name, _, size = tool.ANCHORS.get(number, (f"fixture{number}", None, 64))
            self.partitions.append(dict(number=number, name=name, start=start, size=size))
            start += size
        self.partitions.extend([
            dict(number=36, name="userdata", start=10027008, size=234137536),
            dict(number=37, name="fixture37", start=244164544, size=64),
            dict(number=38, name="fixture38", start=tool.TAIL_START - 64, size=64)])
        self.disk_guid = uuid.UUID("00112233-4455-6677-8899-aabbccddeeff")

    def map(self):
        lines = ["\t".join(["DISK", "/dev/mmcblk0", "MMC", "0",
            str(tool.DISK_SECTORS), str(tool.DISK_BYTES), "512", "512",
            "/sys/devices/platform/bootdevice/mmc_host/mmc0/mmc0:0001/block/mmcblk0", "179:0", "b3:0"])]
        # Sysfs glob order need not be numeric; the parser must canonicalize it.
        for part in sorted(self.partitions, key=lambda item: str(item["number"])):
            number = part["number"]
            lines.append("\t".join(map(str, ["PART", number, part["name"], part["start"],
                part["size"], f"179:{number}", f"b3:{number:x}"])))
        return ("\n".join(lines) + "\nEND\t38\n").encode("ascii")

    def captures(self):
        front, tail = bytearray(tool.EDGE_BYTES), bytearray(tool.EDGE_BYTES)
        table = bytearray(128 * 128)
        type_guid = uuid.UUID("0fc63daf-8483-4772-8e79-3d69d8477de4").bytes_le
        for part in self.partitions:
            position = (part["number"] - 1) * 128
            table[position:position + 16] = type_guid
            table[position + 16:position + 32] = uuid.UUID(int=part["number"]).bytes_le
            struct.pack_into("<QQQ", table, position + 32, part["start"],
                             part["start"] + part["size"] - 1, 0)
            name = part["name"].encode("utf-16-le")
            table[position + 56:position + 56 + len(name)] = name
        front[446:454] = b"\0\0\x02\0\xee\xff\xff\xff"
        struct.pack_into("<II", front, 454, 1, tool.DISK_SECTORS - 1)
        front[510:512] = b"\x55\xaa"
        front[1024:1024 + len(table)] = table
        tail[-512 - len(table):-512] = table

        def header(current, alternate, entries):
            result = bytearray(512)
            struct.pack_into("<8sIIIIQQQQ16sQIII", result, 0, b"EFI PART", 0x10000,
                92, 0, 0, current, alternate, 64, tool.TAIL_START - 1,
                self.disk_guid.bytes_le, entries, 128, 128, zlib.crc32(table))
            struct.pack_into("<I", result, 16, zlib.crc32(result[:92]))
            return result

        front[512:1024] = header(1, tool.DISK_SECTORS - 1, 2)
        tail[-512:] = header(tool.DISK_SECTORS - 1, 1, tool.DISK_SECTORS - 33)
        return bytes(front), bytes(tail)


class FakeRemote:
    """Exercise acquisition state and saved-file reads using bounded host bytes."""

    def __init__(self, fixture=None):
        self.fixture = fixture or Fixture()
        self.maps = {}
        self.reads = []
        self.probes = 0
        self.read_data = {}
        self.fail_read = None
        self.fail_probe = None
        self.corrupt_saved = None
        self.bad_digest = None
        self.bad_count = None
        self.password = None
        self.protocol_checked = False

    def check_protocol(self):
        self.protocol_checked = True

    def run(self, script, limit=16384, *, sink=None, expected_exit=0):
        if script == tool.guard_script(emit=True):
            if limit != tool.MAP_LIMIT or sink is not None:
                raise AssertionError("Map must use its bounded metadata channel")
            self.probes += 1
            if self.fail_probe == self.probes:
                raise tool.AcquisitionError("Fixture permission or final map failure.")
            data = self.maps.get(self.probes, self.fixture.map())
        else:
            if limit != 32768:
                raise AssertionError("A GPT read escaped its fixed 32 KiB bound")
            region = next((name for name in ("front", "tail") if script == tool.read_script(name)), None)
            if region is None:
                raise AssertionError("Unexpected phone command")
            self.reads.append(region)
            index = len(self.reads)
            if self.fail_read == index:
                if sink is not None:
                    sink.write(b"private-partial")
                raise tool.AcquisitionError("Fixture framed transport failed.")
            data = self.read_data.get(index, self.fixture.captures()[region == "tail"])
        digest = hashlib.sha256(data).hexdigest()
        count = len(data)
        if sink is not None:
            if self.corrupt_saved == len(self.reads):
                sink.write(bytes([data[0] ^ 1]) + data[1:])
            else:
                sink.write(data)
        if self.reads and script != tool.guard_script(emit=True):
            if self.bad_digest == len(self.reads):
                digest = "0" * 64
            if self.bad_count == len(self.reads):
                count -= 1
        return b"" if sink is not None else data, count, digest


class AcquisitionTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="titan-gpt-test-")
        self.addCleanup(self.temporary.cleanup)
        self.base = Path(self.temporary.name).resolve()
        self.output = self.base / "capture"

    def assert_incomplete(self):
        manifest = json.loads((self.output / "manifest.json").read_text())
        self.assertEqual(manifest["status"], "incomplete")
        self.assertNotIn("gpt", manifest)
        self.assertFalse(list(self.output.glob("*.bin")))
        self.assertFalse((self.output / "kernel-map.txt").exists())
        for path in self.output.iterdir():
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
        return manifest

    def test_complete_four_reads_and_full_private_metadata(self):
        remote = FakeRemote()
        output, manifest = tool.acquire(remote, self.output)
        self.assertEqual(output, self.output)
        self.assertEqual(remote.reads, ["front", "tail", "front", "tail"])
        self.assertEqual(remote.probes, 6)
        self.assertEqual(manifest["status"], "complete")
        self.assertEqual(manifest["gpt"]["partition_count"], 38)
        self.assertEqual(stat.S_IMODE(output.stat().st_mode), 0o700)
        self.assertFalse(list(output.glob("*.part")))
        self.assertEqual((output / "kernel-map.txt").read_bytes(), remote.fixture.map())
        for name, data in zip(("front", "tail"), remote.fixture.captures()):
            saved = output / f"gpt-{name}.bin"
            self.assertEqual(saved.read_bytes(), data)
            region = manifest["regions"][name]
            for key in ("sha256", "transfer_sha256", "readback_sha256", "repeat_sha256"):
                self.assertEqual(region[key], hashlib.sha256(data).hexdigest())
        for path in output.iterdir():
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)

    def test_permission_failure_precedes_output_creation(self):
        remote = FakeRemote(); remote.fail_probe = 1
        with self.assertRaises(tool.AcquisitionError):
            tool.acquire(remote, self.output)
        self.assertFalse(self.output.exists())
        self.assertEqual(remote.reads, [])

    def test_changed_map_between_windows_stops_before_second_read(self):
        remote = FakeRemote()
        changed = Fixture(); changed.partitions[3]["name"] = "changed"
        remote.maps[3] = changed.map()
        with self.assertRaisesRegex(tool.AcquisitionError, "map changed"):
            tool.acquire(remote, self.output)
        self.assertEqual(remote.reads, ["front"])
        self.assert_incomplete()
        self.assertEqual((self.output / "gpt-front.bin.part").stat().st_size, 32768)

    def test_changed_or_missing_final_map_prevents_publication(self):
        for missing in (False, True):
            with self.subTest(missing=missing):
                self.output = self.base / str(missing)
                remote = FakeRemote()
                if missing:
                    remote.fail_probe = 6
                else:
                    changed = Fixture(); changed.partitions[3]["name"] = "changed"
                    remote.maps[6] = changed.map()
                with self.assertRaises(tool.AcquisitionError):
                    tool.acquire(remote, self.output)
                self.assertEqual(len(remote.reads), 4)
                self.assert_incomplete()

    def test_repeated_window_mutation_rejected(self):
        for index in (3, 4):
            with self.subTest(index=index):
                self.output = self.base / str(index)
                remote = FakeRemote()
                data = remote.fixture.captures()[index == 4]
                remote.read_data[index] = data[:-1] + bytes([data[-1] ^ 1])
                with self.assertRaisesRegex(tool.AcquisitionError, "repeated.*changed"):
                    tool.acquire(remote, self.output)
                self.assert_incomplete()

    def test_torn_primary_backup_pair_retained_as_rejected_evidence(self):
        remote = FakeRemote()
        changed = Fixture(); changed.disk_guid = uuid.UUID(int=999)
        remote.read_data[2] = changed.captures()[1]
        with self.assertRaisesRegex(tool.AcquisitionError, "structure validation"):
            tool.acquire(remote, self.output)
        self.assert_incomplete()
        self.assertEqual(len(remote.reads), 2)
        self.assertEqual((self.output / "gpt-tail.bin.part").read_bytes(), changed.captures()[1])

    def test_zero_disk_guid_requires_explicit_measured_profile_and_retains_warning(self):
        fixture = Fixture(); fixture.disk_guid = uuid.UUID(int=0)
        with self.assertRaisesRegex(tool.gpt.GPTError, "disk GUID is zero"):
            tool.gpt.validate_gpt(*fixture.captures(), tool.DISK_BYTES)
        remote = FakeRemote(fixture)
        output, manifest = tool.acquire(remote, self.output)
        self.assertEqual(manifest["status"], "complete")
        self.assertEqual(manifest["warnings"], ["zero-disk-guid"])
        self.assertEqual(manifest["gpt"]["warnings"], ["zero-disk-guid"])
        self.assertIs(manifest["validation_policy"]["allow_zero_disk_guid"], True)
        self.assertEqual(json.loads((output / "manifest.json").read_text())["warnings"], ["zero-disk-guid"])
        self.assertEqual(len(remote.reads), 4)

    def test_zero_primary_disk_guid_does_not_allow_nonzero_backup_guid(self):
        fixture = Fixture(); fixture.disk_guid = uuid.UUID(int=0)
        remote = FakeRemote(fixture)
        remote.read_data[2] = Fixture().captures()[1]
        with self.assertRaisesRegex(tool.AcquisitionError, "structure validation"):
            tool.acquire(remote, self.output)
        self.assert_incomplete()
        self.assertEqual(remote.reads, ["front", "tail"])

    def test_cli_success_reports_observed_zero_disk_guid_without_raw_metadata(self):
        fixture = Fixture(); fixture.disk_guid = uuid.UUID(int=0)
        remote = FakeRemote(fixture)
        with mock.patch.object(tool.acquisition, "Remote", return_value=remote), \
             mock.patch.object(tool.acquisition, "run_bounded", return_value=(b"List of devices attached\nprivate-serial\tdevice\n", 0, "")), \
             contextlib.redirect_stdout(io.StringIO()) as captured:
            self.assertEqual(tool.main(["--output", str(self.output)]), 0)
        self.assertIn("Warning: the observed GPT disk GUID is zero", captured.getvalue())
        self.assertIn("cannot identify this disk uniquely", captured.getvalue())
        self.assertNotIn("private-serial", captured.getvalue())
        self.assertNotIn(str(fixture.disk_guid), captured.getvalue())

    def test_valid_gpt_with_kernel_name_or_geometry_mismatch_rejected(self):
        for key, value in (("name", "different"), ("start", 1000000)):
            with self.subTest(key=key):
                self.output = self.base / key
                remote = FakeRemote()
                changed = Fixture(); changed.partitions[10][key] = value
                remote.read_data[1], remote.read_data[2] = changed.captures()
                with self.assertRaisesRegex(tool.AcquisitionError, "GPT and complete kernel.*disagree"):
                    tool.acquire(remote, self.output)
                self.assert_incomplete()

    def test_short_extra_and_count_mismatch_never_publish(self):
        for kind in ("short", "extra", "count"):
            with self.subTest(kind=kind):
                self.output = self.base / kind
                remote = FakeRemote()
                data = remote.fixture.captures()[0]
                if kind == "count":
                    remote.bad_count = 1
                else:
                    remote.read_data[1] = data[:-1] if kind == "short" else data + b"X"
                with self.assertRaisesRegex(tool.AcquisitionError, "count or independent"):
                    tool.acquire(remote, self.output)
                self.assert_incomplete()

    def test_saved_corruption_and_transfer_digest_mismatch_rejected(self):
        for attribute in ("corrupt_saved", "bad_digest"):
            with self.subTest(attribute=attribute):
                self.output = self.base / attribute
                remote = FakeRemote(); setattr(remote, attribute, 1)
                with self.assertRaisesRegex(tool.AcquisitionError, "SHA-256"):
                    tool.acquire(remote, self.output)
                self.assert_incomplete()

    def test_remote_failure_retains_partial_without_accepted_image(self):
        remote = FakeRemote(); remote.fail_read = 1
        with self.assertRaisesRegex(tool.AcquisitionError, "transport failed"):
            tool.acquire(remote, self.output)
        self.assert_incomplete()
        self.assertEqual((self.output / "gpt-front.bin.part").read_bytes(), b"private-partial")

    def test_second_link_failure_rolls_back_only_own_publication(self):
        original_link = os.link
        count = 0

        def link(source, destination):
            nonlocal count
            count += 1
            if count == 2:
                raise OSError("fixture publication failure")
            return original_link(source, destination)

        with mock.patch.object(tool.os, "link", side_effect=link):
            with self.assertRaisesRegex(OSError, "publication failure"):
                tool.acquire(FakeRemote(), self.output)
        self.assert_incomplete()
        self.assertEqual(len(list(self.output.glob("*.bin.part"))), 2)

    def test_complete_manifest_failure_rolls_back_all_published_files(self):
        original_write = tool.manifest_write

        def write(output, manifest, durable=True):
            if manifest["status"] == "complete":
                raise OSError("fixture complete manifest failure")
            return original_write(output, manifest, durable)

        with mock.patch.object(tool, "manifest_write", side_effect=write):
            with self.assertRaisesRegex(OSError, "manifest failure"):
                tool.acquire(FakeRemote(), self.output)
        self.assert_incomplete()
        self.assertEqual(len(list(self.output.glob("*.bin.part"))), 2)

    def test_raw_image_fsync_failure_is_incomplete(self):
        original_fsync = os.fsync

        def fsync(descriptor):
            metadata = os.fstat(descriptor)
            if stat.S_ISREG(metadata.st_mode) and metadata.st_size == tool.EDGE_BYTES:
                raise OSError("fixture image fsync failure")
            return original_fsync(descriptor)

        with mock.patch.object(tool.os, "fsync", side_effect=fsync):
            with self.assertRaisesRegex(OSError, "fsync failure"):
                tool.acquire(FakeRemote(), self.output)
        self.assert_incomplete()

    def test_existing_output_or_symlink_never_overwritten(self):
        self.output.mkdir()
        marker = self.output / "existing"
        marker.write_bytes(b"keep")
        with self.assertRaises(FileExistsError):
            tool.acquire(FakeRemote(), self.output)
        self.assertEqual(list(self.output.iterdir()), [marker])
        link = self.base / "link"
        link.symlink_to(self.output, target_is_directory=True)
        with self.assertRaisesRegex(ValueError, "symlink"):
            tool.acquire(FakeRemote(), link)
        dangling = self.base / "dangling"
        dangling.symlink_to(self.base / "missing")
        with self.assertRaisesRegex(ValueError, "symlink"):
            tool.acquire(FakeRemote(), dangling)

    def test_git_and_jj_checkouts_rejected(self):
        for marker in (".git", ".jj"):
            checkout = self.base / marker[1:]
            (checkout / marker).mkdir(parents=True)
            if marker == ".git":
                (checkout / marker / "HEAD").write_text("ref: refs/heads/fixture\n")
            with self.assertRaises(ValueError):
                tool.acquire(FakeRemote(), checkout / "private")
            self.assertFalse((checkout / "private").exists())

    def test_cli_checks_binary_protocol_before_password_and_uses_private_umask(self):
        remote = FakeRemote()
        self.output = self.base / "new-parent" / "new-child" / "capture"

        def prompt():
            self.assertTrue(remote.protocol_checked)
            return b"fixture-secret"

        with mock.patch.object(tool.acquisition, "Remote", return_value=remote), \
             mock.patch.object(tool.acquisition, "run_bounded", return_value=(b"List of devices attached\nfixture\tdevice\n", 0, "")), \
             mock.patch.object(tool.acquisition, "prompt_password", side_effect=prompt), \
             contextlib.redirect_stdout(io.StringIO()) as captured:
            self.assertEqual(tool.main(["--sudo", "--output", str(self.output)]), 0)
        self.assertIsNone(remote.password)
        self.assertNotIn("fixture-secret", captured.getvalue())
        self.assertNotIn(str(remote.fixture.disk_guid), captured.getvalue())
        for path in (self.output, self.output.parent, self.output.parent.parent):
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o700)

    def test_cli_has_no_device_path_geometry_or_arbitrary_read_overrides(self):
        for option in ("--device", "--disk-bytes", "--skip", "--count"):
            with self.subTest(option=option), contextlib.redirect_stderr(io.StringIO()):
                with self.assertRaises(SystemExit) as result:
                    tool.main([option, "1"])
                self.assertEqual(result.exception.code, 2)

    def test_transport_rejects_even_one_byte_beyond_fixed_window(self):
        with self.assertRaises(tool.AcquisitionError):
            tool.acquisition.run_bounded([sys.executable, "-c", "import sys;sys.stdout.buffer.write(b'x'*32769)"],
                                         tool.EDGE_BYTES, 5)


class MapAndCommandTests(unittest.TestCase):
    def test_fixed_read_commands_recheck_all_metadata_and_only_read_32k(self):
        for region, skip in (("front", 0), ("tail", 244285376)):
            script = tool.read_script(region)
            self.assertTrue(script.startswith(tool.guard_script()))
            self.assertEqual(script.count("dd if="), 1)
            self.assertTrue(script.endswith(f"dd if=/dev/mmcblk0 bs=512 skip={skip} count=64 iflag=fullblock status=none\n"))
            self.assertNotIn("of=", script)
            self.assertNotIn("--setro", script)
            self.assertIn('"$partition_count" = 38', script)
            self.assertIn("NF != 2", script)
            subprocess.run(["/bin/sh", "-n"], input=script.encode(), check=True, capture_output=True)
        with self.assertRaises(ValueError):
            tool.read_script("userdata")

    def test_missing_duplicate_unexpected_or_noncanonical_map_records_rejected(self):
        baseline = Fixture().map()
        lines = baseline.splitlines(keepends=True)
        variants = [b"".join(lines[:-2] + lines[-1:]),
            b"".join(lines[:2] + [lines[1]] + lines[3:]),
            baseline.replace(b"PART\t38\t", b"PART\t39\t"),
            baseline.replace(b"PART\t1\t", b"PART\t01\t"),
            baseline.replace(b"\t64\t64\t", b"\t064\t64\t", 1),
            baseline.replace(b"\t64\t64\t", b"\t999999999999999999999999\t64\t", 1),
            baseline.replace(b"END\t38\n", b"END\t38\nEXTRA\n"),
            baseline[:-1], baseline + b"X" * tool.MAP_LIMIT]
        for index, data in enumerate(variants):
            with self.subTest(index=index), self.assertRaises(tool.AcquisitionError):
                tool.validate_map(data)

    def test_identity_geometry_anchors_and_overlap_rejected(self):
        baseline = Fixture().map()
        variants = [baseline.replace(b"MMC\t0", b"SD\t0"),
            baseline.replace(b"\t512\t512\t", b"\t4096\t512\t"),
            baseline.replace(b"\tb3:0\n", b"\tb4:0\n"),
            baseline.replace(b"\tb3:1\n", b"\tb3:2\n"),
            baseline.replace(b"\tboot\t", b"\twrong\t"),
            baseline.replace(b"\t10027008\t234137536\t", b"\t10027009\t234137536\t")]
        for field, value in (("start", 63), ("size", 0), ("size", tool.DISK_SECTORS)):
            fixture = Fixture(); fixture.partitions[0][field] = value
            variants.append(fixture.map())
        fixture = Fixture(); fixture.partitions[2]["start"] = 128
        variants.append(fixture.map())
        fixture = Fixture(); fixture.partitions[-1]["size"] += 1
        variants.append(fixture.map())
        for index, data in enumerate(variants):
            with self.subTest(index=index), self.assertRaises(tool.AcquisitionError):
                tool.validate_map(data)

    def test_gpt_partition_edge_overlap_rejected_independently(self):
        fixture = Fixture()
        kernel = tool.validate_map(fixture.map())
        parsed = tool.gpt.validate_gpt(*fixture.captures(), tool.DISK_BYTES)
        for field, value in (("first_lba", 63), ("last_lba", tool.TAIL_START)):
            changed = json.loads(json.dumps(parsed))
            changed["partitions"][0][field] = value
            with self.assertRaisesRegex(tool.AcquisitionError, "window overlaps a GPT"):
                tool.cross_check(changed, kernel)


if __name__ == "__main__":
    unittest.main()
