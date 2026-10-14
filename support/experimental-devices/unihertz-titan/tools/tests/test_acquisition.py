"""Exercise bounded acquisition with local fixtures only; never contact a phone."""

import contextlib
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import shlex
import stat
import sys
import tempfile
import unittest
from unittest.mock import patch


SCRIPT = Path(__file__).resolve().parents[1] / "acquire-partitions.py"
SPEC = importlib.util.spec_from_file_location("acquisition", SCRIPT)
acquisition = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(acquisition)


def evidence(partition_label="boot", **replacements):
    label = partition_label
    device, number, size = acquisition.PARTITIONS[label]
    disk = "/sys/devices/platform/bootdevice/mmc_host/mmc0/mmc0:0001/block/mmcblk0"
    fields = {
        "label": label, "device": f"/dev/{device}", "mmc_type": "MMC",
        "partition": str(number), "sectors": str(size // 512), "bytes": str(size),
        "sysfs": f"{disk}/{device}", "sysfs_disk": disk, "device_number": f"179:{number}",
        "block_device": "true", "readable": "true", "unmounted": "true", "holders": "none",
    }
    fields.update(replacements)
    return "".join(f"{key}={value}\n" for key, value in fields.items()).encode()


class GeometryTests(unittest.TestCase):
    def test_only_the_three_measured_partitions_are_selected(self):
        self.assertEqual(acquisition.PARTITIONS, {
            "boot": ("mmcblk0p28", 28, 33554432),
            "recovery": ("mmcblk0p2", 2, 33554432),
            "dtbo": ("mmcblk0p30", 30, 8388608),
        })
        for label in acquisition.PARTITIONS:
            self.assertEqual(acquisition.validate_evidence(label, evidence(label))["label"], label)
        with self.assertRaises(ValueError):
            acquisition.guard_script("userdata")

    def test_changed_geometry_parent_type_permissions_or_mounts_are_rejected(self):
        cases = {
            "label": "userdata", "device": "/dev/mmcblk0p36", "mmc_type": "SD",
            "partition": "2", "sectors": "65535", "bytes": "33554431",
            "sysfs": "/sys/devices/other/mmcblk0p28", "sysfs_disk": "/sys/devices/sda",
            "device_number": "179:28\nextra", "block_device": "false",
            "readable": "false", "unmounted": "false", "holders": "dm-0",
        }
        for field, value in cases.items():
            with self.subTest(field=field), self.assertRaises(acquisition.AcquisitionError):
                acquisition.validate_evidence("boot", evidence(**{field: value}))

    def test_ambiguous_or_malformed_output_is_rejected(self):
        for data in (evidence() + b"bytes=33554432\n", evidence() + b"unknown=1\n",
                     evidence().replace(b"MMC", b"\xff"), b"junk\n"):
            with self.subTest(data=data[-40:]), self.assertRaises(acquisition.AcquisitionError):
                acquisition.validate_evidence("boot", data)

    def test_all_content_reads_repeat_the_guards_and_are_bounded(self):
        for label, (device, _, size) in acquisition.PARTITIONS.items():
            guard = acquisition.guard_script(label)
            self.assertIn(f"[ -b /dev/{device} ]", guard)
            self.assertIn(f"/usr/sbin/blockdev --getsize64 /dev/{device}", guard)
            self.assertIn("/proc/self/mountinfo /proc/1/mountinfo", guard)
            self.assertIn("$3 == device_number", guard)
            self.assertIn(f"/sys/class/block/{device}/holders/*", guard)
            for script in (acquisition.read_script(label), acquisition.hash_script(label)):
                self.assertTrue(script.startswith(guard))
                for forbidden in ("of=", "reboot", "fastboot", "flash", "mount ", "umount ",
                                  "fsfreeze", "apt ", "nix ", "tee "):
                    self.assertNotIn(forbidden, script)
            self.assertTrue(acquisition.read_script(label).endswith(
                f"dd if=/dev/{device} bs=1048576 count={size // 1048576} iflag=fullblock status=none\n"))


class StreamTests(unittest.TestCase):
    def run_fixture(self, code, **kwargs):
        return acquisition.run_bounded([sys.executable, "-c", code], **kwargs)

    def test_binary_stream_is_unchanged_and_hashed(self):
        data = b"\x00\r\n\xff"
        sink = io.BytesIO()
        stdout, count, digest = self.run_fixture(
            "import sys; sys.stdout.buffer.write(b'\\x00\\r\\n\\xff')", limit=4, timeout=2, sink=sink)
        self.assertEqual(stdout, b"")
        self.assertEqual(sink.getvalue(), data)
        self.assertEqual(count, len(data))
        self.assertEqual(digest, hashlib.sha256(data).hexdigest())

    def test_excess_stream_failed_exit_and_deadline_are_rejected(self):
        for code, limit, timeout, message in (
            ("import sys; sys.stdout.buffer.write(b'x'*100000)", 8, 2, "byte count"),
            ("import sys; sys.stdout.write('abcd'); sys.exit(1)", 4, 2, "exit 1"),
            ("import time; time.sleep(2)", 4, 0.05, "timed out"),
            ("import sys; sys.stderr.write('x'*20000)", 4, 2, "diagnostic output"),
        ):
            with self.subTest(code=code), self.assertRaisesRegex(acquisition.AcquisitionError, message):
                self.run_fixture(code, limit=limit, timeout=timeout)

    def test_short_stream_is_reported_to_caller_for_exact_size_check(self):
        _, count, _ = self.run_fixture("print('x', end='')", limit=4, timeout=2)
        self.assertEqual(count, 1)

    def test_stderr_status_is_required_even_when_adb_claims_success(self):
        token = "TITAN_TEST_STATUS_123"
        for stderr, host_exit, expected_exit, okay in (
            (f"\n{token}:0\n", 0, 0, True),
            (f"\n{token}:42\n", 0, 42, True),
            (f"\n{token}:42\n", 42, 42, True),
            (f"\n{token}:7\n", 0, 0, False),
            (f"\n{token}:0\n", 1, 0, False),
            ("", 0, 0, False),
            (f"\n{token}:999\n", 0, 0, False),
            (f"\n{token}:0\ntrailing", 0, 0, False),
            (f"\n{token}:0\n\n{token}:0\n", 0, 0, False),
        ):
            code = f"import sys; sys.stderr.write({stderr!r}); sys.exit({host_exit})"
            with self.subTest(stderr=stderr, host_exit=host_exit):
                if okay:
                    self.run_fixture(code, limit=0, timeout=2, status_token=token, expected_exit=expected_exit)
                else:
                    with self.assertRaises(acquisition.AcquisitionError):
                        self.run_fixture(code, limit=0, timeout=2, status_token=token, expected_exit=expected_exit)

    def test_password_uses_stdin_and_never_diagnostic_errors(self):
        password = b"fixture-secret-never-log"
        code = "import sys; line=sys.stdin.buffer.readline(); sys.stderr.buffer.write(line); sys.exit(1)"
        with self.assertRaises(acquisition.AcquisitionError) as raised:
            self.run_fixture(code, limit=0, timeout=2, password=password)
        self.assertNotIn(password.decode(), str(raised.exception))


class TransportTests(unittest.TestCase):
    def test_sudo_and_script_are_quoted_in_one_command_with_password_only_in_stdin(self):
        remote = acquisition.Remote("adb", "private-selector;no-host-shell", 3, b"secret")
        script = "printf '%s\\n' 'a b'; exit 0"
        with patch.object(acquisition, "run_bounded", return_value=(b"", 0, "hash")) as run:
            remote.run(script)
        command = run.call_args.args[0]
        self.assertEqual(command[:5], ["adb", "-s", "private-selector;no-host-shell", "shell", "-T"])
        self.assertEqual(len(command), 6)
        self.assertTrue(command[5].startswith("sudo -S -p '' -- sh -c " + shlex.quote(script) + ";"))
        self.assertNotIn("secret", str(command))
        self.assertEqual(run.call_args.kwargs["password"], b"secret")
        self.assertIn(run.call_args.kwargs["status_token"], command[5])

    def test_protocol_checks_binary_separation_and_nonzero_status(self):
        remote = acquisition.Remote("adb", "phone", 3)
        with patch.object(acquisition, "run_bounded", return_value=(b"shell_v2\ncmd\n", 13, "hash")), \
                patch.object(remote, "run", return_value=(b"\x00\r\n\xff", 4, "hash")) as run:
            remote.check_protocol()
        self.assertEqual(run.call_args.kwargs["expected_exit"], 42)
        with patch.object(acquisition, "run_bounded", return_value=(b"cmd\n", 4, "hash")):
            with self.assertRaisesRegex(acquisition.AcquisitionError, "shell_v2"):
                remote.check_protocol()
        with patch.object(acquisition, "run_bounded", return_value=(b"shell_v2\n", 9, "hash")), \
                patch.object(remote, "run", return_value=(b"corrupt", 7, "hash")):
            with self.assertRaisesRegex(acquisition.AcquisitionError, "binary probe"):
                remote.check_protocol()

    def test_no_password_prompt_without_terminal(self):
        with patch.object(acquisition.sys.stdin, "isatty", return_value=False), \
                patch.object(acquisition.getpass, "getpass") as prompt:
            with self.assertRaisesRegex(acquisition.AcquisitionError, "terminal"):
                acquisition.prompt_password()
        prompt.assert_not_called()

    def test_no_fallback_password_read_when_terminal_echo_control_fails(self):
        with patch.object(acquisition.sys.stdin, "isatty", return_value=True), \
                patch.object(acquisition.sys.stderr, "isatty", return_value=True), \
                patch.object(acquisition.getpass, "getpass", side_effect=acquisition.getpass.fallback_getpass), \
                patch.object(acquisition.getpass, "_raw_input") as fallback_read:
            with self.assertRaisesRegex(acquisition.AcquisitionError, "Cannot disable password echo"):
                acquisition.prompt_password()
        fallback_read.assert_not_called()


class FakeRemote:
    def __init__(self, short=False, bad_hash=False, changed=False, fail=False, corrupt=False):
        self.short, self.bad_hash, self.changed, self.fail = short, bad_hash, changed, fail
        self.corrupt = corrupt
        self.probes, self.calls = 0, []

    def run(self, script, limit=16384, *, sink=None):
        self.calls.append(script)
        if script == acquisition.probe_script("dtbo"):
            self.probes += 1
            data = evidence("dtbo", sectors="1") if self.changed and self.probes > 1 else evidence("dtbo")
            return data, len(data), "unused"
        if script == acquisition.read_script("dtbo"):
            data = b"\x00\r\n\xff" * (acquisition.MIB // 4)
            count = acquisition.PARTITIONS["dtbo"][2] - int(self.short)
            digest = hashlib.sha256()
            for offset in range(0, count, len(data)):
                chunk = data[:min(len(data), count - offset)]
                sink.write(chunk)
                digest.update(chunk)
            self.digest = digest.hexdigest()
            if self.corrupt:
                sink.seek(0)
                sink.write(b"corrupted on disk")
            if self.fail:
                raise acquisition.AcquisitionError("remote read failed")
            return b"", count, self.digest
        if script == acquisition.hash_script("dtbo"):
            data = (("0" * 64 if self.bad_hash else self.digest) + "  /dev/mmcblk0p30\n").encode()
            return data, len(data), "unused"
        raise AssertionError("Unexpected remote command")


class OutputTests(unittest.TestCase):
    def test_success_is_private_exact_and_independently_hashed(self):
        with tempfile.TemporaryDirectory() as temporary:
            output = acquisition.prepare_output(str(Path(temporary) / "images"))
            remote = FakeRemote()
            report = acquisition.acquire_one(remote, output, "dtbo")
            image = output / "dtbo.img"
            self.assertEqual(image.stat().st_size, 8388608)
            self.assertEqual(report["sha256"], hashlib.sha256(image.read_bytes()).hexdigest())
            self.assertEqual(report["sha256"], report["phone_sha256"])
            self.assertEqual(remote.probes, 2)
            self.assertEqual(remote.calls[-1], acquisition.hash_script("dtbo"))
            self.assertEqual(stat.S_IMODE(output.stat().st_mode), 0o700)
            self.assertEqual(stat.S_IMODE(image.stat().st_mode), 0o600)
            acquisition.write_manifest(output, {"status": "complete", "partitions": {"dtbo": report}})
            manifest = output / "manifest.json"
            self.assertEqual(stat.S_IMODE(manifest.stat().st_mode), 0o600)
            self.assertEqual(json.loads(manifest.read_text())["status"], "complete")
            self.assertFalse(list(output.glob("*.part")))

    def test_short_failed_changed_or_unmatched_images_are_never_published(self):
        for options in ({"short": True}, {"fail": True}, {"bad_hash": True}, {"changed": True}, {"corrupt": True}):
            with self.subTest(options=options), tempfile.TemporaryDirectory() as temporary:
                output = Path(temporary)
                with self.assertRaises(acquisition.AcquisitionError):
                    acquisition.acquire_one(FakeRemote(**options), output, "dtbo")
                self.assertFalse(list(output.iterdir()))

    def test_existing_partial_or_image_is_never_deleted_or_overwritten(self):
        for name in ("dtbo.img", "dtbo.img.part"):
            with self.subTest(name=name), tempfile.TemporaryDirectory() as temporary:
                output = Path(temporary)
                (output / name).write_bytes(b"existing")
                with self.assertRaises((acquisition.AcquisitionError, FileExistsError)):
                    acquisition.acquire_one(FakeRemote(), output, "dtbo")
                self.assertEqual((output / name).read_bytes(), b"existing")

    def test_repository_existing_and_symlinked_destinations_are_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            repo = base / "repo"
            repo.mkdir()
            (repo / ".git").write_text("gitdir: /fake")
            alias = base / "alias"
            alias.symlink_to(repo, target_is_directory=True)
            for path in (repo / "backup", alias / "backup"):
                with self.subTest(path=path), self.assertRaisesRegex(ValueError, "Git"):
                    acquisition.prepare_output(str(path))
            with self.assertRaises(FileExistsError):
                acquisition.prepare_output(str(base))

    def test_default_output_uses_private_recovery_state_directory(self):
        with tempfile.TemporaryDirectory() as temporary, patch.dict(os.environ, {"XDG_STATE_HOME": temporary}):
            output = acquisition.prepare_output(None)
            self.assertEqual(output.parent, Path(temporary).resolve() / "mobile-nixos/titan-recovery")
            self.assertEqual(stat.S_IMODE(output.stat().st_mode), 0o700)

    def test_default_invocation_does_not_prompt_or_create_output_when_unreadable(self):
        with tempfile.TemporaryDirectory() as temporary, \
                patch.object(acquisition, "run_bounded", return_value=(b"List of devices attached\nsecret-id\tdevice\n", 50, "hash")), \
                patch.object(acquisition.Remote, "check_protocol"), \
                patch.object(acquisition.Remote, "run", side_effect=acquisition.AcquisitionError("unreadable")), \
                patch.object(acquisition, "prompt_password") as prompt, \
                contextlib.redirect_stderr(io.StringIO()) as terminal:
            output = Path(temporary) / "backup"
            self.assertEqual(acquisition.main(["--output", str(output)]), 1)
            self.assertFalse(output.exists())
            self.assertNotIn("secret-id", terminal.getvalue())
            prompt.assert_not_called()


if __name__ == "__main__":
    unittest.main()
