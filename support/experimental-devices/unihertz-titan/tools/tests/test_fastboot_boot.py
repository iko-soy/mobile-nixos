"""Synthetic temporary-boot helper tests; a fake executable stands in for fastboot."""

import contextlib
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import stat
import sys
import tempfile
import unittest
from unittest import mock


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


HERE = Path(__file__).resolve().parent
tool = load("titan_fastboot_boot_test", HERE.parent / "boot-fastboot-image.py")
envelope = load("titan_fastboot_boot_envelope", HERE.parent / "prepare-rescue-image.py")
SERIAL = "FAKE0123"
VARIABLES = {"product": "g61v71c2k_dfl_tee", "is-userspace": "no", "unlocked": "yes",
             "max-download-size": "0x8000000"}
IMAGE = b"ANDROID!" + bytes(range(256)) * 15 + b"\0" * 248

FAKE = r'''
import hashlib, json, os, sys, time
config = json.load(open(os.environ["TITAN_FAKE_FASTBOOT"]))
args = sys.argv[1:]
entry = list(args)
if len(args) == 4 and args[2] == "boot":
    entry.append(hashlib.sha256(open(args[3], "rb").read()).hexdigest())
with open(config["log"], "a") as log:
    log.write(json.dumps(entry) + "\n")
if args == ["--version"]:
    print("fastboot version fake")
    sys.exit(config.get("version_exit", 0))
if args == ["devices"]:
    with open(config["counter"], "a+") as counter:
        counter.seek(0)
        calls = len(counter.read())
        counter.write(".")
    if calls >= config.get("devices_after", 0):
        sys.stdout.write(config.get("devices", ""))
    sys.exit(0)
if len(args) >= 3 and args[0] == "-s" and args[1] == config["serial"]:
    if args[2] == "getvar" and len(args) == 4:
        time.sleep(config.get("getvar_sleep", {}).get(args[3], 0))
        value = config.get("vars", {}).get(args[3])
        if value is None:
            sys.stderr.write("getvar:%s FAILED (remote: 'unknown variable')\n" % args[3])
            sys.exit(1)
        sys.stderr.write("%s: %s\nFinished. Total time: 0.001s\n" % (args[3], value))
        sys.exit(0)
    if args[2] == "boot" and len(args) == 4:
        time.sleep(config.get("boot_sleep", 0))
        if config.get("mutate_on_boot"):
            os.chmod(args[3], 0o600)
            with open(args[3], "ab") as image:
                image.write(b"x")
        sys.stderr.write("Sending 'boot.img'\nBooting OKAY\nFinished. Total time: 0.100s\n")
        sys.exit(config.get("boot_exit", 0))
sys.stderr.write("unexpected invocation\n")
sys.exit(99)
'''


class TemporaryBootTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name).resolve()
        self.fake = self.root / "fastboot"
        self.fake.write_text("#!" + sys.executable + "\n" + FAKE)
        self.fake.chmod(0o700)
        self.log = self.root / "invocations.jsonl"
        self.image = self.root / "boot.img"
        self.image.write_bytes(IMAGE)
        self.image.chmod(0o600)
        self.config = {"log": str(self.log), "counter": str(self.root / "counter"), "serial": SERIAL,
                       "devices": SERIAL + "\tfastboot\n", "vars": dict(VARIABLES)}
        for patch in (mock.patch.dict(os.environ, {"TITAN_FAKE_FASTBOOT": str(self.root / "config.json")}),
                      mock.patch.dict(tool.PROFILES, {"installed-boot": {
                          "bytes": len(IMAGE), "sha256": hashlib.sha256(IMAGE).hexdigest()}}, clear=True)):
            patch.start()
            self.addCleanup(patch.stop)
        self.configure()

    def configure(self, **changes):
        self.config.update(changes)
        (self.root / "config.json").write_text(json.dumps(self.config))

    def invocations(self):
        return [json.loads(line) for line in self.log.read_text().splitlines()] if self.log.exists() else []

    def run_main(self, name="trial", extra=()):
        stdout, stderr = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            code = tool.main(["--profile", "installed-boot", "--image", str(self.image), "--fastboot",
                              str(self.fake), "--wait", "0", "--output", str(self.root / name), *extra])
        return code, stdout.getvalue(), stderr.getvalue()

    def record(self, name="trial"):
        return json.loads((self.root / name / "trial.json").read_text())

    def test_pinned_profile_matches_the_reviewed_installed_boot_copy(self):
        # A fresh, unpatched load pins the same reviewed copy as the envelope tool.
        real = load("titan_fastboot_boot_constants", HERE.parent / "boot-fastboot-image.py").PROFILES
        self.assertEqual(set(real), {"installed-boot", "rescue-probe"})
        self.assertEqual(real["installed-boot"], {"bytes": envelope.BOOT_BYTES, "sha256": envelope.BOOT_SHA256})
        # The probe envelope fits the boot partition and the bootloader's
        # reported 128 MiB download limit.
        self.assertLess(real["rescue-probe"]["bytes"], min(envelope.BOOT_BYTES, 0x8000000))
        self.assertRegex(real["rescue-probe"]["sha256"], "^[0-9a-f]{64}$")

    def test_identity_queries_then_exactly_one_boot_of_the_verified_private_copy(self):
        code, stdout, stderr = self.run_main()
        self.assertEqual(code, 0, stderr)
        copy = self.root / "trial" / "image.img"
        digest = hashlib.sha256(IMAGE).hexdigest()
        expected = [["--version"], ["devices"]] + [["-s", SERIAL, "getvar", name] for name in tool.IDENTITY]
        expected.append(["-s", SERIAL, "boot", str(copy), digest])
        self.assertEqual(self.invocations(), expected)
        self.assertEqual(copy.read_bytes(), IMAGE)
        self.assertEqual(stat.S_IMODE(copy.stat().st_mode), 0o400)
        saved = self.record()
        self.assertEqual((saved["format"], saved["status"], saved["profile"]),
                         ("titan-fastboot-boot-v1", "complete", "installed-boot"))
        self.assertEqual(saved["image"], {"bytes": len(IMAGE), "sha256": digest})
        self.assertEqual(saved["image_after_boot"], {"bytes": len(IMAGE), "sha256": digest})
        # As in the observation helper, only the private device listing and its
        # own field hold the serial; commands and terminal output do not.
        self.assertEqual(saved["device_serial_private"], SERIAL)
        self.assertNotIn(SERIAL, json.dumps(saved["steps"][2:]) + stdout + stderr)
        self.assertNotIn(str(copy), json.dumps(saved["steps"]))
        self.assertIn("confirm the boot over ADB", stdout)

    def test_mismatched_or_unsafe_images_are_refused_before_fastboot_runs(self):
        cases = {"content": IMAGE[:-1] + b"x", "short": IMAGE[:-1], "long": IMAGE + b"\0"}
        for name, data in cases.items():
            with self.subTest(case=name):
                self.image.write_bytes(data)
                code, _, stderr = self.run_main("image-" + name)
                self.assertEqual(code, 1)
                self.assertIn("nothing was sent", stderr)
                self.assertFalse((self.root / ("image-" + name) / "image.img").exists())
        self.image.write_bytes(IMAGE)
        link = self.root / "link.img"
        link.symlink_to(self.image)
        directory = self.root / "directory.img"
        directory.mkdir()
        for name, path in (("symlink", link), ("directory", directory), ("relative", Path("boot.img"))):
            with self.subTest(case=name):
                stderr = io.StringIO()
                with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(stderr):
                    code = tool.main(["--profile", "installed-boot", "--image", str(path), "--fastboot",
                                      str(self.fake), "--wait", "0", "--output", str(self.root / ("path-" + name))])
                self.assertEqual(code, 1)
                if name == "relative":
                    self.assertIn("absolute", stderr.getvalue())
        self.assertEqual(self.invocations(), [])

    def test_identity_mismatch_sends_nothing(self):
        # Each case starts from the recorded values, so each check is reached on its own.
        cases = {"product": ({"product": "other"}, "'product'"),
                 "userspace": ({"is-userspace": "yes"}, "'is-userspace'"),
                 "locked": ({"unlocked": "no"}, "'unlocked'"),
                 "small": ({"max-download-size": hex(len(IMAGE) - 1)}, "exceeds"),
                 "decimal-small": ({"max-download-size": str(len(IMAGE) - 1)}, "exceeds"),
                 "product-extended": ({"product": "g61v71c2k_dfl_tee-other"}, "'product'"),
                 "exact": ({"max-download-size": hex(len(IMAGE))}, None),
                 "unparsable": ({"max-download-size": "lots"}, "not reported"),
                 "missing": ({"product": None}, "'product'")}
        for name, (change, message) in cases.items():
            with self.subTest(case=name):
                self.log.unlink(missing_ok=True)
                variables = dict(VARIABLES, **change)
                self.configure(vars={key: value for key, value in variables.items() if value is not None})
                code, _, stderr = self.run_main("identity-" + name)
                if message is None:
                    self.assertEqual(code, 0, stderr)
                    continue
                self.assertEqual(code, 1)
                self.assertIn("nothing was sent", stderr)
                self.assertIn(message, stderr)
                self.assertNotIn(SERIAL, stderr)
                self.assertFalse(any("boot" in call for call in self.invocations()))
                saved = self.record("identity-" + name)
                self.assertEqual(saved["status"], "incomplete")
                self.assertIn(message, saved["error"])
        self.configure(vars=dict(VARIABLES))

    def test_hung_identity_query_refuses_before_sending(self):
        self.configure(getvar_sleep={"unlocked": 5})
        with mock.patch.object(tool.trial, "COMMAND_TIMEOUT", 1.0):
            code, _, stderr = self.run_main("hung-query")
        self.assertEqual(code, 1)
        self.assertIn("did not finish", stderr)
        self.assertFalse(any("boot" in call for call in self.invocations()))
        self.assertEqual(self.record("hung-query")["steps"][-1]["status"], "timeout")

    def test_late_device_is_awaited_within_the_requested_wait(self):
        self.configure(devices_after=2)
        with mock.patch.object(tool.trial, "POLL_INTERVAL", 0.1):
            code, _, stderr = self.run_main("late", extra=("--wait", "5"))
        self.assertEqual(code, 0, stderr)
        self.assertEqual(self.invocations()[1:4], [["devices"]] * 3)

    def test_copy_is_created_private_before_it_is_made_read_only(self):
        modes, real_chmod = [], os.chmod

        def observe(path, mode, *args, **kwargs):
            modes.append(stat.S_IMODE(os.lstat(path).st_mode))
            return real_chmod(path, mode, *args, **kwargs)

        output = tool.trial.prepare_output(str(self.root / "modes"))
        previous = os.umask(0o022)
        try:
            with mock.patch.object(tool.os, "chmod", side_effect=observe):
                copy = tool.copy_image(str(self.image), output, "installed-boot")
        finally:
            os.umask(previous)
        self.assertEqual(modes, [0o600])
        self.assertEqual(stat.S_IMODE(copy.stat().st_mode), 0o400)

    def test_device_listing_must_name_exactly_one_fastboot_device(self):
        for name, listing in {"none": "", "two": SERIAL + "\tfastboot\nOTHER\tfastboot\n",
                              "state": SERIAL + "\trecovery\n"}.items():
            with self.subTest(case=name):
                self.log.unlink(missing_ok=True)
                self.configure(devices=listing)
                code, _, _ = self.run_main("listing-" + name)
                self.assertEqual(code, 1)
                self.assertEqual(self.invocations(), [["--version"], ["devices"]])
        self.configure(devices=SERIAL + "\tfastboot\n")

    def test_copy_changed_after_verification_is_not_sent(self):
        original = tool.trial.select_device

        for name, change in (("replaced", lambda data: data[:-1] + b"y"), ("appended", lambda data: data + b"z")):
            self.log.unlink(missing_ok=True)

            def tamper(*args, **kwargs):
                serial = original(*args, **kwargs)
                copy = self.root / ("tamper-" + name) / "image.img"
                copy.chmod(0o600)
                copy.write_bytes(change(IMAGE))
                return serial

            with self.subTest(case=name), mock.patch.object(tool.trial, "select_device", side_effect=tamper):
                code, _, stderr = self.run_main("tamper-" + name)
                self.assertEqual(code, 1)
                self.assertIn("changed", stderr)
                self.assertFalse(any("boot" in call for call in self.invocations()))

    def test_copy_changed_during_identity_queries_is_not_sent(self):
        real = tool.trial.run_bounded

        def tamper(command, *args, **kwargs):
            if command[-2:] == ["getvar", "max-download-size"]:
                copy = self.root / "query-tamper" / "image.img"
                copy.chmod(0o600)
                copy.write_bytes(IMAGE[:-1] + b"q")
            return real(command, *args, **kwargs)

        with mock.patch.object(tool.trial, "run_bounded", side_effect=tamper):
            code, _, stderr = self.run_main("query-tamper")
        self.assertEqual(code, 1)
        self.assertIn("changed", stderr)
        self.assertFalse(any("boot" in call for call in self.invocations()))

    def test_copy_changed_while_fastboot_reads_it_is_reported(self):
        self.configure(mutate_on_boot=True)
        code, _, stderr = self.run_main("during")
        self.assertEqual(code, 1)
        self.assertIn("what was sent is unknown", stderr)
        saved = self.record("during")
        self.assertEqual(saved["status"], "incomplete")
        self.assertEqual(saved["image_after_boot"]["bytes"], len(IMAGE) + 1)

    def test_failing_version_check_queries_nothing(self):
        self.configure(version_exit=1)
        code, _, stderr = self.run_main("version")
        self.assertEqual(code, 1)
        self.assertIn("version", stderr)
        self.assertEqual(self.invocations(), [["--version"]])

    def test_failed_or_hung_boot_command_is_reported_incomplete(self):
        self.configure(boot_exit=1)
        code, _, stderr = self.run_main("failed")
        self.assertEqual(code, 1)
        self.assertIn("did not complete", stderr)
        self.assertNotIn(SERIAL, stderr)
        self.assertEqual(self.record("failed")["status"], "incomplete")
        self.configure(boot_exit=0, boot_sleep=5)
        with mock.patch.object(tool, "BOOT_TIMEOUT", 1.0):
            code, _, _ = self.run_main("hung")
        self.assertEqual(code, 1)
        saved = self.record("hung")
        self.assertEqual((saved["status"], saved["steps"][-1]["status"]), ("incomplete", "timeout"))

    def test_command_line_rejects_unreviewed_profiles_and_options(self):
        stderr = io.StringIO()
        with contextlib.redirect_stderr(stderr), self.assertRaises(SystemExit):
            tool.main(["--profile", "rescue", "--image", str(self.image), "--output", str(self.root / "x")])
        for extra, name in ((["--wait", "601"], "wait"), (["--fastboot", "fastboot"], "relative")):
            with self.subTest(case=name):
                stderr = io.StringIO()
                with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(stderr):
                    code = tool.main(["--profile", "installed-boot", "--image", str(self.image),
                                      "--output", str(self.root / ("option-" + name)), "--fastboot", str(self.fake),
                                      *extra])
                self.assertEqual(code, 1)
        self.assertEqual(self.invocations(), [])

    def test_output_must_be_new_and_outside_checkouts(self):
        (self.root / "existing").mkdir()
        code, _, _ = self.run_main("existing")
        self.assertEqual(code, 1)
        checkout = self.root / "checkout"
        (checkout / ".jj").mkdir(parents=True)
        code, _, _ = self.run_main("checkout/nested")
        self.assertEqual(code, 1)
        self.assertEqual(self.invocations(), [])


if __name__ == "__main__":
    unittest.main()
