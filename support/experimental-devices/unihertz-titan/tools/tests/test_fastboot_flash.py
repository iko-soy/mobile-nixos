"""Synthetic recovery-flash helper tests; a fake executable stands in for fastboot."""

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
tool = load("titan_fastboot_flash_test", HERE.parent / "flash-recovery.py")
boot = load("titan_fastboot_flash_boot", HERE.parent / "boot-fastboot-image.py")
SERIAL = "FAKE0123"
SIZE = 8192
PROBE = b"ANDROID!" + bytes(range(256)) * 15 + b"\0" * 248
ORIGINAL = bytes(reversed(range(256))) * (SIZE // 256)
VARIABLES = {"product": "g61v71c2k_dfl_tee", "is-userspace": "no", "unlocked": "yes",
             "max-download-size": "0x8000000", "partition-size:recovery": hex(SIZE),
             "partition-type:recovery": "raw data"}

FAKE = r'''
import hashlib, json, os, sys, time
config = json.load(open(os.environ["TITAN_FAKE_FASTBOOT"]))
args = sys.argv[1:]
entry = list(args)
if len(args) == 5 and args[2] == "flash":
    entry.append(hashlib.sha256(open(args[4], "rb").read()).hexdigest())
with open(config["log"], "a") as log:
    log.write(json.dumps(entry) + "\n")
if args == ["--version"]:
    print("fastboot version fake")
    sys.exit(config.get("version_exit", 0))
if args == ["devices"]:
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
    if args[2] == "flash" and len(args) == 5 and args[3] == "recovery":
        time.sleep(config.get("flash_sleep", 0))
        if config.get("mutate_on_flash"):
            os.chmod(args[4], 0o600)
            with open(args[4], "ab") as image:
                image.write(b"x")
        sys.stderr.write("Sending 'recovery'\nWriting 'recovery' OKAY\nFinished. Total time: 0.300s\n")
        sys.exit(config.get("flash_exit", 0))
sys.stderr.write("unexpected invocation\n")
sys.exit(99)
'''


class RecoveryFlashTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name).resolve()
        self.fake = self.root / "fastboot"
        self.fake.write_text("#!" + sys.executable + "\n" + FAKE)
        self.fake.chmod(0o700)
        self.log = self.root / "invocations.jsonl"
        self.probe = self.root / "probe.img"
        self.probe.write_bytes(PROBE)
        self.original = self.root / "recovery.img"
        self.original.write_bytes(ORIGINAL)
        padded = PROBE + bytes(SIZE - len(PROBE))
        profiles = {
            "rescue-probe": {"source_bytes": len(PROBE), "source_sha256": hashlib.sha256(PROBE).hexdigest(),
                             "sha256": hashlib.sha256(padded).hexdigest()},
            "original-recovery": {"source_bytes": SIZE, "source_sha256": hashlib.sha256(ORIGINAL).hexdigest(),
                                  "sha256": hashlib.sha256(ORIGINAL).hexdigest()},
        }
        for patch in (mock.patch.dict(os.environ, {"TITAN_FAKE_FASTBOOT": str(self.root / "config.json")}),
                      mock.patch.dict(tool.PROFILES, profiles, clear=True),
                      mock.patch.object(tool, "PARTITION_BYTES", SIZE)):
            patch.start()
            self.addCleanup(patch.stop)
        self.config = {"log": str(self.log), "serial": SERIAL, "devices": SERIAL + "\tfastboot\n",
                       "vars": dict(VARIABLES)}
        self.configure()

    def configure(self, **changes):
        self.config.update(changes)
        (self.root / "config.json").write_text(json.dumps(self.config))

    def invocations(self):
        return [json.loads(line) for line in self.log.read_text().splitlines()] if self.log.exists() else []

    def run_main(self, name="flash", profile="rescue-probe", image=None, extra=()):
        stdout, stderr = io.StringIO(), io.StringIO()
        image = image or (self.probe if profile == "rescue-probe" else self.original)
        with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            code = tool.main(["--profile", profile, "--image", str(image), "--fastboot", str(self.fake),
                              "--wait", "0", "--output", str(self.root / name), *extra])
        return code, stdout.getvalue(), stderr.getvalue()

    def record(self, name="flash"):
        return json.loads((self.root / name / "trial.json").read_text())

    def test_pinned_profiles_match_the_reviewed_images(self):
        real = load("titan_fastboot_flash_constants", HERE.parent / "flash-recovery.py")
        self.assertEqual(set(real.PROFILES), {"rescue-probe", "original-recovery"})
        self.assertEqual(real.PARTITION_BYTES, 33554432)
        self.assertEqual(real.PARTITION, "recovery")
        # The probe is the second version, not the first-version envelope that
        # the boot helper sent; the original is restored byte for byte, so its
        # source and partition content agree.
        probe = real.PROFILES["rescue-probe"]
        self.assertNotEqual(probe["source_sha256"], boot.PROFILES["rescue-probe"]["sha256"])
        self.assertLess(probe["source_bytes"], real.PARTITION_BYTES)
        self.assertRegex(probe["sha256"], "^[0-9a-f]{64}$")
        original = real.PROFILES["original-recovery"]
        self.assertEqual((original["source_bytes"], original["source_sha256"]),
                         (33554432, original["sha256"]))
        self.assertEqual(original["sha256"], "4dd1c1f75cff6e8ec2d4606020f4c790ad3dc10545acc4ea0a11207d2d36be6d")

    def test_probe_is_padded_and_flashed_only_to_recovery_after_identity_queries(self):
        code, stdout, stderr = self.run_main()
        self.assertEqual(code, 0, stderr)
        copy = self.root / "flash" / "image.img"
        padded = PROBE + bytes(SIZE - len(PROBE))
        self.assertEqual(copy.read_bytes(), padded)
        self.assertEqual(stat.S_IMODE(copy.stat().st_mode), 0o400)
        expected = [["--version"], ["devices"]] + [["-s", SERIAL, "getvar", name] for name in tool.IDENTITY]
        expected.append(["-s", SERIAL, "flash", "recovery", str(copy), hashlib.sha256(padded).hexdigest()])
        self.assertEqual(self.invocations(), expected)
        saved = self.record()
        self.assertEqual((saved["format"], saved["status"], saved["profile"], saved["partition"]),
                         ("titan-fastboot-flash-recovery-v1", "complete", "rescue-probe", "recovery"))
        self.assertEqual(saved["image_after_flash"], {"bytes": SIZE, "sha256": hashlib.sha256(padded).hexdigest()})
        self.assertEqual(saved["device_serial_private"], SERIAL)
        self.assertNotIn(SERIAL, json.dumps(saved["steps"][2:]) + stdout + stderr)
        self.assertIn("verify the partition from Ubuntu Touch", stdout)

    def test_original_is_restored_byte_for_byte(self):
        code, _, stderr = self.run_main("restore", profile="original-recovery")
        self.assertEqual(code, 0, stderr)
        self.assertEqual((self.root / "restore" / "image.img").read_bytes(), ORIGINAL)
        self.assertEqual(self.invocations()[-1][2:5], ["flash", "recovery", str(self.root / "restore" / "image.img")])

    def test_wrong_or_unsafe_images_are_refused_before_fastboot_runs(self):
        cases = {"content": PROBE[:-1] + b"x", "short": PROBE[:-1], "long": PROBE + b"\0",
                 "original-as-probe": ORIGINAL}
        for name, data in cases.items():
            with self.subTest(case=name):
                source = self.root / ("source-" + name)
                source.write_bytes(data)
                code, _, stderr = self.run_main("image-" + name, image=source)
                self.assertEqual(code, 1)
                self.assertIn("nothing was sent", stderr)
                self.assertFalse((self.root / ("image-" + name) / "image.img").exists())
        code, _, stderr = self.run_main("probe-as-original", profile="original-recovery", image=self.probe)
        self.assertEqual(code, 1)
        link = self.root / "link.img"
        link.symlink_to(self.probe)
        directory = self.root / "directory.img"
        directory.mkdir()
        for name, path in (("symlink", link), ("directory", directory), ("relative", Path("probe.img"))):
            with self.subTest(case=name):
                code, _, stderr = self.run_main("path-" + name, image=path)
                self.assertEqual(code, 1)
                if name == "relative":
                    self.assertIn("absolute", stderr)
        self.assertEqual(self.invocations(), [])

    def test_identity_mismatch_writes_nothing(self):
        cases = {"product": ({"product": "other"}, "'product'"),
                 "product-extended": ({"product": "g61v71c2k_dfl_tee-x"}, "'product'"),
                 "userspace": ({"is-userspace": "yes"}, "'is-userspace'"),
                 "locked": ({"unlocked": "no"}, "'unlocked'"),
                 "type": ({"partition-type:recovery": "ext4"}, "'partition-type:recovery'"),
                 "size": ({"partition-size:recovery": hex(SIZE * 2)}, "size differs"),
                 "size-smaller": ({"partition-size:recovery": hex(SIZE // 2)}, "size differs"),
                 "size-missing": ({"partition-size:recovery": None}, "'partition-size:recovery'"),
                 "download-small": ({"max-download-size": hex(SIZE - 1)}, "exceeds"),
                 "download-decimal": ({"max-download-size": str(SIZE - 1)}, "exceeds"),
                 "download-exact": ({"max-download-size": str(SIZE)}, None),
                 "download-unparsable": ({"max-download-size": "lots"}, "'max-download-size'")}
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
                self.assertFalse(any("flash" in call for call in self.invocations()))
                saved = self.record("identity-" + name)
                self.assertEqual(saved["status"], "incomplete")
                self.assertIn(message, saved["error"])
        self.configure(vars=dict(VARIABLES))

    def test_hung_query_failing_version_or_device_listing_writes_nothing(self):
        self.configure(getvar_sleep={"partition-type:recovery": 5})
        with mock.patch.object(tool.trial, "COMMAND_TIMEOUT", 1.0):
            code, _, stderr = self.run_main("hung")
        self.assertEqual(code, 1)
        self.assertIn("did not finish", stderr)
        self.configure(getvar_sleep={}, version_exit=1)
        code, _, _ = self.run_main("version")
        self.assertEqual(code, 1)
        self.configure(version_exit=0)
        for name, listing in {"none": "", "two": SERIAL + "\tfastboot\nOTHER\tfastboot\n",
                              "state": SERIAL + "\trecovery\n"}.items():
            with self.subTest(case=name):
                self.configure(devices=listing)
                code, _, _ = self.run_main("listing-" + name)
                self.assertEqual(code, 1)
        self.assertFalse(any("flash" in call for call in self.invocations()))

    def test_copy_changed_before_or_during_the_write_is_detected(self):
        real = tool.trial.run_bounded

        def tamper(command, *args, **kwargs):
            if command[-2:] == ["getvar", "partition-type:recovery"]:
                copy = self.root / "tamper" / "image.img"
                copy.chmod(0o600)
                with copy.open("ab") as stream:
                    stream.write(b"z")
            return real(command, *args, **kwargs)

        with mock.patch.object(tool.trial, "run_bounded", side_effect=tamper):
            code, _, stderr = self.run_main("tamper")
        self.assertEqual(code, 1)
        self.assertIn("changed; nothing was sent", stderr)
        self.assertFalse(any("flash" in call for call in self.invocations()))
        self.configure(mutate_on_flash=True)
        code, _, stderr = self.run_main("during")
        self.assertEqual(code, 1)
        self.assertIn("what was written is unknown", stderr)
        self.assertEqual(self.record("during")["image_after_flash"]["bytes"], SIZE + 1)

    def test_failed_or_hung_flash_is_reported_as_possibly_partial(self):
        self.configure(flash_exit=1)
        code, _, stderr = self.run_main("failed")
        self.assertEqual(code, 1)
        self.assertIn("partly written", stderr)
        self.assertNotIn(SERIAL, stderr)
        self.configure(flash_exit=0, flash_sleep=5)
        with mock.patch.object(tool, "FLASH_TIMEOUT", 1.0):
            code, _, _ = self.run_main("slow")
        self.assertEqual(code, 1)
        saved = self.record("slow")
        self.assertEqual((saved["status"], saved["steps"][-1]["status"]), ("incomplete", "timeout"))

    def test_command_line_rejects_unreviewed_profiles_and_options(self):
        with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
            tool.main(["--profile", "installed-boot", "--image", str(self.probe), "--output", str(self.root / "x")])
        with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
            tool.main(["--profile", "rescue-probe", "--partition", "boot", "--image", str(self.probe),
                       "--output", str(self.root / "y")])
        for extra, name in ((["--wait", "601"], "wait"), (["--fastboot", "fastboot"], "relative")):
            with self.subTest(case=name):
                with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
                    code = tool.main(["--profile", "rescue-probe", "--image", str(self.probe),
                                      "--output", str(self.root / ("option-" + name)), "--fastboot", str(self.fake),
                                      *extra])
                self.assertEqual(code, 1)
        (self.root / "existing").mkdir()
        self.assertEqual(self.run_main("existing")[0], 1)
        (self.root / "checkout" / ".jj").mkdir(parents=True)
        self.assertEqual(self.run_main("checkout/nested")[0], 1)
        self.assertEqual(self.invocations(), [])


if __name__ == "__main__":
    unittest.main()
