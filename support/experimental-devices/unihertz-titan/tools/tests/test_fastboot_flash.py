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
             "max-download-size": "0x8000000", "partition-size:recovery": format(SIZE, "x"),
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

    def test_identity_accepts_the_values_this_bootloader_reported(self):
        # Recorded on 2026-10-15: bare-hex partition size, prefixed download limit.
        real = load("titan_fastboot_flash_identity", HERE.parent / "flash-recovery.py")
        real.check_identity({"product": "g61v71c2k_dfl_tee", "is-userspace": "no", "unlocked": "yes",
                             "max-download-size": "0x8000000", "partition-size:recovery": "2000000",
                             "partition-type:recovery": "raw data"})

    def test_pinned_profiles_match_the_reviewed_images(self):
        real = load("titan_fastboot_flash_constants", HERE.parent / "flash-recovery.py")
        self.assertEqual(set(real.PROFILES), {"rescue-probe", "repo-kernel-probe", "native-probe", "native-diag",
                                              "ram-nixos", "ram-nixos-2", "ram-nixos-3", "ram-nixos-4",
                                              "ram-nixos-5", "ram-nixos-6", "ram-nixos-7", "ram-nixos-8",
                                              "ram-nixos-9", "control-acquisition", "original-recovery"})
        self.assertEqual(real.PARTITION_BYTES, 33554432)
        self.assertEqual(real.PARTITION, "recovery")
        # The probe is the second version, not the first-version envelope that
        # the boot helper sent; the original is restored byte for byte, so its
        # source and partition content agree.
        probe = real.PROFILES["rescue-probe"]
        self.assertNotEqual(probe["source_sha256"], boot.PROFILES["rescue-probe"]["sha256"])
        self.assertLess(probe["source_bytes"], real.PARTITION_BYTES)
        self.assertRegex(probe["sha256"], "^[0-9a-f]{64}$")
        repo = real.PROFILES["repo-kernel-probe"]
        self.assertEqual((repo["source_bytes"], repo["source_sha256"], repo["sha256"]),
                         (9764864, "35fb8d6427b3b32809b48789235158fda460b5d6e6ecbf4ed703ed0f3694050f",
                          "e59463888dae6b7db6c64bbd2c84965d2ffce2a76a5b51a6cb5f0c426a5fc251"))
        native = real.PROFILES["native-probe"]
        self.assertEqual((native["source_bytes"], native["source_sha256"], native["sha256"]),
                         (15712256, "5945dad1ae4041224136a184e49f07abffdef14c63d3797cf43cb9191985da88",
                          "35a45a98f06d1a5fca462a6f2540e370189a26346ec727b892e9776ca2ba63b3"))
        # Header page plus page-padded kernel (15585590), modern probe (65731),
        # overlay table (5765) and DTB table (47337), as built in Nix.
        pages = lambda size: size + (-size) % 2048
        self.assertEqual(native["source_bytes"], 2048 + pages(15585590) + pages(65731) + pages(5765) + pages(47337))
        diag = real.PROFILES["native-diag"]
        self.assertEqual((diag["source_bytes"], diag["source_sha256"], diag["sha256"]),
                         (17606656, "8a58da6ccf326fb6c8432e18a9d5c57b2a9c4b3bfcf44909a93df4c01f029bde",
                          "5a55f9d7a54c9f5bb757b32955f2488909457a042ba42509182fcacb7ec7c6ee"))
        # The same kernel, overlay and DTB tables with the diagnostic ramdisk (1960531).
        self.assertEqual(diag["source_bytes"], 2048 + pages(15585590) + pages(1960531) + pages(5765) + pages(47337))
        ram = real.PROFILES["ram-nixos"]
        self.assertEqual((ram["source_bytes"], ram["source_sha256"], ram["sha256"]),
                         (16510976, "aa1b6751f995c3a201bf2737a3a0ad656b4206d1986ba489e49a8da31c74222a",
                          "b05b933d10f17a927e6d8bd3e132d20a3d40cb12f24cc836a50a1397d2d8d240"))
        # The same kernel and overlay, the stage 0 ramdisk (864739) and the
        # DTB table with the eMMC host disabled (47341).
        self.assertEqual(ram["source_bytes"], 2048 + pages(15585590) + pages(864739) + pages(5765) + pages(47341))
        ram2 = real.PROFILES["ram-nixos-2"]
        self.assertEqual((ram2["source_bytes"], ram2["source_sha256"], ram2["sha256"]),
                         (16510976, "31a5f6d19d2df8cf3bd316a264d52e3d709fa25cba74d5de3df6e0a45fb046d8",
                          "4cb637dff94093043249793f7d703b360a8a572817dd8eafdcf01b43a8d67f52"))
        # The working-environment kernel (15587110), its stage 0 (864753) and
        # the same overlay and DTB tables.
        self.assertEqual(ram2["source_bytes"], 2048 + pages(15587110) + pages(864753) + pages(5765) + pages(47341))
        ram3 = real.PROFILES["ram-nixos-3"]
        self.assertEqual((ram3["source_bytes"], ram3["source_sha256"], ram3["sha256"]),
                         (16510976, "c818ff886df7ce9558ed559edf5c82dc4b98f30e0a476e1ca27293084c4bead6",
                          "1b586f60e6a0cfdc23e748d77a622614bdba6a0447bcbeb7cdda2b48019f505f"))
        # Only the command line differs from ram-nixos-2, so the layout is the same.
        self.assertEqual(ram3["source_bytes"], ram2["source_bytes"])
        ram4 = real.PROFILES["ram-nixos-4"]
        self.assertEqual((ram4["source_bytes"], ram4["source_sha256"], ram4["sha256"]),
                         (16510976, "584a3bc455a37e66052d50d52c1f4e9069343354e8552ccf95994e19ac5b0b5e",
                          "38fe2e1a3693189ecb65ec62d7f0308ea3d9fcceb150251f00106921916af59a"))
        ram5 = real.PROFILES["ram-nixos-5"]
        self.assertEqual((ram5["source_bytes"], ram5["source_sha256"], ram5["sha256"]),
                         (16513024, "40097d4eb20eb38956b83d58a60c717a5678161a8e133e87a791efcb0b177476",
                          "13236a69e548cf4c84199e9d8d02bb236172c9d40239c6ad2c81c4172031bfe9"))
        ram6 = real.PROFILES["ram-nixos-6"]
        self.assertEqual((ram6["source_bytes"], ram6["source_sha256"], ram6["sha256"]),
                         (16513024, "5a4ad5f0aa2d2789d565d7d0a5dfe87452082cbed3e67a94094b75f475decc69",
                          "73bd254c8a62d5708191d93d2491a32750b1ef6e8c0ab00e84478bcdde4fb9af"))
        ram7 = real.PROFILES["ram-nixos-7"]
        self.assertEqual((ram7["source_bytes"], ram7["source_sha256"], ram7["sha256"]),
                         (16513024, "46fb6680f7a8561bf73d0d4074a42c5d821c57dc2859b44aedb8e589727dc5de",
                          "8cd3908218e9b99946ff2b8acb2021bfbea1226f346bcd22f2cd551c5dc30192"))
        ram8 = real.PROFILES["ram-nixos-8"]
        self.assertEqual((ram8["source_bytes"], ram8["source_sha256"], ram8["sha256"]),
                         (16513024, "16dd05a5a0cfc0c0436f121a7d13967fb87f24799334225c4ad9e5a4ec31f3d7",
                          "07070c4d5bf2bd2bb7867ecdfd8313b20c67c57f2126eb107608fcb2fe54ec1d"))
        ram9 = real.PROFILES["ram-nixos-9"]
        self.assertEqual((ram9["source_bytes"], ram9["source_sha256"], ram9["sha256"]),
                         (16513024, "a4b76fcfb55e6b25eb14ceba5da39c8d00f74002440bb1f9645a1a6fb04ec8d5",
                          "7bca74ec3a4348744487060fea451062648e5d3fe815a3864dc9da96d8481dab"))
        control = real.PROFILES["control-acquisition"]
        self.assertEqual((control["source_bytes"], control["source_sha256"], control["sha256"]),
                         (13475840, "41fd9c6bfb7f34f2351678eb52337ac6320672739d3109b0e8e0334b89d87b65",
                          "6729b1463f208f0ac73d3b950e3f8c3599f3343f99ce0addad4d5272ba421155"))
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
                 "size": ({"partition-size:recovery": format(SIZE * 2, "x")}, "size differs"),
                 "size-smaller": ({"partition-size:recovery": format(SIZE // 2, "x")}, "size differs"),
                 # Sizes are hexadecimal: the decimal spelling is a different size.
                 "size-decimal": ({"partition-size:recovery": str(SIZE)}, "size differs"),
                 "size-prefixed": ({"partition-size:recovery": hex(SIZE)}, None),
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
