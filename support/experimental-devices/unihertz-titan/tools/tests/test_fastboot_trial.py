"""Synthetic fastboot trial-helper tests; a fake executable stands in for fastboot."""

import contextlib
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
tool = load("titan_fastboot_trial_test", HERE.parent / "observe-fastboot.py")
SERIAL = "FAKE0123"

FAKE = r'''
import json, os, sys, time
config = json.load(open(os.environ["TITAN_FAKE_FASTBOOT"]))
args = sys.argv[1:]
with open(config["log"], "a") as log:
    log.write(json.dumps(args) + "\n")
if args == ["--version"]:
    print("fastboot version fake")
    sys.exit(0)
if args == ["devices"]:
    with open(config["counter"], "a+") as counter:
        counter.seek(0)
        calls = len(counter.read())
        counter.write(".")
    if calls >= config.get("devices_after", 0):
        sys.stdout.write(config.get("devices", ""))
    sys.exit(0)
if len(args) >= 3 and args[0] == "-s" and args[1] == config["serial"]:
    rest = " ".join(args[2:])
    time.sleep(config.get("sleep", {}).get(rest, 0))
    if rest in config.get("spew", []):
        sys.stderr.write("x" * 200000)
        sys.exit(0)
    if args[2] == "getvar" and len(args) == 4:
        value = config.get("vars", {}).get(args[3])
        if value is None:
            sys.stderr.write("getvar:%s FAILED (remote: 'unknown variable')\n" % args[3])
            sys.exit(1)
        sys.stderr.write("%s: %s\nFinished. Total time: 0.001s\n" % (args[3], value))
        sys.exit(0)
    if args[2:] in (["reboot"], ["continue"]):
        sys.stderr.write("Finished. Total time: 0.050s\n")
        sys.exit(config.get("return_exit", 0))
sys.stderr.write("unexpected invocation\n")
sys.exit(99)
'''


class FastbootTrialTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name).resolve()
        self.fake = self.root / "fastboot"
        self.fake.write_text("#!" + sys.executable + "\n" + FAKE)
        self.fake.chmod(0o700)
        self.log = self.root / "invocations.jsonl"
        self.config = {"log": str(self.log), "counter": str(self.root / "counter"),
                       "serial": SERIAL, "devices": SERIAL + "\tfastboot\n",
                       "vars": {"product": "titan", "unlocked": "yes", "is-userspace": "no",
                                "partition-size:boot": "0x2000000"}}
        self.environment = mock.patch.dict(os.environ, {"TITAN_FAKE_FASTBOOT": str(self.root / "config.json")})
        self.environment.start()
        self.addCleanup(self.environment.stop)
        self.addCleanup(self.temporary.cleanup)

    def configure(self, **changes):
        self.config.update(changes)
        (self.root / "config.json").write_text(json.dumps(self.config))

    def invocations(self):
        return [json.loads(line) for line in self.log.read_text().splitlines()]

    def output(self):
        return tool.prepare_output(str(self.root / "trial"))

    def record(self):
        return json.loads((self.root / "trial" / "trial.json").read_text())

    def test_observe_sends_only_the_fixed_getvar_allowlist(self):
        self.configure()
        record = tool.run_trial([str(self.fake)], self.output(), "observe", wait=0)
        expected = [["--version"], ["devices"]] + [["-s", SERIAL, "getvar", name] for name in tool.VARIABLES]
        self.assertEqual(self.invocations(), expected)
        self.assertEqual(record["status"], "complete")
        self.assertEqual(record["variables"]["product"], "titan")
        self.assertEqual(record["variables"]["partition-size:boot"], "0x2000000")
        self.assertIsNone(record["variables"]["secure"])
        saved = self.record()
        self.assertEqual(saved["variables"], record["variables"])
        self.assertNotIn(SERIAL, json.dumps(saved["steps"][2:]))
        self.assertEqual(stat.S_IMODE(os.stat(self.root / "trial").st_mode), 0o700)
        self.assertEqual(stat.S_IMODE(os.stat(self.root / "trial" / "trial.json").st_mode), 0o600)
        self.assertFalse((self.root / "trial" / "trial.json.part").exists())

    def test_return_sends_exactly_the_selected_command(self):
        for command in tool.RETURN_COMMANDS:
            with self.subTest(command=command):
                self.log.unlink(missing_ok=True)
                (self.root / "counter").unlink(missing_ok=True)
                self.configure()
                output = tool.prepare_output(str(self.root / ("return-" + command)))
                record = tool.run_trial([str(self.fake)], output, "return", command, wait=0)
                self.assertEqual(record["status"], "complete")
                self.assertEqual(self.invocations(), [["--version"], ["devices"], ["-s", SERIAL, command]])

    def test_failed_return_command_is_reported_incomplete(self):
        self.configure(return_exit=1)
        with self.assertRaises(tool.TrialError):
            tool.run_trial([str(self.fake)], self.output(), "return", wait=0)
        self.assertEqual(self.record()["status"], "incomplete")

    def test_device_listing_must_name_exactly_one_fastboot_device(self):
        cases = {"two": SERIAL + "\tfastboot\nOTHER\tfastboot\n", "state": SERIAL + "\trecovery\n",
                 "malformed": SERIAL + " fastboot extra\n"}
        for name, listing in cases.items():
            with self.subTest(name=name):
                self.log.unlink(missing_ok=True)
                self.configure(devices=listing)
                output = tool.prepare_output(str(self.root / ("listing-" + name)))
                with self.assertRaises(tool.TrialError):
                    tool.run_trial([str(self.fake)], output, "observe", wait=0)
                self.assertEqual(self.invocations(), [["--version"], ["devices"]])
                saved = json.loads((output / "trial.json").read_text())
                self.assertEqual(saved["status"], "incomplete")
                self.assertIn("error", saved)

    def test_waits_for_a_late_device_and_stops_when_none_appears(self):
        self.configure(devices_after=2)
        record = tool.run_trial([str(self.fake)], self.output(), "observe", wait=5, poll=0.05)
        self.assertEqual(record["status"], "complete")
        self.assertEqual(self.invocations()[1:4], [["devices"]] * 3)
        self.log.unlink()
        self.configure(devices="")
        with self.assertRaises(tool.TrialError):
            tool.run_trial([str(self.fake)], tool.prepare_output(str(self.root / "none")),
                           "observe", wait=0.2, poll=0.05)
        self.assertTrue(all(call == ["devices"] for call in self.invocations()[1:]))

    def test_hung_or_flooding_query_stops_later_queries(self):
        for name, change in {"timeout": {"sleep": {"getvar version-bootloader": 5}},
                             "flood": {"spew": ["getvar version-bootloader"]}}.items():
            with self.subTest(name=name):
                self.log.unlink(missing_ok=True)
                (self.root / "counter").unlink(missing_ok=True)
                self.configure(**change)
                output = tool.prepare_output(str(self.root / ("stop-" + name)))
                with mock.patch.object(tool, "COMMAND_TIMEOUT", 1.0):
                    with self.assertRaises(tool.TrialError):
                        tool.run_trial([str(self.fake)], output, "observe", wait=0)
                calls = self.invocations()
                self.assertEqual(calls[-1], ["-s", SERIAL, "getvar", "version-bootloader"])
                self.assertEqual(len(calls), 4)
                saved = json.loads((output / "trial.json").read_text())
                self.assertEqual(saved["steps"][-1]["status"], "timeout" if name == "timeout" else "output-limit")
                self.config.pop("sleep", None)
                self.config.pop("spew", None)

    def test_output_directory_must_be_new_private_and_outside_checkouts(self):
        with self.assertRaises(tool.TrialError):
            tool.prepare_output("relative/trial")
        (self.root / "existing").mkdir()
        with self.assertRaises(FileExistsError):
            tool.prepare_output(str(self.root / "existing"))
        for marker in (".git", ".jj"):
            with self.subTest(marker=marker):
                checkout = self.root / ("checkout" + marker)
                (checkout / marker).mkdir(parents=True)
                with self.assertRaises(tool.TrialError):
                    tool.prepare_output(str(checkout / "nested-output"))
        with self.assertRaises(FileNotFoundError):
            tool.prepare_output(str(self.root / "missing-parent" / "trial"))

    def test_command_line_keeps_the_serial_private(self):
        self.configure()
        stdout, stderr = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            code = tool.main(["observe", "--fastboot", str(self.fake), "--wait", "0",
                              "--output", str(self.root / "cli")])
        self.assertEqual(code, 0)
        self.assertNotIn(SERIAL, stdout.getvalue() + stderr.getvalue())
        self.assertIn("4 of 15 variables answered", stdout.getvalue())

    def test_command_line_rejects_unreviewed_options(self):
        self.configure()
        cases = (["observe", "--command", "continue"], ["return", "--wait", "601"],
                 ["return", "--fastboot", "fastboot"])
        for extra in cases:
            with self.subTest(extra=extra):
                stderr = io.StringIO()
                with contextlib.redirect_stderr(stderr):
                    code = tool.main(extra + ["--output", str(self.root / ("rejected-" + str(len(extra))))])
                self.assertEqual(code, 1)
        stderr = io.StringIO()
        with contextlib.redirect_stderr(stderr), self.assertRaises(SystemExit):
            tool.main(["return", "--command", "flash", "--output", str(self.root / "flash")])
        self.assertFalse(self.log.exists())


if __name__ == "__main__":
    unittest.main()
