"""Synthetic tests of the control-region splitter and verifier; no phone or port."""

import contextlib
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import re
import stat
import tempfile
import unittest
from unittest import mock


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


HERE = Path(__file__).resolve().parent
tool = load("titan_control_receive_test", HERE.parent / "receive-control-regions.py")
catalog = load("titan_control_receive_catalog", HERE.parent / "verify-backup-catalog.py")
SMALL = (("boot_para", 1, 64, 2, "raw"), ("nvcfg", 6, 66, 4, "ext4"), ("nvram", 25, 70, 3, "raw"),
         ("protect2", 10, 73, 2, "ext4"))


def region_bytes(index, sectors):
    data = bytes((index * 37 + i) % 251 for i in range(sectors * 512))
    return data if index % 2 else data[:512] + bytes(len(data) - 512)


def manifest(regions, contents, states=None, second=None, header=None, tail="end\n"):
    total = sum(sectors * 512 for _, _, _, sectors, _ in regions)
    text = header if header is not None else f"TITAN-CONTROL-REGIONS v1 regions={len(regions)} bytes={total}\n"
    for (label, number, start, sectors, kind), data in zip(regions, contents):
        digest = hashlib.sha256(data).hexdigest()
        state = (states or {}).get(label, "clean" if kind == "ext4" else "-")
        text += (f"region {label} {number} {start} {sectors} {sectors * 512} {digest} "
                 f"{(second or {}).get(label, digest)} {kind} {state}\n")
    return (text + tail).encode("ascii")


class SplitTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name).resolve()
        self.contents = [region_bytes(i, sectors) for i, (_, _, _, sectors, _) in enumerate(SMALL)]

    def payload(self, name="payload.bin", trailer=None):
        path = self.root / name
        path.write_bytes(b"".join(self.contents) + (trailer if trailer is not None else manifest(SMALL, self.contents)))
        return path

    def test_regions_are_split_privately_and_verified_against_both_passes(self):
        report = tool.split_and_verify(self.payload(), self.root / "regions", SMALL)
        self.assertTrue(report["all_stable"] and report["all_consistent"])
        for (label, number, start, sectors, kind), data in zip(SMALL, self.contents):
            path = self.root / "regions" / (label + ".img")
            self.assertEqual(path.read_bytes(), data)
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
            entry = report["regions"][label]
            self.assertEqual((entry["sha256"], entry["kind"], entry["start"], entry["bytes"]),
                             (hashlib.sha256(data).hexdigest(), kind, start, sectors * 512))
        self.assertEqual(stat.S_IMODE((self.root / "regions").stat().st_mode), 0o700)
        saved = json.loads((self.root / "regions" / "report.json").read_text())
        self.assertEqual(saved, report)

    def test_unstable_or_unclean_regions_are_kept_but_not_called_consistent(self):
        changed = manifest(SMALL, self.contents, second={"nvram": "0" * 64}, states={"protect2": "orphans-pending"})
        report = tool.split_and_verify(self.payload(trailer=changed), self.root / "regions", SMALL)
        self.assertFalse(report["regions"]["nvram"]["stable"] or report["regions"]["nvram"]["consistent"])
        self.assertTrue(report["regions"]["protect2"]["stable"])
        self.assertFalse(report["regions"]["protect2"]["consistent"])
        self.assertTrue(report["regions"]["boot_para"]["consistent"])
        self.assertFalse(report["all_stable"] or report["all_consistent"])
        self.assertEqual((self.root / "regions" / "nvram.img").read_bytes(), self.contents[2])

    def test_malformed_payloads_and_manifests_are_refused(self):
        good = manifest(SMALL, self.contents)
        lines = good.decode().split("\n")
        cases = {
            "first-pass-mismatch": manifest(SMALL, [b"x" * len(self.contents[0])] + self.contents[1:]),
            "header": manifest(SMALL, self.contents, header="TITAN-CONTROL-REGIONS v2\n"),
            "missing-end": manifest(SMALL, self.contents, tail=""),
            "label": good.replace(b"region nvcfg 6", b"region nvdata 6"),
            "geometry": good.replace(b"region nvram 25 70 3", b"region nvram 25 71 3"),
            "kind": good.replace(b" ext4 clean\nregion nvram", b" raw clean\nregion nvram"),
            "state": manifest(SMALL, self.contents, states={"nvcfg": "repaired"}),
            "raw-state": manifest(SMALL, self.contents, states={"boot_para": "clean"}),
            "digest": good.replace(lines[1].split()[6].encode(), b"Z" * 64, 1),
            "non-ascii": good.replace(b"end", b"\xffnd"),
            "extra-line": good + b"region extra\n",
            "oversized": good + b"#" * tool.MANIFEST_MAX,
        }
        for name, trailer in cases.items():
            with self.subTest(case=name), self.assertRaises(tool.VerificationError):
                tool.split_and_verify(self.payload(name + ".bin", trailer), self.root / ("out-" + name), SMALL)
        truncated = self.root / "truncated.bin"
        truncated.write_bytes(b"".join(self.contents)[:-1])
        with self.assertRaises(tool.VerificationError):
            tool.split_and_verify(truncated, self.root / "out-truncated", SMALL)
        link = self.root / "link.bin"
        link.symlink_to(self.payload())
        with self.assertRaises(tool.VerificationError):
            tool.split_and_verify(link, self.root / "out-link", SMALL)
        (self.root / "existing").mkdir()
        with self.assertRaises(FileExistsError):
            tool.split_and_verify(self.payload("again.bin"), self.root / "existing", SMALL)

    def test_table_agrees_with_the_catalog_layout(self):
        layout = {name: (number, start, sectors) for number, name, start, sectors in catalog.EXPECTED_LAYOUT}
        for label, number, start, sectors, kind in tool.REGIONS:
            self.assertEqual(layout[label], (number, start, sectors))
        self.assertEqual(sum(sectors * 512 for _, _, _, sectors, _ in tool.REGIONS), 771719168)
        self.assertEqual({label for label, *_ in tool.REGIONS},
                         set(catalog.REMAINING_GPT) - {"userdata"})

    def test_table_agrees_with_the_compiled_producer_table(self):
        # Nix supplies the source explicitly; a checkout has it beside tools/.
        source = Path(os.environ.get("TITAN_CONTROL_SOURCE") or HERE.parent.parent / "control" / "producer.c").read_text()
        production = source.split("#else", 1)[1].split("#endif", 1)[0]
        compiled = [(label, int(number), int(start), int(sectors), "ext4" if ext4 == "1" else "raw")
                    for label, number, start, sectors, ext4 in
                    re.findall(r'\{ "([a-z_0-9]+)", (\d+), (\d+), (\d+), ([01]) \}', production)]
        self.assertEqual(tuple(compiled), tool.REGIONS)


class CommandTests(unittest.TestCase):
    def test_flow_waits_for_the_gadget_receives_then_verifies(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            calls = []
            listener = mock.Mock()
            listener.prepare_output.side_effect = lambda path: (os.mkdir(path, 0o700), Path(path))[1]
            listener.wait_for_port.return_value = "/dev/cu.usbmodem-control"
            receiver = mock.Mock()

            def receive(arguments):
                calls.append(arguments)
                (root / "out" / "transfer").mkdir()
                (root / "out" / "transfer" / "payload.bin").write_bytes(b"ignored")
                return 0

            receiver.main.side_effect = receive
            report = {"region_bytes": 1, "regions": {"nvcfg": {"stable": True, "consistent": True, "kind": "ext4",
                                                               "ext4_state": "clean"}}}
            modules = {"read-probe-report.py": listener, "receive.py": receiver}
            with mock.patch.object(tool, "load", side_effect=lambda name, filename, directory=None: modules[filename]), \
                    mock.patch.object(tool, "split_and_verify", return_value=report) as split, \
                    contextlib.redirect_stdout(io.StringIO()) as stdout:
                code = tool.main(["--output", str(root / "out")])
            self.assertEqual(code, 0)
            self.assertEqual(calls[0][:4], ["--tty", "/dev/cu.usbmodem-control", "--label", "control-regions-raw"])
            split.assert_called_once_with(root / "out" / "transfer" / "payload.bin", root / "out" / "regions")
            self.assertIn("1 consistent", stdout.getvalue())
            receiver.main.side_effect = lambda arguments: 1
            with mock.patch.object(tool, "load", side_effect=lambda name, filename, directory=None: modules[filename]), \
                    mock.patch.object(tool, "split_and_verify") as split, \
                    contextlib.redirect_stderr(io.StringIO()) as stderr:
                code = tool.main(["--output", str(root / "second")])
            self.assertEqual(code, 1)
            split.assert_not_called()
            self.assertIn("did not complete", stderr.getvalue())

    def test_option_ranges_are_enforced(self):
        for extra in (["--wait", "601"], ["--timeout", "0"], ["--timeout", "3601"]):
            with self.subTest(extra=extra), tempfile.TemporaryDirectory() as temporary, \
                    contextlib.redirect_stderr(io.StringIO()):
                self.assertEqual(tool.main(["--output", str(Path(temporary) / "out"), *extra]), 1)


if __name__ == "__main__":
    unittest.main()
