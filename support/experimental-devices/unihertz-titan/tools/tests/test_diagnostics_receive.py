"""Synthetic tests of the diagnostics splitter; no phone or port."""

import contextlib
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
tool = load("titan_diag_receive_test", HERE.parent / "receive-diagnostics.py")


def stream(overrides=None, trailer=b"end\n"):
    contents = {"cmdline": b"console=ttyS0 marker=1\n", "kmsg": b"6,1,0,-;Linux version test\n",
                "fdt": None, "bindings": 13, "interrupts": b"  1: 0 GICv3\n", "cpuinfo": b"processor : 0\n",
                "partitions": b"major minor\n", "iomem": b"40000000-bfffffff : System RAM\n"}
    contents.update(overrides or {})
    data = b"TITAN-DIAG v1\n"
    for name, _, _ in tool.SECTIONS:
        value = contents[name]
        if value is None:
            data += f"section {name} missing\n".encode()
        elif isinstance(value, int):
            data += f"section {name} error {value}\n".encode()
        elif isinstance(value, tuple):
            data += f"section {name} {len(value[0])} truncated\n".encode() + value[0]
        else:
            data += f"section {name} {len(value)}\n".encode() + value
    return data + trailer


class SplitTests(unittest.TestCase):
    def test_sections_are_split_privately_with_an_index(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "payload.bin").write_bytes(stream({"kmsg": (b"6,1,0,-;x\n",)}))
            index = tool.split(root / "payload.bin", root / "sections")
            names = [entry["name"] for entry in index["sections"]]
            self.assertEqual(names, [name for name, _, _ in tool.SECTIONS])
            self.assertEqual((root / "sections" / "cmdline.txt").read_bytes(), b"console=ttyS0 marker=1\n")
            fdt = next(entry for entry in index["sections"] if entry["name"] == "fdt")
            self.assertTrue(fdt["missing"])
            self.assertIsNone(fdt["error"])
            self.assertFalse((root / "sections" / "fdt.dtb").exists())
            bindings = next(entry for entry in index["sections"] if entry["name"] == "bindings")
            self.assertEqual((bindings["missing"], bindings["error"]), (False, 13))
            self.assertFalse((root / "sections" / "bindings.txt").exists())
            kmsg = next(entry for entry in index["sections"] if entry["name"] == "kmsg")
            self.assertTrue(kmsg["truncated"])
            self.assertEqual(stat.S_IMODE((root / "sections").stat().st_mode), 0o700)
            for path in (root / "sections").iterdir():
                self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
            self.assertEqual(json.loads((root / "sections" / "index.json").read_text()), index)

    def test_malformed_streams_are_refused(self):
        good = stream()
        cases = {
            "banner": b"TITAN-DIAG v2\n" + good[14:],
            "order": good.replace(b"section cmdline", b"section kmsgxxx", 1),
            "length": re.sub(rb"section iomem [0-9]+", b"section iomem 99", good),
            "limit": stream({"cmdline": b"x" * 4097}),
            "trailer": stream(trailer=b"end\nextra"),
            "missing-trailer": stream(trailer=b""),
            "leading-zero": re.sub(rb"section partitions ([0-9]+)", rb"section partitions 0\1", good),
            "error-range": good.replace(b"section bindings error 13", b"section bindings error 40960"),
            "error-with-body": good.replace(b"section bindings error 13\n", b"section bindings error 13\nx"),
        }
        for name, data in cases.items():
            with self.subTest(case=name), self.assertRaises(tool.DiagnosticsError):
                tool.parse(data)

    def test_table_matches_the_producer(self):
        source = Path(os.environ.get("TITAN_DIAG_PRODUCER_SOURCE") or HERE.parent.parent / "diag" / "producer.c").read_text()
        compiled = re.findall(r'\{ "([a-z]+)", "([^"]+)", ([^,]+), SOURCE_[A-Z]+ \}', source)
        self.assertEqual([name for name, _, _ in compiled], [name for name, _, _ in tool.SECTIONS])
        limits = {"4096": 4096, "KMSG_LIMIT": 4 << 20, "2U << 20": 2 << 20, "256U << 10": 256 << 10, "64U << 10": 64 << 10}
        self.assertEqual([limits[limit] for _, _, limit in compiled], [limit for _, limit, _ in tool.SECTIONS])


class CommandTests(unittest.TestCase):
    def test_flow_waits_receives_and_splits(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            listener = mock.Mock()
            listener.prepare_output.side_effect = lambda path: (os.mkdir(path, 0o700), Path(path))[1]
            listener.wait_for_port.return_value = "/dev/cu.usbmodem-diag"
            receiver = mock.Mock()
            calls = []

            def receive(arguments):
                calls.append(arguments)
                (root / "out" / "transfer").mkdir()
                (root / "out" / "transfer" / "payload.bin").write_bytes(stream())
                return 0

            receiver.main.side_effect = receive
            modules = {"read-probe-report.py": listener, "receive.py": receiver}
            with mock.patch.object(tool, "load", side_effect=lambda name, filename, directory=None: modules[filename]), \
                    contextlib.redirect_stdout(io.StringIO()) as stdout:
                self.assertEqual(tool.main(["--output", str(root / "out")]), 0)
            self.assertEqual(calls[0][:4], ["--tty", "/dev/cu.usbmodem-diag", "--label", "titan-diagnostics"])
            self.assertIn("fdt: missing", stdout.getvalue())
            self.assertIn("bindings: read error 13", stdout.getvalue())
            receiver.main.side_effect = lambda arguments: 1
            with mock.patch.object(tool, "load", side_effect=lambda name, filename, directory=None: modules[filename]), \
                    contextlib.redirect_stderr(io.StringIO()) as stderr:
                self.assertEqual(tool.main(["--output", str(root / "second")]), 1)
            self.assertIn("did not complete", stderr.getvalue())

    def test_option_ranges_are_enforced(self):
        for extra in (["--wait", "601"], ["--timeout", "0"], ["--timeout", "901"]):
            with self.subTest(extra=extra), tempfile.TemporaryDirectory() as temporary, \
                    contextlib.redirect_stderr(io.StringIO()):
                self.assertEqual(tool.main(["--output", str(Path(temporary) / "out"), *extra]), 1)


if __name__ == "__main__":
    unittest.main()
