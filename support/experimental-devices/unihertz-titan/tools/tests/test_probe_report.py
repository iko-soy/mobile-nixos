"""Synthetic probe-report reader tests; a pseudo-terminal stands in for the phone."""

import importlib.util
import json
import os
from pathlib import Path
import stat
import tempfile
import threading
import time
import unittest
from unittest import mock


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


HERE = Path(__file__).resolve().parent
tool = load("titan_probe_report_test", HERE.parent / "read-probe-report.py")


def report(sequence, uptime, deadline=160, kernel="4.14.141+"):
    return (f"TITAN_PROBE v1 seq={sequence} uptime={uptime} deadline={deadline} "
            f"kernel={kernel} storage=guarded usb=bound\n").encode("ascii")


class ProbeReportTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name).resolve()
        self.master, slave = os.openpty()
        self.port = os.ttyname(slave)
        os.close(slave)
        self.addCleanup(os.close, self.master)

    def feed(self, data, delay=0.3):
        def writer():
            time.sleep(delay)
            os.write(self.master, data)
        thread = threading.Thread(target=writer)
        thread.start()
        self.addCleanup(thread.join)

    def run_reader(self, name, data, wanted=3, seconds=3.0):
        output = tool.prepare_output(str(self.root / name))
        self.feed(data)
        return output, tool.run(output, 0, seconds, wanted, port=self.port)

    def saved(self, output):
        return json.loads((output / "report.json").read_text())

    def test_valid_lines_are_parsed_saved_privately_and_nothing_is_sent(self):
        data = b"\r\n" + report(1, 20) + report(2, 22) + b"TITAN_PROBE v1 seq=3 uptime=24 "
        data += b"deadline=160 kernel=4.14.141+ storage=guarded usb=bound\r\n"
        # Keep a slave descriptor open: closing the last one would discard any
        # bytes the reader wrote before the master side could see them.
        holder = os.open(self.port, os.O_RDWR | os.O_NOCTTY)
        self.addCleanup(os.close, holder)
        output, record = self.run_reader("valid", data)
        self.assertEqual(record["status"], "complete")
        self.assertEqual([line["seq"] for line in record["lines"]], [1, 2, 3])
        self.assertEqual(record["lines"][0], {"seq": 1, "uptime": 20, "deadline": 160, "kernel": "4.14.141+"})
        # Nothing reached the phone side: the master has no bytes to read.
        os.set_blocking(self.master, False)
        try:
            sent = os.read(self.master, 4096)
        except BlockingIOError:
            sent = b""
        self.assertEqual(sent, b"")
        self.assertEqual(self.saved(output), record)
        self.assertEqual(stat.S_IMODE(output.stat().st_mode), 0o700)
        self.assertEqual(stat.S_IMODE((output / "report.json").stat().st_mode), 0o600)

    def test_port_is_opened_read_only(self):
        with mock.patch.object(tool.os, "open", wraps=os.open) as opened:
            output, _ = self.run_reader("read-only", report(1, 20) + report(2, 22) + report(3, 24))
        flags = [call.args[1] for call in opened.call_args_list if call.args[0] == self.port]
        self.assertEqual(len(flags), 1)
        self.assertEqual(flags[0] & os.O_ACCMODE, os.O_RDONLY)

    def test_malformed_or_inconsistent_reports_are_refused(self):
        cases = {
            "only-malformed": b"TITAN_PROBE v1 seq=2 uptime=22 deadline=160 kernel=x storage=guarded usb=bound extra=1\n" * 4,
            "deadline-changes": report(1, 20) + report(2, 22, deadline=170) + report(3, 24),
            "sequence-repeats": report(1, 20) + report(1, 22) + report(2, 24),
            "after-deadline": report(1, 160) + report(2, 162) + report(3, 164),
            "kernel-changes": report(1, 20) + report(2, 22, kernel="other") + report(3, 24),
        }
        for name, data in cases.items():
            with self.subTest(case=name):
                output = tool.prepare_output(str(self.root / name))
                self.feed(data, delay=0.1)
                with self.assertRaises(tool.ReportError):
                    tool.run(output, 0, 2.0, 3, port=self.port)
                self.assertEqual(self.saved(output)["status"], "incomplete")
                time.sleep(0.2)
                # Drain anything left for the next case.
                fd = tool.open_raw(self.port)
                try:
                    while True:
                        try:
                            if not os.read(fd, 65536):
                                break
                        except BlockingIOError:
                            break
                finally:
                    os.close(fd)

    def test_fragments_are_counted_but_do_not_count_as_lines(self):
        fragment = b"TITAN_PROBE v1 seq=2 upt"
        output, record = self.run_reader("fragment", report(1, 20) + fragment + report(3, 24) + report(4, 26)
                                         + report(5, 28))
        self.assertEqual(record["status"], "complete")
        self.assertEqual(record["rejected_lines"], 1)
        self.assertEqual([line["seq"] for line in record["lines"]], [1, 4, 5])

    def test_too_few_lines_or_unbounded_input_stop_the_reader(self):
        output = tool.prepare_output(str(self.root / "few"))
        self.feed(report(1, 20), delay=0.1)
        with self.assertRaisesRegex(tool.ReportError, "Only 1 of 3"):
            tool.run(output, 0, 1.0, 3, port=self.port)
        output = tool.prepare_output(str(self.root / "long"))
        self.feed(b"x" * 600, delay=0.1)
        with self.assertRaisesRegex(tool.ReportError, "bound"):
            tool.run(output, 0, 2.0, 3, port=self.port)
        output = tool.prepare_output(str(self.root / "flood"))
        self.feed(report(1, 20) * 40, delay=0.1)
        with mock.patch.object(tool, "BYTE_LIMIT", 1000), self.assertRaisesRegex(tool.ReportError, "more than"):
            tool.run(output, 0, 2.0, 20, port=self.port)

    def device(self, port, vendor="Titan rescue experiment", product="Titan read-only acquisition",
               serial="TITAN-RESCUE-EXPERIMENT-0001", ids=(4617, 5), indent=""):
        return (f'{indent}+-o {product}@01100000  <class IOUSBHostDevice, id 0x1>\n'
                f'{indent}    "idVendor" = {ids[0]}\n{indent}    "idProduct" = {ids[1]}\n'
                f'{indent}    "USB Vendor Name" = "{vendor}"\n{indent}    "USB Product Name" = "{product}"\n'
                f'{indent}    "USB Serial Number" = "{serial}"\n'
                f'{indent}  +-o AppleUSBACMData  <class AppleUSBACMData, id 0x2>\n'
                f'{indent}      "IOCalloutDevice" = "{port}"\n')

    def test_only_the_probe_device_is_selected(self):
        # Ubuntu Touch's own gadget shares 1209:0005; the MediaTek preloader
        # port appears briefly on every reset. Neither may be opened.
        ubuntu = self.device("/dev/cu.usbmodem101", vendor="A-gold", product="Titan", serial="TITA0000")
        preloader = self.device("/dev/cu.usbmodem102", vendor="MediaTek", product="MT65xx Preloader",
                                serial="", ids=(3725, 8192))
        probe = self.device("/dev/cu.usbmodem103")
        self.assertEqual(tool.probe_ports(ubuntu + preloader), [])
        self.assertEqual(tool.probe_ports(ubuntu + probe + preloader), [["/dev/cu.usbmodem103"]])
        with mock.patch.object(tool.os.path, "exists", return_value=True):
            snapshots = iter([ubuntu, ubuntu + preloader, ubuntu + probe])
            self.assertEqual(tool.wait_for_port(3, poll=0.01, registry=lambda: next(snapshots)), "/dev/cu.usbmodem103")
            with self.assertRaisesRegex(tool.ReportError, "More than one"):
                tool.wait_for_port(1, poll=0.01, registry=lambda: probe + self.device("/dev/cu.usbmodem104"))
            with self.assertRaisesRegex(tool.ReportError, "No probe device"):
                tool.wait_for_port(0.05, poll=0.01, registry=lambda: ubuntu + preloader)
        for change in ({"vendor": "Titan rescue"}, {"serial": "TITAN-RESCUE-EXPERIMENT-0002"},
                       {"product": "Titan"}, {"ids": (4617, 4)}):
            with self.subTest(change=change):
                self.assertEqual(tool.probe_ports(self.device("/dev/cu.usbmodem105", **change)), [])

    def test_probe_behind_a_hub_is_found_and_ports_stay_with_their_device(self):
        hub = ('+-o USB2.0 Hub@01100000  <class IOUSBHostDevice, id 0x9>\n'
               '    "idVendor" = 1507\n    "idProduct" = 1552\n    "USB Product Name" = "USB2.0 Hub"\n')
        nested = hub + self.device("/dev/cu.usbmodem201", indent="  | ") + \
            self.device("/dev/cu.usbmodem202", vendor="A-gold", product="Titan", serial="TITA0000", indent="  | ")
        self.assertEqual(tool.probe_ports(nested), [["/dev/cu.usbmodem201"]])

    def test_output_and_option_ranges_are_enforced(self):
        with self.assertRaises(tool.ReportError):
            tool.prepare_output("relative/output")
        (self.root / "checkout" / ".jj").mkdir(parents=True)
        with self.assertRaises(tool.ReportError):
            tool.prepare_output(str(self.root / "checkout" / "nested"))
        (self.root / "existing").mkdir()
        with self.assertRaises(FileExistsError):
            tool.prepare_output(str(self.root / "existing"))
        for extra in (["--wait", "601"], ["--seconds", "0"], ["--lines", "21"]):
            with self.subTest(extra=extra), mock.patch("sys.stderr"):
                self.assertEqual(tool.main(["--output", str(self.root / "cli"), *extra]), 1)
        self.assertFalse((self.root / "cli").exists())


if __name__ == "__main__":
    unittest.main()
