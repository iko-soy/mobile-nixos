#!/usr/bin/env python3
"""Regression checks for newline-delimited rescue VM console markers."""

import argparse
import importlib.util
import unittest


class MarkerTests(unittest.TestCase):
    def test_all_split_points_wait_for_newline(self):
        for marker in ("TITAN_RESCUE_VM_PASS", "TITAN_RESCUE_FAILED vm-test-returned"):
            for ending in (b"\n", b"\r\n"):
                complete = marker.encode("ascii") + ending
                for split in range(len(complete)):
                    with self.subTest(marker=marker, ending=ending, split=split):
                        self.assertFalse(self.harness.has_marker(complete[:split], marker))
                        if marker.startswith("TITAN_RESCUE_FAILED"):
                            self.assertFalse(self.harness.has_marker(complete[:split], "TITAN_RESCUE_FAILED"))
                self.assertTrue(self.harness.has_marker(complete, marker))

    def test_complete_line_survives_trailing_fragment(self):
        prior = b"TITAN_RESCUE_VM_FAIL sentinel-bytes-mismatch\n"
        incomplete = prior + b"TITAN_RESCUE_FAILED "
        self.assertTrue(self.harness.has_marker(incomplete, "TITAN_RESCUE_VM_FAIL sentinel-bytes-mismatch"))
        self.assertFalse(self.harness.has_marker(incomplete, "TITAN_RESCUE_FAILED"))
        completed = incomplete + b"vm-test-returned\n"
        self.assertTrue(self.harness.has_marker(completed, "TITAN_RESCUE_FAILED"))
        self.assertTrue(self.harness.has_marker(completed, "TITAN_RESCUE_FAILED vm-test-returned"))

    def test_distinct_markers_and_reasons_do_not_match(self):
        for record in (b"TITAN_RESCUE_FAILED_OTHER reason\n", b"prefix TITAN_RESCUE_FAILED reason\n",
                       b"TITAN_RESCUE_VM_FAIL reason\n"):
            with self.subTest(record=record):
                self.assertFalse(self.harness.has_marker(record, "TITAN_RESCUE_FAILED"))
        self.assertTrue(self.harness.has_marker(b"TITAN_RESCUE_FAILED other-reason\n", "TITAN_RESCUE_FAILED"))
        self.assertFalse(self.harness.has_marker(b"TITAN_RESCUE_FAILED other-reason\n",
                                                "TITAN_RESCUE_FAILED vm-test-returned"))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("harness", help="Path to the exact vm-check.py under test")
    args = parser.parse_args()
    spec = importlib.util.spec_from_file_location("rescue_vm_harness", args.harness)
    MarkerTests.harness = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(MarkerTests.harness)
    unittest.main(argv=[__file__], verbosity=2)
