"""Verify fixed ARM64 probe arguments with mocks; never issue host raw syscalls."""

import builtins
import contextlib
import ctypes
import errno
import importlib.util
import io
import json
import os
from pathlib import Path
import shlex
import stat
import tempfile
import types
import unittest
from unittest.mock import Mock, mock_open, patch


SCRIPT = Path(__file__).resolve().parents[1] / "probe-kernel-apis.py"
SPEC = importlib.util.spec_from_file_location("kernel_apis", SCRIPT)
apis = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(apis)
# Keep real ABI/layout and mock-syscall checks on every test platform. The host
# wrapper itself must not need this Linux-probe dependency (tested below).
apis.load_ctypes()


class FakeKernel:
    def __init__(self, missing=(), metadata=True):
        self.missing, self.metadata, self.calls = set(missing), metadata, []
        self.libc = types.SimpleNamespace(syscall=Mock(side_effect=self.call))

    def call(self, number, *arguments):
        name = next(name for name, value in apis.SYSCALLS.items() if number.value == value)
        self.calls.append((name, arguments))
        if name in self.missing:
            ctypes.set_errno(errno.ENOSYS)
            return -1
        if name == "statx":
            metadata = ctypes.cast(arguments[-1], ctypes.POINTER(apis.Statx)).contents
            metadata.mask = apis.STATX_BASIC_STATS | (apis.STATX_MNT_ID if self.metadata else 0)
            metadata.attributes_mask = apis.STATX_ATTR_MOUNT_ROOT if self.metadata else 0
            metadata.attributes = apis.STATX_ATTR_MOUNT_ROOT if self.metadata else 0
            metadata.inode = metadata.mount_id = 123456789
            return 0
        if name == "pidfd_open":
            return 77
        if name == "pidfd_send_signal":
            return 0
        if name == "close_range":
            ctypes.set_errno(errno.EINVAL)
            return -1
        if name == "name_to_handle_at":
            handle = ctypes.cast(arguments[2], ctypes.POINTER(apis.FileHandle)).contents
            handle.handle_type = 123456789
            handle.handle[:] = b"private-file-handle".ljust(128, b"x")
            return 0
        if name == "openat2":
            return 78
        raise AssertionError("Unexpected syscall")


def mocked_report(kernel=None):
    kernel = kernel or FakeKernel()
    with patch.object(apis, "check_architecture"), \
            patch.object(apis.ctypes, "CDLL", return_value=kernel.libc), \
            patch.object(apis, "process_policy", return_value={"status": "read", "fields": {"Seccomp": 0, "NoNewPrivs": 0}}), \
            patch.object(apis.os, "getpid", return_value=9999999), \
            patch.object(apis.os, "close") as close:
        report = apis.probe_kernel_apis()
    return report, close


class AbiTests(unittest.TestCase):
    def test_arm64_struct_sizes_and_offsets(self):
        self.assertEqual(ctypes.sizeof(apis.StatxTimestamp), 16)
        self.assertEqual(ctypes.sizeof(apis.Statx), 256)
        self.assertEqual(apis.Statx.mask.offset, 0)
        self.assertEqual(apis.Statx.attributes.offset, 8)
        self.assertEqual(apis.Statx.attributes_mask.offset, 56)
        self.assertEqual(apis.Statx.mount_id.offset, 144)
        self.assertEqual(ctypes.sizeof(apis.FileHandle), 136)
        self.assertEqual(apis.FileHandle.handle.offset, 8)
        self.assertEqual(ctypes.sizeof(apis.OpenHow), 24)
        self.assertEqual(apis.OpenHow.resolve.offset, 16)

    def test_wrong_architecture_stops_before_loading_libc(self):
        for system, machine, byteorder in (("Darwin", "arm64", "little"),
                                           ("Linux", "x86_64", "little"),
                                           ("Linux", "aarch64", "big")):
            with self.subTest(system=system, machine=machine, byteorder=byteorder), \
                    patch.object(apis.platform, "system", return_value=system), \
                    patch.object(apis.platform, "machine", return_value=machine), \
                    patch.object(apis.sys, "byteorder", byteorder), \
                    patch.object(apis.ctypes, "CDLL") as library:
                with self.assertRaisesRegex(apis.ProbeError, "require Linux aarch64"):
                    apis.probe_kernel_apis()
                library.assert_not_called()

    def test_wrong_pointer_or_structure_size_stops_before_loading_libc(self):
        real_sizeof = ctypes.sizeof
        for wrong_type, wrong_size in ((ctypes.c_void_p, 4), (apis.Statx, 128)):
            with self.subTest(wrong_type=wrong_type), \
                    patch.object(apis.platform, "system", return_value="Linux"), \
                    patch.object(apis.platform, "machine", return_value="aarch64"), \
                    patch.object(apis.sys, "byteorder", "little"), \
                    patch.object(apis.ctypes, "sizeof", side_effect=lambda value: wrong_size if value is wrong_type else real_sizeof(value)), \
                    patch.object(apis.ctypes, "CDLL") as library:
                with self.assertRaises(apis.ProbeError):
                    apis.probe_kernel_apis()
                library.assert_not_called()


class SyscallTests(unittest.TestCase):
    def test_only_fixed_nonmutating_arguments_and_owned_descriptors_are_used(self):
        kernel = FakeKernel()
        report, close = mocked_report(kernel)
        self.assertTrue(report["probe_completed"])
        self.assertEqual([name for name, _ in kernel.calls], [
            "statx", "statx", "statx", "pidfd_open", "pidfd_send_signal",
            "close_range", "name_to_handle_at", "openat2"])
        self.assertEqual(apis.SYSCALLS, {"name_to_handle_at": 264, "statx": 291,
                                       "pidfd_send_signal": 424, "pidfd_open": 434,
                                       "close_range": 436, "openat2": 437})
        for (_, arguments), path in zip(kernel.calls[:3], (b"/", b"/proc", b"/sys")):
            self.assertEqual([value.value for value in arguments[:-1]], [-100, path, 0x4800, 0x17FF])
        self.assertEqual([value.value for value in kernel.calls[3][1]], [9999999, 0])
        self.assertEqual([value.value for value in kernel.calls[4][1]], [77, 0, None, 0])
        self.assertEqual([value.value for value in kernel.calls[5][1]], [1, 0, 0])
        handle_arguments = kernel.calls[6][1]
        self.assertEqual([handle_arguments[i].value for i in (0, 1, 4)], [-100, b"/", 0])
        handle = ctypes.cast(handle_arguments[2], ctypes.POINTER(apis.FileHandle)).contents
        self.assertEqual(handle.handle_bytes, 128)
        open_arguments = kernel.calls[7][1]
        self.assertEqual([open_arguments[i].value for i in (0, 1, 3)], [-100, b"/", 24])
        how = ctypes.cast(open_arguments[2], ctypes.POINTER(apis.OpenHow)).contents
        self.assertEqual((how.flags, how.mode, how.resolve), (0x280000, 0, 0))
        self.assertEqual([call.args for call in close.call_args_list], [(77,), (78,)])
        self.assertEqual(kernel.libc.syscall.restype, ctypes.c_long)
        self.assertEqual(kernel.libc.syscall.argtypes, [ctypes.c_long])

    def test_statx_success_without_mount_metadata_is_not_sufficient(self):
        report, _ = mocked_report(FakeKernel(metadata=False))
        for record in report["probes"]["statx"].values():
            self.assertEqual(record["status"], "success")
            self.assertTrue(record["metadata"]["basic_stats_complete"])
            self.assertFalse(record["metadata"]["mount_id_returned"])
            self.assertFalse(record["metadata"]["mount_root_attribute_supported"])
            self.assertIsNone(record["metadata"]["is_mount_root"])
        self.assertIn("statx: 0/3", apis.summary(report))

    def test_unavailable_apis_are_recorded_without_guessing_permission_or_boot_results(self):
        kernel = FakeKernel(missing=apis.SYSCALLS)
        report, close = mocked_report(kernel)
        self.assertTrue(report["probe_completed"])
        self.assertEqual(report["probes"]["pidfd_send_signal_0"]["status"], "not-run")
        self.assertFalse(report["probes"]["close_range_invalid_range"]["entrypoint_recognized"])
        self.assertEqual(report["probes"]["pidfd_open"]["classification"], "unavailable-or-filtered")
        self.assertNotIn("metadata", report["probes"]["statx"]["/"])
        close.assert_not_called()
        self.assertNotIn("pidfd_send_signal", [name for name, _ in kernel.calls])

    def test_errno_interpretation_distinguishes_absence_permissions_and_other_failures(self):
        for code, classification in ((errno.ENOSYS, "unavailable-or-filtered"),
                                     (errno.EPERM, "permission-or-policy-denied"),
                                     (errno.EACCES, "permission-or-policy-denied"),
                                     (errno.EOPNOTSUPP, "operation-not-supported"),
                                     (errno.EINVAL, "invalid-argument"),
                                     (errno.EOVERFLOW, "other-error"), (9999, "other-error")):
            with self.subTest(code=code):
                self.assertEqual(apis.result_record(-1, code)["classification"], classification)
        self.assertEqual(apis.result_record(-1, 9999)["errno_name"], "UNKNOWN")
        self.assertEqual(apis.result_record(3, 0)["classification"], "available")

    def test_report_does_not_expose_handles_pids_inodes_or_mount_ids(self):
        report, _ = mocked_report()
        serialized = json.dumps(report)
        for private in ("123456789", "9999999", "private-file-handle"):
            self.assertNotIn(private, serialized)
        self.assertEqual(report["probes"]["close_range_invalid_range"]["expected_errno"], "EINVAL")
        self.assertTrue(report["probes"]["close_range_invalid_range"]["entrypoint_recognized"])

    def test_policy_reads_only_selected_fields_and_preserves_unknown(self):
        status = "Name:\tprivate-name\nPid:\t123456789\nSeccomp:\t2\nNoNewPrivs:\t1\n"
        with patch("builtins.open", mock_open(read_data=status)) as opened:
            result = apis.process_policy()
        opened.assert_called_once_with("/proc/self/status", encoding="ascii")
        self.assertEqual(result, {"status": "read", "fields": {"Seccomp": 2, "NoNewPrivs": 1}})
        with patch("builtins.open", side_effect=PermissionError()):
            self.assertEqual(apis.process_policy()["fields"], {"Seccomp": None, "NoNewPrivs": None})
        with patch("builtins.open", mock_open(read_data="Seccomp:\tunknown\n")):
            self.assertIsNone(apis.process_policy()["fields"]["Seccomp"])


class HostTests(unittest.TestCase):
    def test_import_and_host_paths_never_import_ctypes(self):
        report, _ = mocked_report()
        inventory = apis.load_inventory()
        original_import = builtins.__import__

        def forbid_ctypes(name, *arguments, **keywords):
            if name in {"ctypes", "_ctypes"} or name.startswith("ctypes."):
                raise AssertionError("The host path must not import ctypes")
            return original_import(name, *arguments, **keywords)

        with patch("builtins.__import__", side_effect=forbid_ctypes):
            spec = importlib.util.spec_from_file_location("fresh_kernel_apis", SCRIPT)
            fresh = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(fresh)
            with contextlib.redirect_stdout(io.StringIO()), self.assertRaises(SystemExit) as exit:
                fresh.main(["--help"])
            self.assertEqual(exit.exception.code, 0)
            with patch.object(fresh.platform, "system", return_value="Darwin"), \
                    patch.object(fresh, "load_ctypes") as loader, \
                    contextlib.redirect_stderr(io.StringIO()):
                self.assertEqual(fresh.main(["--local"]), 1)
            loader.assert_not_called()
            with tempfile.TemporaryDirectory() as temporary, \
                    patch.object(fresh, "load_inventory", return_value=inventory), \
                    patch.object(inventory, "run_command", return_value=(b"List of devices attached\nprivate-id\tdevice usb:1-1 transport_id:1\n", b"", 0, False)), \
                    patch.object(inventory, "check_adb_transport"), \
                    patch.object(inventory, "run_probe", return_value=(json.dumps(report).encode(), b"", 0, False)), \
                    contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(fresh.main(["--output", str(Path(temporary) / "report")]), 0)
            self.assertIsNone(fresh.ctypes)

    def test_adb_uses_collector_checks_no_installed_script_and_private_report(self):
        report, _ = mocked_report()
        inventory = apis.load_inventory()
        with tempfile.TemporaryDirectory() as temporary, \
                patch.object(apis, "load_inventory", return_value=inventory), \
                patch.object(inventory, "run_command", return_value=(b"List of devices attached\nprivate-id\tdevice usb:1-1 transport_id:1\n", b"", 0, False)), \
                patch.object(inventory, "check_adb_transport") as check, \
                patch.object(inventory, "run_probe", return_value=(json.dumps(report).encode(), b"", 0, False)) as run, \
                contextlib.redirect_stdout(io.StringIO()) as terminal:
            output = Path(temporary) / "api-report"
            self.assertEqual(apis.main(["--output", str(output)]), 0)
            self.assertEqual(stat.S_IMODE(output.stat().st_mode), 0o700)
            self.assertEqual(stat.S_IMODE((output / "report.json").stat().st_mode), 0o600)
            saved = json.loads((output / "report.json").read_text())
            self.assertEqual(saved["transport"], "adb")
            self.assertNotIn("private-id", (output / "report.json").read_text())
        check.assert_called_once_with("adb", "private-id", 30)
        arguments = shlex.split(run.call_args.args[2])
        self.assertEqual(arguments[:3], ["python3", "-B", "-c"])
        self.assertEqual(arguments[3], SCRIPT.read_text())
        self.assertEqual(arguments[4:], ["--probe-stdout"])
        self.assertNotIn("private-id", terminal.getvalue())
        self.assertIn("do not establish", terminal.getvalue())

    def test_failed_remote_probe_is_not_saved_or_printed_as_valid(self):
        inventory = apis.load_inventory()
        for stdout, stderr, code, timed_out in ((b"secret-data", b"", 1, False),
                                               (b"secret-data", b"secret-error", 0, False),
                                               (b"secret-data", b"", 0, True),
                                               (b"{}", b"", 0, False)):
            with self.subTest(code=code, timed_out=timed_out), tempfile.TemporaryDirectory() as temporary, \
                    patch.object(apis, "load_inventory", return_value=inventory), \
                    patch.object(inventory, "run_command", return_value=(b"List of devices attached\nprivate-id\tdevice usb:1-1 transport_id:1\n", b"", 0, False)), \
                    patch.object(inventory, "check_adb_transport"), \
                    patch.object(inventory, "run_probe", return_value=(stdout, stderr, code, timed_out)), \
                    contextlib.redirect_stderr(io.StringIO()) as terminal:
                output = Path(temporary) / "api-report"
                self.assertEqual(apis.main(["--output", str(output)]), 1)
                self.assertFalse(output.exists())
                self.assertNotIn("secret", terminal.getvalue())
                self.assertNotIn("private-id", terminal.getvalue())

    def test_internal_probe_mode_does_not_load_inventory_or_write_files(self):
        report, _ = mocked_report()
        with patch.object(apis, "probe_kernel_apis", return_value=report), \
                patch.object(apis, "load_inventory") as inventory, \
                patch.object(apis, "prepare_output") as output, \
                contextlib.redirect_stdout(io.StringIO()) as terminal:
            self.assertEqual(apis.main(["--probe-stdout"]), 0)
        self.assertEqual(json.loads(terminal.getvalue()), report)
        inventory.assert_not_called()
        output.assert_not_called()

    def test_local_mac_gate_fails_before_output_and_without_adb(self):
        with patch.object(apis.platform, "system", return_value="Darwin"), \
                patch.object(apis.ctypes, "CDLL") as library, \
                patch.object(apis, "prepare_output") as output, \
                contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(apis.main(["--local"]), 1)
        library.assert_not_called()
        output.assert_not_called()

    def test_private_output_rejects_git_and_existing_directories(self):
        inventory = apis.load_inventory()
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / ".git").write_text("gitdir: /fixture")
            with self.assertRaisesRegex(ValueError, "Git"):
                apis.prepare_output(inventory, str(root / "report"))
        with tempfile.TemporaryDirectory() as temporary:
            with self.assertRaises(FileExistsError):
                apis.prepare_output(inventory, temporary)

    def test_default_output_is_private_and_summary_rejects_untrusted_labels(self):
        report, _ = mocked_report()
        report["probes"]["openat2"]["classification"] = "private injected text"
        self.assertNotIn("private injected text", apis.summary(report))
        with tempfile.TemporaryDirectory() as temporary, patch.dict(os.environ, {"XDG_STATE_HOME": temporary}):
            output = apis.prepare_output(apis.load_inventory(), None)
            self.assertEqual(output.parent, Path(temporary).resolve() / "mobile-nixos/titan-kernel-apis")
            self.assertEqual(stat.S_IMODE(output.stat().st_mode), 0o700)


if __name__ == "__main__":
    unittest.main()
