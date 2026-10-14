"""Exercise host-side safety and evidence handling without an attached device."""

import contextlib
import importlib.util
import io
import json
import os
from pathlib import Path
import re
import shlex
import stat
import subprocess
import tempfile
import unittest
from unittest.mock import patch


SCRIPT = Path(__file__).resolve().parents[1] / "collect-inventory.py"
SPEC = importlib.util.spec_from_file_location("inventory", SCRIPT)
inventory = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(inventory)


class DeviceSelectionTests(unittest.TestCase):
    def test_single_authorized_device(self):
        devices = inventory.parse_devices("List of devices attached\nprivate-selector\tdevice\n\n")
        self.assertEqual(inventory.select_device(devices, None), "private-selector")

    def test_multiple_transports_require_selection_even_if_one_is_offline(self):
        devices = {"phone": "device", "other": "offline"}
        with self.assertRaisesRegex(ValueError, "Multiple ADB"):
            inventory.select_device(devices, None)
        self.assertEqual(inventory.select_device(devices, "phone"), "phone")

    def test_missing_unauthorized_and_offline_devices_are_rejected(self):
        for devices, selected in [({}, None), ({"phone": "unauthorized"}, None),
                                  ({"phone": "offline"}, "phone"), ({"phone": "device"}, "other")]:
            with self.subTest(devices=devices, selected=selected), self.assertRaises(ValueError):
                inventory.select_device(devices, selected)


class OutputTests(unittest.TestCase):
    def test_output_is_new_and_private(self):
        with tempfile.TemporaryDirectory() as temporary:
            output = inventory.prepare_output(str(Path(temporary) / "inventory"))
            inventory.write_private(output / "result", b"private")
            self.assertEqual(stat.S_IMODE(output.stat().st_mode), 0o700)
            self.assertEqual(stat.S_IMODE((output / "result").stat().st_mode), 0o600)
            with self.assertRaises(FileExistsError):
                inventory.prepare_output(str(output))

    def test_git_worktree_and_symlink_destinations_are_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            repo = base / "repo"
            repo.mkdir()
            (repo / ".git").write_text("gitdir: /some/worktree")
            alias = base / "alias"
            alias.symlink_to(repo, target_is_directory=True)
            for destination in (repo / "logs", alias / "logs"):
                with self.subTest(destination=destination), self.assertRaisesRegex(ValueError, "Git"):
                    inventory.prepare_output(str(destination))

    def test_default_output_respects_state_directory(self):
        with tempfile.TemporaryDirectory() as temporary, patch.dict(os.environ, {"XDG_STATE_HOME": temporary}):
            output = inventory.prepare_output(None)
            self.assertEqual(output.parent, Path(temporary).resolve() / "mobile-nixos/titan-inventory")
            self.assertEqual(stat.S_IMODE(output.stat().st_mode), 0o700)


class EvidenceTests(unittest.TestCase):
    def test_usb_probe_handles_legacy_attribute_and_configfs_directory(self):
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            legacy = base / "android_usb/android0"
            legacy.mkdir(parents=True)
            (legacy / "functions").write_text("adb\n")
            functions = base / "usb_gadget/g1/functions"
            (functions / "ffs.adb").mkdir(parents=True)
            (functions / "acm.GS0").mkdir()
            script = inventory.PROBES["usb.txt"]
            for source, fixture in (("/sys/class/android_usb", "android_usb"),
                                    ("/sys/class/udc", "udc"),
                                    ("/sys/kernel/config/usb_gadget", "usb_gadget")):
                script = script.replace(source, shlex.quote(str(base / fixture)))
            stdout, stderr, code, timed_out = inventory.run_local_probe(script, 2)
        self.assertEqual((stderr, code, timed_out), (b"", 0, False))
        self.assertIn(b"functions=adb\n", stdout)
        self.assertIn(b"functions=\nacm.GS0\nffs.adb\n", stdout)

    def test_storage_classification_needs_driver_or_device_type(self):
        cases = [
            (b"mmcblk0.type=MMC\n", "eMMC"),
            (b"host0.proc_name=ufshcd\n", "UFS"),
            (b"mmcblk0.type=SD\nsda.model=Generic\n", "unknown"),
            (b"mmcblk0.type=MMC\nhost0.proc_name=ufshcd\n", "ambiguous"),
        ]
        for evidence, expected in cases:
            with self.subTest(evidence=evidence):
                result = inventory.summarize({"storage.txt": evidence})
                self.assertTrue(result["storage_variant_hint"].startswith(expected))

    def test_summary_omits_unselected_property_fields(self):
        result = inventory.summarize({
            "android-properties.txt": b"ro.product.model=Titan\nro.serialno=secret\n",
            "kernel.txt": b"4.14.141\naarch64\n",
        })
        self.assertEqual(result["model"], "Titan")
        self.assertEqual(result["kernel_release"], "4.14.141")
        self.assertNotIn("secret", json.dumps(result))


class AdbBoundaryTests(unittest.TestCase):
    def test_remote_script_quoting_and_no_host_shell(self):
        script = "printf '%s\\n' 'a b; $(not-executed)'; printf '\\000\\015\\012\\377'; printf denied >&2; exit 7"
        host_run = subprocess.run

        def mock_adb(command, **kwargs):
            # Execute the shell service's single command as a real shell would,
            # then emulate Ubuntu Touch adbd dropping the remote exit status.
            remote = host_run(["sh", "-c", command[-1]], **kwargs)
            return subprocess.CompletedProcess(command, 0, remote.stdout, remote.stderr)

        with patch.object(inventory.subprocess, "run", side_effect=mock_adb) as run:
            result = inventory.run_probe("adb", "phone; host-injection", script, 4)
        command = run.call_args.args[0]
        self.assertEqual(command[:6], ["adb", "-s", "phone; host-injection", "shell", "-T", "-n"])
        self.assertEqual(len(command), 7)
        self.assertNotIn("shell", run.call_args.kwargs)
        self.assertEqual(result, (b"a b; $(not-executed)\n\x00\r\n\xff", b"denied", 7, False))

    def test_missing_or_invalid_status_trailer_cannot_report_success(self):
        for stderr in (b"", b"shell error", b"\n__TITAN_INVENTORY_STATUS_test:999\n"):
            with self.subTest(stderr=stderr), patch.object(inventory.secrets, "token_hex", return_value="test"):
                with patch.object(inventory.subprocess, "run") as run:
                    run.return_value = subprocess.CompletedProcess([], 0, b"false evidence", stderr)
                    stdout, error, code, timed_out = inventory.run_probe("adb", "phone", "false", 1)
                self.assertEqual(stdout, b"false evidence")
                self.assertIsNone(code)
                self.assertFalse(timed_out)
                self.assertIn(b"trailer missing or invalid", error)

    def test_transport_failure_cannot_be_hidden_by_successful_remote_status(self):
        with patch.object(inventory.secrets, "token_hex", return_value="test"):
            with patch.object(inventory.subprocess, "run") as run:
                run.return_value = subprocess.CompletedProcess(
                    [], 1, b"partial", b"warning\n__TITAN_INVENTORY_STATUS_test:0\n",
                )
                stdout, error, code, timed_out = inventory.run_probe("adb", "phone", "true", 1)
        self.assertEqual((stdout, code, timed_out), (b"partial", 1, False))
        self.assertTrue(error.startswith(b"warning"))
        self.assertIn(b"transport failed", error)

    def test_transport_requires_shell_v2_and_correct_binary_stderr_and_status(self):
        with patch.object(inventory, "run_command", return_value=(b"cmd\n", b"", 0, False)):
            with patch.object(inventory, "run_probe") as probe:
                with self.assertRaisesRegex(ValueError, "shell_v2"):
                    inventory.check_adb_transport("adb", "phone", 1)
                probe.assert_not_called()
        failures = [
            (b"\x00\r\r\n\xff", b"titan-inventory-check\n", 7, False),
            (b"\x00\r\n\xff", b"", 7, False),
            (b"\x00\r\n\xff", b"titan-inventory-check\n", 0, False),
            (b"\x00\r\n\xff", b"titan-inventory-check\n", 7, True),
        ]
        for result in failures:
            with self.subTest(result=result):
                with patch.object(inventory, "run_command", return_value=(b"shell_v2\n", b"", 0, False)):
                    with patch.object(inventory, "run_probe", return_value=result):
                        with self.assertRaisesRegex(ValueError, "check failed"):
                            inventory.check_adb_transport("adb", "phone", 1)

    def test_preflight_failure_does_not_create_output_or_disclose_serial(self):
        old_umask = os.umask(0o077)
        try:
            with tempfile.TemporaryDirectory() as temporary, patch.object(inventory.subprocess, "run") as run:
                run.side_effect = [
                    subprocess.CompletedProcess([], 0, b"List of devices attached\nsecret-id\tdevice\n", b""),
                    subprocess.CompletedProcess([], 0, b"cmd\n", b""),
                ]
                output = Path(temporary) / "inventory"
                terminal = io.StringIO()
                with contextlib.redirect_stderr(terminal), self.assertRaises(SystemExit) as error:
                    inventory.main(["--output", str(output)])
                self.assertEqual(error.exception.code, 1)
                self.assertFalse(output.exists())
                self.assertEqual(run.call_count, 2)
                self.assertNotIn("secret-id", terminal.getvalue())
        finally:
            os.umask(old_umask)

    def test_timeout_retains_partial_output(self):
        error = subprocess.TimeoutExpired(["adb"], 1, output=b"partial", stderr=b"denied")
        with patch.object(inventory.subprocess, "run", side_effect=error):
            self.assertEqual(inventory.run_probe("adb", "phone", "dmesg", 1),
                             (b"partial", b"denied", None, True))

    def test_mock_collection_uses_only_allowlisted_reads_and_no_private_logs_by_default(self):
        calls = []

        def mock_adb(command, **kwargs):
            calls.append(command)
            if command == ["adb", "devices"]:
                return subprocess.CompletedProcess(command, 0, b"List of devices attached\nsecret-id\tdevice\n", b"")
            if command == ["adb", "-s", "secret-id", "features"]:
                return subprocess.CompletedProcess(command, 0, b"shell_v2\n", b"")
            self.assertEqual(command[:6], ["adb", "-s", "secret-id", "shell", "-T", "-n"])
            script = shlex.split(command[6])[2].removesuffix(";")
            self.assertIn(script, [inventory.ADB_CHECK_SCRIPT, *inventory.PROBES.values()])
            marker = re.search(r"(__TITAN_INVENTORY_STATUS_[a-f0-9]+:)", command[6])[1].encode()

            def framed(code, stdout, stderr):
                return subprocess.CompletedProcess(command, 0, stdout, stderr + b"\n" + marker + str(code).encode() + b"\n")

            if script == inventory.ADB_CHECK_SCRIPT:
                return framed(7, b"\x00\r\n\xff", b"titan-inventory-check\n")
            if script == inventory.PROBES["config.gz"]:
                return framed(1, b"", b"Permission denied")
            if script == inventory.PROBES["kernel.txt"]:
                return framed(0, b"4.14.141\naarch64\n", b"")
            return framed(0, b"available\n", b"")

        old_umask = os.umask(0o077)
        try:
            with tempfile.TemporaryDirectory() as temporary, patch.object(inventory.subprocess, "run", side_effect=mock_adb):
                output = Path(temporary) / "inventory"
                terminal = io.StringIO()
                with contextlib.redirect_stdout(terminal):
                    self.assertEqual(inventory.main(["--output", str(output)]), 1)
                self.assertEqual(len(calls), 3 + len(inventory.PROBES))
                self.assertFalse((output / "dmesg.txt").exists())
                self.assertFalse((output / "cmdline.txt").exists())
                report = json.loads((output / "report.json").read_text())
                self.assertEqual(report["probes"]["config.gz"]["exit_code"], 1)
                self.assertFalse(report["complete"])
                self.assertEqual(report["probes_needing_review"], 1)
                self.assertEqual((output / "config.gz.stderr").read_bytes(), b"Permission denied")
                self.assertNotIn("secret-id", terminal.getvalue())
                for path in output.iterdir():
                    self.assertNotIn(b"secret-id", path.read_bytes())
        finally:
            os.umask(old_umask)


class SshBoundaryTests(unittest.TestCase):
    def test_only_simple_destinations_are_accepted(self):
        for host in ("titan", "phablet@192.0.2.4", "phablet@titan.example", "2001:db8::1", "phablet@[2001:db8::1]"):
            with self.subTest(host=host):
                self.assertEqual(inventory.validate_ssh_host(host), host)
        for host in ("", "-oProxyCommand=command", "user@-host", "host -oProxyCommand=command",
                     "host;command", "user@host\n", "$(command)", "ssh://host", "host`command`"):
            with self.subTest(host=host), self.assertRaises(ValueError):
                inventory.validate_ssh_host(host)

    def test_ssh_uses_verified_host_keys_batch_authentication_and_quoted_script(self):
        script = "printf '%s\\n' 'a b'; cat /proc/version"
        with patch.object(inventory.subprocess, "run") as run:
            run.return_value = subprocess.CompletedProcess([], 0, b"result", b"")
            self.assertEqual(inventory.run_ssh_probe("phablet@titan", 2222, script, 4),
                             (b"result", b"", 0, False))
        command = run.call_args.args[0]
        self.assertEqual(command[:3], ["ssh", "-n", "-T"])
        self.assertIn("BatchMode=yes", command)
        self.assertIn("StrictHostKeyChecking=yes", command)
        self.assertEqual(command[command.index("-p") + 1], "2222")
        self.assertEqual(command[-3:-1], ["--", "phablet@titan"])
        self.assertEqual(shlex.split(command[-1]), ["sh", "-c", script])
        self.assertNotIn("-F", command)
        self.assertNotIn("shell", run.call_args.kwargs)

    def test_ssh_config_path_is_one_argument_and_preserves_authentication_options(self):
        config = "/private directory/ssh config; $(not-a-command) 'quoted'"
        with patch.object(inventory.subprocess, "run") as run:
            run.return_value = subprocess.CompletedProcess([], 0, b"result", b"")
            inventory.run_ssh_probe("titan-forward", 2222, "true", 4, config)
        command = run.call_args.args[0]
        self.assertEqual(command[command.index("-F") + 1], config)
        self.assertEqual(command.count(config), 1)
        self.assertLess(command.index("-F"), command.index("--"))
        self.assertIn("BatchMode=yes", command)
        self.assertIn("StrictHostKeyChecking=yes", command)
        self.assertEqual(command[command.index("-p") + 1], "2222")
        self.assertEqual(command[-3:], ["--", "titan-forward", "sh -c true"])
        self.assertNotIn("shell", run.call_args.kwargs)

    def test_ssh_config_requires_ssh_and_nonempty_path_before_any_command(self):
        for arguments in (["--ssh-config", "/private/config"],
                          ["--local", "--ssh-config", "/private/config"],
                          ["--serial", "phone", "--ssh-config", "/private/config"],
                          ["--ssh", "titan", "--ssh-config", ""],
                          ["--ssh", "titan", "--ssh-config", "/private/config", "--ssh-port", "0"],
                          ["--ssh", "titan", "--ssh-config", "/private/config", "--ssh-port", "65536"]):
            with self.subTest(arguments=arguments), patch.object(inventory.subprocess, "run") as run:
                with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit) as error:
                    inventory.main(arguments)
                self.assertEqual(error.exception.code, 2)
                run.assert_not_called()

    def test_invalid_destination_is_rejected_before_invocation(self):
        with patch.object(inventory.subprocess, "run") as run, self.assertRaises(ValueError):
            inventory.run_ssh_probe("-oProxyCommand=command", 22, "true", 2)
        run.assert_not_called()

    def test_empty_explicit_ssh_destination_does_not_fall_back_to_adb(self):
        old_umask = os.umask(0o077)
        try:
            with patch.object(inventory.subprocess, "run") as run:
                with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
                    inventory.main(["--ssh", ""])
                run.assert_not_called()
        finally:
            os.umask(old_umask)

    def test_failed_login_stops_before_creating_output_or_running_probes(self):
        old_umask = os.umask(0o077)
        try:
            with tempfile.TemporaryDirectory() as temporary, patch.object(inventory.subprocess, "run") as run:
                run.return_value = subprocess.CompletedProcess([], 255, b"", b"Permission denied")
                output = Path(temporary) / "inventory"
                with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
                    inventory.main(["--ssh", "phablet@titan", "--output", str(output)])
                self.assertFalse(output.exists())
                self.assertEqual(run.call_count, 1)
                self.assertEqual(shlex.split(run.call_args.args[0][-1]), ["sh", "-c", "true"])
        finally:
            os.umask(old_umask)

    def test_config_preflight_failure_does_not_disclose_transport_details(self):
        config = "/private directory/titan config"
        destination = "phablet@private-host"
        old_umask = os.umask(0o077)
        try:
            with tempfile.TemporaryDirectory() as temporary, patch.object(inventory.subprocess, "run") as run:
                run.return_value = subprocess.CompletedProcess(
                    [], 255, b"", f"Cannot read {config} for {destination}".encode(),
                )
                output = Path(temporary) / "inventory"
                terminal = io.StringIO()
                with contextlib.redirect_stderr(terminal), self.assertRaises(SystemExit):
                    inventory.main([
                        "--ssh", destination, "--ssh-config", config, "--output", str(output),
                    ])
                self.assertFalse(output.exists())
                self.assertEqual(run.call_count, 1)
                command = run.call_args.args[0]
                self.assertEqual(command[command.index("-F") + 1], config)
                self.assertEqual(shlex.split(command[-1]), ["sh", "-c", "true"])
                self.assertNotIn(config, terminal.getvalue())
                self.assertNotIn(destination, terminal.getvalue())
        finally:
            os.umask(old_umask)

    def test_ssh_collection_uses_same_probes_without_adb(self):
        calls = []
        config = "/private directory/titan config"

        def mock_ssh(command, **kwargs):
            calls.append(command)
            self.assertEqual(command[0], "ssh")
            self.assertEqual(command[-2], "phablet@private-host")
            self.assertEqual(command[command.index("-F") + 1], config)
            self.assertEqual(command[command.index("-p") + 1], "2222")
            script = shlex.split(command[-1])[2]
            self.assertIn(script, ["true", *inventory.PROBES.values(), *inventory.PRIVATE_PROBES.values()])
            return subprocess.CompletedProcess(command, 0, b"available\n", b"")

        old_umask = os.umask(0o077)
        try:
            with tempfile.TemporaryDirectory() as temporary, patch.object(inventory.subprocess, "run", side_effect=mock_ssh):
                output = Path(temporary) / "inventory"
                terminal = io.StringIO()
                with contextlib.redirect_stdout(terminal):
                    self.assertEqual(inventory.main([
                        "--ssh", "phablet@private-host", "--ssh-config", config, "--ssh-port", "2222",
                        "--include-private-logs", "--output", str(output),
                    ]), 0)
                self.assertEqual(len(calls), 1 + len(inventory.PROBES) + len(inventory.PRIVATE_PROBES))
                self.assertTrue((output / "dmesg.txt").exists())
                self.assertEqual(json.loads((output / "report.json").read_text())["transport"], "ssh")
                self.assertNotIn("private-host", terminal.getvalue())
                self.assertNotIn(config, terminal.getvalue())
                for path in output.iterdir():
                    self.assertNotIn(b"private-host", path.read_bytes())
                    self.assertNotIn(config.encode(), path.read_bytes())
        finally:
            os.umask(old_umask)


class LocalBoundaryTests(unittest.TestCase):
    def test_local_transport_runs_the_exact_script_without_elevation(self):
        script = inventory.PROBES["kernel.txt"]
        with patch.object(inventory.subprocess, "run") as run:
            run.return_value = subprocess.CompletedProcess([], 0, b"4.14.141\n", b"")
            self.assertEqual(inventory.run_local_probe(script, 3), (b"4.14.141\n", b"", 0, False))
        self.assertEqual(run.call_args.args[0], ["sh", "-c", script])
        self.assertNotIn("shell", run.call_args.kwargs)
        self.assertEqual(run.call_args.kwargs["timeout"], 3)

    def test_conflicting_transports_fail_before_running_any_command(self):
        for arguments in (["--local", "--ssh", "phablet@titan"],
                          ["--local", "--serial", "phone"], ["--local", "--ssh-port", "2222"],
                          ["--ssh", "phablet@titan", "--serial", "phone"]):
            with self.subTest(arguments=arguments), patch.object(inventory.subprocess, "run") as run:
                with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit) as error:
                    inventory.main(arguments)
                self.assertEqual(error.exception.code, 2)
                run.assert_not_called()

    def test_local_collection_uses_same_probes_and_protected_output(self):
        calls = []

        def mock_local(command, **kwargs):
            calls.append(command)
            self.assertEqual(command[:2], ["sh", "-c"])
            self.assertEqual(len(command), 3)
            self.assertIn(command[2], inventory.PROBES.values())
            if command[2] == inventory.PROBES["config.gz"]:
                return subprocess.CompletedProcess(command, 1, b"", b"Permission denied")
            return subprocess.CompletedProcess(command, 0, b"available\n", b"")

        old_umask = os.umask(0o077)
        try:
            with tempfile.TemporaryDirectory() as temporary, patch.object(inventory.subprocess, "run", side_effect=mock_local):
                output = Path(temporary) / "inventory"
                with contextlib.redirect_stdout(io.StringIO()):
                    self.assertEqual(inventory.main(["--local", "--output", str(output)]), 1)
                self.assertEqual(len(calls), len(inventory.PROBES))
                self.assertFalse((output / "dmesg.txt").exists())
                self.assertFalse((output / "cmdline.txt").exists())
                report = json.loads((output / "report.json").read_text())
                self.assertEqual(report["transport"], "local")
                self.assertEqual(report["probes"]["config.gz"]["exit_code"], 1)
                self.assertEqual(stat.S_IMODE(output.stat().st_mode), 0o700)
                for path in output.iterdir():
                    self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
        finally:
            os.umask(old_umask)

    def test_local_collection_rejects_repository_output_before_probing(self):
        old_umask = os.umask(0o077)
        try:
            with tempfile.TemporaryDirectory() as temporary, patch.object(inventory.subprocess, "run") as run:
                repo = Path(temporary) / "repo"
                repo.mkdir()
                (repo / ".git").write_text("gitdir: /some/worktree")
                output = repo / "inventory"
                with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
                    inventory.main(["--local", "--output", str(output)])
                run.assert_not_called()
                self.assertFalse(output.exists())
        finally:
            os.umask(old_umask)


if __name__ == "__main__":
    unittest.main()
