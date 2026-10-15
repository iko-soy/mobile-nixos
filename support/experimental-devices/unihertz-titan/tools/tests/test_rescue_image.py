"""Private host repackaging tests: synthetic bytes only, never a phone or Nix input."""

import contextlib
import gzip
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import stat
import struct
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

import test_boot_image
import test_rescue_ramdisk


SCRIPT = Path(__file__).resolve().parents[1] / "prepare-rescue-image.py"
SPEC = importlib.util.spec_from_file_location("prepare_rescue_image", SCRIPT)
prepare = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(prepare)


def fixture():
    kernel = bytes(range(256)) * 9 + b"kernel"
    dtb = test_boot_image.dt_table()
    raw = test_boot_image.image(dtb=dtb, kernel=kernel)
    struct.pack_into("<I", raw, 28, 0)
    command = prepare.SOURCE_CMDLINE.encode("ascii")
    raw[64:576] = (command + b"\0").ljust(512, b"\0")
    raw[608:1632] = bytes(1024)
    # Independent legacy ID fixture includes second, legacy-dt, recovery-dtbo.
    digest = hashlib.sha1(usedforsecurity=False)
    for item in (kernel, b"R" * 31, b"", b"", b"", dtb):
        digest.update(item)
        digest.update(struct.pack("<I", len(item)))
    raw[576:608] = digest.digest() + bytes(12)
    boot = bytes(test_boot_image.avb_image(raw, size=33554432))
    ramdisk = test_rescue_ramdisk.fixture()[0]
    constants = {
        "BOOT_SHA256": hashlib.sha256(boot).hexdigest(),
        "KERNEL_BYTES": len(kernel), "KERNEL_SHA256": hashlib.sha256(kernel).hexdigest(),
        "DTB_BYTES": len(dtb), "DTB_SHA256": hashlib.sha256(dtb).hexdigest(),
        "RAMDISK_BYTES": len(ramdisk), "RAMDISK_SHA256": hashlib.sha256(ramdisk).hexdigest(),
    }
    return boot, ramdisk, kernel, dtb, constants


class RescueImageTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.boot, cls.ramdisk, cls.kernel, cls.dtb, cls.constants = fixture()

    def setUp(self):
        self.profile = patch.multiple(prepare, **self.constants)
        self.profile.start()
        self.addCleanup(self.profile.stop)

    @contextlib.contextmanager
    def private_inputs(self):
        # Nix may set TMPDIR below /nix/var/nix/builds on Darwin. Production
        # intentionally refuses every /nix path, even when it is not the store.
        # Keep these synthetic-only filesystem fixtures in a private ordinary
        # temporary directory; do not relax the helper's path checks for tests.
        with tempfile.TemporaryDirectory(prefix="titan-rescue-image-test-", dir="/tmp") as temporary:
            parent = Path(temporary).resolve()
            boot, ramdisk, output = parent / "boot.img", parent / "initramfs.gz", parent / "prepared"
            for name, data in ((boot, self.boot), (ramdisk, self.ramdisk)):
                name.write_bytes(data)
                name.chmod(0o600)
            yield parent, boot, ramdisk, output

    def test_preserved_payloads_fixed_arguments_and_no_avb(self):
        image, report = prepare.assemble_image(self.boot, self.ramdisk)
        info = prepare.boot_inspector.inspect_image(image)
        source = prepare.boot_inspector.inspect_image(self.boot)
        self.assertEqual(info["load_addresses"], source["load_addresses"])
        self.assertEqual(info["cmdline"], prepare.RESCUE_CMDLINE)
        self.assertNotIn("systempart", info["cmdline"])
        self.assertNotIn("halium_lvm_vg", info["cmdline"])
        self.assertIn("rdinit=/init init=/init panic=0", info["cmdline"])
        self.assertEqual(prepare.payload(image, info, "kernel"), self.kernel)
        self.assertEqual(prepare.payload(image, info, "dtb"), self.dtb)
        self.assertEqual(prepare.payload(image, info, "ramdisk"), self.ramdisk)
        self.assertEqual(info["padded_payload_end"], len(image))
        self.assertEqual(len(image) % 2048, 0)
        self.assertLess(len(image), 33554432)
        self.assertIsNone(info["avb"])
        self.assertEqual(image[48:64], bytes(16))
        self.assertEqual(image[1660:2048], bytes(388))
        self.assertNotEqual(image[576:608], self.boot[576:608])
        self.assertEqual(report["image"]["sha256"], hashlib.sha256(image).hexdigest())
        self.assertEqual(report["inputs"]["usb_ramdisk"]["sha256"], hashlib.sha256(self.ramdisk).hexdigest())
        self.assertTrue(report["inputs"]["usb_ramdisk"]["validation"]["static_aarch64"])
        for claim in ("avb_metadata_included", "authentication_performed", "full_partition_image",
                      "bootability_verified", "bootloader_acceptance_verified",
                      "recovery_procedure_verified", "device_action_performed"):
            self.assertIs(report["policy"][claim], False)

    def test_whole_artifact_hashes_and_lengths_are_fixed(self):
        changed_boot = bytes([self.boot[0] ^ 1]) + self.boot[1:]
        changed_ramdisk = bytes([self.ramdisk[0] ^ 1]) + self.ramdisk[1:]
        for data, expected in ((self.boot[:-1], "byte count"), (changed_boot, "SHA-256")):
            with self.subTest(kind="boot", expected=expected), self.assertRaisesRegex(prepare.PreparationError, expected):
                prepare.validate_boot(data)
        for data, expected in ((self.ramdisk[:-1], "byte count"), (changed_ramdisk, "SHA-256")):
            with self.subTest(kind="ramdisk", expected=expected), self.assertRaisesRegex(prepare.PreparationError, expected):
                prepare.validate_ramdisk(data)

    def test_independent_geometry_and_exact_source_fields(self):
        for offset, value in ((12, 0), (28, 1), (48, 65), (64, 88), (575, 1),
                              (608, 1), (1660, 1), (576, 0)):
            changed = bytearray(self.boot)
            changed[offset] = value if changed[offset] != value else value ^ 1
            changed = bytes(changed)
            with self.subTest(offset=offset), patch.object(prepare, "BOOT_SHA256", prepare.sha256(changed)):
                with self.assertRaises(prepare.PreparationError):
                    prepare.validate_boot(changed)

    def test_component_hashes_independently_reject_mutation(self):
        original = prepare.boot_inspector.inspect_image(self.boot)
        for name, error in (("kernel", "kernel differs"), ("dtb", "DTB differs")):
            changed = bytearray(self.boot)
            # The DT table's hardware ID may change without invalidating its
            # geometry, so this rejection specifically exercises payload hash.
            offset = (original["segments"][name]["offset"] + 40 if name == "dtb"
                      else original["segments"][name]["end"] - 1)
            changed[offset] ^= 1
            changed = bytes(changed)
            with self.subTest(name=name), patch.object(prepare, "BOOT_SHA256", prepare.sha256(changed)):
                with self.assertRaisesRegex(prepare.PreparationError, error):
                    prepare.validate_boot(changed)

    def test_exact_ramdisk_archive_is_independently_parsed(self):
        changed = self.ramdisk + b"\0"
        with patch.multiple(prepare, RAMDISK_BYTES=len(changed), RAMDISK_SHA256=prepare.sha256(changed)):
            with self.assertRaisesRegex(prepare.PreparationError, "archive validation"):
                prepare.validate_ramdisk(changed)

    def test_output_capacity_checked_before_publication(self):
        original = prepare.boot_inspector.inspect_image(self.boot)
        with patch.object(prepare, "validate_boot", return_value=(original, bytes(33554432), self.dtb)):
            with self.assertRaisesRegex(prepare.PreparationError, "capacity"):
                prepare.assemble_image(self.boot, self.ramdisk)

    def test_private_publication_and_saved_bytes(self):
        with self.private_inputs() as (parent, boot, ramdisk, output):
            report = prepare.prepare(boot, ramdisk, output)
            self.assertEqual(stat.S_IMODE(output.stat().st_mode), 0o700)
            self.assertEqual({item.name for item in output.iterdir()}, {prepare.IMAGE_NAME, prepare.MANIFEST_NAME})
            for path in output.iterdir():
                self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
                self.assertEqual(path.stat().st_nlink, 1)
            self.assertEqual(json.loads((output / prepare.MANIFEST_NAME).read_text()), report)
            saved = (output / prepare.IMAGE_NAME).read_bytes()
            self.assertEqual(prepare.sha256(saved), report["image"]["sha256"])
            self.assertEqual(len(saved), report["image"]["bytes"])
            self.assertEqual(boot.read_bytes(), self.boot)
            self.assertEqual(ramdisk.read_bytes(), self.ramdisk)

    def test_nonregular_and_unsafe_inputs_rejected_before_open(self):
        with self.private_inputs() as (parent, boot, ramdisk, output):
            symlink, fifo, directory = parent / "link", parent / "pipe", parent / "directory"
            symlink.symlink_to(boot)
            os.mkfifo(fifo, 0o600)
            directory.mkdir(mode=0o700)
            for path in (symlink, fifo, directory, Path("/dev/null")):
                with self.subTest(path=path.name), patch.object(prepare.os, "open") as opened:
                    with self.assertRaises(prepare.PreparationError):
                        prepare.PrivateInput(path, 33554432)
                    opened.assert_not_called()
            boot.chmod(0o644)
            with patch.object(prepare.os, "open") as opened, self.assertRaisesRegex(prepare.PreparationError, "privately owned"):
                prepare.PrivateInput(boot, 33554432)
            opened.assert_not_called()
            boot.chmod(0o600)
            os.link(boot, parent / "hardlink")
            with patch.object(prepare.os, "open") as opened, self.assertRaisesRegex(prepare.PreparationError, "one link"):
                prepare.PrivateInput(boot, 33554432)
            opened.assert_not_called()

    def test_open_identity_change_and_short_read(self):
        with self.private_inputs() as (parent, boot, ramdisk, output):
            real_open = os.open

            def replace_before_open(path, flags, *args, **kwargs):
                if Path(path) == boot:
                    replacement = parent / "replacement"
                    replacement.write_bytes(self.boot)
                    replacement.chmod(0o600)
                    os.replace(replacement, boot)
                return real_open(path, flags, *args, **kwargs)

            with patch.object(prepare.os, "open", side_effect=replace_before_open):
                with self.assertRaisesRegex(prepare.PreparationError, "identity changed"):
                    prepare.PrivateInput(boot, 33554432)
            with patch.object(prepare.os, "read", return_value=b""):
                with self.assertRaisesRegex(prepare.PreparationError, "ended before"):
                    prepare.PrivateInput(boot, 33554432)

    def test_input_mutation_and_path_replacement_abort_before_output(self):
        real_assemble = prepare.assemble_image
        for replace in (False, True):
            with self.subTest(replace=replace), self.private_inputs() as (parent, boot, ramdisk, output):
                def alter_after_validation(*args):
                    result = real_assemble(*args)
                    if replace:
                        replacement = parent / "replacement"
                        replacement.write_bytes(self.boot)
                        replacement.chmod(0o600)
                        os.replace(replacement, boot)
                    else:
                        with boot.open("r+b") as handle:
                            handle.write(b"M")
                    return result
                with patch.object(prepare, "assemble_image", side_effect=alter_after_validation):
                    with self.assertRaisesRegex(prepare.PreparationError, "changed during"):
                        prepare.prepare(boot, ramdisk, output)
                self.assertFalse(output.exists())

    def test_existing_outputs_and_unsafe_parent_are_refused(self):
        with self.private_inputs() as (parent, boot, ramdisk, output):
            output.mkdir()
            (output / "keep").write_bytes(b"unchanged")
            with self.assertRaisesRegex(prepare.PreparationError, "new private"):
                prepare.prepare(boot, ramdisk, output)
            link = parent / "output-link"
            link.symlink_to(output, target_is_directory=True)
            with self.assertRaisesRegex(prepare.PreparationError, "new private"):
                prepare.prepare(boot, ramdisk, link)
            self.assertEqual((output / "keep").read_bytes(), b"unchanged")
            unsafe = parent / "unsafe"
            unsafe.mkdir(mode=0o777)
            unsafe.chmod(0o777)
            with self.assertRaisesRegex(prepare.PreparationError, "Output parent"):
                prepare.prepare(boot, ramdisk, unsafe / "result")
            self.assertFalse((unsafe / "result").exists())

    def test_repository_and_nix_scope_refused(self):
        with tempfile.TemporaryDirectory(prefix="titan-rescue-scope-test-", dir="/tmp") as temporary:
            parent = Path(temporary)
            for marker in (".git", ".jj"):
                (parent / marker).mkdir()
                with self.subTest(marker=marker), self.assertRaisesRegex(prepare.PreparationError, "repository"):
                    prepare.private_path(parent / "input")
                (parent / marker).rmdir()
        with self.assertRaisesRegex(prepare.PreparationError, "Nix"):
            prepare.private_path("/nix")

    def test_first_or_second_publication_failure_removes_completed_names(self):
        real_link = os.link
        for failing_call in (1, 2):
            with self.subTest(failing_call=failing_call), self.private_inputs() as (parent, boot, ramdisk, output):
                calls = 0

                def fail_link(*args, **kwargs):
                    nonlocal calls
                    calls += 1
                    if calls == failing_call:
                        raise OSError("injected link failure")
                    return real_link(*args, **kwargs)

                with patch.object(prepare.os, "link", side_effect=fail_link), self.assertRaises(OSError):
                    prepare.prepare(boot, ramdisk, output)
                self.assertFalse((output / prepare.IMAGE_NAME).exists())
                self.assertFalse((output / prepare.MANIFEST_NAME).exists())

    def test_directory_fsync_failure_revokes_published_names(self):
        real_fsync = os.fsync
        with self.private_inputs() as (parent, boot, ramdisk, output):
            def fail_published_directory(fd):
                if stat.S_ISDIR(os.fstat(fd).st_mode) and (output / prepare.MANIFEST_NAME).exists():
                    raise OSError("injected directory fsync failure")
                return real_fsync(fd)
            with patch.object(prepare.os, "fsync", side_effect=fail_published_directory), self.assertRaises(OSError):
                prepare.prepare(boot, ramdisk, output)
            self.assertFalse((output / prepare.IMAGE_NAME).exists())
            self.assertFalse((output / prepare.MANIFEST_NAME).exists())

    def test_partial_write_or_readback_failure_never_publishes(self):
        real_write = os.write
        for corrupt in (False, True):
            with self.subTest(corrupt=corrupt), self.private_inputs() as (parent, boot, ramdisk, output):
                def faulty_write(fd, data):
                    if corrupt:
                        return real_write(fd, b"X" + bytes(data)[1:])
                    real_write(fd, bytes(data)[:7])
                    raise OSError("injected partial write")
                with patch.object(prepare.os, "write", side_effect=faulty_write):
                    with self.assertRaises((OSError, prepare.PreparationError)):
                        prepare.prepare(boot, ramdisk, output)
                self.assertFalse((output / prepare.IMAGE_NAME).exists())
                self.assertFalse((output / prepare.MANIFEST_NAME).exists())
                self.assertTrue(all(item.name.endswith(".partial") for item in output.iterdir()))

    def test_post_publication_identity_check_revokes_result(self):
        real_fsync = os.fsync
        with self.private_inputs() as (parent, boot, ramdisk, output):
            def alter_published_mode(fd):
                if stat.S_ISDIR(os.fstat(fd).st_mode) and (output / prepare.MANIFEST_NAME).exists():
                    (output / prepare.IMAGE_NAME).chmod(0o644)
                return real_fsync(fd)
            with patch.object(prepare.os, "fsync", side_effect=alter_published_mode):
                with self.assertRaisesRegex(prepare.PreparationError, "Published output"):
                    prepare.prepare(boot, ramdisk, output)
            self.assertFalse((output / prepare.IMAGE_NAME).exists())
            self.assertFalse((output / prepare.MANIFEST_NAME).exists())

    def test_cli_failure_is_sanitized_and_has_no_success_output(self):
        stdout, stderr = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            with patch.object(prepare, "prepare", side_effect=OSError("private path /secret/name")):
                status = prepare.main(["--boot", "private", "--ramdisk", "private", "--output", "private"])
        self.assertEqual(status, 1)
        self.assertEqual(stdout.getvalue(), "")
        self.assertNotIn("/secret/name", stderr.getvalue())

    def test_probe_profile_uses_its_own_pin_and_archive_profile(self):
        paths = (".", "dev", "init", "proc", "run", "sys", "tmp")
        probe = test_rescue_ramdisk.compressed(test_rescue_ramdisk.archive([
            test_rescue_ramdisk.record(path, test_rescue_ramdisk.elf(b"probe") if path == "init" else b"",
                                       inode=index, directory=path != "init")
            for index, path in enumerate(paths)]))
        pins = {"PROBE_RAMDISK_BYTES": len(probe), "PROBE_RAMDISK_SHA256": hashlib.sha256(probe).hexdigest()}
        with patch.multiple(prepare, **pins):
            image, report = prepare.assemble_image(self.boot, probe, "usb-probe")
            self.assertEqual(report["ramdisk_profile"], "usb-probe")
            self.assertEqual(report["inputs"]["usb_ramdisk"]["format"], "titan-usb-probe-initramfs-v1")
            info = prepare.boot_inspector.inspect_image(image)
            # Only the probe uses its own command line, with a panic restart.
            self.assertEqual(info["cmdline"], prepare.PROBE_CMDLINE)
            self.assertEqual(report["policy"]["rescue_cmdline"], prepare.PROBE_CMDLINE)
            self.assertEqual(prepare.PROBE_CMDLINE, prepare.RESCUE_CMDLINE.replace("panic=0", "panic=5"))
            self.assertEqual(prepare.payload(image, info, "ramdisk"), probe)
            self.assertEqual(prepare.payload(image, info, "kernel"), self.kernel)
            # Each ramdisk is accepted only under its own profile.
            for data, profile in ((probe, "usb-acquisition"), (self.ramdisk, "usb-probe")):
                with self.subTest(profile=profile), self.assertRaises(prepare.PreparationError):
                    prepare.assemble_image(self.boot, data, profile)
            with self.assertRaisesRegex(prepare.PreparationError, "Unknown"):
                prepare.assemble_image(self.boot, probe, "rescue")
            with self.private_inputs() as (parent, boot, ramdisk, output):
                ramdisk.write_bytes(probe)
                report = prepare.prepare(boot, ramdisk, output, "usb-probe")
                self.assertEqual(json.loads((output / prepare.MANIFEST_NAME).read_text())["ramdisk_profile"], "usb-probe")
        _, default = prepare.assemble_image(self.boot, self.ramdisk)
        self.assertEqual(default["ramdisk_profile"], "usb-acquisition")
        stderr = io.StringIO()
        with contextlib.redirect_stderr(stderr), self.assertRaises(SystemExit):
            prepare.main(["--boot", "b", "--ramdisk", "r", "--output", "o", "--ramdisk-profile", "rescue"])

    def probe_fixture(self):
        paths = (".", "dev", "init", "proc", "run", "sys", "tmp")
        probe = test_rescue_ramdisk.compressed(test_rescue_ramdisk.archive([
            test_rescue_ramdisk.record(path, test_rescue_ramdisk.elf(b"probe") if path == "init" else b"",
                                       inode=index, directory=path != "init")
            for index, path in enumerate(paths)]))
        dtbo = b"DTBO" * 1000 + b"tail"
        recovery = bytes(test_boot_image.image(recovery=dtbo))
        pins = {"PROBE_RAMDISK_BYTES": len(probe), "PROBE_RAMDISK_SHA256": hashlib.sha256(probe).hexdigest(),
                "RECOVERY_BYTES": len(recovery), "RECOVERY_SHA256": hashlib.sha256(recovery).hexdigest(),
                "RECOVERY_DTBO_BYTES": len(dtbo), "RECOVERY_DTBO_SHA256": hashlib.sha256(dtbo).hexdigest()}
        return probe, dtbo, recovery, pins

    def test_recovery_layout_carries_the_pinned_stock_section(self):
        probe, dtbo, recovery, pins = self.probe_fixture()
        with patch.multiple(prepare, **pins):
            self.assertEqual(prepare.validate_recovery(recovery), dtbo)
            image, report = prepare.assemble_image(self.boot, probe, "usb-probe", dtbo)
            info = prepare.boot_inspector.inspect_image(image)
            self.assertEqual(prepare.payload(image, info, "recovery_dtbo"), dtbo)
            self.assertEqual(prepare.payload(image, info, "ramdisk"), probe)
            self.assertEqual(prepare.payload(image, info, "kernel"), self.kernel)
            self.assertEqual(report["layout"], "recovery")
            self.assertEqual(report["inputs"]["recovery_dtbo"]["sha256"], hashlib.sha256(dtbo).hexdigest())
            # The legacy ID covers the section in mkbootimg's recovery-DTBO slot.
            digest = hashlib.sha1(usedforsecurity=False)
            for item in (self.kernel, probe, b"", b"", dtbo, self.dtb):
                digest.update(item)
                digest.update(struct.pack("<I", len(item)))
            self.assertEqual(image[576:608], digest.digest() + bytes(12))
            _, plain = prepare.assemble_image(self.boot, probe, "usb-probe")
            self.assertEqual(plain["layout"], "boot")
            for data, profile, section in ((self.ramdisk, "usb-acquisition", dtbo), (probe, "usb-probe", dtbo[:-1] + b"x")):
                with self.subTest(profile=profile), self.assertRaises(prepare.PreparationError):
                    prepare.assemble_image(self.boot, data, profile, section)
            with self.assertRaises(prepare.PreparationError):
                prepare.validate_recovery(recovery[:-1] + b"x")
            with self.private_inputs() as (parent, boot, ramdisk, output):
                ramdisk.write_bytes(probe)
                stock = parent / "recovery.img"
                stock.write_bytes(recovery)
                stock.chmod(0o600)
                with self.assertRaisesRegex(prepare.PreparationError, "only for the probe"):
                    prepare.prepare(boot, ramdisk, output, "usb-acquisition", stock)
                self.assertFalse(output.exists())
                prepare.prepare(boot, ramdisk, output, "usb-probe", stock)
                self.assertEqual(json.loads((output / prepare.MANIFEST_NAME).read_text())["layout"], "recovery")

    def test_control_profile_uses_its_own_pin_and_the_recovery_layout(self):
        probe, dtbo, recovery, pins = self.probe_fixture()
        paths = (".", "bin", "bin/titan-control-produce", "bin/titan-rescue-send", "dev", "init",
                 "proc", "run", "sys", "tmp")
        files = {"bin/titan-control-produce": b"producer", "bin/titan-rescue-send": b"sender", "init": b"control"}
        control = test_rescue_ramdisk.compressed(test_rescue_ramdisk.archive([
            test_rescue_ramdisk.record(path, test_rescue_ramdisk.elf(files[path]) if path in files else b"",
                                       inode=index, directory=path not in files)
            for index, path in enumerate(paths)]))
        pins.update({"CONTROL_RAMDISK_BYTES": len(control),
                     "CONTROL_RAMDISK_SHA256": hashlib.sha256(control).hexdigest()})
        with patch.multiple(prepare, **pins):
            image, report = prepare.assemble_image(self.boot, control, "usb-control", dtbo)
            info = prepare.boot_inspector.inspect_image(image)
            self.assertEqual((report["ramdisk_profile"], report["layout"]), ("usb-control", "recovery"))
            self.assertEqual(report["inputs"]["usb_ramdisk"]["format"], "titan-usb-control-initramfs-v1")
            # It restarts by itself, so it shares the probe's command line.
            self.assertEqual(info["cmdline"], prepare.PROBE_CMDLINE)
            self.assertEqual(prepare.payload(image, info, "ramdisk"), control)
            self.assertEqual(prepare.payload(image, info, "recovery_dtbo"), dtbo)
            self.assertEqual(prepare.payload(image, info, "kernel"), self.kernel)
            # Each ramdisk is accepted only under its own profile and pin.
            for data, profile in ((control, "usb-probe"), (control, "usb-acquisition"), (probe, "usb-control")):
                with self.subTest(profile=profile), self.assertRaises(prepare.PreparationError):
                    prepare.assemble_image(self.boot, data, profile)
            with self.private_inputs() as (parent, boot, ramdisk, output):
                ramdisk.write_bytes(control)
                stock = parent / "recovery.img"
                stock.write_bytes(recovery)
                stock.chmod(0o600)
                prepare.prepare(boot, ramdisk, output, "usb-control", stock)
                written = json.loads((output / prepare.MANIFEST_NAME).read_text())
                self.assertEqual((written["ramdisk_profile"], written["layout"]), ("usb-control", "recovery"))
        self.assertEqual(prepare.ramdisk_pin("usb-control"),
                         (3773960, "14a573ef702b5bf1a85abcbdd634cf780d9403c64e8bc5829708810964757d48"))

    def test_probe_can_carry_the_pinned_repository_kernel(self):
        probe, dtbo, recovery, pins = self.probe_fixture()
        image = b"synthetic repository kernel image " * 2048
        kernel = gzip.compress(image, mtime=0)
        pins.update({"REPO_KERNEL_BYTES": len(kernel), "REPO_KERNEL_SHA256": hashlib.sha256(kernel).hexdigest(),
                     "REPO_IMAGE_BYTES": len(image), "REPO_IMAGE_SHA256": hashlib.sha256(image).hexdigest()})
        with patch.multiple(prepare, **pins):
            envelope, report = prepare.assemble_image(self.boot, probe, "usb-probe", dtbo, kernel)
            info = prepare.boot_inspector.inspect_image(envelope)
            # Only the kernel changes; the DTB, ramdisk, section and command line stay.
            self.assertEqual(prepare.payload(envelope, info, "kernel"), kernel)
            self.assertEqual(prepare.payload(envelope, info, "dtb"), self.dtb)
            self.assertEqual(prepare.payload(envelope, info, "ramdisk"), probe)
            self.assertEqual(prepare.payload(envelope, info, "recovery_dtbo"), dtbo)
            self.assertEqual(info["cmdline"], prepare.PROBE_CMDLINE)
            self.assertEqual(report["inputs"]["kernel"], {"bytes": len(kernel), "sha256": hashlib.sha256(kernel).hexdigest(),
                                                          "source": "repository build (kernel.nix)"})
            digest = hashlib.sha1(usedforsecurity=False)
            for item in (kernel, probe, b"", b"", dtbo, self.dtb):
                digest.update(item)
                digest.update(struct.pack("<I", len(item)))
            self.assertEqual(envelope[576:608], digest.digest() + bytes(12))
            _, installed = prepare.assemble_image(self.boot, probe, "usb-probe", dtbo)
            self.assertEqual(installed["inputs"]["kernel"]["source"], "installed boot")
            # Any other profile, a changed stream or a changed decompressed image is refused.
            with self.assertRaisesRegex(prepare.PreparationError, "only with the probe"):
                prepare.assemble_image(self.boot, self.ramdisk, "usb-acquisition", b"", kernel)
            with self.assertRaises(prepare.PreparationError):
                prepare.assemble_image(self.boot, probe, "usb-probe", dtbo, kernel[:-1] + b"x")
            with patch.object(prepare, "REPO_IMAGE_SHA256", "0" * 64), self.assertRaises(prepare.PreparationError):
                prepare.assemble_image(self.boot, probe, "usb-probe", dtbo, kernel)
            # A stream without its gzip trailer still inflates to the whole image,
            # but never reaches its end.
            truncated = kernel[:-8]
            with patch.multiple(prepare, REPO_KERNEL_BYTES=len(truncated),
                                REPO_KERNEL_SHA256=hashlib.sha256(truncated).hexdigest()), \
                    self.assertRaisesRegex(prepare.PreparationError, "image differs"):
                prepare.assemble_image(self.boot, probe, "usb-probe", dtbo, truncated)
            trailing = kernel + b"\0"
            with patch.multiple(prepare, REPO_KERNEL_BYTES=len(trailing),
                                REPO_KERNEL_SHA256=hashlib.sha256(trailing).hexdigest()), \
                    self.assertRaises(prepare.PreparationError):
                prepare.assemble_image(self.boot, probe, "usb-probe", dtbo, trailing)
            # The same image in a different gzip stream fails the stream pin itself.
            recompressed = gzip.compress(image, compresslevel=1, mtime=0)
            self.assertNotEqual(recompressed, kernel)
            with self.assertRaisesRegex(prepare.PreparationError, "pinned repository build"):
                prepare.assemble_image(self.boot, probe, "usb-probe", dtbo, recompressed)
            with self.assertRaisesRegex(prepare.PreparationError, "recovery layout"):
                prepare.assemble_image(self.boot, probe, "usb-probe", b"", kernel)
            real_assemble = prepare.assemble_image
            with self.private_inputs() as (parent, boot, ramdisk, output):
                ramdisk.write_bytes(probe)
                stock = parent / "recovery.img"
                stock.write_bytes(recovery)
                stock.chmod(0o600)
                kernel_file = parent / "Image.gz"
                kernel_file.write_bytes(kernel)
                kernel_file.chmod(0o600)
                for profile, section in (("usb-control", stock), ("usb-probe", None)):
                    with self.subTest(profile=profile), \
                            self.assertRaisesRegex(prepare.PreparationError, "only for the probe in the recovery layout"):
                        prepare.prepare(boot, ramdisk, output, profile, section, kernel_file)
                    self.assertFalse(output.exists())

                def alter_kernel(*args):
                    result = real_assemble(*args)
                    with kernel_file.open("r+b") as handle:
                        handle.write(kernel[:1])
                    return result
                with patch.object(prepare, "assemble_image", side_effect=alter_kernel), \
                        self.assertRaisesRegex(prepare.PreparationError, "changed during"):
                    prepare.prepare(boot, ramdisk, output, "usb-probe", stock, kernel_file)
                self.assertFalse(output.exists())
                # A change after the first recheck, while outputs are written, is
                # caught by the recheck before publication.
                kernel_file.write_bytes(kernel)
                kernel_file.chmod(0o600)
                real_write = prepare.write_private

                def alter_while_writing(*args):
                    with kernel_file.open("r+b") as handle:
                        handle.write(kernel[:1])
                    return real_write(*args)
                with patch.object(prepare, "write_private", side_effect=alter_while_writing), \
                        self.assertRaisesRegex(prepare.PreparationError, "changed during"):
                    prepare.prepare(boot, ramdisk, output, "usb-probe", stock, kernel_file)
                self.assertFalse((output / prepare.IMAGE_NAME).exists())
                os.rmdir(output)
                kernel_file.unlink()
                kernel_file.write_bytes(kernel)
                kernel_file.chmod(0o600)
                prepare.prepare(boot, ramdisk, output, "usb-probe", stock, kernel_file)
                written = json.loads((output / prepare.MANIFEST_NAME).read_text())
                self.assertEqual(written["inputs"]["kernel"]["source"], "repository build (kernel.nix)")
        self.assertEqual((prepare.REPO_KERNEL_BYTES, prepare.REPO_KERNEL_SHA256, prepare.REPO_IMAGE_BYTES,
                          prepare.REPO_IMAGE_SHA256),
                         (9532189, "cd370ef6438dc4e76ddc4477ed1392675cb034b6f737f682f755cfec445d5f0b",
                          27197452, "34a45c8ac5e1e7574deaf97e8fbc536e062cc7a50cca7e0af906d77c818d2570"))

    def test_flash_profiles_agree_with_the_envelope_pins(self):
        # Each recovery-layout envelope is a header page plus page-padded kernel,
        # ramdisk, recovery-DTBO and DTB sections; the flash helper pins its size.
        # Fresh module copies: setUp patches the pins of the shared module.
        modules = {}
        for name, path in (("flash", SCRIPT.with_name("flash-recovery.py")), ("real", SCRIPT)):
            spec = importlib.util.spec_from_file_location(f"titan_pin_check_{name}", path)
            modules[name] = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(modules[name])
        flash, real = modules["flash"], modules["real"]
        pages = lambda size: size + (-size) % real.PAGE_SIZE
        tail = pages(real.RECOVERY_DTBO_BYTES) + pages(real.DTB_BYTES)
        expected = {"rescue-probe": (real.KERNEL_BYTES, real.PROBE_RAMDISK_BYTES),
                    "repo-kernel-probe": (real.REPO_KERNEL_BYTES, real.PROBE_RAMDISK_BYTES),
                    "control-acquisition": (real.KERNEL_BYTES, real.CONTROL_RAMDISK_BYTES)}
        for name, (kernel, ramdisk) in expected.items():
            with self.subTest(profile=name):
                self.assertEqual(flash.PROFILES[name]["source_bytes"],
                                 real.PAGE_SIZE + pages(kernel) + pages(ramdisk) + tail)

    @unittest.skipUnless(os.environ.get("TITAN_MKBOOTIMG_SOURCE"), "pinned mkbootimg source required for independent assembly comparison")
    def test_recovery_layout_byte_identical_to_pinned_mkbootimg(self):
        probe, dtbo, recovery, pins = self.probe_fixture()
        source = Path(os.environ["TITAN_MKBOOTIMG_SOURCE"])
        script = source / "mkbootimg.py" if source.is_dir() else source
        with patch.multiple(prepare, **pins):
            expected, _ = prepare.assemble_image(self.boot, probe, "usb-probe", dtbo)
        with tempfile.TemporaryDirectory(prefix="titan-synthetic-mkbootimg-") as temporary:
            parent = Path(temporary)
            for name, data in (("kernel", self.kernel), ("ramdisk", probe), ("dtb", self.dtb), ("dtbo", dtbo)):
                (parent / name).write_bytes(data)
            output = parent / "reference.img"
            result = subprocess.run(
                [sys.executable, str(script), "--kernel", str(parent / "kernel"),
                 "--ramdisk", str(parent / "ramdisk"), "--dtb", str(parent / "dtb"),
                 "--recovery_dtbo", str(parent / "dtbo"),
                 "--cmdline", prepare.PROBE_CMDLINE, "--header_version", "2", "--os_version", "10",
                 "--os_patch_level", "2025-08", "--base", "0x40000000", "--kernel_offset", "0x80000",
                 "--ramdisk_offset", "0x15000000", "--second_offset", "0xf00000",
                 "--tags_offset", "0x14000000", "--pagesize", "2048", "--dtb_offset", "0x14000000",
                 "--output", str(output)], capture_output=True, timeout=15, check=False,
                env={**os.environ, "PYTHONDONTWRITEBYTECODE": "1"})
            self.assertEqual(result.returncode, 0, result.stderr.decode(errors="replace"))
            self.assertEqual(output.read_bytes(), expected)

    @unittest.skipUnless(os.environ.get("TITAN_MKBOOTIMG_SOURCE"), "pinned mkbootimg source required for independent assembly comparison")
    def test_byte_identical_to_pinned_mkbootimg(self):
        source = Path(os.environ["TITAN_MKBOOTIMG_SOURCE"])
        script = source / "mkbootimg.py" if source.is_dir() else source
        expected, _ = prepare.assemble_image(self.boot, self.ramdisk)
        with tempfile.TemporaryDirectory(prefix="titan-synthetic-mkbootimg-") as temporary:
            parent = Path(temporary)
            for name, data in (("kernel", self.kernel), ("ramdisk", self.ramdisk), ("dtb", self.dtb)):
                (parent / name).write_bytes(data)
                (parent / name).chmod(0o600)
            output = parent / "reference.img"
            result = subprocess.run(
                [sys.executable, str(script), "--kernel", str(parent / "kernel"),
                 "--ramdisk", str(parent / "ramdisk"), "--dtb", str(parent / "dtb"),
                 "--cmdline", prepare.RESCUE_CMDLINE, "--header_version", "2", "--os_version", "10",
                 "--os_patch_level", "2025-08", "--base", "0x40000000", "--kernel_offset", "0x80000",
                 "--ramdisk_offset", "0x15000000", "--second_offset", "0xf00000",
                 "--tags_offset", "0x14000000", "--pagesize", "2048", "--dtb_offset", "0x14000000",
                 "--output", str(output)], capture_output=True, timeout=15, check=False,
                env={**os.environ, "PYTHONDONTWRITEBYTECODE": "1"})
            self.assertEqual(result.returncode, 0, result.stderr.decode(errors="replace"))
            self.assertEqual(output.read_bytes(), expected)


if __name__ == "__main__":
    unittest.main()
