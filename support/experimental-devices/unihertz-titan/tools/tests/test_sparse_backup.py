"""Host-only fixtures. Optional real ext4 integration: run this file --integration."""

import argparse
import contextlib
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import shutil
import stat
import struct
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch


SCRIPT = Path(__file__).resolve().parents[1] / "verify-sparse-backup.py"
SPEC = importlib.util.spec_from_file_location("sparse_backup", SCRIPT)
backup = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(backup)
SIZE = 32 * 1024 * 1024


def filesystem_fixture(size=SIZE, *, state=1, incompat=0x40, blocks=None):
    # Deliberately minimal superblock: real filesystem checking is exercised by
    # the separately invoked integration fixture, never faked as production proof.
    data = bytearray(size)
    struct.pack_into("<I", data, 1024 + 4, size // 4096 if blocks is None else blocks)
    struct.pack_into("<II", data, 1024 + 20, 0, 2)
    struct.pack_into("<H", data, 1024 + 56, 0xEF53)
    struct.pack_into("<H", data, 1024 + 58, state)
    struct.pack_into("<I", data, 1024 + 96, incompat)
    # A sizeable interior zero gap exercises sparse allocation without assuming
    # a particular ratio for tiny files or the host filesystem's extent size.
    data[size // 2:size // 2 + 4] = b"test"
    return bytes(data)


def fake_executable(directory, name, body):
    path = directory / name
    path.write_text(f"#!{sys.executable}\n" + body + "\n")
    path.chmod(0o700)
    return str(path)


class WorkflowTests(unittest.TestCase):
    def run_fixture(self, base, data=None, zstd_body=None, fsck_body=None, extra=()):
        archive = base / "private archive.zst"
        archive.write_bytes(filesystem_fixture() if data is None else data)
        zstd = fake_executable(base, "fake zstd", zstd_body or (
            "import sys; assert sys.argv[1:] == ['-d', '-c']; "
            "sys.stdout.buffer.write(sys.stdin.buffer.read())"
        ))
        fsck = fake_executable(base, "fake e2fsck", fsck_body or (
            "import sys; assert sys.argv[1] == '-fn' and len(sys.argv) == 3; "
            "assert sys.argv[2].endswith('filesystem.img.part'); "
            "sys.stderr.write('fixture e2fsck version\\n')"
        ))
        output = base / "checked"
        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()), \
                patch.object(backup, "check_sparse_support", return_value={"fixture": True}):
            code = backup.main([
                str(archive), "--output", str(output), "--expected-bytes", str(SIZE),
                "--max-allocated-bytes", str(SIZE), "--min-free-bytes", "0",
                "--timeout", "5", "--zstd", zstd, "--e2fsck", fsck, *extra,
            ])
        manifest = json.loads((output / "manifest.json").read_text()) if output.exists() else None
        return code, output, manifest

    def test_exact_sparse_image_private_publication_hashes_and_readonly_check(self):
        with tempfile.TemporaryDirectory() as temporary:
            code, output, manifest = self.run_fixture(Path(temporary))
            self.assertEqual(code, 0)
            image = output / "filesystem.img"
            self.assertEqual(image.read_bytes(), filesystem_fixture())
            self.assertEqual(image.stat().st_size, SIZE)
            self.assertLessEqual(image.stat().st_blocks * 512, manifest["max_allocated_bytes"])
            self.assertLess(manifest["data_bytes_written"], SIZE)
            self.assertEqual(manifest["decoded_sha256"], hashlib.sha256(image.read_bytes()).hexdigest())
            self.assertEqual(manifest["readback_sha256"], manifest["decoded_sha256"])
            self.assertEqual(manifest["status"], "complete")
            self.assertEqual(manifest["ext4"]["logical_bytes"], SIZE)
            self.assertEqual(manifest["e2fsck_exit_code"], 0)
            self.assertEqual(stat.S_IMODE(output.stat().st_mode), 0o700)
            for path in output.iterdir():
                self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
                self.assertFalse(path.name.endswith(".part"))

    def test_short_extra_corrupt_dirty_or_wrong_geometry_never_publish(self):
        cases = [
            (filesystem_fixture()[:-1], "short"),
            (filesystem_fixture() + b"x", "byte bound"),
            (bytes(SIZE), "superblock"),
            (filesystem_fixture(state=0), "dirty"),
            (filesystem_fixture(state=3), "dirty"),
            (filesystem_fixture(incompat=0x44), "recovery"),
            (filesystem_fixture(blocks=SIZE // 4096 - 1), "geometry"),
        ]
        for data, message in cases:
            with self.subTest(message=message), tempfile.TemporaryDirectory() as temporary:
                code, output, manifest = self.run_fixture(Path(temporary), data=data)
                self.assertEqual(code, 1)
                self.assertEqual(manifest["status"], "failed")
                self.assertIn(message, manifest["error"])
                self.assertFalse((output / "filesystem.img").exists())
                self.assertFalse(list(output.glob("*.part")))

    def test_failed_or_warning_decompressor_never_publishes(self):
        for trailer, message in (("sys.exit(2)", "exit 2"),
                                 ("sys.stderr.write('warning\\n')", "diagnostics")):
            with self.subTest(trailer=trailer), tempfile.TemporaryDirectory() as temporary:
                code, output, manifest = self.run_fixture(
                    Path(temporary), zstd_body="import sys; sys.stdout.buffer.write(sys.stdin.buffer.read()); " + trailer,
                )
                self.assertEqual(code, 1)
                self.assertIn(message, manifest["error"])
                self.assertFalse((output / "filesystem.img").exists())
                self.assertTrue((output / "zstd.stderr").is_file())

    def test_fsck_errors_or_modifications_reject_image_and_keep_private_logs(self):
        cases = (
            ("import sys; sys.stdout.write('repair required\\n'); sys.exit(4)", "exit 4"),
            ("import sys; f=open(sys.argv[2], 'r+b'); f.write(b'changed'); f.close()", "changed"),
        )
        for body, message in cases:
            with self.subTest(message=message), tempfile.TemporaryDirectory() as temporary:
                code, output, manifest = self.run_fixture(Path(temporary), fsck_body=body)
                self.assertEqual(code, 1)
                self.assertIn(message, manifest["error"])
                self.assertFalse((output / "filesystem.img").exists())
                self.assertTrue((output / "e2fsck.stdout").is_file())
                self.assertTrue((output / "e2fsck.stderr").is_file())

    def test_data_budget_and_free_space_reserve_fail_closed(self):
        with tempfile.TemporaryDirectory() as temporary:
            code, output, manifest = self.run_fixture(Path(temporary), extra=["--max-allocated-bytes", "1"])
            self.assertEqual(code, 1)
            self.assertIn("budget", manifest["error"])
            self.assertFalse((output / "filesystem.img").exists())
        with tempfile.TemporaryDirectory() as temporary, patch.object(backup, "free_bytes", return_value=0):
            code, output, manifest = self.run_fixture(Path(temporary), extra=["--min-free-bytes", "1"])
            self.assertEqual(code, 1)
            self.assertIn("reserve", manifest["error"])
            self.assertFalse((output / "filesystem.img").exists())

    def test_timeout_removes_only_owned_partial(self):
        with tempfile.TemporaryDirectory() as temporary:
            code, output, manifest = self.run_fixture(
                Path(temporary), zstd_body="import time; time.sleep(10)", extra=["--timeout", "0.05"],
            )
            self.assertEqual(code, 1)
            self.assertIn("timed out", manifest["error"])
            self.assertFalse((output / "filesystem.img.part").exists())

    def test_changed_archive_failed_readback_and_final_reserve_do_not_publish(self):
        with tempfile.TemporaryDirectory() as temporary:
            code, output, manifest = self.run_fixture(Path(temporary), zstd_body=(
                "import sys; from pathlib import Path; "
                "sys.stdout.buffer.write(sys.stdin.buffer.read()); "
                "Path(__file__).with_name('private archive.zst').touch()"
            ))
            self.assertEqual(code, 1)
            self.assertIn("archive changed", manifest["error"])
            self.assertFalse((output / "filesystem.img").exists())
        with tempfile.TemporaryDirectory() as temporary, \
                patch.object(backup, "reread_hash", return_value="0" * 64):
            code, output, manifest = self.run_fixture(Path(temporary))
            self.assertEqual(code, 1)
            self.assertIn("readback SHA-256", manifest["error"])
            self.assertFalse((output / "filesystem.img").exists())
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)

            def remaining_space(_):
                return 0 if (base / "checked/e2fsck.stdout").exists() else 1024 * 1024 * 1024

            with patch.object(backup, "free_bytes", side_effect=remaining_space):
                code, output, manifest = self.run_fixture(base)
            self.assertEqual(code, 1)
            self.assertIn("reserve", manifest["error"])
            self.assertFalse((output / "filesystem.img").exists())


class BoundaryTests(unittest.TestCase):
    def test_nonregular_and_symlink_inputs_are_rejected_without_reading(self):
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            target = base / "archive"
            target.write_bytes(b"fixture")
            alias = base / "alias"
            alias.symlink_to(target)
            fifo = base / "fifo"
            os.mkfifo(fifo)
            for source in (base, alias, fifo, Path("/dev/null")):
                with self.subTest(source=source), self.assertRaises((backup.ValidationError, OSError)):
                    backup.open_archive(source)

    def test_repository_and_existing_outputs_are_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            repo = base / "repo"
            repo.mkdir()
            (repo / ".git").write_text("gitdir: /fixture")
            alias = base / "alias"
            alias.symlink_to(repo)
            for output in (repo / "private", alias / "private"):
                with self.subTest(output=output), self.assertRaisesRegex(ValueError, "Git"):
                    backup.prepare_output(str(output))
            with self.assertRaises(FileExistsError):
                backup.prepare_output(str(base))

    def test_existing_partial_and_destination_are_preserved(self):
        for name in ("filesystem.img.part", "filesystem.img"):
            with self.subTest(name=name), tempfile.TemporaryDirectory() as temporary:
                base = Path(temporary)
                archive = base / "archive"
                archive.write_bytes(filesystem_fixture())
                output = base / "output"
                output.mkdir()
                existing = output / name
                existing.write_bytes(b"existing")
                source, metadata = backup.open_archive(archive)
                try:
                    with patch.object(backup, "run_stream") as run:
                        with self.assertRaises((backup.ValidationError, FileExistsError)):
                            backup.validate_archive(
                                archive, output, expected=SIZE, allocation_budget=65536, minimum_free=0,
                                timeout=1, zstd="unused", e2fsck="unused", source=source, source_metadata=metadata,
                            )
                        run.assert_not_called()
                    self.assertEqual(existing.read_bytes(), b"existing")
                finally:
                    os.close(source)

    def test_sparse_runs_across_chunk_boundaries_and_trailing_hole(self):
        data = bytes(4096) + b"x" * 4096 + bytes(8192)
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "image"
            descriptor = os.open(path, os.O_RDWR | os.O_CREAT | os.O_EXCL, 0o600)
            try:
                writer = backup.SparseWriter(descriptor, Path(temporary), len(data), 65536, 0)
                for offset in range(0, len(data), 997):
                    writer.feed(data[offset:offset + 997])
                writer.finish()
                self.assertEqual(writer.data_bytes, 4096)
                self.assertEqual(backup.reread_hash(descriptor, len(data), 2), hashlib.sha256(data).hexdigest())
                self.assertEqual(path.read_bytes(), data)
                os.ftruncate(descriptor, len(data) - 1)
                with self.assertRaisesRegex(backup.ValidationError, "short"):
                    backup.reread_hash(descriptor, len(data), 2)
                os.ftruncate(descriptor, len(data) + 1)
                with self.assertRaisesRegex(backup.ValidationError, "exceeded"):
                    backup.reread_hash(descriptor, len(data), 2)
            finally:
                os.close(descriptor)

    def test_actual_allocation_budget_and_diagnostic_bounds(self):
        with patch.object(backup.os, "fstat") as metadata:
            metadata.return_value.st_blocks = 129
            with self.assertRaisesRegex(backup.ValidationError, "physical allocation"):
                backup.check_storage(Path("/"), 1, 65536, 0)
        with self.assertRaisesRegex(backup.ValidationError, "byte bound"):
            backup.run_stream(
                [sys.executable, "-c", "import sys; sys.stderr.write('x' * 2000000)"], 2,
            )

    def test_free_space_checks_reserve_bounded_logs_and_manifests(self):
        with patch.object(backup.os, "fstat") as metadata:
            metadata.return_value.st_blocks = 0
            with patch.object(backup, "free_bytes", return_value=backup.OUTPUT_OVERHEAD + 999):
                with self.assertRaisesRegex(backup.ValidationError, "reserve"):
                    backup.check_storage(Path("/"), 1, 65536, 1000)
            with patch.object(backup, "free_bytes", return_value=backup.OUTPUT_OVERHEAD + 1000):
                backup.check_storage(Path("/"), 1, 65536, 1000)

    def test_sparse_capability_probe_is_bounded_private_and_cleans_own_scratch(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            evidence = backup.check_sparse_support(directory, 0)
            self.assertEqual(evidence["maximum_scratch_bytes"], 32 * 1024 * 1024)
            self.assertLessEqual(evidence["seek_write_allocated_bytes"], backup.LOG_LIMIT)
            self.assertLessEqual(evidence["trailing_truncate_allocated_bytes"], backup.LOG_LIMIT)
            self.assertFalse(list(directory.iterdir()))
            with patch.object(backup, "free_bytes", return_value=backup.SPARSE_PROBE_BYTES):
                with self.assertRaisesRegex(backup.ValidationError, "free space"):
                    backup.check_sparse_support(directory, 0)
            with patch.object(backup.os, "fstat") as metadata:
                metadata.return_value.st_blocks = backup.SPARSE_PROBE_BYTES // 512
                with self.assertRaisesRegex(backup.ValidationError, "sparse zero gap"):
                    backup.check_sparse_support(directory, 0)
            self.assertFalse(list(directory.iterdir()))

    def test_invalid_limits_fail_before_opening_input(self):
        for extra in (["--expected-bytes", "1023"], ["--expected-bytes", "0"],
                      ["--max-allocated-bytes", "0"], ["--min-free-bytes", "-1"],
                      ["--expected-bytes", "4096", "--max-allocated-bytes", "4095"],
                      ["--timeout", "nan"], ["--timeout", "0"]):
            with self.subTest(extra=extra), patch.object(backup, "open_archive") as open_source:
                with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
                    backup.main(["unused", "--expected-bytes", str(SIZE),
                                 "--max-allocated-bytes", "65536", "--min-free-bytes", "0", *extra])
                open_source.assert_not_called()


def integration(argv):
    """Create only local synthetic files; check a real clean and dirty ext4 archive."""
    parser = argparse.ArgumentParser(description=integration.__doc__)
    parser.add_argument("--integration", action="store_true", required=True)
    parser.add_argument("--e2fsprogs-bin", default="/opt/homebrew/opt/e2fsprogs/sbin")
    parser.add_argument("--zstd", default="zstd")
    parser.add_argument("--output", help="new private fixture directory outside Git")
    args = parser.parse_args(argv)
    tools = {name: backup.executable(str(Path(args.e2fsprogs_bin) / name))
             for name in ("mke2fs", "e2image", "debugfs", "e2fsck")}
    zstd = backup.executable(args.zstd)
    previous_umask = os.umask(0o077)
    try:
        output = backup.prepare_output(args.output)
        source, sparse = output / "source.ext4", output / "e2image.ext4"
        payload = output / "fixture.txt"
        payload.write_bytes(b"Titan synthetic inactive ext4 backup fixture\n")
        size = 32 * 1024 * 1024
        with source.open("xb") as stream:
            stream.truncate(size)

        def run(command):
            return subprocess.run(command, check=True, capture_output=True, timeout=60).stdout

        run([tools["mke2fs"], "-q", "-t", "ext4", "-F", "-b", "4096",
             "-E", "lazy_itable_init=0,lazy_journal_init=0", str(source)])
        quoted_payload = str(payload).replace("\\", "\\\\").replace('"', '\\"')
        run([tools["debugfs"], "-w", "-R", f'write "{quoted_payload}" /fixture.txt', str(source)])
        run([tools["e2image"], "-ra", str(source), str(sparse)])
        archive = output / "clean.ext4.zst"
        with archive.open("xb") as sink:
            subprocess.run([zstd, "-q", "-c", str(sparse)], stdout=sink, check=True, timeout=60)
        common = ["--expected-bytes", str(size), "--max-allocated-bytes", str(8 * 1024 * 1024),
                  "--min-free-bytes", str(64 * 1024 * 1024), "--timeout", "60",
                  "--zstd", zstd, "--e2fsck", tools["e2fsck"]]
        if backup.main([str(archive), "--output", str(output / "clean-verified"), *common]) != 0:
            raise AssertionError("Real clean ext4 fixture failed validation")
        restored = output / "clean-verified/filesystem.img"
        if run([tools["debugfs"], "-R", "cat /fixture.txt", str(restored)]) != payload.read_bytes():
            raise AssertionError("Real e2image fixture did not preserve file content")
        dirty = output / "dirty.ext4"
        shutil.copyfile(restored, dirty)
        run([tools["debugfs"], "-w", "-R", "ssv state 0", str(dirty)])
        dirty_archive = output / "dirty.ext4.zst"
        with dirty_archive.open("xb") as sink:
            subprocess.run([zstd, "-q", "-c", str(dirty)], stdout=sink, check=True, timeout=60)
        if backup.main([str(dirty_archive), "--output", str(output / "dirty-rejected"), *common]) != 1:
            raise AssertionError("Dirty ext4 fixture was accepted")
        if (output / "dirty-rejected/filesystem.img").exists():
            raise AssertionError("Dirty ext4 fixture was published")
        print(f"Real ext4 integration passed; private synthetic fixtures: {output}")
        return 0
    finally:
        os.umask(previous_umask)


if __name__ == "__main__":
    if "--integration" in sys.argv:
        sys.exit(integration(sys.argv[1:]))
    unittest.main()
