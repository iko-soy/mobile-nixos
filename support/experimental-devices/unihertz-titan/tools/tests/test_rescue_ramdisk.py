#!/usr/bin/env python3
"""Host-only regressions for the exact rescue archive profile; no extraction."""

import contextlib
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import stat
import struct
import tempfile
import unittest
from unittest.mock import patch
import zlib


SPEC = importlib.util.spec_from_file_location("rescue_ramdisk", Path(__file__).resolve().parents[1] / "inspect-rescue-ramdisk.py")
ramdisk = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(ramdisk)

PATHS = (".", "bin", "bin/busybox", "bin/e2image", "bin/titan-block-produce",
         "bin/titan-rescue-send", "bin/zstd", "dev", "init", "proc", "run", "sys", "tmp")
FILE_PATHS = tuple(path for path in PATHS if path == "init" or path.startswith("bin/"))


def elf(tag=b"fixture"):
    result = bytearray(512)
    result[:16] = b"\x7fELF\x02\x01\x01" + bytes(9)
    struct.pack_into("<HHIQQQIHHHHHH", result, 16, 2, 183, 1, 0x400100, 64, 0, 0, 64, 56, 2, 0, 0, 0)
    struct.pack_into("<IIQQQQQQ", result, 64, 1, 5, 0, 0x400000, 0x400000, len(result), len(result), 4096)
    struct.pack_into("<IIQQQQQQ", result, 120, 0x6474E551, 6, 0, 0, 0, 0, 0, 16)
    result[256:260] = bytes.fromhex("c0035fd6")  # AArch64 ret; never executed.
    result[264:264 + len(tag)] = tag
    return bytes(result)


def record(name, payload=b"", *, inode=0, directory=False, fields=None):
    encoded = name.encode("ascii") + b"\0"
    mode = (stat.S_IFDIR | (0o1777 if name == "tmp" else 0o755)) if directory else stat.S_IFREG | 0o555
    values = [inode, mode, 0, 0, 2 if directory else 1, 1, len(payload), 0, 0, 0, 0, len(encoded), 0]
    if fields:
        for index, value in fields.items():
            values[index] = value
    result = b"070701" + b"".join(f"{value:08x}".encode() for value in values) + encoded
    result += bytes((-len(result)) % 4)
    result += payload
    return result + bytes((-len(result)) % 4)


def archive(records=None):
    if records is None:
        records = [record(path, elf(path.encode()) if path in FILE_PATHS else b"",
                          inode=index, directory=path not in FILE_PATHS)
                   for index, path in enumerate(PATHS)]
    trailer = record("TRAILER!!!", fields={1: 0, 4: 1, 5: 0})
    result = b"".join(records) + trailer
    return result + bytes((-len(result)) % 512)


def compressed(raw):
    encoder = zlib.compressobj(9, zlib.DEFLATED, -zlib.MAX_WBITS)
    return (bytes.fromhex("1f8b0800000000000203") + encoder.compress(raw) + encoder.flush() +
            struct.pack("<II", zlib.crc32(raw), len(raw) & 0xFFFFFFFF))


def fixture():
    """Independent synthetic fixture shared with private boot-package tests."""
    data = compressed(archive())
    archive_manifest = f"{hashlib.sha256(data).hexdigest()}  initramfs.cpio.gz\n".encode()
    payload_manifest = b"".join(f"{hashlib.sha256(elf(path.encode())).hexdigest()}  {path}\n".encode()
                                for path in FILE_PATHS)
    return data, archive_manifest, payload_manifest


class RamdiskTests(unittest.TestCase):
    def reject(self, raw, message=None):
        with self.assertRaisesRegex(ramdisk.RamdiskFormatError, message or "."):
            ramdisk.inspect_ramdisk(compressed(raw))

    def changed_record(self, path, **changes):
        return archive([record(name, changes.get("payload", elf(name.encode())) if name == path else
                               elf(name.encode()) if name in FILE_PATHS else b"",
                               inode=index, directory=name not in FILE_PATHS,
                               fields=changes.get("fields") if name == path else None)
                        for index, name in enumerate(PATHS)])

    def test_exact_synthetic_profile_and_both_manifests(self):
        data, sums, payloads = fixture()
        report = ramdisk.inspect_ramdisk(data)
        self.assertEqual(report["compressed_bytes"], len(data))
        self.assertEqual([item["path"] for item in report["entries"]], list(PATHS))
        self.assertEqual(len(report["payload_sha256"]), 6)
        self.assertTrue(ramdisk.verify_manifests(report, sums, payloads))
        self.assertFalse(report["validation"]["manifests_verified"])
        self.assertFalse(report["validation"]["bootability_verified"])
        self.assertFalse(report["validation"]["code_provenance_verified"])

    def test_gzip_concatenation_trailing_data_and_corruption(self):
        data = fixture()[0]
        for changed in (data + data, data + b"\0", data[:-1], data[:-8] + bytes(8),
                        bytes([data[0] ^ 1]) + data[1:], data[:3] + b"\x08" + data[4:]):
            with self.subTest(size=len(changed)), self.assertRaises(ramdisk.RamdiskFormatError):
                ramdisk.inspect_ramdisk(changed)

    def test_compressed_and_decompressed_bounds(self):
        data = fixture()[0]
        with patch.object(ramdisk, "MAX_COMPRESSED", len(data) - 1):
            with self.assertRaisesRegex(ramdisk.RamdiskFormatError, "Compressed"):
                ramdisk.inspect_ramdisk(data)
        with patch.object(ramdisk, "MAX_UNCOMPRESSED", 1024):
            with self.assertRaisesRegex(ramdisk.RamdiskFormatError, "Decompressed"):
                ramdisk.inspect_ramdisk(compressed(bytes(1024 * 1024)))

    def test_uncompressed_second_archive_and_noncanonical_padding(self):
        raw = archive()
        self.reject(raw + raw, "Extra archive")
        self.reject(raw + bytes(512), "Extra archive")
        self.reject(raw[:-1] + b"x", "padding")
        self.reject(raw[:-1], "padding")

    def test_missing_duplicate_extra_and_unsafe_names(self):
        records = [record(path, elf(path.encode()) if path in FILE_PATHS else b"",
                          inode=index, directory=path not in FILE_PATHS)
                   for index, path in enumerate(PATHS)]
        self.reject(archive(records[:-1]))
        self.reject(archive(records + [record("extra", elf())]))
        for name in ("init", "/init", "../init", "./bin", "bin//busybox", "bin/../init"):
            altered = records.copy()
            altered[1] = record(name, inode=1, directory=True)
            with self.subTest(name=name):
                self.reject(archive(altered), "Unexpected")

    def test_forbidden_file_types_modes_ownership_and_hardlinks(self):
        for field, value in ((1, stat.S_IFLNK | 0o777), (1, stat.S_IFCHR | 0o555),
                             (1, stat.S_IFREG | 0o755), (1, stat.S_IFREG | 0o4555),
                             (2, 1), (3, 1), (4, 2), (0, 0), (5, 2), (7, 1), (12, 1)):
            with self.subTest(field=field, value=value):
                self.reject(self.changed_record("init", fields={field: value}))

    def test_directory_content_and_tmp_permissions(self):
        self.reject(self.changed_record("tmp", payload=b"x"), "directory")
        self.reject(self.changed_record("tmp", payload=b"", fields={1: stat.S_IFDIR | 0o755}))

    def test_malformed_newc_header_name_and_lengths(self):
        raw = archive()
        self.reject(b"070702" + raw[6:])
        self.reject(raw[:6] + b"-0000001" + raw[14:])
        self.reject(raw[:94] + b"ffffffff" + raw[102:])
        self.reject(raw[:111] + b"x" + raw[112:])
        self.reject(raw[:110])
        self.reject(self.changed_record("init", fields={6: 0xFFFFFFFF}), "Truncated")

    def test_init_must_be_static_aarch64_not_a_script_or_other_elf(self):
        self.reject(self.changed_record("init", payload=b"#!/bin/sh\n"), "ELF")
        for offset, value in ((4, 1), (5, 2), (7, 3), (16, 3), (18, 62)):
            changed = bytearray(elf())
            changed[offset] = value
            with self.subTest(offset=offset):
                self.reject(self.changed_record("init", payload=bytes(changed)))

    def test_dynamic_interpreter_bad_entry_stack_and_segments(self):
        changes = ((64, "<I", 2), (64, "<I", 3), (24, "<Q", 0x500000),
                   (68, "<I", 7), (124, "<I", 7), (96, "<Q", 513),
                   (104, "<Q", 511), (112, "<Q", 3), (32, "<Q", 500),
                   (56, "<H", 65535), (40, "<Q", 100), (60, "<H", 1))
        for offset, fmt, value in changes:
            changed = bytearray(elf())
            struct.pack_into(fmt, changed, offset, value)
            with self.subTest(offset=offset, value=value):
                self.reject(self.changed_record("init", payload=bytes(changed)))

    def test_payload_elf_validation_applies_to_all_six_files(self):
        for path in FILE_PATHS:
            with self.subTest(path=path):
                self.reject(self.changed_record(path, payload=b"not ELF"))

    def test_manifest_mismatch_missing_duplicate_extra_and_unsafe_path(self):
        data, sums, payloads = fixture()
        report = ramdisk.inspect_ramdisk(data)
        for changed in (payloads.replace(payloads[:1], b"0" if payloads[:1] != b"0" else b"1", 1),
                        b"\n".join(payloads.split(b"\n")[1:]), payloads + payloads.splitlines(keepends=True)[0],
                        payloads.replace(b"bin/busybox", b"../busybox"), payloads.replace(b"\n", b"\r\n"),
                        payloads[:-1], payloads + b"\n"):
            with self.subTest(manifest=changed[:12]), self.assertRaises(ramdisk.RamdiskFormatError):
                ramdisk.verify_manifests(report, sums, changed)
        with self.assertRaisesRegex(ramdisk.RamdiskFormatError, "Archive manifest"):
            ramdisk.verify_manifests(report, b"0" * 64 + b"  initramfs.cpio.gz\n", payloads)

    def test_readonly_cli_checks_manifests_without_extracting(self):
        data, sums, payloads = fixture()
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            for name, contents in (("ramdisk.gz", data), ("SHA256SUMS", sums), ("payload-SHA256SUMS", payloads)):
                (root / name).write_bytes(contents)
            with contextlib.redirect_stdout(io.StringIO()) as stdout:
                code = ramdisk.main([str(root / "ramdisk.gz"), "--sha256sums", str(root / "SHA256SUMS"),
                                     "--payload-sha256sums", str(root / "payload-SHA256SUMS"), "--json"])
            self.assertEqual(code, 0)
            self.assertTrue(json.loads(stdout.getvalue())["validation"]["manifests_verified"])
            self.assertEqual(len(list(root.iterdir())), 3)

    def test_nonregular_symlink_and_oversized_inputs_reject_before_open(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "regular").write_bytes(b"abcd")
            (root / "link").symlink_to(root / "regular")
            os.mkfifo(root / "fifo")
            for path in (root, root / "link", root / "fifo", root / "regular"):
                with self.subTest(path=path), patch.object(ramdisk.os, "open") as opened:
                    with self.assertRaises(ramdisk.RamdiskFormatError):
                        ramdisk.read_regular(path, 3)
                    opened.assert_not_called()

    def test_changed_file_during_read_is_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "input"
            path.write_bytes(b"abc")
            original = os.read
            def growing(descriptor, count):
                result = original(descriptor, count)
                if result:
                    path.write_bytes(b"changed input")
                return result
            with patch.object(ramdisk.os, "read", side_effect=growing):
                with self.assertRaisesRegex(ramdisk.RamdiskFormatError, "changed"):
                    ramdisk.read_regular(path, 32)


if __name__ == "__main__":
    unittest.main()
