"""GPT boundary tests with independently assembled disk-edge fixtures."""

import importlib.util
import json
import os
from pathlib import Path
import struct
import subprocess
import sys
import tempfile
import unittest
import uuid
import zlib


SCRIPT = Path(__file__).resolve().parents[1] / "inspect-gpt.py"
SPEC = importlib.util.spec_from_file_location("inspect_gpt", SCRIPT)
gpt = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(gpt)

DISK_GUID = uuid.UUID("00112233-4455-6677-8899-aabbccddeeff")
TYPE_GUID = uuid.UUID("0fc63daf-8483-4772-8e79-3d69d8477de4")
PART_GUIDS = [uuid.UUID("12345678-1234-5678-9abc-000000000001"),
              uuid.UUID("12345678-1234-5678-9abc-000000000002")]


class Fixture:
    """Only allocate captured edges and entry arrays, never the logical disk."""

    def __init__(self, disk_bytes=8 * 1024 * 1024, sector_bytes=512,
                 region_bytes=32768, count=128, size=128):
        self.disk_bytes = disk_bytes
        self.sector_bytes = sector_bytes
        self.region_bytes = region_bytes
        sectors = disk_bytes // sector_bytes
        self.primary_table = bytearray(count * size)
        for index, name, first, last, unique in (
                (0, "private-boot", 64, 127, PART_GUIDS[0]),
                (2, "private-userdata", 256, 511, PART_GUIDS[1])):
            offset = index * size
            self.primary_table[offset:offset + 16] = TYPE_GUID.bytes_le
            self.primary_table[offset + 16:offset + 32] = unique.bytes_le
            struct.pack_into("<QQQ", self.primary_table, offset + 32, first, last, 0)
            encoded = name.encode("utf-16-le")
            self.primary_table[offset + 56:offset + 56 + len(encoded)] = encoded
        self.backup_table = bytearray(self.primary_table)
        base = dict(revision=0x10000, header_size=92, reserved=0,
                    first_usable=64, last_usable=sectors - 65,
                    disk_guid=DISK_GUID.bytes_le, count=count, size=size)
        self.primary = dict(base, current=1, alternate=sectors - 1, entries=2)
        table_sectors = (len(self.primary_table) + sector_bytes - 1) // sector_bytes
        self.backup = dict(base, current=sectors - 1, alternate=1,
                           entries=sectors - 1 - table_sectors)

    def change_entry(self, offset, data, index=0, both=True):
        start = index * self.primary["size"] + offset
        self.primary_table[start:start + len(data)] = data
        if both:
            self.backup_table[start:start + len(data)] = data

    def set_header(self, key, value, both=True):
        self.primary[key] = value
        if both:
            self.backup[key] = value

    def header(self, fields, table):
        block = bytearray(self.sector_bytes)
        struct.pack_into("<8sIIIIQQQQ16sQIII", block, 0, b"EFI PART",
                         fields["revision"], fields["header_size"], 0,
                         fields["reserved"], fields["current"], fields["alternate"],
                         fields["first_usable"], fields["last_usable"],
                         fields["disk_guid"], fields["entries"], fields["count"],
                         fields["size"], zlib.crc32(table))
        struct.pack_into("<I", block, 16, zlib.crc32(block[:fields["header_size"]]))
        return block

    def captures(self):
        front, tail = bytearray(self.region_bytes), bytearray(self.region_bytes)
        front[510:512] = b"\x55\xaa"
        front[446:454] = b"\0\0\x02\0\xee\xff\xff\xff"
        struct.pack_into("<II", front, 454, 1,
                         min(self.disk_bytes // self.sector_bytes - 1, 0xFFFFFFFF))

        def put(offset, data):
            if 0 <= offset and offset + len(data) <= len(front):
                front[offset:offset + len(data)] = data
            elif self.disk_bytes - len(tail) <= offset and offset + len(data) <= self.disk_bytes:
                start = offset - (self.disk_bytes - len(tail))
                tail[start:start + len(data)] = data

        put(self.primary["entries"] * self.sector_bytes, self.primary_table)
        put(self.backup["entries"] * self.sector_bytes, self.backup_table)
        put(self.sector_bytes, self.header(self.primary, self.primary_table))
        put(self.disk_bytes - self.sector_bytes, self.header(self.backup, self.backup_table))
        return front, tail

    def validate(self, **policy):
        return gpt.validate_gpt(*self.captures(), self.disk_bytes, self.sector_bytes, **policy)


class GPTTests(unittest.TestCase):
    def test_titan_sized_disk_uses_only_two_32k_regions_and_preserves_indices(self):
        fixture = Fixture(disk_bytes=125074145280)
        result = fixture.validate()
        self.assertEqual(result["disk_bytes"], 125074145280)
        self.assertEqual(result["disk_sectors"], 244285440)
        self.assertEqual(result["disk_guid"], str(DISK_GUID))
        self.assertEqual(result["partition_count"], 2)
        self.assertEqual(result["partitions"][0], {
            "number": 1, "name": "private-boot", "first_lba": 64,
            "last_lba": 127, "sectors": 64, "type_guid": str(TYPE_GUID),
            "unique_guid": str(PART_GUIDS[0]), "attributes": 0})
        self.assertEqual(result["partitions"][1]["number"], 3)
        self.assertEqual(result["primary"]["current_lba"], 1)
        self.assertEqual(result["backup"]["backup_lba"], 1)
        self.assertEqual(result["warnings"], [])

    def test_variable_counts_entry_sizes_and_partial_final_sector_crc(self):
        for count, size in ((3, 128), (127, 128), (129, 128), (64, 256), (32, 512)):
            with self.subTest(count=count, size=size):
                fixture = Fixture(count=count, size=size)
                front, tail = fixture.captures()
                end = fixture.primary["entries"] * 512 + count * size
                # Sector padding is not part of the array CRC.
                if end % 512:
                    front[end] = 0xA5
                result = gpt.validate_gpt(front, tail, fixture.disk_bytes)
                self.assertEqual(result["primary"]["entry_count"], count)
                self.assertEqual(result["primary"]["entry_size"], size)

    def test_4096_byte_sectors_and_protective_mbr_saturation(self):
        self.assertEqual(Fixture(sector_bytes=4096).validate()["sector_bytes"], 4096)
        result = Fixture(disk_bytes=(0x100000000 + 100) * 512).validate()
        self.assertEqual(result["protective_mbr"]["sectors"], 0xFFFFFFFF)

    def test_unused_entries_and_name_padding_are_not_live_metadata(self):
        fixture = Fixture()
        fixture.change_entry(16, b"\xff" * 112, index=1)
        fixture.change_entry(56, "ok\0".encode("utf-16-le") + b"\0\xd8")
        self.assertEqual(fixture.validate()["partitions"][0]["name"], "ok")

    def test_unicode_names_attributes_and_empty_names(self):
        fixture = Fixture()
        fixture.change_entry(56, bytes(72))
        fixture.change_entry(56, "恢复📦\0".encode("utf-16-le"))
        fixture.change_entry(48, struct.pack("<Q", 0xFFFF000000000007))
        self.assertEqual(fixture.validate()["partitions"][0]["name"], "恢复📦")
        fixture.change_entry(56, bytes(72))
        fixture.change_entry(56, bytes(72), index=2)
        self.assertEqual([part["name"] for part in fixture.validate()["partitions"]], ["", ""])

    def test_mbr_signature_hybrid_type_start_and_coverage(self):
        for offset, data in ((510, b"\0\0"), (462, b"\x80"), (450, b"\x83"),
                             (454, struct.pack("<I", 2)), (458, struct.pack("<I", 100))):
            with self.subTest(offset=offset):
                fixture = Fixture()
                front, tail = fixture.captures()
                front[offset:offset + len(data)] = data
                with self.assertRaises(gpt.GPTError):
                    gpt.validate_gpt(front, tail, fixture.disk_bytes)

    def test_mbr_legacy_fields_do_not_select_partitions(self):
        fixture = Fixture()
        front, tail = fixture.captures()
        front[:446] = b"\x99" * 446
        front[446:450] = b"\x80\xaa\xbb\xcc"
        front[451:454] = b"\xaa\xbb\xcc"
        self.assertEqual(gpt.validate_gpt(front, tail, fixture.disk_bytes)["partition_count"], 2)

    def test_both_header_crcs_and_array_crcs_are_checked(self):
        for which, offset in (("front", 512 + 16), ("tail", 32768 - 512 + 16),
                              ("front", 2 * 512 + 56), ("tail", 32768 - 33 * 512 + 56)):
            with self.subTest(which=which, offset=offset):
                fixture = Fixture()
                front, tail = fixture.captures()
                data = front if which == "front" else tail
                data[offset] ^= 1
                with self.assertRaisesRegex(gpt.GPTError, "CRC mismatch"):
                    gpt.validate_gpt(front, tail, fixture.disk_bytes)

    def test_header_signature_revision_size_and_reserved(self):
        for key, value in (("revision", 0x20000), ("header_size", 91),
                           ("header_size", 513), ("reserved", 1)):
            with self.subTest(key=key, value=value):
                fixture = Fixture()
                fixture.set_header(key, value)
                with self.assertRaises(gpt.GPTError):
                    fixture.validate()
        for offset in (512, 512 + 92):
            fixture = Fixture()
            front, tail = fixture.captures()
            front[offset] ^= 1
            with self.assertRaises(gpt.GPTError):
                gpt.validate_gpt(front, tail, fixture.disk_bytes)

    def test_header_locations_and_geometry_must_agree(self):
        for key, value in (("current", 2), ("alternate", 2),
                           ("disk_guid", uuid.UUID(int=99).bytes_le),
                           ("first_usable", 65), ("last_usable", 16000),
                           ("header_size", 96)):
            with self.subTest(key=key):
                fixture = Fixture()
                fixture.set_header(key, value, both=False)
                with self.assertRaises(gpt.GPTError):
                    fixture.validate()

    def test_zero_guid_bad_usable_bounds_and_table_reservation(self):
        for key, value in (("disk_guid", bytes(16)), ("first_usable", 1),
                           ("first_usable", 16300), ("last_usable", 16383),
                           ("first_usable", 33), ("last_usable", 16351)):
            with self.subTest(key=key, value=value):
                fixture = Fixture(count=3)
                fixture.set_header(key, value)
                with self.assertRaises(gpt.GPTError):
                    fixture.validate()

    def test_zero_disk_guid_requires_explicit_boolean_policy_and_warns(self):
        fixture = Fixture()
        fixture.set_header("disk_guid", bytes(16))
        with self.assertRaisesRegex(gpt.GPTError, "disk GUID is zero"):
            fixture.validate()
        with self.assertRaisesRegex(gpt.GPTError, "disk GUID is zero"):
            fixture.validate(allow_zero_disk_guid=False)
        accepted = fixture.validate(allow_zero_disk_guid=True)
        self.assertEqual(accepted["warnings"], ["zero-disk-guid"])
        self.assertEqual(accepted["disk_guid"], str(uuid.UUID(int=0)))
        self.assertEqual(accepted["partition_count"], 2)
        self.assertEqual(Fixture().validate(allow_zero_disk_guid=True)["warnings"], [])
        for value in (None, 0, 1, "true", [], {}):
            with self.subTest(value=value), self.assertRaisesRegex(gpt.GPTError, "must be boolean"):
                fixture.validate(allow_zero_disk_guid=value)
        with self.assertRaises(TypeError):
            gpt.validate_gpt(*fixture.captures(), fixture.disk_bytes, 512, True)

    def test_zero_disk_guid_policy_does_not_relax_other_identity_or_crc_checks(self):
        fixture = Fixture()
        fixture.set_header("disk_guid", bytes(16), both=False)
        with self.assertRaisesRegex(gpt.GPTError, "metadata disagree"):
            fixture.validate(allow_zero_disk_guid=True)
        fixture.set_header("disk_guid", bytes(16))
        fixture.change_entry(16, bytes(16))
        with self.assertRaisesRegex(gpt.GPTError, "partition GUID is zero or duplicated"):
            fixture.validate(allow_zero_disk_guid=True)
        fixture = Fixture()
        fixture.set_header("disk_guid", bytes(16))
        fixture.change_entry(16, PART_GUIDS[0].bytes_le, index=2)
        with self.assertRaisesRegex(gpt.GPTError, "partition GUID is zero or duplicated"):
            fixture.validate(allow_zero_disk_guid=True)
        fixture = Fixture()
        fixture.set_header("disk_guid", bytes(16))
        front, tail = fixture.captures()
        front[512 + 16] ^= 1
        with self.assertRaisesRegex(gpt.GPTError, "header CRC mismatch"):
            gpt.validate_gpt(front, tail, fixture.disk_bytes, allow_zero_disk_guid=True)

    def test_table_count_size_and_resource_bound(self):
        for key, value in (("count", 0), ("count", 0xFFFFFFFF), ("size", 0),
                           ("size", 64), ("size", 136), ("size", 0x80000000)):
            with self.subTest(key=key, value=value):
                fixture = Fixture()
                fixture.set_header(key, value)
                with self.assertRaises(gpt.GPTError):
                    fixture.validate()

    def test_tables_cannot_overlap_headers_or_usable_range(self):
        for which, location in (("primary", 1), ("primary", 50),
                                ("backup", 16000), ("backup", 16380),
                                ("backup", (1 << 64) - 1)):
            with self.subTest(which=which, location=location):
                fixture = Fixture()
                getattr(fixture, which)["entries"] = location
                with self.assertRaises(gpt.GPTError):
                    fixture.validate()

    def test_valid_table_outside_captures_is_rejected_without_more_reads(self):
        fixture = Fixture(disk_bytes=32 * 1024 * 1024)
        fixture.primary["entries"] = 2048
        fixture.set_header("first_usable", 4096)
        with self.assertRaisesRegex(gpt.GPTError, "missing from the captured regions"):
            fixture.validate()

    def test_individually_valid_but_different_tables_rejected(self):
        fixture = Fixture()
        fixture.change_entry(56, "different\0".encode("utf-16-le"), both=False)
        with self.assertRaisesRegex(gpt.GPTError, "disagree"):
            fixture.validate()

    def test_crc_collision_does_not_replace_exact_table_comparison(self):
        fixture = Fixture()
        # Equal CRC32 deltas, independently precomputed over 8-byte strings.
        first = bytes.fromhex("fbc8b7a48942d678")
        second = bytes.fromhex("f49d17b7b3437b60")
        self.assertEqual(zlib.crc32(first), zlib.crc32(second))
        fixture.primary_table[128 + 16:128 + 24] = first
        fixture.backup_table[128 + 16:128 + 24] = second
        with self.assertRaisesRegex(gpt.GPTError, "entry tables disagree"):
            fixture.validate()

    def test_used_guids_ranges_overlap_and_reserved_fields(self):
        changes = [(16, bytes(16), 0), (16, PART_GUIDS[0].bytes_le, 2),
                   (32, struct.pack("<QQ", 63, 127), 0),
                   (32, struct.pack("<QQ", 128, 127), 0),
                   (32, struct.pack("<QQ", 100, 300), 2),
                   (40, struct.pack("<Q", 16383), 2),
                   (48, struct.pack("<Q", 8), 0)]
        for offset, data, index in changes:
            with self.subTest(offset=offset, index=index, data=data):
                fixture = Fixture()
                fixture.change_entry(offset, data, index=index)
                with self.assertRaises(gpt.GPTError):
                    fixture.validate()
        fixture = Fixture(count=64, size=256)
        fixture.change_entry(128, b"x")
        with self.assertRaisesRegex(gpt.GPTError, "reserved extension"):
            fixture.validate()

    def test_malformed_unterminated_and_duplicate_names(self):
        for data in (b"\0\xd8\0\0", b"\0\xdc\0\0", b"x\0" * 36):
            fixture = Fixture()
            fixture.change_entry(56, bytes(72))
            fixture.change_entry(56, data)
            with self.assertRaises(gpt.GPTError):
                fixture.validate()
        fixture = Fixture()
        fixture.change_entry(56, bytes(72), index=2)
        fixture.change_entry(56, "private-boot\0".encode("utf-16-le"), index=2)
        with self.assertRaisesRegex(gpt.GPTError, "name is duplicated"):
            fixture.validate()

    def test_input_geometry_lengths_and_types(self):
        fixture = Fixture()
        front, tail = fixture.captures()
        bad_args = [(front[:-1], tail, fixture.disk_bytes, 512),
                    (front, tail[:-512], fixture.disk_bytes, 512),
                    (bytes(1049088), bytes(1049088), fixture.disk_bytes, 512),
                    (front, tail, 3 * 1024 * 1024, 512),
                    (front, tail, fixture.disk_bytes + 1, 512),
                    (front, tail, fixture.disk_bytes, 0),
                    (front, tail, fixture.disk_bytes, 768),
                    (front, tail, fixture.disk_bytes, True),
                    (None, tail, fixture.disk_bytes, 512)]
        for args in bad_args:
            with self.subTest(types=tuple(type(value).__name__ for value in args)):
                with self.assertRaises(gpt.GPTError):
                    gpt.validate_gpt(*args)

    def test_cli_default_is_sanitized_and_json_is_explicit(self):
        fixture = Fixture()
        with tempfile.TemporaryDirectory() as directory:
            front_path, tail_path = Path(directory) / "front", Path(directory) / "tail"
            front, tail = fixture.captures()
            front_path.write_bytes(front)
            tail_path.write_bytes(tail)
            command = [sys.executable, str(SCRIPT), "--front", str(front_path),
                       "--tail", str(tail_path), "--disk-bytes", str(fixture.disk_bytes)]
            result = subprocess.run(command, capture_output=True, text=True, check=True)
            self.assertEqual(result.stdout, "GPT valid: 2 used partitions; both copies agree\n")
            self.assertEqual(result.stderr, "")
            private = subprocess.run(command + ["--json"], capture_output=True, text=True, check=True)
            self.assertEqual(json.loads(private.stdout)["disk_guid"], str(DISK_GUID))
            self.assertEqual(front_path.read_bytes(), front)
            self.assertEqual(tail_path.read_bytes(), tail)

    def test_cli_refuses_special_or_oversized_inputs_without_blocking(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "fifo"
            os.mkfifo(path)
            command = [sys.executable, str(SCRIPT), "--front", str(path), "--tail", str(path),
                       "--disk-bytes", str(8 * 1024 * 1024)]
            result = subprocess.run(command, capture_output=True, text=True, timeout=5)
            self.assertEqual(result.returncode, 1)
            self.assertEqual(result.stdout, "")
            path.unlink()
            path.write_bytes(bytes(1024 * 1024 + 1))
            result = subprocess.run(command, capture_output=True, text=True, timeout=5)
            self.assertEqual(result.returncode, 1)
            self.assertEqual(result.stdout, "")
            self.assertNotIn(str(path), result.stderr)

    def test_cli_zero_disk_guid_is_explicit_and_visible(self):
        fixture = Fixture()
        fixture.set_header("disk_guid", bytes(16))
        with tempfile.TemporaryDirectory() as directory:
            front_path, tail_path = Path(directory) / "front", Path(directory) / "tail"
            front, tail = fixture.captures()
            front_path.write_bytes(front)
            tail_path.write_bytes(tail)
            command = [sys.executable, str(SCRIPT), "--front", str(front_path),
                       "--tail", str(tail_path), "--disk-bytes", str(fixture.disk_bytes)]
            strict = subprocess.run(command, capture_output=True, text=True)
            self.assertEqual(strict.returncode, 1)
            self.assertEqual(strict.stdout, "")
            self.assertIn("disk GUID is zero", strict.stderr)
            allowed = subprocess.run(command + ["--allow-zero-disk-guid"],
                                     capture_output=True, text=True, check=True)
            self.assertEqual(allowed.stdout,
                             "GPT checks passed with warning: disk GUID is zero "
                             "(not a unique disk identity); 2 used partitions; both copies agree\n")
            self.assertEqual(allowed.stderr, "")
            self.assertNotIn("private-boot", allowed.stdout)
            private = subprocess.run(command + ["--allow-zero-disk-guid", "--json"],
                                     capture_output=True, text=True, check=True)
            self.assertEqual(json.loads(private.stdout)["warnings"], ["zero-disk-guid"])
            self.assertEqual(front_path.read_bytes(), front)
            self.assertEqual(tail_path.read_bytes(), tail)


if __name__ == "__main__":
    unittest.main()
