"""Boundary tests for the inspector, using independently assembled format fixtures."""

import importlib.util
import json
from pathlib import Path
import struct
import subprocess
import sys
import tempfile
import unittest


SCRIPT = Path(__file__).resolve().parents[1] / "inspect-boot-image.py"
spec = importlib.util.spec_from_file_location("inspect_boot_image", SCRIPT)
boot = importlib.util.module_from_spec(spec)
spec.loader.exec_module(boot)


def fdt():
    # Reservation terminator; BEGIN_NODE, empty name, END_NODE, END; no strings.
    structure = struct.pack(">4I", 1, 0, 2, 9)
    return struct.pack(">10I", 0xD00DFEED, 72, 56, 72, 40, 17, 16, 0, 0, 16) + bytes(16) + structure


def dt_table():
    blob = fdt()
    return (struct.pack(">8I", 0xD7B7AB1E, 64 + len(blob), 32, 32, 1, 32, 2048, 0)
            + struct.pack(">8I", len(blob), 64, 0, 0, 0, 0, 0, 0) + blob)


def image(dtb=None, page_size=2048, recovery=b"", kernel=b"K" * 2051):
    dtb = dt_table() if dtb is None else dtb
    ramdisk = b"R" * 31
    header = bytearray(page_size)
    header[:8] = b"ANDROID!"
    os_version = (10 << 25) | (25 << 4) | 8
    struct.pack_into("<10I", header, 8, len(kernel), 0x40080000, len(ramdisk),
                     0x55000000, 0, 0x40F00000, 0x54000000, page_size, 2, os_version)
    header[64:72] = b"init=/i\0"
    recovery_offset = page_size + ((len(kernel) + page_size - 1) // page_size) * page_size + page_size
    struct.pack_into("<IQIIQ", header, 1632, len(recovery), recovery_offset if recovery else 0,
                     1660, len(dtb), 0x54000000)
    result = header
    for payload in (kernel, ramdisk, recovery, dtb):
        result += payload
        result += bytes((-len(payload)) % page_size)
    return result


def avb_image(payload=None, size=65536):
    payload = image() if payload is None else payload
    result = bytearray(payload)
    result += bytes((-len(result)) % 4096)
    offset = len(result)
    vbmeta = bytearray(256)
    vbmeta[:4] = b"AVB0"
    struct.pack_into(">IIQQI", vbmeta, 4, 1, 0, 0, 0, 0)
    struct.pack_into(">I", vbmeta, 120, 2)
    result += vbmeta
    result += bytes(size - 64 - len(result))
    result += struct.pack(">4sIIQQQ28x", b"AVBf", 1, 0, len(payload), offset, len(vbmeta))
    return result


class BootImageTests(unittest.TestCase):
    def test_page_alignment_and_os_metadata(self):
        info = boot.inspect_image(image())
        self.assertEqual(info["segments"]["kernel"], {"offset": 2048, "size": 2051, "end": 4099})
        self.assertEqual(info["segments"]["ramdisk"]["offset"], 6144)
        self.assertEqual(info["segments"]["dtb"]["offset"], 8192)
        self.assertEqual(info["padded_payload_end"], 10240)
        self.assertEqual(info["os_version"], "10.0.0")
        self.assertEqual(info["os_patch_level"], "2025-08")
        self.assertEqual(info["cmdline"], "init=/i")
        self.assertEqual(info["dtb"]["entries"][0]["fdt"]["total_size"], 72)

    def test_raw_and_table_dtb_may_have_trailing_data(self):
        for payload in (fdt(), dt_table()):
            with self.subTest(magic=payload[:4]):
                info = boot.inspect_image(image(payload + b"extra DTB data"))
                self.assertEqual(info["dtb"]["trailing_bytes"], 14)

    def test_recovery_dtbo_and_larger_pages(self):
        info = boot.inspect_image(image(page_size=4096, recovery=b"O" * 4101))
        self.assertEqual(info["segments"]["recovery_dtbo"]["offset"], 12288)
        self.assertEqual(info["segments"]["dtb"]["offset"], 20480)

    def test_truncated_headers_and_payloads(self):
        original = image()
        for length in (0, 8, 1632, 1659, 4098, 6144, 8192, len(original) - 1):
            with self.subTest(length=length), self.assertRaises(boot.ImageFormatError):
                boot.inspect_image(original[:length])

    def test_bad_header_fields(self):
        for offset, value in ((40, 3), (36, 0), (36, 3000), (1644, 1648),
                              (8, 0), (8, 0xFFFFFFFF), (1648, 0), (1648, 0xFFFFFFFF)):
            data = image()
            struct.pack_into("<I", data, offset, value)
            with self.subTest(offset=offset, value=value), self.assertRaises(boot.ImageFormatError):
                boot.inspect_image(data)

    def test_bad_magic_and_patch_month(self):
        data = image()
        data[0] = 0
        with self.assertRaisesRegex(boot.ImageFormatError, "magic"):
            boot.inspect_image(data)
        data = image()
        struct.pack_into("<I", data, 44, (10 << 25) | (25 << 4) | 13)
        with self.assertRaisesRegex(boot.ImageFormatError, "month"):
            boot.inspect_image(data)

    def test_recovery_offset_cannot_skip_or_overlap_payloads(self):
        for offset in (0, 2048, 65536):
            data = image(recovery=b"O")
            struct.pack_into("<Q", data, 1636, offset)
            with self.subTest(offset=offset), self.assertRaisesRegex(boot.ImageFormatError, "recovery DTBO offset"):
                boot.inspect_image(data)

    def test_dtb_malformed_header_and_ranges(self):
        for offset, value in ((0, 0), (4, 0xFFFFFFFF), (8, 80), (12, 80), (16, 41), (32, 500)):
            blob = bytearray(fdt())
            struct.pack_into(">I", blob, offset, value)
            with self.subTest(offset=offset), self.assertRaises(boot.ImageFormatError):
                boot.inspect_image(image(blob))

    def test_dt_table_malformed_entries_and_payloads(self):
        for offset, value in ((4, 0xFFFFFFFF), (8, 8), (12, 4), (16, 0xFFFFFFFF),
                              (20, 0), (32, 0xFFFFFFFF), (36, 32), (36, 65536), (64, 0)):
            blob = bytearray(dt_table())
            struct.pack_into(">I", blob, offset, value)
            with self.subTest(offset=offset), self.assertRaises(boot.ImageFormatError):
                boot.inspect_image(image(blob))

    def test_fdt_overlap_and_missing_reservation_terminator(self):
        for changes in (((8, 40),), ((12, 56), (32, 16)), ((16, 56),), ((40, 1),)):
            blob = bytearray(fdt())
            for offset, value in changes:
                struct.pack_into(">I", blob, offset, value)
            with self.subTest(changes=changes), self.assertRaises(boot.ImageFormatError):
                boot.inspect_image(image(blob))

    def test_avb_without_authentication_is_not_verified(self):
        info = boot.inspect_image(avb_image())
        self.assertEqual(info["avb"]["original_image_size"], 10240)
        self.assertEqual(info["avb"]["vbmeta_offset"], 12288)
        self.assertTrue(info["avb"]["verification_disabled"])
        self.assertEqual(info["avb"]["algorithm_type"], 0)
        self.assertFalse(info["validation"]["cryptographic_verification_performed"])
        self.assertFalse(info["validation"]["bootability_verified"])

    def test_bad_avb_footer_geometry(self):
        for relative_offset, value in ((12, 10239), (12, 12289), (20, 0),
                                       (20, 2**64 - 1), (28, 255), (28, 65536)):
            data = avb_image()
            struct.pack_into(">Q", data, len(data) - 64 + relative_offset, value)
            with self.subTest(offset=relative_offset, value=value), self.assertRaises(boot.ImageFormatError):
                boot.inspect_image(data)

    def test_bad_vbmeta_geometry(self):
        for field_offset, value in ((12, 63), (12, 65536), (20, 65536),
                                    (32, 1), (40, 1), (56, 1), (72, 1), (104, 1)):
            data = avb_image()
            struct.pack_into(">Q", data, 12288 + field_offset, value)
            with self.subTest(offset=field_offset), self.assertRaises(boot.ImageFormatError):
                boot.inspect_image(data)
        data = avb_image()
        data[12288] = 0
        with self.assertRaisesRegex(boot.ImageFormatError, "vbmeta magic"):
            boot.inspect_image(data)

    def test_titan_profile_and_partition_limit(self):
        self.assertEqual(boot.titan_errors(boot.inspect_image(avb_image(size=32 * 1024 * 1024))), [])
        self.assertTrue(boot.titan_errors(boot.inspect_image(image())))
        self.assertTrue(boot.titan_errors(boot.inspect_image(avb_image())))
        oversized = boot.inspect_image(image() + bytes(32 * 1024 * 1024))
        self.assertTrue(any("exceeds" in error for error in boot.titan_errors(oversized)))
        data = avb_image(size=32 * 1024 * 1024)
        struct.pack_into("<I", data, 12, 0)
        self.assertTrue(any("kernel load address" in error for error in boot.titan_errors(boot.inspect_image(data))))

    def test_cli_json_failure_and_profile_status(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "boot.img"
            for payload, options, status in ((b"truncated", [], 1), (image(), [], 0),
                                              (image(), ["--check-titan"], 1)):
                path.write_bytes(payload)
                result = subprocess.run([sys.executable, str(SCRIPT), "--json", *options, str(path)],
                                        capture_output=True, text=True, check=False)
                self.assertEqual(result.returncode, status, result.stderr)
                report = json.loads(result.stdout)
                self.assertFalse(report["validation"]["bootability_verified"])
                self.assertEqual(bool(report["validation"]["errors"]), bool(status))


if __name__ == "__main__":
    unittest.main()
