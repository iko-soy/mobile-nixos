#!/usr/bin/env python3
"""Inspect Android v2 boot-image geometry; never verify bootability or signatures.

The Titan profile follows the pinned UBports deviceinfo. Its DTB is an Android
DT table containing an FDT, not a raw FDT. UBports first adds a hash footer and
then calls append_vbmeta_image with a separate vbmeta.img: the final footer does
not establish that a boot-image hash descriptor or a trusted signature exists.
"""

import argparse
import json
import os
from pathlib import Path
import stat
import struct
import sys


HEADER_SIZE = 1660
TITAN_PARTITION_SIZE = 32 * 1024 * 1024
# Boot, recovery and dtbo inputs are at most one 32 MiB partition; refuse
# multi-gigabyte copies, devices or FIFOs before reading them into memory.
INPUT_LIMIT = 2 * TITAN_PARTITION_SIZE
FDT_MAGIC = 0xD00DFEED
DT_TABLE_MAGIC = 0xD7B7AB1E


class ImageFormatError(ValueError):
    """The image cannot be interpreted safely as the supported format."""


def require(condition, message):
    if not condition:
        raise ImageFormatError(message)


def aligned(size, alignment):
    return (size + alignment - 1) // alignment * alignment


def bounded(offset, size, limit, label):
    require(0 <= offset <= limit and 0 <= size <= limit - offset,
            f"{label} lies outside its containing region")


def c_string(value):
    return value.split(b"\0", 1)[0].decode("utf-8", errors="replace")


def inspect_fdt(data):
    require(len(data) >= 40, "truncated FDT header")
    (magic, total_size, structure_offset, strings_offset, reserve_offset,
     version, compatible_version, boot_cpu, strings_size,
     structure_size) = struct.unpack_from(">10I", data)
    require(magic == FDT_MAGIC, "invalid FDT magic")
    require(40 <= total_size <= len(data), "FDT total size exceeds DTB payload or is too small")
    require(version >= 17 and compatible_version <= 17,
            "unsupported FDT version (requires compatibility with version 17)")
    require(compatible_version <= version, "invalid FDT compatible version")
    for offset, size, label in ((structure_offset, structure_size, "FDT structure"),
                                (strings_offset, strings_size, "FDT strings")):
        require(offset >= 40, f"{label} overlaps the FDT header")
        bounded(offset, size, total_size, label)
    require(structure_offset % 4 == 0, "unaligned FDT structure")
    require(reserve_offset >= 40 and reserve_offset % 8 == 0,
            "invalid FDT reservation-map offset")
    bounded(reserve_offset, 16, total_size, "FDT reservation map")
    reserve_limit = min([total_size] + [offset for offset in (structure_offset, strings_offset)
                                      if offset > reserve_offset])
    reserve_end = reserve_offset
    while True:
        bounded(reserve_end, 16, reserve_limit, "FDT reservation map (missing terminator)")
        address, size = struct.unpack_from(">QQ", data, reserve_end)
        reserve_end += 16
        if address == 0 and size == 0:
            break
    regions = [(reserve_offset, reserve_end, "reservation map"),
               (structure_offset, structure_offset + structure_size, "structure"),
               (strings_offset, strings_offset + strings_size, "strings")]
    for index, (start, end, label) in enumerate(regions):
        if start == end:
            continue
        for other_start, other_end, other_label in regions[index + 1:]:
            if other_start != other_end:
                require(end <= other_start or other_end <= start,
                        f"FDT {label} overlaps {other_label}")
    return {
        "format": "fdt", "total_size": total_size, "version": version,
        "compatible_version": compatible_version, "boot_cpu": boot_cpu,
        "structure_offset": structure_offset, "structure_size": structure_size,
        "strings_offset": strings_offset, "strings_size": strings_size,
        "reservation_map_offset": reserve_offset,
        "reservation_map_size": reserve_end - reserve_offset,
        # Appended data and padding are legal; do not mistake them for corruption.
        "trailing_bytes": len(data) - total_size,
    }


def inspect_dtb(data):
    require(len(data) >= 4, "missing or truncated DTB payload")
    magic = struct.unpack_from(">I", data)[0]
    if magic == FDT_MAGIC:
        return inspect_fdt(data)
    require(magic == DT_TABLE_MAGIC, "DTB has neither FDT nor Android DT-table magic")
    require(len(data) >= 32, "truncated Android DT-table header")
    (_, total_size, header_size, entry_size, entry_count, entries_offset,
     page_size, version) = struct.unpack_from(">8I", data)
    require(32 <= header_size <= total_size <= len(data), "invalid Android DT-table size")
    require(version in (0, 1), "unsupported Android DT-table version")
    require(entry_count > 0 and entry_size >= 32, "empty or invalid Android DT table")
    require(entries_offset >= header_size, "DT-table entries overlap the header")
    bounded(entries_offset, entry_count * entry_size, total_size, "DT-table entries")
    entries_end = entries_offset + entry_count * entry_size
    entries = []
    for index in range(entry_count):
        values = struct.unpack_from(">8I", data, entries_offset + index * entry_size)
        size, offset, identifier, revision, *custom = values
        require(offset >= entries_end, "DT-table payload overlaps the entries")
        bounded(offset, size, total_size, f"DT-table entry {index}")
        require(version == 0 or custom[0] & 0xF == 0,
                "compressed DT-table entries are not supported")
        entries.append({
            "offset": offset, "size": size, "id": identifier,
            "revision": revision, "custom": custom,
            "fdt": inspect_fdt(data[offset:offset + size]),
        })
    return {
        "format": "android-dt-table", "total_size": total_size,
        "header_size": header_size, "entry_size": entry_size,
        "page_size": page_size, "version": version, "entries": entries,
        "trailing_bytes": len(data) - total_size,
    }


def inspect_avb(data, payload_end):
    if len(data) < 64 or data[-64:-60] != b"AVBf":
        return None
    _, major, minor, original_size, offset, size = struct.unpack_from(
        ">4sIIQQQ", data, len(data) - 64)
    require(major == 1, "unsupported AVB footer version")
    require(payload_end <= original_size <= offset,
            "AVB original image size truncates boot payloads or overlaps vbmeta")
    require(size >= 256, "truncated AVB vbmeta header")
    bounded(offset, size, len(data) - 64, "AVB vbmeta")
    require(data[offset:offset + 4] == b"AVB0", "invalid AVB vbmeta magic")
    required_major, required_minor, auth_size, aux_size, algorithm = struct.unpack_from(
        ">IIQQI", data, offset + 4)
    require(auth_size % 64 == 0 and aux_size % 64 == 0,
            "AVB authentication and auxiliary blocks must be multiples of 64 bytes")
    bounded(256, auth_size + aux_size, size, "AVB authentication and auxiliary blocks")
    for field, field_offset, limit in (
        ("hash", 32, auth_size), ("signature", 48, auth_size),
        ("public key", 64, aux_size), ("public key metadata", 80, aux_size),
        ("descriptors", 96, aux_size),
    ):
        region_offset, region_size = struct.unpack_from(">QQ", data, offset + field_offset)
        bounded(region_offset, region_size, limit, f"AVB {field}")
    flags = struct.unpack_from(">I", data, offset + 120)[0]
    return {
        "footer_offset": len(data) - 64, "footer_version": f"{major}.{minor}",
        "original_image_size": original_size, "vbmeta_offset": offset,
        "vbmeta_size": size, "vbmeta_required_version": f"{required_major}.{required_minor}",
        "authentication_block_size": auth_size, "auxiliary_block_size": aux_size,
        "algorithm_type": algorithm, "flags": flags,
        "hashtree_disabled": bool(flags & 1), "verification_disabled": bool(flags & 2),
        "release_string": c_string(data[offset + 128:offset + 176]),
    }


def inspect_image(data):
    """Return decoded metadata or raise ImageFormatError for malformed geometry."""
    require(len(data) >= HEADER_SIZE, "truncated Android v2 boot header")
    require(data[:8] == b"ANDROID!", "invalid Android boot magic")
    fields = struct.unpack_from("<10I", data, 8)
    (kernel_size, kernel_address, ramdisk_size, ramdisk_address,
     second_size, second_address, tags_address, page_size,
     header_version, encoded_os) = fields
    require(header_version == 2, f"unsupported boot header version {header_version}; expected 2")
    require(page_size in (2048, 4096, 8192, 16384), "invalid boot page size")
    recovery_size, recovery_offset, header_size, dtb_size, dtb_address = struct.unpack_from(
        "<IQIIQ", data, 1632)
    require(header_size == HEADER_SIZE, f"invalid v2 header size {header_size}; expected {HEADER_SIZE}")
    require(kernel_size > 0, "missing kernel payload")
    require(dtb_size > 0, "missing v2 DTB payload")
    os_version = encoded_os >> 11
    patch = encoded_os & 0x7FF
    month = patch & 15
    require(patch == 0 or 1 <= month <= 12, "invalid OS patch-level month")
    segments = {}
    cursor = page_size
    for name, size in (("kernel", kernel_size), ("ramdisk", ramdisk_size),
                       ("second", second_size), ("recovery_dtbo", recovery_size),
                       ("dtb", dtb_size)):
        if name == "recovery_dtbo" and size:
            require(recovery_offset == cursor,
                    "recovery DTBO offset does not follow page-aligned boot payloads")
        bounded(cursor, size, len(data), f"{name} payload")
        segments[name] = {"offset": cursor, "size": size, "end": cursor + size}
        cursor += aligned(size, page_size)
    require(cursor <= len(data), "truncated final boot-payload page padding")
    dtb = segments["dtb"]
    result = {
        "file_size": len(data), "header_version": header_version,
        "header_size": header_size, "page_size": page_size,
        "os_version": f"{os_version >> 14}.{(os_version >> 7) & 127}.{os_version & 127}",
        "os_patch_level": f"{2000 + (patch >> 4):04d}-{month:02d}" if patch else None,
        "board": c_string(data[48:64]),
        "cmdline": c_string(data[64:576]) + c_string(data[608:1632]),
        "load_addresses": {
            "kernel": kernel_address, "ramdisk": ramdisk_address,
            "second": second_address, "tags": tags_address, "dtb": dtb_address,
        },
        "recovery_dtbo_header_offset": recovery_offset,
        "segments": segments, "padded_payload_end": cursor,
        "dtb": inspect_dtb(data[dtb["offset"]:dtb["end"]]),
        "avb": inspect_avb(data, cursor),
        "validation": {
            "geometry_valid": True,
            "scope": "Android boot, DTB and AVB geometry; not DT nodes or AVB descriptors",
            "cryptographic_verification_performed": False,
            "bootability_verified": False,
        },
    }
    return result


def titan_errors(info):
    """Compare the final image to the known UBports Titan packaging profile."""
    errors = []
    for field, expected in (("page_size", 2048), ("os_version", "10.0.0"),
                            ("os_patch_level", "2025-08")):
        if info[field] != expected:
            errors.append(f"Titan {field} must be {expected!r}; got {info[field]!r}")
    for name, expected in (("kernel", 0x40080000), ("ramdisk", 0x55000000),
                           ("tags", 0x54000000), ("dtb", 0x54000000)):
        if info["load_addresses"][name] != expected:
            errors.append(f"Titan {name} load address must be {expected:#x}")
    if not info["segments"]["ramdisk"]["size"]:
        errors.append("Titan image must contain a ramdisk")
    if info["file_size"] > TITAN_PARTITION_SIZE:
        errors.append("Titan image exceeds the 32 MiB boot partition")
    if info["avb"] is None:
        errors.append("Titan final image must have an appended AVB footer and vbmeta")
    elif info["file_size"] != TITAN_PARTITION_SIZE:
        errors.append("Titan final AVB image must fill the 32 MiB boot partition")
    return errors


def read_image(path, limit=None):
    """Read one bounded regular file without following a final symlink."""
    limit = INPUT_LIMIT if limit is None else limit
    descriptor = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_size > limit:
            raise ImageFormatError(f"Input must be a regular file of at most {limit} bytes")
        parts, count = [], 0
        while True:
            data = os.read(descriptor, min(1048576, limit + 1 - count))
            if not data:
                break
            parts.append(data)
            count += len(data)
            if count > limit:
                raise ImageFormatError(f"Input grew beyond {limit} bytes while being read")
        return b"".join(parts)
    finally:
        os.close(descriptor)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("image", type=Path)
    parser.add_argument("--json", action="store_true", help="emit machine-readable metadata")
    parser.add_argument("--check-titan", action="store_true",
                        help="also check the final UBports Titan packaging profile")
    args = parser.parse_args(argv)
    try:
        report = inspect_image(read_image(args.image))
        errors = titan_errors(report) if args.check_titan else []
        report["validation"]["titan_profile_checked"] = args.check_titan
        report["validation"]["errors"] = errors
        success = not errors
    except (OSError, ImageFormatError) as error:
        report = {"validation": {"geometry_valid": False,
                  "cryptographic_verification_performed": False,
                  "bootability_verified": False,
                  "titan_profile_checked": args.check_titan, "errors": [str(error)]}}
        success = False
    if args.json:
        print(json.dumps(report, indent=2, sort_keys=True))
    else:
        if report["validation"]["geometry_valid"]:
            print(f"Android v2 image: {report['file_size']} bytes, {report['page_size']}-byte pages")
            print(f"OS {report['os_version']}, patch {report['os_patch_level']}, DTB {report['dtb']['format']}")
            print("AVB footer: " + ("present" if report["avb"] else "absent"))
        for error in report["validation"]["errors"]:
            print(f"ERROR: {error}")
        print("Structural inspection only; signatures, hashes and bootability are unverified.")
    return 0 if success else 1


if __name__ == "__main__":
    sys.exit(main())
