#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Validate both GPT copies from private bounded disk-edge captures, read-only.

Format reference: UEFI 2.11, sections 5.2.3 and 5.3:
https://uefi.org/specs/UEFI/2.11/05_GUID_Partition_Table_Format.html

This intentionally requires both copies to agree; it never repairs a disk or
accepts one valid copy as a backup. Parser bounds and duplicate-name rejection
are additional acquisition policies. The generic parser is not a Titan geometry
check: its caller must separately validate the measured disk and partition map.
Returned GUIDs and names are private inventory, not sanitized console output.
The explicit zero-disk-GUID policy accommodates an observed Titan anomaly; it
does not establish unique disk identity or relax any other validation check.
"""

import argparse
import json
import os
from pathlib import Path
import stat
import struct
import sys
import uuid
import zlib


MAX_REGION_BYTES = 1024 * 1024
MAX_TABLE_BYTES = 512 * 1024
MIN_TABLE_RESERVATION = 16384
ZERO_GUID = bytes(16)


class GPTError(ValueError):
    """The captures do not contain a complete, mutually consistent GPT."""


def require(condition, reason):
    if not condition:
        raise GPTError(reason)


def _guid(raw):
    return str(uuid.UUID(bytes_le=raw))


def _protective_mbr(front, disk_sectors, sector_bytes):
    require(front[510:512] == b"\x55\xaa", "invalid protective MBR signature")
    records = [front[446 + index * 16:462 + index * 16] for index in range(4)]
    used = [(index, record) for index, record in enumerate(records) if any(record)]
    require(len(used) == 1, "protective MBR has missing or hybrid partition records")
    index, record = used[0]
    start, count = struct.unpack_from("<II", record, 8)
    require(record[4] == 0xEE and start == 1,
            "invalid protective MBR partition type or start")
    require(count == min(disk_sectors - 1, 0xFFFFFFFF),
            "protective MBR does not cover the disk")
    require(not any(front[512:sector_bytes]), "nonzero protective MBR reserved bytes")
    # CHS, legacy boot flags/code and the unused MBR disk signature do not select
    # GPT partitions. Do not infer geometry or execution permissions from them.
    return {"record_number": index + 1, "type": 0xEE,
            "first_lba": start, "sectors": count}


def _header(read_at, lba, other_lba, disk_sectors, sector_bytes, which,
            allow_zero_disk_guid):
    block = read_at(lba * sector_bytes, sector_bytes)
    values = struct.unpack_from("<8sIIIIQQQQ16sQIII", block)
    (signature, revision, header_size, header_crc, reserved, current_lba,
     backup_lba, first_usable, last_usable, disk_guid, entries_lba, entry_count,
     entry_size, table_crc) = values
    require(signature == b"EFI PART", which + " GPT signature is invalid")
    require(revision == 0x00010000, which + " GPT revision is unsupported")
    require(92 <= header_size <= sector_bytes, which + " GPT header size is invalid")
    require(reserved == 0 and not any(block[92:]),
            which + " GPT reserved header bytes are nonzero")
    checksum_bytes = bytearray(block[:header_size])
    checksum_bytes[16:20] = bytes(4)
    require(zlib.crc32(checksum_bytes) == header_crc, which + " GPT header CRC mismatch")
    require(current_lba == lba and backup_lba == other_lba,
            which + " GPT header locations are not reciprocal")
    require(disk_guid != ZERO_GUID or allow_zero_disk_guid,
            which + " GPT disk GUID is zero")
    require(2 <= first_usable <= last_usable < disk_sectors - 1,
            which + " GPT usable range is invalid")
    require(entry_count > 0, which + " GPT entry count is zero")
    require(entry_size >= 128 and entry_size & (entry_size - 1) == 0,
            which + " GPT entry size is unsupported")
    table_bytes = entry_count * entry_size
    require(table_bytes <= MAX_TABLE_BYTES, which + " GPT entry table exceeds the bound")
    table_sectors = (table_bytes + sector_bytes - 1) // sector_bytes
    require(entries_lba < disk_sectors and table_sectors <= disk_sectors - entries_lba,
            which + " GPT entry table exceeds the disk")
    reservation_sectors = (MIN_TABLE_RESERVATION + sector_bytes - 1) // sector_bytes
    require(first_usable >= 2 + reservation_sectors
            and last_usable < disk_sectors - 1 - reservation_sectors,
            which + " GPT does not reserve the minimum table space")
    if which == "primary":
        require(entries_lba >= 2 and entries_lba + table_sectors <= first_usable,
                "primary GPT entry table overlaps headers or usable space")
    else:
        require(entries_lba > last_usable
                and entries_lba + table_sectors <= disk_sectors - 1,
                "backup GPT entry table overlaps headers or usable space")
    table = read_at(entries_lba * sector_bytes, table_bytes)
    require(zlib.crc32(table) == table_crc, which + " GPT entry-table CRC mismatch")
    return ({"revision": revision, "header_size": header_size,
             "header_crc32": header_crc, "current_lba": current_lba,
             "backup_lba": backup_lba, "first_usable_lba": first_usable,
             "last_usable_lba": last_usable, "disk_guid": _guid(disk_guid),
             "entries_lba": entries_lba, "entry_count": entry_count,
             "entry_size": entry_size, "table_bytes": table_bytes,
             "table_sectors": table_sectors, "table_crc32": table_crc}, table)


def _partitions(table, header):
    partitions = []
    guids = set()
    names = set()
    size = header["entry_size"]
    for index in range(header["entry_count"]):
        entry = table[index * size:(index + 1) * size]
        type_guid = entry[:16]
        if type_guid == ZERO_GUID:
            # The type GUID defines an unused entry. Remaining fields need not
            # be interpreted as a live range, unique GUID or UTF-16 name.
            continue
        unique_guid = entry[16:32]
        require(unique_guid != ZERO_GUID and unique_guid not in guids,
                "used partition GUID is zero or duplicated")
        guids.add(unique_guid)
        first, last, attributes = struct.unpack_from("<QQQ", entry, 32)
        require(header["first_usable_lba"] <= first <= last <= header["last_usable_lba"],
                "partition range lies outside usable space")
        require(attributes & 0x0000FFFFFFFFFFF8 == 0,
                "partition has nonzero reserved attribute bits")
        require(not any(entry[128:]), "partition has nonzero reserved extension bytes")
        raw_name = entry[56:128]
        end = next((offset for offset in range(0, 72, 2)
                    if raw_name[offset:offset + 2] == b"\0\0"), 72)
        require(end < 72, "partition name lacks a UTF-16 terminator")
        try:
            name = raw_name[:end].decode("utf-16-le", errors="strict")
        except UnicodeDecodeError as error:
            raise GPTError("partition name is not well-formed UTF-16") from error
        require(not name or name not in names, "nonempty partition name is duplicated")
        if name:
            names.add(name)
        partitions.append({"number": index + 1, "name": name, "first_lba": first,
                           "last_lba": last, "sectors": last - first + 1,
                           "type_guid": _guid(type_guid), "unique_guid": _guid(unique_guid),
                           "attributes": attributes})
    ordered = sorted(partitions, key=lambda item: item["first_lba"])
    for previous, current in zip(ordered, ordered[1:]):
        require(previous["last_lba"] < current["first_lba"], "partition ranges overlap")
    return partitions


def validate_gpt(front: bytes, tail: bytes, disk_bytes: int, sector_bytes=512,
                 *, allow_zero_disk_guid=False) -> dict:
    """Validate bounded first/last regions; return private parsed metadata.

    Both slices must be equally sized, whole-sector captures at offsets zero and
    disk_bytes - len(tail), each at most 1 MiB. Logical sectors must be powers of
    two from 512 through 65536 bytes; the disk must contain at least 4 MiB and
    whole sectors. These are parser resource bounds, not evidence of a particular
    phone model. Every referenced GPT byte must exist in a supplied slice.

    Strict validation rejects a zero disk GUID. The keyword-only boolean
    allow_zero_disk_guid permits that anomaly alone and records zero-disk-guid
    in the returned warnings list. Both disk GUIDs must still agree; every used
    partition must still have a nonzero, unique GUID.
    """
    require(type(allow_zero_disk_guid) is bool, "allow_zero_disk_guid must be boolean")
    require(isinstance(front, (bytes, bytearray)) and isinstance(tail, (bytes, bytearray)),
            "GPT captures must be byte buffers")
    require(type(sector_bytes) is int and 512 <= sector_bytes <= 65536
            and sector_bytes & (sector_bytes - 1) == 0,
            "unsupported logical sector size")
    require(len(front) == len(tail) and sector_bytes <= len(front) <= MAX_REGION_BYTES
            and len(front) % sector_bytes == 0,
            "GPT captures must be equal bounded whole-sector regions")
    require(type(disk_bytes) is int and disk_bytes >= 4 * 1024 * 1024
            and disk_bytes % sector_bytes == 0
            and disk_bytes // sector_bytes <= 1 << 64,
            "invalid disk byte count")
    front, tail = bytes(front), bytes(tail)
    region_bytes = len(front)
    tail_offset = disk_bytes - region_bytes

    def read_at(offset, size):
        require(0 <= offset <= disk_bytes and 0 <= size <= disk_bytes - offset,
                "GPT read range exceeds disk bounds")
        if offset + size <= region_bytes:
            return front[offset:offset + size]
        if tail_offset <= offset and offset + size <= disk_bytes:
            start = offset - tail_offset
            return tail[start:start + size]
        raise GPTError("referenced GPT bytes are missing from the captured regions")

    sectors = disk_bytes // sector_bytes
    mbr = _protective_mbr(front, sectors, sector_bytes)
    primary, primary_table = _header(read_at, 1, sectors - 1, sectors, sector_bytes,
                                     "primary", allow_zero_disk_guid)
    backup, backup_table = _header(read_at, sectors - 1, 1, sectors, sector_bytes,
                                   "backup", allow_zero_disk_guid)
    for field in ("revision", "header_size", "first_usable_lba", "last_usable_lba",
                  "disk_guid", "entry_count", "entry_size", "table_crc32"):
        require(primary[field] == backup[field], "primary and backup GPT metadata disagree")
    require(primary_table == backup_table, "primary and backup GPT entry tables disagree")
    partitions = _partitions(primary_table, primary)
    warnings = ["zero-disk-guid"] if primary["disk_guid"] == _guid(ZERO_GUID) else []
    return {"format": "gpt", "disk_bytes": disk_bytes, "sector_bytes": sector_bytes,
            "disk_sectors": sectors, "disk_guid": primary["disk_guid"],
            "protective_mbr": mbr, "primary": primary, "backup": backup,
            "partitions": partitions, "partition_count": len(partitions), "warnings": warnings}


def _read_capture(path):
    fd = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        before = os.fstat(fd)
        require(stat.S_ISREG(before.st_mode) and 512 <= before.st_size <= MAX_REGION_BYTES,
                "capture must be a regular file between 512 bytes and 1 MiB")
        chunks = []
        length = 0
        while length <= before.st_size:
            chunk = os.read(fd, min(65536, before.st_size + 1 - length))
            if not chunk:
                break
            chunks.append(chunk)
            length += len(chunk)
        after = os.fstat(fd)
        require(length == before.st_size, "capture length changed while reading")
        require((before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns,
                 before.st_ctime_ns) == (after.st_dev, after.st_ino, after.st_size,
                                        after.st_mtime_ns, after.st_ctime_ns),
                "capture metadata changed while reading")
        return b"".join(chunks)
    finally:
        os.close(fd)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.split("\n", 1)[0])
    parser.add_argument("--front", required=True, type=Path)
    parser.add_argument("--tail", required=True, type=Path)
    parser.add_argument("--disk-bytes", required=True, type=int)
    parser.add_argument("--sector-bytes", type=int, default=512)
    parser.add_argument("--allow-zero-disk-guid", action="store_true",
                        help="allow the observed Titan zero disk GUID with a warning; "
                             "does not establish unique identity or relax other checks")
    parser.add_argument("--json", action="store_true",
                        help="emit full private inventory including GUIDs and partition names")
    args = parser.parse_args(argv)
    try:
        result = validate_gpt(_read_capture(args.front), _read_capture(args.tail),
                              args.disk_bytes, args.sector_bytes,
                              allow_zero_disk_guid=args.allow_zero_disk_guid)
    except GPTError as error:
        print("GPT invalid: " + str(error), file=sys.stderr)
        return 1
    except OSError:
        print("GPT invalid: cannot read capture files", file=sys.stderr)
        return 1
    if args.json:
        print(json.dumps(result, indent=2, sort_keys=True))
    elif result["warnings"]:
        print("GPT checks passed with warning: disk GUID is zero (not a unique disk identity); "
              f"{result['partition_count']} used partitions; both copies agree")
    else:
        print(f"GPT valid: {result['partition_count']} used partitions; both copies agree")
    return 0


if __name__ == "__main__":
    sys.exit(main())
