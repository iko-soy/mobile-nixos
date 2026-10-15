#!/usr/bin/env python3
"""Inspect the exact build-only Titan USB acquisition initramfs without extracting.

This deliberately accepts less than Linux's general initramfs grammar: one
gzip member, one newc archive and the fixed production file set. It verifies
structure and optional build manifests, not code provenance or bootability.
Format references: docs.kernel.org/driver-api/early-userspace/buffer-format.html
and refspecs.linuxfoundation.org/elf/gabi4+/ch5.pheader.html.
"""

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import struct
import sys
import zlib


MAX_COMPRESSED = 16 * 1024 * 1024
MAX_UNCOMPRESSED = 32 * 1024 * 1024
MAX_MANIFEST = 4096
FILES = ("init", "bin/busybox", "bin/e2image", "bin/titan-block-produce",
         "bin/titan-rescue-send", "bin/zstd")
DIRECTORIES = (".", "bin", "dev", "proc", "run", "sys", "tmp")
EXPECTED = tuple(sorted(FILES + DIRECTORIES))
GZIP_HEADER = bytes.fromhex("1f8b0800000000000203")
TRAILER = (0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 11, 0)


class RamdiskFormatError(ValueError):
    """The archive does not match the bounded production ramdisk profile."""


def require(condition, message):
    if not condition:
        raise RamdiskFormatError(message)


def bounded(offset, size, limit, message):
    require(0 <= offset <= limit and 0 <= size <= limit - offset, message)


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def static_aarch64(data):
    require(len(data) >= 64, "Truncated ELF header.")
    require(data[:16] == b"\x7fELF\x02\x01\x01" + b"\0" * 9,
            "Payload must be ELF64 little-endian with the expected ABI.")
    (kind, machine, version, entry, phoff, shoff, flags, ehsize,
     phsize, phcount, shsize, shcount, shstrings) = struct.unpack_from("<HHIQQQIHHHHHH", data, 16)
    require((kind, machine, version, flags, ehsize) == (2, 183, 1, 0, 64),
            "Payload must be a conventional AArch64 ET_EXEC executable.")
    require(phsize == 56 and 1 <= phcount <= 128 and phoff >= ehsize,
            "Invalid ELF program-header table.")
    bounded(phoff, phsize * phcount, len(data), "Truncated ELF program-header table.")
    if shcount == 0:
        require(shoff == 0 and shsize in (0, 64) and shstrings == 0,
                "Unsupported ELF extended section numbering.")
    else:
        require(shsize == 64 and shcount <= 4096 and shoff >= ehsize and shstrings < shcount,
                "Invalid ELF section-header table.")
        bounded(shoff, shsize * shcount, len(data), "Truncated ELF section-header table.")
    executable_entry, loads, stack_count = False, [], 0
    for index in range(phcount):
        (ptype, pflags, offset, address, physical, size, memory, alignment) = struct.unpack_from(
            "<IIQQQQQQ", data, phoff + index * phsize)
        require(ptype not in (2, 3), "Dynamic ELF segments or an interpreter are forbidden.")
        bounded(offset, size, len(data), "ELF segment exceeds the file.")
        require(alignment in (0, 1) or alignment & (alignment - 1) == 0,
                "ELF segment alignment is not a power of two.")
        require(pflags & ~7 == 0, "Unexpected ELF segment flags.")
        if ptype == 1:
            require(size <= memory and memory <= (1 << 64) - address,
                    "Invalid ELF load-segment memory range.")
            require(alignment <= 1 or offset % alignment == address % alignment,
                    "Inconsistent ELF load-segment alignment.")
            require(pflags & 3 != 3, "Writable executable ELF load segment is forbidden.")
            require(all(address + memory <= start or end <= address for start, end in loads),
                    "ELF load segments overlap.")
            loads.append((address, address + memory))
            if pflags & 1 and address <= entry < address + size:
                executable_entry = True
        if ptype == 0x6474E551:
            stack_count += 1
            require(pflags == 6 and size == 0 and memory == 0,
                    "ELF stack must be explicitly non-executable.")
    require(loads and executable_entry and stack_count == 1,
            "ELF lacks a valid file-backed entry point or non-executable stack.")
    return {"class": 64, "byte_order": "little", "machine": "AArch64", "type": "ET_EXEC",
            "program_headers": phcount, "load_segments": len(loads),
            "interpreter": False, "dynamic_segment": False, "executable_stack": False}


def inspect_ramdisk(data):
    """Return structural evidence for the exact production profile; never extract."""
    require(isinstance(data, bytes), "Ramdisk input must be bytes.")
    require(18 <= len(data) <= MAX_COMPRESSED, "Compressed ramdisk exceeds its byte bound or is truncated.")
    require(data[:10] == GZIP_HEADER, "Expected the reproducible gzip -n -9 header.")
    decoder = zlib.decompressobj(16 + zlib.MAX_WBITS)
    try:
        archive = decoder.decompress(data, MAX_UNCOMPRESSED + 1)
    except zlib.error as error:
        raise RamdiskFormatError("Invalid gzip stream, checksum or length.") from error
    require(len(archive) <= MAX_UNCOMPRESSED, "Decompressed ramdisk exceeds its byte bound.")
    require(decoder.eof and not decoder.unconsumed_tail and not decoder.unused_data,
            "Ramdisk must contain exactly one complete gzip member without trailing data.")
    entries, payloads, offset = [], {}, 0
    for index in range(len(EXPECTED) + 1):
        bounded(offset, 110, len(archive), "Truncated newc header.")
        header = archive[offset:offset + 110]
        require(header[:6] == b"070701" and re.fullmatch(b"[0-9a-fA-F]{104}", header[6:]),
                "Invalid newc header or hexadecimal field.")
        fields = tuple(int(header[6 + i * 8:14 + i * 8], 16) for i in range(13))
        inode, mode, uid, gid, links, mtime, size, major, minor, rmajor, rminor, namesize, checksum = fields
        require(2 <= namesize <= 128, "Invalid newc filename length.")
        name_start = offset + 110
        bounded(name_start, namesize, len(archive), "Truncated newc filename.")
        name = archive[name_start:name_start + namesize]
        require(name[-1:] == b"\0" and b"\0" not in name[:-1], "Invalid newc filename termination.")
        try:
            name = name[:-1].decode("ascii")
        except UnicodeDecodeError as error:
            raise RamdiskFormatError("Non-ASCII newc filename.") from error
        content = (name_start + namesize + 3) & ~3
        require(not any(archive[name_start + namesize:content]), "Nonzero newc name padding.")
        bounded(content, size, len(archive), "Truncated newc payload.")
        following = (content + size + 3) & ~3
        bounded(content + size, following - content - size, len(archive), "Truncated newc data padding.")
        require(not any(archive[content + size:following]), "Nonzero newc data padding.")
        if index == len(EXPECTED):
            require(name == "TRAILER!!!" and fields == TRAILER, "Missing or invalid final newc trailer.")
            require(len(archive) % 512 == 0 and len(archive) - following < 512 and
                    not any(archive[following:]), "Extra archive, overlay or invalid final padding.")
            break
        require(name == EXPECTED[index], "Unexpected, duplicated, unsafe or out-of-order ramdisk entry.")
        directory = name in DIRECTORIES
        expected_mode = (stat.S_IFDIR | (0o1777 if name == "tmp" else 0o755)) if directory else stat.S_IFREG | 0o555
        require(mode == expected_mode and uid == gid == 0 and mtime == 1,
                "Ramdisk ownership, permissions, file type or timestamp differs from the fixed profile.")
        require(inode == index and links == (2 if directory else 1) and
                (major, minor, rmajor, rminor, checksum) == (0, 0, 0, 0, 0),
                "Unexpected ramdisk link, inode or device metadata.")
        item = {"path": name, "kind": "directory" if directory else "file",
                "mode": format(mode, "06o"), "uid": uid, "gid": gid, "mtime": mtime, "bytes": size}
        if directory:
            require(size == 0, "Ramdisk directory contains payload bytes.")
        else:
            payload = archive[content:content + size]
            item.update({"sha256": sha256(payload), "elf": static_aarch64(payload)})
            payloads[name] = item["sha256"]
        entries.append(item)
        offset = following
    return {"format": "titan-usb-acquisition-initramfs-v1", "compressed_bytes": len(data),
            "uncompressed_bytes": len(archive), "sha256": sha256(data),
            "uncompressed_sha256": sha256(archive), "entries": entries, "payload_sha256": payloads,
            "validation": {"single_gzip_member": True, "exact_profile": True, "static_aarch64": True,
                           "manifests_verified": False, "code_provenance_verified": False,
                           "bootability_verified": False}}


def parse_manifest(data, expected):
    require(isinstance(data, bytes) and 0 < len(data) <= MAX_MANIFEST and data.endswith(b"\n"),
            "Manifest is empty, oversized or lacks a final newline.")
    hashes = {}
    for line in data.splitlines(keepends=True):
        match = re.fullmatch(rb"([0-9a-f]{64})  ([A-Za-z0-9/.-]+)\n", line)
        require(match is not None, "Manifest must use canonical SHA256SUMS records.")
        name = match[2].decode("ascii")
        require(name in expected and name not in hashes, "Manifest contains an unexpected or repeated path.")
        hashes[name] = match[1].decode("ascii")
    require(set(hashes) == set(expected), "Manifest is missing expected files.")
    return hashes


def verify_manifests(report, archive_manifest, payload_manifest):
    """Check both external build manifests against parsed bytes; mutate no report."""
    archives = parse_manifest(archive_manifest, ("initramfs.cpio.gz",))
    payloads = parse_manifest(payload_manifest, FILES)
    require(archives["initramfs.cpio.gz"] == report["sha256"], "Archive manifest SHA-256 mismatch.")
    require(payloads == report["payload_sha256"], "Payload manifest SHA-256 mismatch.")
    return True


def read_regular(path, limit):
    node = os.lstat(path)
    require(stat.S_ISREG(node.st_mode) and 0 < node.st_size <= limit,
            "Input must be a nonempty bounded regular file.")
    descriptor = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        before = os.fstat(descriptor)
        require(stat.S_ISREG(before.st_mode) and 0 < before.st_size <= limit and
                (node.st_dev, node.st_ino) == (before.st_dev, before.st_ino),
                "Input must be a nonempty bounded regular file.")
        parts, count = [], 0
        while True:
            data = os.read(descriptor, min(65536, limit + 1 - count))
            if not data:
                break
            parts.append(data)
            count += len(data)
            require(count <= limit, "Input grew beyond its byte bound.")
        after = os.fstat(descriptor)
        identity = lambda item: (item.st_dev, item.st_ino, item.st_mode, item.st_nlink,
                                 item.st_size, item.st_mtime_ns, item.st_ctime_ns)
        require(count == before.st_size and identity(before) == identity(after), "Input changed while being read.")
        return b"".join(parts)
    finally:
        os.close(descriptor)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("ramdisk", type=Path)
    parser.add_argument("--sha256sums", type=Path, help="external archive SHA256SUMS")
    parser.add_argument("--payload-sha256sums", type=Path, help="external payload-SHA256SUMS")
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args(argv)
    if (args.sha256sums is None) != (args.payload_sha256sums is None):
        parser.error("provide both SHA-256 manifests or neither")
    try:
        report = inspect_ramdisk(read_regular(args.ramdisk, MAX_COMPRESSED))
        if args.sha256sums is not None:
            report["validation"]["manifests_verified"] = verify_manifests(report,
                read_regular(args.sha256sums, MAX_MANIFEST), read_regular(args.payload_sha256sums, MAX_MANIFEST))
        if args.json:
            print(json.dumps(report, indent=2, sort_keys=True))
        else:
            print("Exact USB acquisition ramdisk profile: 13 entries, six static AArch64 executables.")
            if args.sha256sums is not None:
                print("Archive and payload SHA-256 manifests agree.")
            print("Structural validation only; code provenance and bootability are not verified.")
        return 0
    except (OSError, RamdiskFormatError) as error:
        print(f"Ramdisk inspection failed: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
