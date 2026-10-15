#!/usr/bin/env python3
"""Wrap one flattened device tree in an Android DT table, as the Titan's stock
boot and recovery images carry their DTB and overlay (native-n0.adoc).

The layout matches the stock tables: a 32-byte big-endian header (magic
0xd7b7ab1e, total size, header size 32, entry size 32, one entry, entries at
offset 32, page size 2048, version 0), one 32-byte entry (size, offset 64, id 0,
revision 0, four zero custom words) and the FDT at offset 64, unpadded.
"""

import argparse
import struct
import sys

MAGIC = 0xD7B7AB1E
FDT_MAGIC = b"\xd0\x0d\xfe\xed"
HEADER = struct.Struct(">8I")
ENTRY = struct.Struct(">8I")
MAX_FDT = 4 * 1024 * 1024


def table(fdt):
    if not isinstance(fdt, bytes) or len(fdt) < 40 or len(fdt) > MAX_FDT or fdt[:4] != FDT_MAGIC:
        raise ValueError("input is not a bounded flattened device tree")
    if struct.unpack(">I", fdt[4:8])[0] != len(fdt):
        raise ValueError("FDT total size field does not match the input length")
    offset = HEADER.size + ENTRY.size
    header = HEADER.pack(MAGIC, offset + len(fdt), HEADER.size, ENTRY.size, 1, HEADER.size, 2048, 0)
    entry = ENTRY.pack(len(fdt), offset, 0, 0, 0, 0, 0, 0)
    return header + entry + fdt


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("fdt")
    parser.add_argument("output")
    args = parser.parse_args(argv)
    with open(args.fdt, "rb") as stream:
        data = stream.read(MAX_FDT + 1)
    with open(args.output, "xb") as stream:
        stream.write(table(data))
    return 0


if __name__ == "__main__":
    sys.exit(main())
