"""Synthetic tests of the native route's DT-table packer (native/dt-table.py)."""

import importlib.util
import os
from pathlib import Path
import struct
import tempfile
import unittest


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


HERE = Path(__file__).resolve().parent
# Nix supplies the packer explicitly; a checkout has it beside tools/.
packer = load("titan_native_dt_table", os.environ.get("TITAN_NATIVE_DT_TABLE") or
              HERE.parent.parent / "native" / "dt-table.py")
inspector = load("titan_native_dt_inspector", HERE.parent / "inspect-boot-image.py")


def fdt(name=b"titan"):
    """A minimal version-17 FDT: one root node with a name-like property."""
    strings = b"model\0"
    value = name + b"\0"
    value += bytes(-len(value) % 4)
    structure = (struct.pack(">II", 1, 0) + struct.pack(">III", 3, len(name) + 1, 0) + value
                 + struct.pack(">II", 2, 9))
    reserve = bytes(16)
    header_size = 40
    reserve_offset = header_size
    structure_offset = reserve_offset + len(reserve)
    strings_offset = structure_offset + len(structure)
    total = strings_offset + len(strings)
    header = struct.pack(">10I", 0xD00DFEED, total, structure_offset, strings_offset, reserve_offset,
                         17, 16, 0, len(strings), len(structure))
    return header + reserve + structure + strings


class TableTests(unittest.TestCase):
    def test_table_matches_the_stock_layout_and_parses_independently(self):
        tree = fdt()
        data = packer.table(tree)
        self.assertEqual(struct.unpack(">8I", data[:32]), (0xD7B7AB1E, 64 + len(tree), 32, 32, 1, 32, 2048, 0))
        self.assertEqual(struct.unpack(">8I", data[32:64]), (len(tree), 64, 0, 0, 0, 0, 0, 0))
        self.assertEqual(data[64:], tree)
        info = inspector.inspect_dtb(data)
        self.assertEqual((info["format"], info["total_size"], info["trailing_bytes"]),
                         ("android-dt-table", len(data), 0))
        self.assertEqual([(entry["offset"], entry["size"], entry["fdt"]["version"]) for entry in info["entries"]],
                         [(64, len(tree), 17)])

    def test_invalid_trees_are_refused(self):
        tree = fdt()
        for name, data in (("magic", b"\0" + tree[1:]), ("short", tree[:39]),
                           ("size-field", tree + b"\0"), ("not-bytes", bytearray(tree)),
                           ("oversize", tree[:4] + struct.pack(">I", packer.MAX_FDT + 1) + tree[8:]
                            + bytes(packer.MAX_FDT + 1 - len(tree)))):
            with self.subTest(case=name), self.assertRaises(ValueError):
                packer.table(data)

    def test_cli_writes_a_new_file_only(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "tree.dtb").write_bytes(fdt())
            self.assertEqual(packer.main([str(root / "tree.dtb"), str(root / "table.img")]), 0)
            self.assertEqual((root / "table.img").read_bytes(), packer.table(fdt()))
            with self.assertRaises(FileExistsError):
                packer.main([str(root / "tree.dtb"), str(root / "table.img")])


if __name__ == "__main__":
    unittest.main()
