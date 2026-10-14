#!/usr/bin/env python3
"""Check the source guard using newly generated GPT disks in isolated TCG VMs."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import selectors
import stat
import struct
import subprocess
import sys
import tempfile
import time
import uuid
import zlib


SECTOR = 512
DISK_BYTES = 64 * 1024 * 1024
PARTITION_BYTES = 16 * 1024 * 1024
PARTITION_START = 2048
OUTPUT_LIMIT = 4 * 1024 * 1024
TIMEOUT = 90
CASES = ("valid", "wrong-label", "wrong-start", "wrong-size", "unprotected",
         "extra-mount", "symlink-node", "claim-conflict", "recheck-ro-clear", "recheck-node-change")
EXPECTED = {
    "wrong-label": "partition-identity-mismatch",
    "wrong-start": "partition-geometry-mismatch",
    "wrong-size": "partition-geometry-mismatch",
    "unprotected": "block-not-read-only",
    "extra-mount": "unexpected-mount",
    "symlink-node": "block-node-mismatch",
    "claim-conflict": "partition-claim-conflict",
    "recheck-ro-clear": "block-not-read-only",
    "recheck-node-change": "block-node-mismatch",
}


def private_write(path, data):
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "wb") as stream:
        stream.write(data)


def regular_input(value, executable=False):
    path = Path(value).expanduser().resolve(strict=True)
    if not stat.S_ISREG(path.stat().st_mode):
        raise ValueError("QEMU, kernel and initramfs inputs must be regular files.")
    if executable and not os.access(path, os.X_OK):
        raise ValueError("The supplied QEMU executable is not executable.")
    return path


def create_disk(directory, case):
    """Create a protective MBR plus matching CRC-checked primary/backup GPT."""
    sectors = DISK_BYTES // SECTOR
    start = PARTITION_START + (case == "wrong-start")
    length = PARTITION_BYTES // SECTOR + (case == "wrong-size")
    label = "wrong-label" if case == "wrong-label" else "userdata"
    entries = bytearray(128 * 128)
    entries[:128] = struct.pack(
        "<16s16sQQQ72s", uuid.UUID("0fc63daf-8483-4772-8e79-3d69d8477de4").bytes_le,
        uuid.UUID("2cc9dbb8-ccab-49b7-a1f5-cb2615546ab5").bytes_le,
        start, start + length - 1, 0, label.encode("utf-16le"),
    )
    entries_crc = zlib.crc32(entries)

    def header(current, alternate, table):
        data = bytearray(struct.pack(
            "<8sIIIIQQQQ16sQIII", b"EFI PART", 0x00010000, 92, 0, 0,
            current, alternate, 34, sectors - 34,
            uuid.UUID("52c48f16-4919-48cd-886b-e207ad9dd081").bytes_le,
            table, 128, 128, entries_crc,
        ))
        struct.pack_into("<I", data, 16, zlib.crc32(data))
        return bytes(data).ljust(SECTOR, b"\0")

    mbr = bytearray(SECTOR)
    mbr[446:462] = struct.pack("<B3sB3sII", 0, b"\0\x02\0", 0xEE, b"\xff" * 3, 1, sectors - 1)
    mbr[510:] = b"\x55\xaa"
    descriptor, filename = tempfile.mkstemp(prefix="gpt-fixture-", suffix=".raw", dir=directory)
    with os.fdopen(descriptor, "wb") as stream:
        if not stat.S_ISREG(os.fstat(stream.fileno()).st_mode):
            raise RuntimeError("Generated disk is not a regular file.")
        stream.truncate(DISK_BYTES)
        for lba, data in ((0, mbr), (1, header(1, sectors - 1, 2)), (2, entries),
                          (sectors - 33, entries), (sectors - 1, header(sectors - 1, 1, sectors - 33))):
            stream.seek(lba * SECTOR)
            stream.write(data)
        stream.flush()
        os.fsync(stream.fileno())
    return Path(filename)


def disk_hash(path):
    digest, count = hashlib.sha256(), 0
    with path.open("rb") as stream:
        while data := stream.read(1024 * 1024):
            count += len(data)
            if count > DISK_BYTES:
                raise RuntimeError("Generated disk grew beyond its fixed logical size.")
            digest.update(data)
    if count != DISK_BYTES:
        raise RuntimeError("Generated disk changed its fixed logical size.")
    return digest.hexdigest()


def lines(console):
    return console.replace(b"\r", b"").split(b"\n")


def run_case(case, output, qemu, kernel, initrd):
    directory = output / case
    directory.mkdir(mode=0o700)
    result = {"case": case, "passed": False}
    captured = {"stdout": bytearray(), "stderr": bytearray()}
    disk = process = None
    started = time.monotonic()
    try:
        disk = create_disk(directory, case)
        result.update({"disk_file": disk.name, "disk_sha256_before": disk_hash(disk)})
        command = [
            str(qemu), "-machine", "q35,accel=tcg", "-cpu", "max", "-m", "512M",
            "-nodefaults", "-no-user-config", "-display", "none", "-monitor", "none",
            "-serial", "stdio", "-nic", "none", "-no-reboot",
            "-kernel", str(kernel), "-initrd", str(initrd),
            "-append", f"console=ttyS0,115200 rdinit=/init loglevel=4 panic=0 titan.source_case={case}",
            # Only our newly created basename enters QEMU option syntax.
            "-drive", f"file={disk.name},if=none,format=raw,id=probe",
            "-device", "virtio-blk-pci,drive=probe",
        ]
        process = subprocess.Popen(command, cwd=directory, stdin=subprocess.DEVNULL,
                                   stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        with selectors.DefaultSelector() as selector:
            selector.register(process.stdout, selectors.EVENT_READ, "stdout")
            selector.register(process.stderr, selectors.EVENT_READ, "stderr")
            while selector.get_map():
                if time.monotonic() - started >= TIMEOUT:
                    raise RuntimeError("QEMU exceeded the 90-second case deadline.")
                for key, _ in selector.select(0.1):
                    remaining = OUTPUT_LIMIT - sum(map(len, captured.values()))
                    data = os.read(key.fileobj.fileno(), min(65536, remaining + 1))
                    if not data:
                        selector.unregister(key.fileobj)
                    elif len(data) > remaining:
                        raise RuntimeError("QEMU exceeded the 4 MiB diagnostic bound.")
                    else:
                        captured[key.data].extend(data)
                if any(line.startswith((b"TITAN_SOURCE_VM_FAIL ", b"TITAN_RESCUE_FAILED "))
                       for line in lines(captured["stdout"])):
                    raise RuntimeError("Guest reported a fixture or source-guard assertion failure.")
        code = process.wait(timeout=max(0.1, TIMEOUT - (time.monotonic() - started)))
        console = lines(captured["stdout"])
        expected_pass = f"TITAN_SOURCE_VM_PASS {case}".encode()
        if code != 0 or console.count(expected_pass) != 1:
            raise RuntimeError("Guest did not print its exact PASS marker once and power off with status 0.")
        if b"TITAN_RESCUE_READY v1" not in console:
            raise RuntimeError("Guest did not complete rescue block protection before the callback.")
        other_passes = [line for line in console if line.startswith(b"TITAN_SOURCE_VM_PASS ")]
        if other_passes != [expected_pass]:
            raise RuntimeError("Guest reported an unexpected success case.")
        result["expected_rejection"] = [line.decode("ascii") for line in console
                                        if line.startswith(b"TITAN_SOURCE_VM_EXPECTED ")]
        if case != "valid" and result["expected_rejection"] != [
                f"TITAN_SOURCE_VM_EXPECTED {case} {EXPECTED[case]}"]:
            raise RuntimeError("Negative case did not record its exact expected rejection.")
        if case == "valid" and result["expected_rejection"]:
            raise RuntimeError("Valid case unexpectedly reported a rejection.")
        result["passed"] = True
    except (OSError, ValueError, RuntimeError, subprocess.TimeoutExpired) as error:
        result["error"] = str(error)
    finally:
        if process is not None:
            if process.poll() is None:
                process.terminate()
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=5)
            result["qemu_exit_code"] = process.returncode
            process.stdout.close()
            process.stderr.close()
        if disk is not None:
            try:
                result["disk_sha256_after"] = disk_hash(disk)
                if result.get("disk_sha256_before") != result["disk_sha256_after"]:
                    raise RuntimeError("Guest changed the writable host disk fixture.")
            except (OSError, RuntimeError) as error:
                result.update({"passed": False, "error": str(error)})
        result["elapsed_seconds"] = round(time.monotonic() - started, 3)
        private_write(directory / "console.log", captured["stdout"])
        private_write(directory / "qemu.stderr", captured["stderr"])
    return result


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("qemu", "kernel", "initrd", "output"):
        parser.add_argument("--" + name, required=True)
    args = parser.parse_args(argv)
    original_umask = os.umask(0o077)
    try:
        qemu = regular_input(args.qemu, executable=True)
        kernel, initrd = regular_input(args.kernel), regular_input(args.initrd)
        output = Path(args.output).expanduser().absolute()
        output.mkdir(mode=0o700)
        cases = []
        for case in CASES:
            result = run_case(case, output, qemu, kernel, initrd)
            cases.append(result)
            print(f"{case}: {'passed' if result['passed'] else 'FAILED'}", flush=True)
        report = {"passed": all(case["passed"] for case in cases), "cases": cases,
                  "scope": "Generated GPT disks in x86_64 TCG guests only; no Titan hardware validation."}
        private_write(output / "summary.json", (json.dumps(report, indent=2) + "\n").encode())
        return 0 if report["passed"] else 1
    except (OSError, ValueError, KeyboardInterrupt) as error:
        print(f"Source VM check stopped: {error}", file=sys.stderr)
        return 1
    finally:
        os.umask(original_umask)


if __name__ == "__main__":
    sys.exit(main())
