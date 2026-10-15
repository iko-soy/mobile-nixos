#!/usr/bin/env python3
"""Exercise the USB mount-profile source guard in disposable networkless VMs.

Uses generated GPT disks and actual configfs mounts, without gadgets, acquisition,
phone operations, physical devices or hardware compatibility claims.
"""

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import selectors
import signal
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
CASES = ("sealed", "missing-configfs", "writable-configfs", "wrong-path",
         "extra-alias", "mount-only-readonly", "recheck-writable")
EXPECTED = {case: "unexpected-mount" for case in CASES if case != "sealed"}
EXPECTED["missing-configfs"] = "mount-inventory-incomplete"


def private_write(path, data):
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(descriptor, "wb") as stream:
        stream.write(data)
        stream.flush()
        os.fsync(stream.fileno())


def regular_input(value, executable=False):
    path = Path(value).expanduser().resolve(strict=True)
    if not stat.S_ISREG(path.stat().st_mode):
        raise ValueError("QEMU, kernel and initramfs inputs must be regular files.")
    if executable and not os.access(path, os.X_OK):
        raise ValueError("The supplied QEMU executable is not executable.")
    return path


def file_hash(path, maximum=256 * 1024 * 1024, exact=None):
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    digest, count = hashlib.sha256(), 0
    with os.fdopen(descriptor, "rb") as stream:
        metadata = os.fstat(stream.fileno())
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_size > maximum:
            raise RuntimeError("Fixture input is not a bounded regular file.")
        while data := stream.read(min(1024 * 1024, maximum - count + 1)):
            count += len(data)
            if count > maximum:
                raise RuntimeError("Fixture input exceeded its byte bound.")
            digest.update(data)
    if exact is not None and count != exact:
        raise RuntimeError("Generated disk changed its fixed logical size.")
    return digest.hexdigest()


def create_disk(directory):
    """Create a protective MBR plus matching CRC-checked primary/backup GPT."""
    sectors = DISK_BYTES // SECTOR
    start = PARTITION_START
    length = PARTITION_BYTES // SECTOR
    label = "userdata"
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
    descriptor, filename = tempfile.mkstemp(prefix="mount-policy-gpt-", suffix=".raw", dir=directory)
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


def console_lines(data):
    return [line.removesuffix(b"\r") for line in data.split(b"\n")]


def verify_markers(console, case, kernel_version):
    lines = console_lines(console)
    if lines.count(b"TITAN_RESCUE_START v1") != 1 or lines.count(b"TITAN_RESCUE_READY v1") != 1:
        raise RuntimeError("Guest did not complete the expected rescue block protection once.")
    expected = [f"TITAN_MOUNT_VM_START {case}", f"TITAN_MOUNT_VM_KERNEL {kernel_version}"]
    if case in EXPECTED:
        expected.append(f"TITAN_MOUNT_VM_EXPECTED {case} {EXPECTED[case]}")
    expected.append(f"TITAN_MOUNT_VM_PASS {case}")
    observed = [line for line in lines if line.startswith(b"TITAN_MOUNT_VM_")]
    if observed != [line.encode("ascii") for line in expected]:
        raise RuntimeError("Guest mount-policy markers did not match the exact case, kernel, stages and outcome.")
    if lines.index(b"TITAN_RESCUE_READY v1") > lines.index(expected[0].encode()):
        raise RuntimeError("Mount-policy callback ran before rescue block protection completed.")
    if any(line.startswith(b"TITAN_RESCUE_FAILED") for line in lines):
        raise RuntimeError("Guest reported a rescue failure.")
    return expected


def stop_process(process):
    if process.poll() is not None:
        return
    for sig in (signal.SIGTERM, signal.SIGKILL):
        try:
            os.killpg(process.pid, sig)
        except ProcessLookupError:
            pass
        try:
            process.wait(timeout=5)
            return
        except subprocess.TimeoutExpired:
            if sig == signal.SIGKILL:
                raise RuntimeError("QEMU process group did not stop after SIGKILL.")


def run_case(case, output, qemu, kernel, initrd, kernel_version):
    directory = output / case
    directory.mkdir(mode=0o700)
    result = {"case": case, "passed": False, "expected_kernel_version": kernel_version,
              "expected_outcome": EXPECTED.get(case, "sealed-source-open-recheck-and-cleanup")}
    captured = {"stdout": bytearray(), "stderr": bytearray()}
    disk = process = None
    started = time.monotonic()
    try:
        disk = create_disk(directory)
        result.update({"disk_file": disk.name,
                       "disk_sha256_before": file_hash(disk, DISK_BYTES, DISK_BYTES)})
        command = [
            str(qemu), "-machine", "q35,accel=tcg", "-cpu", "max", "-m", "512M",
            "-nodefaults", "-no-user-config", "-display", "none", "-monitor", "none",
            "-serial", "stdio", "-nic", "none", "-no-reboot",
            "-kernel", str(kernel), "-initrd", str(initrd),
            "-append", f"console=ttyS0,115200 rdinit=/init loglevel=4 panic=0 titan_mount_test={case}",
            # Only our newly generated basename enters QEMU option syntax.
            "-drive", f"file={disk.name},if=none,format=raw,id=probe",
            "-device", "virtio-blk-pci,drive=probe",
        ]
        process = subprocess.Popen(command, cwd=directory, stdin=subprocess.DEVNULL,
                                   stdout=subprocess.PIPE, stderr=subprocess.PIPE, start_new_session=True)
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
                if any(line.startswith((b"TITAN_MOUNT_VM_FAIL", b"TITAN_RESCUE_FAILED"))
                       for line in console_lines(captured["stdout"])):
                    raise RuntimeError("Guest reported a mount-policy or rescue assertion failure.")
        code = process.wait(timeout=max(0.1, TIMEOUT - (time.monotonic() - started)))
        if code != 0:
            raise RuntimeError("Guest did not power off with QEMU status 0.")
        result["observed_markers"] = verify_markers(captured["stdout"], case, kernel_version)
        result["observed_kernel_version"] = kernel_version
        result["passed"] = True
    except (OSError, ValueError, RuntimeError, subprocess.TimeoutExpired) as error:
        result["error"] = str(error)
    finally:
        if process is not None:
            try:
                stop_process(process)
            except (OSError, RuntimeError) as error:
                result.update({"passed": False, "error": str(error)})
            result["qemu_exit_code"] = process.returncode
            process.stdout.close()
            process.stderr.close()
        if disk is not None:
            try:
                result["disk_sha256_after"] = file_hash(disk, DISK_BYTES, DISK_BYTES)
                if result.get("disk_sha256_before") != result["disk_sha256_after"]:
                    raise RuntimeError("Guest changed the writable host storage fixture.")
            except (OSError, RuntimeError) as error:
                result.update({"passed": False, "error": str(error)})
        result["elapsed_seconds"] = round(time.monotonic() - started, 3)
        private_write(directory / "console.log", captured["stdout"])
        private_write(directory / "qemu.stderr", captured["stderr"])
        private_write(directory / "result.json", (json.dumps(result, indent=2) + "\n").encode())
        if not result["passed"]:
            print(f"{case}: {result.get('error', 'guest validation failed')}", file=sys.stderr)
            tail = bytes(captured["stdout"][-4096:])
            print(f"{case}: final {len(tail)} synthetic guest console bytes:", file=sys.stderr)
            # Escape CR and other controls so Nix's progress logger cannot
            # erase serial-console lines when it handles CRLF as a redraw.
            print(json.dumps(tail.decode("utf-8", errors="replace")), file=sys.stderr, flush=True)
    return result


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("qemu", "kernel", "initrd", "kernel-version", "output"):
        parser.add_argument("--" + name, required=True)
    args = parser.parse_args(argv)
    if not re.fullmatch(r"[A-Za-z0-9._+-]{1,128}", args.kernel_version):
        parser.error("--kernel-version must be a bounded Linux release identifier")
    previous_umask = os.umask(0o077)
    try:
        qemu = regular_input(args.qemu, executable=True)
        kernel, initrd = regular_input(args.kernel), regular_input(args.initrd)
        report = {"format": 1, "passed": False, "cases": [],
                  "expected_kernel_version": args.kernel_version,
                  "kernel_sha256": file_hash(kernel), "initrd_sha256": file_hash(initrd),
                  "kernel_expectation": "real configfs and fixed-profile source guard in the same guest",
                  "scope": "Generated GPT disks and configfs in x86_64 TCG guests only; no Titan validation."}
        output = Path(args.output).expanduser().absolute()
        output.mkdir(mode=0o700)  # Refuse existing directories, files and symlinks.
        for case in CASES:
            result = run_case(case, output, qemu, kernel, initrd, args.kernel_version)
            report["cases"].append(result)
            print(f"{case}: {'passed' if result['passed'] else 'FAILED'}", flush=True)
        report["passed"] = all(result["passed"] for result in report["cases"])
        private_write(output / "summary.json", (json.dumps(report, indent=2) + "\n").encode())
        return 0 if report["passed"] else 1
    except (OSError, ValueError, RuntimeError, KeyboardInterrupt) as error:
        print(f"Mount-policy VM check stopped: {error}", file=sys.stderr)
        return 1
    finally:
        os.umask(previous_umask)


if __name__ == "__main__":
    sys.exit(main())
