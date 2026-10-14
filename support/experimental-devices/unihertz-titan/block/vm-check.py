#!/usr/bin/env python3
"""Run the guarded block pipeline only against generated ext4/GPT VM fixtures."""

import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import selectors
import shutil
import socket
import stat
import struct
import subprocess
import sys
import tempfile
import threading
import time
import uuid
import zlib


DISK_BYTES = 64 * 1024 * 1024
FILESYSTEM_BYTES = 16 * 1024 * 1024
START = 2048
LIMIT = 32 * 1024 * 1024
LOG_LIMIT = 4 * 1024 * 1024
TIMEOUT = 90
PAYLOAD = bytes(range(256)) * 257 + b"Titan guarded synthetic block pipeline\n"
CASES = ("valid", "dirty-filesystem", "wrong-label", "output-limit", "post-readonly-change")


def private_write(path, data):
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "wb") as stream:
        stream.write(data)


def regular(value, executable=False):
    path = Path(value).expanduser().resolve(strict=True)
    if not stat.S_ISREG(path.stat().st_mode) or (executable and not os.access(path, os.X_OK)):
        raise ValueError("Executable/kernel/initramfs inputs must be regular files with appropriate access.")
    return path


def tool(arguments, timeout=20, cwd=None):
    result = subprocess.run(arguments, capture_output=True, timeout=timeout, cwd=cwd)
    if len(result.stdout) + len(result.stderr) > LOG_LIMIT:
        raise RuntimeError("Fixture tool exceeded its diagnostic bound.")
    if result.returncode:
        raise RuntimeError(f"Fixture tool {Path(arguments[0]).name} failed: " +
                           (result.stdout + result.stderr).decode(errors="replace")[:8192])
    return result.stdout + result.stderr


def create_filesystem(output, tools):
    filesystem, known = output / "synthetic.ext4", output / "known.bin"
    private_write(known, PAYLOAD)
    descriptor = os.open(filesystem, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "wb") as stream:
        stream.truncate(FILESYSTEM_BYTES)
    tool([str(tools["mke2fs"]), "-q", "-F", "-t", "ext4", "-E",
          "lazy_itable_init=0,lazy_journal_init=0", str(filesystem)])
    tool([str(tools["debugfs"]), "-w", "-R", "write known.bin /known.bin", "synthetic.ext4"], cwd=output)
    tool([str(tools["e2fsck"]), "-fn", str(filesystem)])
    return filesystem


def create_disk(directory, case, filesystem):
    sectors = DISK_BYTES // 512
    entries = bytearray(128 * 128)
    label = "wrong-label" if case == "wrong-label" else "userdata"
    entries[:128] = struct.pack("<16s16sQQQ72s",
        uuid.UUID("0fc63daf-8483-4772-8e79-3d69d8477de4").bytes_le,
        uuid.UUID("4accf687-af56-43cc-a651-1c3023d3aa74").bytes_le,
        START, START + FILESYSTEM_BYTES // 512 - 1, 0, label.encode("utf-16le"))

    def header(current, alternate, table):
        data = bytearray(struct.pack("<8sIIIIQQQQ16sQIII", b"EFI PART", 0x10000, 92, 0, 0,
            current, alternate, 34, sectors - 34,
            uuid.UUID("72d509eb-d7eb-4d61-bd09-d277d81cacbe").bytes_le,
            table, 128, 128, zlib.crc32(entries)))
        struct.pack_into("<I", data, 16, zlib.crc32(data))
        return data.ljust(512, b"\0")

    mbr = bytearray(512)
    mbr[446:462] = struct.pack("<B3sB3sII", 0, b"\0\x02\0", 0xEE, b"\xff" * 3, 1, sectors - 1)
    mbr[510:] = b"\x55\xaa"
    descriptor, name = tempfile.mkstemp(prefix="synthetic-gpt-", suffix=".raw", dir=directory)
    with os.fdopen(descriptor, "wb") as stream:
        if not stat.S_ISREG(os.fstat(stream.fileno()).st_mode):
            raise RuntimeError("New fixture is not a regular file.")
        stream.truncate(DISK_BYTES)
        for lba, data in ((0, mbr), (1, header(1, sectors - 1, 2)), (2, entries),
                          (sectors - 33, entries), (sectors - 1, header(sectors - 1, 1, sectors - 33))):
            stream.seek(lba * 512)
            stream.write(data)
        stream.seek(START * 512)
        count = 0
        with filesystem.open("rb") as source:
            while data := source.read(65536):
                count += len(data)
                if count > FILESYSTEM_BYTES:
                    raise RuntimeError("Synthetic filesystem exceeded its fixed bound.")
                if any(data):
                    stream.write(data)
                else:
                    stream.seek(len(data), os.SEEK_CUR)
        if count != FILESYSTEM_BYTES:
            raise RuntimeError("Synthetic filesystem length changed.")
        if case == "dirty-filesystem":
            stream.seek(START * 512 + 1024 + 58)
            stream.write(struct.pack("<H", 2))
        stream.flush()
        os.fsync(stream.fileno())
    return Path(name)


def digest_disk(path):
    digest, count = hashlib.sha256(), 0
    with path.open("rb") as stream:
        while data := stream.read(1024 * 1024):
            count += len(data)
            if count > DISK_BYTES:
                raise RuntimeError("Guest disk grew beyond its fixed size.")
            digest.update(data)
    if count != DISK_BYTES:
        raise RuntimeError("Guest disk size changed.")
    return digest.hexdigest()


def restore_payload(directory, tools):
    restored, recovered = directory / "restored.ext4", directory / "recovered.bin"
    tool([str(tools["zstd"]), "-d", "--sparse", "-q", str(directory / "received" / "payload.bin"),
          "-o", str(restored)])
    if not restored.is_file() or restored.stat().st_size != FILESYSTEM_BYTES:
        raise RuntimeError("Restored filesystem has the wrong logical size.")
    diagnostics = tool([str(tools["e2fsck"]), "-fn", str(restored)])
    tool([str(tools["debugfs"]), "-R", "dump /known.bin recovered.bin", "restored.ext4"], cwd=directory)
    if recovered.read_bytes() != PAYLOAD:
        raise RuntimeError("Restored known payload does not match.")
    private_write(directory / "e2fsck.log", diagnostics)
    return hashlib.sha256(PAYLOAD).hexdigest()


def run_case(case, output, qemu, kernel, initrd, filesystem, tools, receiver):
    directory = output / case
    directory.mkdir(mode=0o700)
    result = {"case": case, "passed": False}
    captured = {"stdout": bytearray(), "stderr": bytearray()}
    transfer = {}
    disk = process = endpoint = worker = None
    started = time.monotonic()
    # Short private paths avoid sockaddr_un's platform-dependent path limit.
    uart = tempfile.TemporaryDirectory(prefix="titan-uart-", dir="/tmp")
    uart_path = Path(uart.name) / "s"
    try:
        disk = create_disk(directory, case, filesystem)
        result.update({"disk_file": disk.name, "disk_sha256_before": digest_disk(disk)})
        command = [str(qemu), "-machine", "q35,accel=tcg", "-cpu", "max", "-m", "512M",
            "-nodefaults", "-no-user-config", "-display", "none", "-monitor", "none",
            "-serial", "stdio", "-nic", "none", "-no-reboot",
            "-chardev", f"socket,id=transfer,path={uart_path},server=on,wait=off",
            "-device", "isa-serial,chardev=transfer,index=1",
            "-kernel", str(kernel), "-initrd", str(initrd),
            "-append", f"console=ttyS0,115200 rdinit=/init loglevel=4 panic=0 titan.block_case={case}",
            "-drive", f"file={disk.name},if=none,format=raw,id=fixture",
            "-device", "virtio-blk-pci,drive=fixture"]
        process = subprocess.Popen(command, cwd=directory, stdin=subprocess.DEVNULL,
                                   stdout=subprocess.PIPE, stderr=subprocess.PIPE)

        def receive_transfer():
            try:
                transfer["report"] = receiver.receive(endpoint.fileno(), label="block-fixture",
                    max_bytes=LIMIT, output=directory / "received", timeout_seconds=45)
            except Exception as error:
                transfer["error"] = str(error)
                try:
                    endpoint.shutdown(socket.SHUT_RDWR)
                except OSError:
                    pass

        with selectors.DefaultSelector() as selector:
            selector.register(process.stdout, selectors.EVENT_READ, "stdout")
            selector.register(process.stderr, selectors.EVENT_READ, "stderr")
            while selector.get_map():
                if time.monotonic() - started >= TIMEOUT:
                    raise RuntimeError("QEMU exceeded the 90-second case deadline.")
                if endpoint is None and uart_path.exists():
                    candidate = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                    try:
                        candidate.settimeout(0.1)
                        candidate.connect(str(uart_path))
                        candidate.settimeout(None)
                        endpoint = candidate
                    except (FileNotFoundError, ConnectionRefusedError, TimeoutError):
                        candidate.close()
                for key, _ in selector.select(0.05):
                    remaining = LOG_LIMIT - sum(map(len, captured.values()))
                    data = os.read(key.fileobj.fileno(), min(65536, remaining + 1))
                    if not data:
                        selector.unregister(key.fileobj)
                    elif len(data) > remaining:
                        raise RuntimeError("QEMU exceeded the 4 MiB diagnostic bound.")
                    else:
                        captured[key.data].extend(data)
                console = captured["stdout"].replace(b"\r", b"").split(b"\n")
                if any(line.startswith((b"TITAN_BLOCK_VM_FAIL ", b"TITAN_RESCUE_FAILED ")) for line in console):
                    raise RuntimeError("Guest fixture reported failure.")
                if endpoint is not None and worker is None and f"TITAN_BLOCK_VM_TRANSFER_READY {case}".encode() in console:
                    worker = threading.Thread(target=receive_transfer, daemon=True)
                    worker.start()
        code = process.wait(timeout=max(0.1, TIMEOUT - (time.monotonic() - started)))
        if worker is None:
            raise RuntimeError("Guest never established raw transport readiness.")
        worker.join(5)
        if worker.is_alive():
            raise RuntimeError("Host receiver did not finish after guest shutdown.")
        console = captured["stdout"].replace(b"\r", b"").split(b"\n")
        expected = 0 if case == "valid" else 4 if case == "output-limit" else 2
        status_marker = f"TITAN_BLOCK_VM_STATUS {case} producer={expected} sender={0 if case == 'valid' else 5} status={expected}".encode()
        if code != 0 or console.count(f"TITAN_BLOCK_VM_PASS {case}".encode()) != 1 or console.count(status_marker) != 1:
            raise RuntimeError("Guest did not confirm exact pipeline results and power off successfully.")
        if b"TITAN_RESCUE_READY v1" not in console:
            raise RuntimeError("Guest did not complete rescue read-only protection.")
        changes = console.count(b"TITAN_BLOCK_VM_POST_GUARD_CHANGED")
        if changes != (1 if case == "post-readonly-change" else 0):
            raise RuntimeError("Post-read-only mutation case did not reach its exact gate.")
        saved = directory / "received"
        report = json.loads((saved / "report.json").read_text())
        if case == "valid":
            if "error" in transfer or not report["completed"] or not report["readback_verified"]:
                raise RuntimeError("Valid transfer failed independent host verification.")
            result["restored_payload_sha256"] = restore_payload(directory, tools)
        elif ("error" not in transfer or report["status"] != "incomplete" or report["completed"]
              or report["readback_verified"] or (saved / "payload.bin").exists()
              or not (saved / "payload.partial").is_file()):
            raise RuntimeError("Negative transfer unexpectedly completed or published a payload.")
        if case in ("dirty-filesystem", "wrong-label") and report["bytes_received"] != 0:
            raise RuntimeError("Preflight rejection unexpectedly transmitted filesystem bytes.")
        if case == "output-limit" and report["bytes_received"] > 1:
            raise RuntimeError("Producer exceeded the configured compressed-byte limit.")
        result.update({"passed": True, "producer_status": expected,
                       "host_completed": report["completed"], "received_bytes": report["bytes_received"]})
    except (OSError, ValueError, RuntimeError, subprocess.TimeoutExpired) as error:
        result["error"] = str(error)
    finally:
        if endpoint is not None:
            try:
                endpoint.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
        if worker is not None:
            worker.join(5)
        if endpoint is not None:
            endpoint.close()
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
        uart.cleanup()
        if disk is not None:
            try:
                result["disk_sha256_after"] = digest_disk(disk)
                if result.get("disk_sha256_before") != result["disk_sha256_after"]:
                    raise RuntimeError("Guest changed the synthetic disk contents.")
            except (OSError, RuntimeError) as error:
                result.update({"passed": False, "error": str(error)})
        result["elapsed_seconds"] = round(time.monotonic() - started, 3)
        result["receiver_error"] = transfer.get("error")
        private_write(directory / "console.log", captured["stdout"])
        private_write(directory / "qemu.stderr", captured["stderr"])
    return result


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("qemu", "kernel", "initrd", "output"):
        parser.add_argument("--" + name, required=True)
    args = parser.parse_args(argv)
    previous = os.umask(0o077)
    try:
        qemu, kernel, initrd = regular(args.qemu, True), regular(args.kernel), regular(args.initrd)
        tools = {name: regular(shutil.which(name) or name, True) for name in ("mke2fs", "debugfs", "e2fsck", "zstd")}
        source = Path(os.environ["TITAN_TRANSPORT_SOURCE"]) / "receive.py"
        spec = importlib.util.spec_from_file_location("block_vm_receiver", source)
        receiver = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(receiver)
        output = Path(args.output).expanduser().absolute()
        output.mkdir(mode=0o700)
        filesystem = create_filesystem(output, tools)
        results = []
        for case in CASES:
            result = run_case(case, output, qemu, kernel, initrd, filesystem, tools, receiver)
            results.append(result)
            print(f"{case}: {'passed' if result['passed'] else 'FAILED'}", flush=True)
        report = {"passed": all(result["passed"] for result in results), "cases": results,
                  "scope": "Synthetic x86_64 VM block sources and second UART only; no Titan hardware validation."}
        private_write(output / "summary.json", (json.dumps(report, indent=2) + "\n").encode())
        return 0 if report["passed"] else 1
    except (OSError, ValueError, KeyError, RuntimeError, subprocess.TimeoutExpired, KeyboardInterrupt) as error:
        print(f"Block VM check stopped: {error}", file=sys.stderr)
        return 1
    finally:
        os.umask(previous)


if __name__ == "__main__":
    sys.exit(main())
