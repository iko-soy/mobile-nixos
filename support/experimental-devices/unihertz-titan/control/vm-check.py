#!/usr/bin/env python3
"""Run the offline control-region acquisition in networkless TCG guests.

Each case boots the VM build of the control profile against a generated GPT
disk with the producer's sixteen VM regions, four of them real ext4 images. The
real TTR1 receiver takes the stream through a QEMU UART, the Mac-side splitter
checks every region against the disk, and the host answers on a separate VM-only
receipt UART. The guest must then restart with the command `bootloader`.
"""

import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import selectors
import shutil
import signal
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

LABEL = "control-regions-raw"
LIMIT = 33554432
TIMEOUT = 240
LOG_LIMIT = 4 * 1024 * 1024
DISK_BYTES = 16 * 1024 * 1024
CASES = ("valid", "dirty-calibration", "wrong-label", "host-absent", "receiver-limit")
# The receiver-limit host accepts less than the stream, so the sender fails first.
SMALL_LIMIT = 65536


def load_module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def private_write(path, data):
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "wb") as stream:
        stream.write(data)


def vm_regions(source):
    """The producer's VM table, parsed from its source so the two cannot drift."""
    text = Path(source).read_text()
    section = text.split("#ifdef TITAN_CONTROL_VM_TEST", 1)[1].split("#else", 1)[0]
    sizes = {name: int(value) for name, value in re.findall(r"#define (RAW_SECTORS|FS_SECTORS) (\d+)", section)}
    rows = re.findall(r'\{ "([a-z_0-9]+)", (\d+), (\d+), (RAW_SECTORS|FS_SECTORS), ([01]) \}', section)
    regions = tuple((label, int(number), int(start), sizes[size], "ext4" if ext4 == "1" else "raw")
                    for label, number, start, size, ext4 in rows)
    if len(regions) != 16:
        raise RuntimeError("Could not parse the producer's sixteen VM regions.")
    return regions


def region_content(label, sectors, filesystem_tool, directory):
    """Deterministic raw bytes, or a fresh ext4 image of the region's size."""
    if filesystem_tool is None:
        seed, data = label.encode(), bytearray()
        while len(data) < sectors * 512:
            seed = hashlib.sha256(seed).digest()
            data += seed
        return bytes(data[:sectors * 512])
    image = directory / (label + ".ext4")
    with image.open("xb") as stream:
        stream.truncate(sectors * 512)
    subprocess.run([filesystem_tool, "-q", "-F", "-t", "ext4", "-b", "1024", "-E",
                    "lazy_itable_init=0,lazy_journal_init=0", str(image)], check=True,
                   capture_output=True, timeout=30)
    return image.read_bytes()


def create_disk(directory, case, regions, mke2fs):
    sectors = DISK_BYTES // 512
    entries = bytearray(128 * 128)
    contents = {}
    for index, (label, number, start, size, kind) in enumerate(regions):
        name = "seccfx" if case == "wrong-label" and label == "seccfg" else label
        entries[index * 128:(index + 1) * 128] = struct.pack("<16s16sQQQ72s",
            uuid.UUID("0fc63daf-8483-4772-8e79-3d69d8477de4").bytes_le,
            uuid.UUID(int=number).bytes_le, start, start + size - 1, 0, name.encode("utf-16le"))
        data = bytearray(region_content(label, size, mke2fs if kind == "ext4" else None, directory))
        if case == "dirty-calibration" and label == "nvdata":
            struct.pack_into("<H", data, 1024 + 0x3A, 0)
        contents[label] = bytes(data)

    def header(current, alternate, table):
        data = bytearray(struct.pack("<8sIIIIQQQQ16sQIII", b"EFI PART", 0x10000, 92, 0, 0,
            current, alternate, 34, sectors - 34, uuid.UUID("72d509eb-d7eb-4d61-bd09-d277d81cacbe").bytes_le,
            table, 128, 128, zlib.crc32(entries)))
        struct.pack_into("<I", data, 16, zlib.crc32(data))
        return data.ljust(512, b"\0")

    mbr = bytearray(512)
    mbr[446:462] = struct.pack("<B3sB3sII", 0, b"\0\x02\0", 0xEE, b"\xff" * 3, 1, sectors - 1)
    mbr[510:] = b"\x55\xaa"
    descriptor, name = tempfile.mkstemp(prefix="synthetic-gpt-", suffix=".raw", dir=directory)
    with os.fdopen(descriptor, "wb") as stream:
        stream.truncate(DISK_BYTES)
        for lba, data in ((0, mbr), (1, header(1, sectors - 1, 2)), (2, entries),
                          (sectors - 33, entries), (sectors - 1, header(sectors - 1, 1, sectors - 33))):
            stream.seek(lba * 512)
            stream.write(data)
        for label, number, start, size, kind in regions:
            stream.seek(start * 512)
            stream.write(contents[label])
        stream.flush()
        os.fsync(stream.fileno())
    return Path(name), contents


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def lines(data):
    return data.replace(b"\r", b"").split(b"\n")[:-1]


def connect_socket(path):
    if not path.exists():
        return None
    endpoint = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        endpoint.settimeout(0.1)
        endpoint.connect(str(path))
        endpoint.setblocking(False)
        return endpoint
    except (FileNotFoundError, ConnectionRefusedError, TimeoutError):
        endpoint.close()
        return None


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
            continue


def validate(case, directory, receiver_error, contents, regions, splitter):
    """Return the receipt word after checking the host-side outcome for the case."""
    if case in ("wrong-label", "receiver-limit"):
        if receiver_error is None or (directory / "received" / "payload.bin").exists():
            raise RuntimeError(f"The {case} case transferred a complete payload.")
        return "INCOMPLETE"
    if receiver_error is not None:
        raise RuntimeError(f"The receiver failed: {receiver_error}")
    report = splitter.split_and_verify(directory / "received" / "payload.bin", directory / "regions", regions)
    for label, *_ in regions:
        if (directory / "regions" / (label + ".img")).read_bytes() != contents[label]:
            raise RuntimeError(f"Region {label} differs from the disk.")
    states = {label: item["ext4_state"] for label, item in report["regions"].items() if item["kind"] == "ext4"}
    expected = {label: "clean" for label in states}
    if case == "dirty-calibration":
        expected["nvdata"] = "unclean-state"
    if states != expected or not report["all_stable"]:
        raise RuntimeError(f"Unexpected region states: {states}")
    if report["all_consistent"] != (case == "valid"):
        raise RuntimeError("The consistency verdict does not match the case.")
    return "VERIFIED"


def run_case(case, output, qemu, kernel, initrd, version, regions, mke2fs, receiver, splitter):
    directory = output / case
    directory.mkdir(mode=0o700)
    result = {"case": case, "passed": False}
    captured = {"stdout": bytearray(), "stderr": bytearray()}
    transfer, receipt_offset = {}, 0
    disk = process = data = control = worker = None
    started = time.monotonic()
    uart = tempfile.TemporaryDirectory(prefix="titan-control-", dir="/tmp")
    data_path, control_path = Path(uart.name) / "d", Path(uart.name) / "c"
    try:
        disk, contents = create_disk(directory, case, regions, mke2fs)
        result["disk_sha256_before"] = digest(disk)
        command = [str(qemu), "-machine", "q35,accel=tcg", "-cpu", "max", "-m", "512M",
            "-nodefaults", "-no-user-config", "-display", "none", "-monitor", "none",
            "-serial", "stdio", "-nic", "none", "-no-reboot",
            "-chardev", f"socket,id=transfer,path={data_path},server=on,wait=off",
            "-device", "isa-serial,chardev=transfer,index=1",
            "-chardev", f"socket,id=receipt,path={control_path},server=on,wait=off",
            "-device", "isa-serial,chardev=receipt,index=2",
            "-kernel", str(kernel), "-initrd", str(initrd),
            "-append", "console=ttyS0,115200 rdinit=/init loglevel=4 panic=0",
            "-drive", f"file={disk.name},if=none,format=raw,id=fixture",
            "-device", "virtio-blk-pci,drive=fixture"]
        process = subprocess.Popen(command, cwd=directory, stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, start_new_session=True)

        def receive_transfer():
            receiver_error = None
            try:
                receiver.receive(data.fileno(), label=LABEL,
                                 max_bytes=SMALL_LIMIT if case == "receiver-limit" else LIMIT,
                                 output=directory / "received", timeout_seconds=120)
            except Exception as error:
                receiver_error = str(error)
            transfer["receiver_error"] = receiver_error
            try:
                transfer["receipt"] = validate(case, directory, receiver_error, contents, regions, splitter)
            except Exception as error:
                transfer.update({"validation_error": str(error), "receipt": "ABORT"})

        with selectors.DefaultSelector() as selector:
            selector.register(process.stdout, selectors.EVENT_READ, "stdout")
            selector.register(process.stderr, selectors.EVENT_READ, "stderr")
            while selector.get_map():
                if time.monotonic() - started >= TIMEOUT:
                    raise RuntimeError("QEMU exceeded the case deadline.")
                if data is None:
                    data = connect_socket(data_path)
                if control is None:
                    control = connect_socket(control_path)
                for key, _ in selector.select(0.02):
                    remaining = LOG_LIMIT - sum(map(len, captured.values()))
                    chunk = os.read(key.fileobj.fileno(), min(65536, remaining + 1))
                    if not chunk:
                        selector.unregister(key.fileobj)
                    elif len(chunk) > remaining:
                        raise RuntimeError("QEMU exceeded the diagnostic bound.")
                    else:
                        captured[key.data].extend(chunk)
                records = lines(captured["stdout"])
                if any(line.startswith(b"TITAN_RESCUE_FAILED") for line in records):
                    raise RuntimeError("The guest's storage guard failed.")
                if (case != "host-absent" and worker is None and data is not None and control is not None
                        and b"TITAN_CONTROL_TRANSFER_READY" in records):
                    worker = threading.Thread(target=receive_transfer, daemon=True)
                    worker.start()
                # No host answers: the guest must give up by itself and restart.
                if case == "host-absent" and any(line.startswith(b"TITAN_CONTROL_FAILED") for line in records):
                    transfer.setdefault("receipt", "INCOMPLETE")
                if control is not None and "receipt" in transfer:
                    receipt = f"TVM1 {transfer['receipt']}\n".encode("ascii")
                    if receipt_offset < len(receipt):
                        try:
                            receipt_offset += control.send(receipt[receipt_offset:])
                        except BlockingIOError:
                            pass
        code = process.wait(timeout=max(0.1, TIMEOUT - (time.monotonic() - started)))
        if worker is None and case != "host-absent":
            raise RuntimeError("The guest never reached the transfer.")
        if worker is not None:
            worker.join(5)
        if "validation_error" in transfer or "receipt" not in transfer:
            raise RuntimeError(transfer.get("validation_error", "Host validation did not finish."))
        console = bytes(captured["stdout"])
        if code != 0 or b"reboot: Restarting system with command 'bootloader'" not in console:
            raise RuntimeError("The guest did not restart into the bootloader by itself.")
        expected = [b"TITAN_PROBE_USB_BOUND", b"TITAN_CONTROL_TRANSFER_READY"]
        if case == "wrong-label":
            expected += [b"TITAN_CONTROL_RESULT producer-status=3 ", b"TITAN_CONTROL_FAILED worker-result-nonzero",
                         b"TITAN_CONTROL_VM_RECEIPT INCOMPLETE", b"TITAN_CONTROL_VM_RESTART failure"]
        elif case == "host-absent":
            # The producer's own timeout ends it without a status record; PID 1
            # then stops the waiting sender after its grace period.
            expected += [b"TITAN_CONTROL_RESULT producer-status=4294967295 producer=14 sender=9",
                         b"TITAN_CONTROL_FAILED worker-result-nonzero", b"TITAN_CONTROL_VM_RECEIPT INCOMPLETE",
                         b"TITAN_CONTROL_VM_RESTART failure"]
        elif case == "receiver-limit":
            # The sender stops at the host's limit; the blocked producer is then
            # killed by PID 1 or by the closed pipe, without a status record.
            expected += [b"TITAN_CONTROL_FAILED worker-result-nonzero", b"TITAN_CONTROL_VM_RECEIPT INCOMPLETE",
                         b"TITAN_CONTROL_VM_RESTART failure"]
            if not re.search(rb"(?m)^TITAN_CONTROL_RESULT producer-status=4294967295 producer=(9|13) sender=1024\r?$",
                             console):
                raise RuntimeError("The producer was not stopped after the sender failed.")
        else:
            expected += [b"TITAN_CONTROL_RESULT producer-status=0 ", b"TITAN_CONTROL_COMPLETE",
                         b"TITAN_CONTROL_VM_RECEIPT VERIFIED", b"TITAN_CONTROL_VM_RESTART success"]
        records = lines(console)
        missing = [marker.decode() for marker in expected if not any(line.startswith(marker) for line in records)]
        if missing:
            raise RuntimeError("Missing markers: " + ", ".join(missing))
        if any(line.startswith((b"TITAN_PROBE_DEADLINE_REBOOT", b"TITAN_PROBE_BACKSTOP_REBOOT")) for line in records):
            raise RuntimeError("The guest restarted from its deadline instead of the pipeline.")
        if not any(line == f"TITAN_PROBE_KERNEL {version}".encode() for line in records):
            raise RuntimeError("Unexpected guest kernel release.")
        # The pipeline, not the deadline process, must have restarted the guest.
        armed = re.search(rb"TITAN_PROBE_ARMED start=(\d+) deadline=(\d+) backstop=10", console)
        restart = re.search(rb"\[\s*(\d+)\.\d+\] reboot: Restarting system with command 'bootloader'", console)
        if armed is None or restart is None or int(restart.group(1)) >= int(armed.group(2)) - 5:
            raise RuntimeError("The guest restart was not clearly before its deadline.")
        result["restart_seconds"], result["deadline_seconds"] = int(restart.group(1)), int(armed.group(2))
        if case in ("valid", "dirty-calibration"):
            # Both passes must reach the disk, not the page cache.
            reads = {int(number): int(sectors) for number, sectors in
                     re.findall(rb"TITAN_CONTROL_VM_READ (\d+) (\d+)", console)}
            short = [label for label, number, start, sectors, kind in regions if reads.get(number, 0) < 2 * sectors]
            if short:
                raise RuntimeError("Regions read fewer than twice from the disk: " + ", ".join(short))
            result["sectors_read"] = reads
        result.update({"passed": True, "receipt": transfer["receipt"]})
    except (OSError, ValueError, RuntimeError, subprocess.SubprocessError) as error:
        result["error"] = str(error)
    finally:
        for endpoint in (data, control):
            if endpoint is not None:
                try:
                    endpoint.shutdown(socket.SHUT_RDWR)
                except OSError:
                    pass
                endpoint.close()
        if worker is not None:
            worker.join(5)
        if process is not None:
            stop_process(process)
            result["qemu_exit_code"] = process.returncode
            process.stdout.close()
            process.stderr.close()
        uart.cleanup()
        if disk is not None:
            result["disk_sha256_after"] = digest(disk)
            if result.get("disk_sha256_before") != result["disk_sha256_after"]:
                result.update({"passed": False, "error": "The guest changed the generated disk."})
        result["elapsed_seconds"] = round(time.monotonic() - started, 3)
        result["receiver_error"] = transfer.get("receiver_error")
        private_write(directory / "console.log", captured["stdout"])
        private_write(directory / "qemu.stderr", captured["stderr"])
        private_write(directory / "result.json", (json.dumps(result, indent=2) + "\n").encode())
        if not result["passed"]:
            print(f"{case}: {result.get('error')}", file=sys.stderr)
            print(json.dumps(bytes(captured["stdout"][-4096:]).decode(errors="replace")), file=sys.stderr, flush=True)
    return result


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("qemu", "kernel", "kernel-version", "initrd", "output"):
        parser.add_argument("--" + name, required=True)
    args = parser.parse_args(argv)
    previous = os.umask(0o077)
    try:
        regions = vm_regions(os.environ["TITAN_CONTROL_SOURCE"])
        receiver = load_module("control_receiver", Path(os.environ["TITAN_TRANSPORT_SOURCE"]) / "receive.py")
        splitter = load_module("control_splitter", Path(os.environ["TITAN_TOOLS_SOURCE"]) / "receive-control-regions.py")
        mke2fs = shutil.which("mke2fs")
        if not mke2fs:
            raise ValueError("mke2fs is required for the ext4 regions.")
        output = Path(args.output).absolute()
        output.mkdir(mode=0o700)
        cases = []
        for case in CASES:
            result = run_case(case, output, args.qemu, args.kernel, args.initrd, args.kernel_version,
                              regions, mke2fs, receiver, splitter)
            cases.append(result)
            print(f"{case}: {'passed' if result['passed'] else 'FAILED'}", flush=True)
        report = {"passed": all(case["passed"] for case in cases), "cases": cases,
                  "scope": "Synthetic x86_64 TCG guests only; no Titan hardware, vendor kernel or USB stack."}
        private_write(output / "summary.json", (json.dumps(report, indent=2) + "\n").encode())
        return 0 if report["passed"] else 1
    except (OSError, ValueError, KeyError, RuntimeError) as error:
        print(f"VM check stopped: {error}", file=sys.stderr)
        return 1
    finally:
        os.umask(previous)


if __name__ == "__main__":
    raise SystemExit(main())
