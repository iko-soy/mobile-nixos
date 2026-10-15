#!/usr/bin/env python3
"""Run the native-route diagnostic image in a networkless TCG guest.

The VM build of the diagnostic profile guards a blank virtio disk, binds the
dummy USB gadget, streams the guest's kernel and firmware state over TTR1
through a QEMU UART to the real receiver, and the Mac splitter checks the
sections against what this guest must contain. The host answers on a second,
VM-only receipt UART, and the guest must then restart with the command
`bootloader` by itself, before its deadline, leaving the disk unchanged.
"""

import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import selectors
import signal
import socket
import subprocess
import sys
import tempfile
import threading
import time

LABEL = "titan-diagnostics"
LIMIT = 8388608
TIMEOUT = 240
LOG_LIMIT = 4 * 1024 * 1024
DISK_BYTES = 16 * 1024 * 1024
MARKER = "titan_diag_vm=1"


def load_module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def private_write(path, data):
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "wb") as stream:
        stream.write(data)


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


def validate(directory, splitter):
    """Return the section index after checking it against this guest."""
    index = splitter.split(directory / "received" / "payload.bin", directory / "sections")
    entries = {entry["name"]: entry for entry in index["sections"]}

    def content(name):
        file = entries[name].get("file")
        return b"" if file is None else (directory / "sections" / file).read_bytes()

    if MARKER.encode() not in content("cmdline"):
        raise RuntimeError("The command-line section does not carry this guest's marker.")
    if b"Linux version" not in content("kmsg"):
        raise RuntimeError("The kernel log lacks the version banner.")
    if b"vda" not in content("partitions"):
        raise RuntimeError("The partitions section lacks the virtio disk.")
    if not re.search(rb"^virtio virtio[0-9]+ virtio_blk$", content("bindings"), re.MULTILINE):
        raise RuntimeError("The bindings section lacks the bound virtio disk.")
    if not entries["fdt"]["missing"]:
        raise RuntimeError("An x86 guest has no flattened device tree to read.")
    for name in ("interrupts", "cpuinfo", "iomem"):
        if not content(name):
            raise RuntimeError(f"The {name} section is empty.")
    if any(entry["truncated"] or entry["error"] is not None for entry in index["sections"]):
        raise RuntimeError("A section was truncated or unreadable.")
    return index


def run(output, qemu, kernel, initrd, version, receiver, splitter):
    directory = output / "valid"
    directory.mkdir(mode=0o700)
    result = {"case": "valid", "passed": False}
    captured = {"stdout": bytearray(), "stderr": bytearray()}
    transfer, receipt_offset = {}, 0
    process = data = control = worker = None
    started = time.monotonic()
    uart = tempfile.TemporaryDirectory(prefix="titan-diag-", dir="/tmp")
    data_path, control_path = Path(uart.name) / "d", Path(uart.name) / "c"
    disk = directory / "blank.raw"
    try:
        with disk.open("xb") as stream:
            stream.truncate(DISK_BYTES)
        result["disk_sha256_before"] = digest(disk)
        command = [str(qemu), "-machine", "q35,accel=tcg", "-cpu", "max", "-m", "512M",
            "-nodefaults", "-no-user-config", "-display", "none", "-monitor", "none",
            "-serial", "stdio", "-nic", "none", "-no-reboot",
            "-chardev", f"socket,id=transfer,path={data_path},server=on,wait=off",
            "-device", "isa-serial,chardev=transfer,index=1",
            "-chardev", f"socket,id=receipt,path={control_path},server=on,wait=off",
            "-device", "isa-serial,chardev=receipt,index=2",
            "-kernel", str(kernel), "-initrd", str(initrd),
            "-append", f"console=ttyS0,115200 rdinit=/init loglevel=4 panic=0 {MARKER}",
            "-drive", f"file={disk.name},if=none,format=raw,id=fixture",
            "-device", "virtio-blk-pci,drive=fixture"]
        process = subprocess.Popen(command, cwd=directory, stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, start_new_session=True)

        def receive_transfer():
            try:
                receiver.receive(data.fileno(), label=LABEL, max_bytes=LIMIT,
                                 output=directory / "received", timeout_seconds=120)
                transfer["index"] = validate(directory, splitter)
                transfer["receipt"] = "VERIFIED"
            except Exception as error:
                transfer.update({"error": str(error), "receipt": "ABORT"})

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
                if (worker is None and data is not None and control is not None
                        and b"TITAN_CONTROL_TRANSFER_READY" in records):
                    worker = threading.Thread(target=receive_transfer, daemon=True)
                    worker.start()
                if control is not None and "receipt" in transfer:
                    receipt = f"TVM1 {transfer['receipt']}\n".encode("ascii")
                    if receipt_offset < len(receipt):
                        try:
                            receipt_offset += control.send(receipt[receipt_offset:])
                        except BlockingIOError:
                            pass
        code = process.wait(timeout=max(0.1, TIMEOUT - (time.monotonic() - started)))
        if worker is None:
            raise RuntimeError("The guest never reached the transfer.")
        worker.join(5)
        if "error" in transfer or "receipt" not in transfer:
            raise RuntimeError(transfer.get("error", "Host validation did not finish."))
        console = bytes(captured["stdout"])
        records = lines(console)
        expected = [b"TITAN_PROBE_USB_BOUND", b"TITAN_CONTROL_TRANSFER_READY",
                    b"TITAN_CONTROL_RESULT producer-status=0 ", b"TITAN_CONTROL_COMPLETE",
                    b"TITAN_CONTROL_VM_RECEIPT VERIFIED", b"TITAN_CONTROL_VM_RESTART success"]
        missing = [marker.decode() for marker in expected if not any(line.startswith(marker) for line in records)]
        if code != 0 or missing:
            raise RuntimeError("Missing markers: " + ", ".join(missing) if missing else "QEMU exited abnormally.")
        if not any(line == f"TITAN_PROBE_KERNEL {version}".encode() for line in records):
            raise RuntimeError("Unexpected guest kernel release.")
        armed = re.search(rb"TITAN_PROBE_ARMED start=(\d+) deadline=(\d+) backstop=10", console)
        restart = re.search(rb"\[\s*(\d+)\.\d+\] reboot: Restarting system with command 'bootloader'", console)
        if armed is None or restart is None or int(restart.group(1)) >= int(armed.group(2)) - 5:
            raise RuntimeError("The guest restart was not clearly before its deadline.")
        result.update({"passed": True, "sections": transfer["index"]["sections"],
                       "restart_seconds": int(restart.group(1)), "deadline_seconds": int(armed.group(2))})
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
        if disk.exists():
            result["disk_sha256_after"] = digest(disk)
            if result.get("disk_sha256_before") != result["disk_sha256_after"]:
                result.update({"passed": False, "error": "The guest changed the disk."})
        result["elapsed_seconds"] = round(time.monotonic() - started, 3)
        private_write(directory / "console.log", captured["stdout"])
        private_write(directory / "qemu.stderr", captured["stderr"])
        private_write(directory / "result.json", (json.dumps(result, indent=2) + "\n").encode())
        if not result["passed"]:
            print(f"valid: {result.get('error')}", file=sys.stderr)
            print(json.dumps(bytes(captured["stdout"][-4096:]).decode(errors="replace")), file=sys.stderr, flush=True)
    return result


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("qemu", "kernel", "kernel-version", "initrd", "output"):
        parser.add_argument("--" + name, required=True)
    args = parser.parse_args(argv)
    previous = os.umask(0o077)
    try:
        receiver = load_module("diag_receiver", Path(os.environ["TITAN_TRANSPORT_SOURCE"]) / "receive.py")
        splitter = load_module("diag_splitter", Path(os.environ["TITAN_TOOLS_SOURCE"]) / "receive-diagnostics.py")
        output = Path(args.output).absolute()
        output.mkdir(mode=0o700)
        result = run(output, args.qemu, args.kernel, args.initrd, args.kernel_version, receiver, splitter)
        print(f"valid: {'passed' if result['passed'] else 'FAILED'}", flush=True)
        private_write(output / "summary.json", (json.dumps(
            {"passed": result["passed"], "cases": [result],
             "scope": "Synthetic x86_64 TCG guest only; no Titan hardware, vendor kernel or USB stack."},
            indent=2) + "\n").encode())
        return 0 if result["passed"] else 1
    except (OSError, ValueError, KeyError, RuntimeError) as error:
        print(f"VM check stopped: {error}", file=sys.stderr)
        return 1
    finally:
        os.umask(previous)


if __name__ == "__main__":
    raise SystemExit(main())
