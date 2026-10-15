#!/usr/bin/env python3
"""Test guarded acquisition through real guest ACM and a VM-only UART relay.

The host sends its separate fixture receipt only after validating the received
archive or expected incomplete outcome. No physical USB or phone is accessed.
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
import subprocess
import sys
import tempfile
import threading
import time


CASES = ("valid", "dirty-filesystem", "wrong-label", "output-limit",
         "post-readonly-change", "forced-producer-death")
LABEL = "usb-userdata-fixture"
LIMIT = 32 * 1024 * 1024
LOG_LIMIT = 4 * 1024 * 1024
TIMEOUT = 90
PREFIX = b"TITAN_USB_PIPELINE_VM_"


def load_module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def private_write(path, data):
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(descriptor, "wb") as stream:
        stream.write(data)
        stream.flush()
        os.fsync(stream.fileno())


def file_hash(path):
    digest, count = hashlib.sha256(), 0
    with path.open("rb") as stream:
        while data := stream.read(1024 * 1024):
            count += len(data)
            if count > 256 * 1024 * 1024:
                raise RuntimeError("Kernel/initramfs exceeded the fixture input bound.")
            digest.update(data)
    return digest.hexdigest()


def lines(data):
    return [line.removesuffix(b"\r") for line in data.split(b"\n")]


def verify_markers(console, case, kernel_version):
    records = lines(console)
    expected = [PREFIX + f"START {case}".encode(), PREFIX + f"KERNEL {kernel_version}".encode(),
                b"TITAN_USB_PIPELINE_RAW_READY", b"TITAN_USB_PIPELINE_BOUND_SEALED",
                b"TITAN_USB_PIPELINE_TRANSFER_READY"]
    if case == "post-readonly-change":
        expected.append(PREFIX + b"POST_GUARD_CHANGED")
    if case == "forced-producer-death":
        expected += [PREFIX + b"FORCED_PRODUCER_DEATH", PREFIX + b"ORPHANS_REAPED proc-status"]
    expected += [PREFIX + b"WORKERS_REAPED", PREFIX + b"RECEIPT " + (b"VERIFIED" if case == "valid" else b"INCOMPLETE"),
                 PREFIX + f"PASS {case}".encode()]
    if [line for line in records if line.startswith(b"TITAN_USB_PIPELINE_")] != expected:
        raise RuntimeError("Guest did not confirm the exact USB, worker, host-receipt and cleanup stages.")
    if records.count(b"TITAN_RESCUE_START v1") != 1 or records.count(b"TITAN_RESCUE_READY v1") != 1:
        raise RuntimeError("Guest did not complete rescue block protection exactly once.")
    if records.index(b"TITAN_RESCUE_READY v1") > records.index(expected[0]):
        raise RuntimeError("USB pipeline started before rescue block protection.")
    if any(line.startswith(b"TITAN_RESCUE_FAILED") for line in records):
        raise RuntimeError("Guest reported rescue failure.")
    return [item.decode("ascii") for item in expected]


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
    except BaseException:
        endpoint.close()
        raise


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
                raise RuntimeError("QEMU failed to stop after SIGKILL.")


def validate_received(case, directory, receiver_error, fixtures, tools):
    saved = directory / "received"
    report = json.loads((saved / "report.json").read_text())
    if case == "valid":
        if receiver_error is not None or report.get("status") != "complete" or not report.get("completed") or not report.get("readback_verified"):
            raise RuntimeError("Valid transfer failed independent host verification.")
        restored_hash = fixtures.restore_payload(directory, tools)
        return report, restored_hash, "VERIFIED"
    if (receiver_error is None or report.get("status") != "incomplete" or report.get("completed")
        or report.get("readback_verified") or (saved / "payload.bin").exists()
        or not (saved / "payload.partial").is_file()):
        raise RuntimeError("Negative transfer did not retain an explicitly incomplete archive.")
    received = report["bytes_received"]
    if case in ("dirty-filesystem", "wrong-label") and received != 0:
        raise RuntimeError("Source preflight rejection transmitted filesystem bytes.")
    if case == "output-limit" and received > 1:
        raise RuntimeError("Compressed output exceeded the one-byte fixture limit.")
    if case == "post-readonly-change" and received <= 0:
        raise RuntimeError("Completion-stage fault did not follow actual payload transfer.")
    return report, None, "INCOMPLETE"


def run_case(case, output, qemu, kernel, initrd, version, filesystem, tools, receiver, fixtures):
    directory = output / case
    directory.mkdir(mode=0o700)
    result = {"case": case, "passed": False, "expected_kernel_version": version}
    captured = {"stdout": bytearray(), "stderr": bytearray()}
    transfer, receipt_offset = {}, 0
    disk = process = data = control = worker = None
    started = time.monotonic()
    uart = tempfile.TemporaryDirectory(prefix="titan-usb-pipeline-", dir="/tmp")
    data_path, control_path = Path(uart.name) / "d", Path(uart.name) / "c"
    try:
        disk = fixtures.create_disk(directory, case, filesystem)
        result.update({"disk_file": disk.name, "disk_sha256_before": fixtures.digest_disk(disk)})
        command = [str(qemu), "-machine", "q35,accel=tcg", "-cpu", "max", "-m", "512M",
            "-nodefaults", "-no-user-config", "-display", "none", "-monitor", "none",
            "-serial", "stdio", "-nic", "none", "-no-reboot",
            "-chardev", f"socket,id=transfer,path={data_path},server=on,wait=off",
            "-device", "isa-serial,chardev=transfer,index=1",
            "-chardev", f"socket,id=receipt,path={control_path},server=on,wait=off",
            "-device", "isa-serial,chardev=receipt,index=2",
            "-kernel", str(kernel), "-initrd", str(initrd),
            "-append", f"console=ttyS0,115200 rdinit=/init loglevel=4 panic=0 titan_usb_pipeline_test={case}",
            "-drive", f"file={disk.name},if=none,format=raw,id=fixture",
            "-device", "virtio-blk-pci,drive=fixture"]
        process = subprocess.Popen(command, cwd=directory, stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, start_new_session=True)

        def receive_transfer():
            receiver_error = None
            try:
                receiver.receive(data.fileno(), label=LABEL, max_bytes=LIMIT,
                    output=directory / "received", timeout_seconds=15 if case == "forced-producer-death" else 45)
            except Exception as error:
                receiver_error = str(error)
            transfer["receiver_error"] = receiver_error
            try:
                report, restored_hash, receipt = validate_received(case, directory, receiver_error, fixtures, tools)
                transfer.update({"report": report, "restored_hash": restored_hash, "receipt": receipt})
            except Exception as error:
                transfer.update({"validation_error": str(error), "receipt": "ABORT"})

        with selectors.DefaultSelector() as selector:
            selector.register(process.stdout, selectors.EVENT_READ, "stdout")
            selector.register(process.stderr, selectors.EVENT_READ, "stderr")
            while selector.get_map():
                if time.monotonic() - started >= TIMEOUT:
                    raise RuntimeError("QEMU exceeded the 90-second case deadline.")
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
                        raise RuntimeError("QEMU exceeded the 4 MiB diagnostic bound.")
                    else:
                        captured[key.data].extend(chunk)
                records = lines(captured["stdout"])
                if any(line.startswith((PREFIX + b"FAIL", b"TITAN_USB_PIPELINE_FAILED", b"TITAN_RESCUE_FAILED")) for line in records):
                    raise RuntimeError("Guest reported a USB pipeline assertion failure.")
                if (worker is None and data is not None and control is not None and
                    b"TITAN_USB_PIPELINE_TRANSFER_READY" in records and PREFIX + f"START {case}".encode() in records):
                    worker = threading.Thread(target=receive_transfer, daemon=True)
                    worker.start()
                if control is not None and "receipt" in transfer:
                    receipt = f"TVM1 {transfer['receipt']}\n".encode("ascii")
                    if receipt_offset < len(receipt):
                        try:
                            count = control.send(receipt[receipt_offset:])
                            if count <= 0:
                                raise RuntimeError("VM receipt channel made no progress.")
                            receipt_offset += count
                        except BlockingIOError:
                            pass
        code = process.wait(timeout=max(0.1, TIMEOUT - (time.monotonic() - started)))
        if worker is None:
            raise RuntimeError("Guest never established the complete raw ACM/UART path.")
        worker.join(5)
        if worker.is_alive() or "validation_error" in transfer or "receipt" not in transfer:
            raise RuntimeError(transfer.get("validation_error", "Host receiver/restore validation did not finish."))
        if code != 0 or receipt_offset != len(f"TVM1 {transfer['receipt']}\n".encode()):
            raise RuntimeError("Guest did not receive its fixture receipt and power off successfully.")
        result["observed_markers"] = verify_markers(captured["stdout"], case, version)
        result.update({"passed": True, "host_receipt": transfer["receipt"],
            "host_completed": transfer["report"]["completed"],
            "received_bytes": transfer["report"]["bytes_received"],
            "restored_payload_sha256": transfer.get("restored_hash")})
    except (OSError, ValueError, RuntimeError, subprocess.TimeoutExpired) as error:
        result["error"] = str(error)
    finally:
        if data is not None:
            try:
                data.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
        if worker is not None:
            worker.join(5)
            if worker.is_alive():
                result.update({"passed": False, "error": "Host validation thread did not stop within cleanup bound."})
        for endpoint in (data, control):
            if endpoint is not None:
                endpoint.close()
        if process is not None:
            try:
                stop_process(process)
            except (OSError, RuntimeError) as error:
                result.update({"passed": False, "error": str(error)})
            result["qemu_exit_code"] = process.returncode
            process.stdout.close(); process.stderr.close()
        uart.cleanup()
        if disk is not None:
            try:
                result["disk_sha256_after"] = fixtures.digest_disk(disk)
                if result.get("disk_sha256_before") != result["disk_sha256_after"]:
                    raise RuntimeError("Guest changed the generated GPT/filesystem image.")
            except (OSError, RuntimeError) as error:
                result.update({"passed": False, "error": str(error)})
        result["elapsed_seconds"] = round(time.monotonic() - started, 3)
        result["receiver_error"] = transfer.get("receiver_error")
        private_write(directory / "console.log", captured["stdout"])
        private_write(directory / "qemu.stderr", captured["stderr"])
        private_write(directory / "result.json", (json.dumps(result, indent=2) + "\n").encode())
        if not result["passed"]:
            print(f"{case}: {result.get('error', 'validation failed')}", file=sys.stderr)
            print(json.dumps(bytes(captured["stdout"][-4096:]).decode(errors="replace")), file=sys.stderr, flush=True)
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
        fixtures = load_module("usb_pipeline_fixtures", Path(os.environ["TITAN_BLOCK_FIXTURE_SOURCE"]) / "vm-check.py")
        receiver = load_module("usb_pipeline_receiver", Path(os.environ["TITAN_TRANSPORT_SOURCE"]) / "receive.py")
        qemu = fixtures.regular(args.qemu, True)
        kernel, initrd = fixtures.regular(args.kernel), fixtures.regular(args.initrd)
        tools = {name: fixtures.regular(shutil.which(name) or name, True)
                 for name in ("mke2fs", "debugfs", "e2fsck", "zstd")}
        output = Path(args.output).expanduser().absolute()
        output.mkdir(mode=0o700)
        report = {"format": 1, "passed": False, "cases": [], "expected_kernel_version": args.kernel_version,
            "kernel_sha256": file_hash(kernel), "initrd_sha256": file_hash(initrd),
            "scope": "Synthetic x86_64 TCG, real dummy_hcd ACM and generated block images; no Titan or physical USB validation."}
        filesystem = fixtures.create_filesystem(output, tools)
        for case in CASES:
            result = run_case(case, output, qemu, kernel, initrd, args.kernel_version,
                              filesystem, tools, receiver, fixtures)
            report["cases"].append(result)
            print(f"{case}: {'passed' if result['passed'] else 'FAILED'}", flush=True)
        report["passed"] = all(case["passed"] for case in report["cases"])
        private_write(output / "summary.json", (json.dumps(report, indent=2) + "\n").encode())
        return 0 if report["passed"] else 1
    except (OSError, ValueError, KeyError, RuntimeError, subprocess.TimeoutExpired, KeyboardInterrupt) as error:
        print(f"USB pipeline VM check stopped: {error}", file=sys.stderr)
        return 1
    finally:
        os.umask(previous_umask)


if __name__ == "__main__":
    sys.exit(main())
