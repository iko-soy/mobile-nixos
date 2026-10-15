#!/usr/bin/env python3
"""Check the USB probe's report and fixed-deadline reboot in networkless TCG guests."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import selectors
import stat
import subprocess
import sys
import tempfile
import time


SENTINEL = b"TITAN_USB_PROBE_VM_SENTINEL_v1\n"
DISK_BYTES = 1024 * 1024
OUTPUT_LIMIT = 4 * 1024 * 1024
TIMEOUT = 150
# Must match DEADLINE_SECONDS and BACKSTOP_SECONDS in the VM build of probe.c.
DEADLINE = 45
BACKSTOP = 10
# Generous upper bounds for TCG boot time before PID 1 arms the deadline.
LATE = 40

CASES = {
    "valid": {
        "argument": "valid",
        "required": ["TITAN_RESCUE_START", "TITAN_PROBE_ARMED", "TITAN_RESCUE_READY",
                     "TITAN_PROBE_KERNEL", "TITAN_PROBE_USB_BOUND", "TITAN_PROBE_REPORT",
                     "TITAN_PROBE_VM_REPORTS_RECEIVED", "TITAN_PROBE_DEADLINE_REBOOT"],
        "forbidden": ["TITAN_PROBE_FAILED", "TITAN_PROBE_VM_FAIL", "TITAN_RESCUE_FAILED",
                      "TITAN_PROBE_BACKSTOP_REBOOT"],
        "earliest": DEADLINE,
    },
    "stuck": {
        "argument": "stuck",
        "required": ["TITAN_PROBE_USB_BOUND", "TITAN_PROBE_VM_STUCK", "TITAN_PROBE_DEADLINE_REBOOT"],
        "forbidden": ["TITAN_PROBE_FAILED", "TITAN_RESCUE_FAILED", "TITAN_PROBE_BACKSTOP_REBOOT",
                      "TITAN_PROBE_REPORT"],
        "earliest": DEADLINE,
    },
    "child-killed": {
        "argument": "child-killed",
        "required": ["TITAN_PROBE_VM_CHILD_KILLED", "TITAN_PROBE_USB_BOUND",
                     "TITAN_PROBE_VM_REPORTS_RECEIVED", "TITAN_PROBE_BACKSTOP_REBOOT"],
        "forbidden": ["TITAN_PROBE_FAILED", "TITAN_PROBE_VM_FAIL", "TITAN_RESCUE_FAILED",
                      "TITAN_PROBE_DEADLINE_REBOOT"],
        "earliest": DEADLINE + BACKSTOP,
    },
    "missing-disk": {
        "argument": "valid",
        "required": ["TITAN_PROBE_ARMED", "TITAN_RESCUE_FAILED no-storage-before-deadline",
                     "TITAN_PROBE_DEADLINE_REBOOT"],
        "forbidden": ["TITAN_RESCUE_READY", "TITAN_PROBE_USB_BOUND", "TITAN_PROBE_BACKSTOP_REBOOT"],
        "earliest": DEADLINE,
    },
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


def disk_hash(path):
    with path.open("rb") as stream:
        data = stream.read(DISK_BYTES + 1)
    if len(data) != DISK_BYTES:
        raise RuntimeError("The generated guest disk changed its logical size.")
    return hashlib.sha256(data).hexdigest()


def lines(console):
    # Only complete lines count; a trailing fragment may still be arriving.
    return [line for line in console.replace(b"\r", b"").split(b"\n")[:-1]]


def has_marker(console, marker):
    marker = marker.encode("ascii")
    return any(line == marker or line.startswith(marker + b" ") for line in lines(console))


def marker_values(console, marker):
    """Return the integer fields of the first complete marker line, or None."""
    prefix = marker.encode("ascii") + b" "
    for line in lines(console):
        if line.startswith(prefix):
            return {key.decode(): int(value) for key, value in re.findall(rb"([a-z]+)=(-?\d+)", line)}
    return None


def run_case(name, output, qemu, kernel, initrd, kernel_version):
    spec = CASES[name]
    directory = output / name
    directory.mkdir(mode=0o700)
    result = {"case": name, "passed": False, "self_rebooted": False}
    disk, process, started = None, None, time.monotonic()
    captured = {"stdout": bytearray(), "stderr": bytearray()}
    try:
        command = [
            str(qemu), "-machine", "q35,accel=tcg", "-cpu", "max", "-m", "512M",
            "-nodefaults", "-no-user-config", "-display", "none", "-monitor", "none",
            "-serial", "stdio", "-nic", "none", "-no-reboot",
            "-kernel", str(kernel), "-initrd", str(initrd),
            "-append", ("console=ttyS0,115200 rdinit=/init loglevel=4 panic=0 "
                        f"titan_usb_probe_test={spec['argument']}"),
        ]
        if name != "missing-disk":
            descriptor, filename = tempfile.mkstemp(prefix="fixture-", suffix=".raw", dir=directory)
            disk = Path(filename)
            with os.fdopen(descriptor, "wb") as stream:
                stream.write(SENTINEL)
                stream.truncate(DISK_BYTES)
                stream.flush()
                os.fsync(stream.fileno())
            result["disk_file"] = disk.name
            result["disk_sha256_before"] = disk_hash(disk)
            # Only a generated basename enters QEMU's comma-separated option
            # syntax. The image is deliberately writable on the host.
            command += ["-drive", f"file={disk.name},if=none,format=raw,id=probe",
                        "-device", "virtio-blk-pci,drive=probe"]
        process = subprocess.Popen(command, cwd=directory, stdin=subprocess.DEVNULL,
                                   stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        with selectors.DefaultSelector() as selector:
            selector.register(process.stdout, selectors.EVENT_READ, "stdout")
            selector.register(process.stderr, selectors.EVENT_READ, "stderr")
            while selector.get_map():
                if time.monotonic() - started >= TIMEOUT:
                    raise RuntimeError("The guest did not reboot by itself within the case deadline.")
                for key, _ in selector.select(0.1):
                    remaining = OUTPUT_LIMIT - sum(map(len, captured.values()))
                    data = os.read(key.fileobj.fileno(), min(65536, remaining + 1))
                    if not data:
                        selector.unregister(key.fileobj)
                        continue
                    if len(data) > remaining:
                        raise RuntimeError("QEMU exceeded the 4 MiB diagnostic bound.")
                    captured[key.data].extend(data)
                for marker in spec["forbidden"]:
                    if has_marker(captured["stdout"], marker):
                        raise RuntimeError(f"The guest printed the forbidden marker {marker}.")
        code = process.wait(timeout=max(0.1, TIMEOUT - (time.monotonic() - started)))
        elapsed = time.monotonic() - started
        result["exit_seconds"] = round(elapsed, 3)
        console = captured["stdout"]
        if code != 0:
            raise RuntimeError(f"QEMU exited with status {code} instead of a guest reboot.")
        if b"reboot: Restarting system with command 'bootloader'" not in console:
            raise RuntimeError("The kernel did not report a restart into the bootloader.")
        missing = [marker for marker in spec["required"] if not has_marker(console, marker)]
        if missing:
            raise RuntimeError("Missing markers: " + ", ".join(missing))
        if name == "valid" and not has_marker(console, f"TITAN_PROBE_KERNEL {kernel_version}"):
            raise RuntimeError("The probe reported an unexpected kernel release.")
        # Boot-clock markers pin the deadline to PID 1's start and the restart
        # to the deadline, independent of the guest's own boot time.
        armed = marker_values(console, "TITAN_PROBE_ARMED")
        if armed is None or armed.get("deadline", 0) - armed.get("start", 0) != DEADLINE:
            raise RuntimeError("The armed deadline is not exactly the VM deadline after PID 1's start.")
        backstop = name == "child-killed"
        restart = marker_values(console, "TITAN_PROBE_BACKSTOP_REBOOT" if backstop else "TITAN_PROBE_DEADLINE_REBOOT")
        offset = None if restart is None else restart.get("now", -10**6) - armed["deadline"]
        low = BACKSTOP if backstop else 0
        if offset is None or not low <= offset <= low + 3:
            raise RuntimeError(f"The restart marker was {offset} s after the deadline, not within {low}-{low + 3} s.")
        result["restart_offset_seconds"] = offset
        if elapsed < spec["earliest"] - 1:
            raise RuntimeError("The guest rebooted before its deadline.")
        if elapsed > spec["earliest"] + LATE:
            raise RuntimeError("The guest rebooted later than its deadline allows.")
        result["self_rebooted"] = True
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
                    raise RuntimeError("The guest changed the writable host disk fixture.")
            except (OSError, RuntimeError) as error:
                result.update({"passed": False, "error": str(error)})
        result["elapsed_seconds"] = round(time.monotonic() - started, 3)
        private_write(directory / "console.log", captured["stdout"])
        private_write(directory / "qemu.stderr", captured["stderr"])
    return result


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("qemu", "kernel", "kernel-version", "initrd", "output"):
        parser.add_argument("--" + name, required=True)
    args = parser.parse_args(argv)
    previous_umask = os.umask(0o077)
    try:
        qemu = regular_input(args.qemu, executable=True)
        kernel, initrd = regular_input(args.kernel), regular_input(args.initrd)
        output = Path(args.output).expanduser().absolute()
        output.mkdir(mode=0o700)  # Refuse existing directories, files and symlinks.
        cases = []
        for name in CASES:
            result = run_case(name, output, qemu, kernel, initrd, args.kernel_version)
            cases.append(result)
            print(f"{name}: {'passed' if result['passed'] else 'FAILED'}", flush=True)
        report = {"passed": all(case["passed"] for case in cases), "cases": cases,
                  "scope": "Synthetic x86_64 TCG guests only; no Titan hardware, vendor kernel or USB stack."}
        private_write(output / "summary.json", (json.dumps(report, indent=2) + "\n").encode())
        return 0 if report["passed"] else 1
    except (OSError, ValueError, KeyboardInterrupt) as error:
        print(f"VM check stopped: {error}", file=sys.stderr)
        return 1
    finally:
        os.umask(previous_umask)


if __name__ == "__main__":
    raise SystemExit(main())
