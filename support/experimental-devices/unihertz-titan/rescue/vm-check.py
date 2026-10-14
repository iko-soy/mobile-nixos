#!/usr/bin/env python3
"""Exercise the rescue PID 1 against generated disks in networkless TCG guests."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import selectors
import stat
import subprocess
import sys
import tempfile
import time


SENTINEL = b"TITAN_RESCUE_VM_SENTINEL_v1\n"
DISK_BYTES = 1024 * 1024
OUTPUT_LIMIT = 4 * 1024 * 1024
TIMEOUT = 90
FAILURE_HOLD_SECONDS = 2


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


def has_marker(console, marker):
    marker = marker.encode("ascii")
    return any(line == marker or line.startswith(marker + b" ")
               for line in console.replace(b"\r", b"").split(b"\n"))


def run_case(name, output, qemu, kernel, initrd):
    directory = output / name
    directory.mkdir(mode=0o700)
    result = {"case": name, "passed": False, "host_terminated": False}
    disk, process, started = None, None, time.monotonic()
    captured = {"stdout": bytearray(), "stderr": bytearray()}
    try:
        command = [
            str(qemu), "-machine", "q35,accel=tcg", "-cpu", "max", "-m", "512M",
            "-nodefaults", "-no-user-config", "-display", "none", "-monitor", "none",
            "-serial", "stdio", "-nic", "none", "-no-reboot",
            "-kernel", str(kernel), "-initrd", str(initrd),
            "-append", "console=ttyS0,115200 rdinit=/init loglevel=4 panic=0",
        ]
        if name != "missing-disk":
            descriptor, filename = tempfile.mkstemp(prefix="fixture-", suffix=".raw", dir=directory)
            disk = Path(filename)
            with os.fdopen(descriptor, "wb") as stream:
                if not stat.S_ISREG(os.fstat(stream.fileno()).st_mode):
                    raise RuntimeError("Generated disk is not a regular file.")
                stream.write(SENTINEL if name == "read-only-guard" else b"WRONG_" + SENTINEL)
                stream.truncate(DISK_BYTES)
                stream.flush()
                os.fsync(stream.fileno())
            result["disk_file"] = disk.name
            result["disk_sha256_before"] = disk_hash(disk)
            # Only a generated basename enters QEMU's comma-separated option
            # syntax. The image is deliberately writable on the host.
            command += ["-drive", f"file={disk.name},if=none,format=raw,id=probe",
                        "-device", "virtio-blk-pci,drive=probe"]
        process = subprocess.Popen(
            command, cwd=directory, stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        )
        failure_seen = None
        with selectors.DefaultSelector() as selector:
            selector.register(process.stdout, selectors.EVENT_READ, "stdout")
            selector.register(process.stderr, selectors.EVENT_READ, "stderr")
            while selector.get_map():
                now = time.monotonic()
                if now - started >= TIMEOUT:
                    raise RuntimeError("QEMU exceeded the 90-second case deadline.")
                for key, _ in selector.select(0.1):
                    remaining = OUTPUT_LIMIT - sum(map(len, captured.values()))
                    data = os.read(key.fileobj.fileno(), min(65536, remaining + 1))
                    if not data:
                        selector.unregister(key.fileobj)
                        continue
                    if len(data) > remaining:
                        raise RuntimeError("QEMU exceeded the 4 MiB diagnostic bound.")
                    captured[key.data].extend(data)
                console = captured["stdout"]
                passed = has_marker(console, "TITAN_RESCUE_VM_PASS")
                failed = has_marker(console, "TITAN_RESCUE_FAILED")
                ready = has_marker(console, "TITAN_RESCUE_READY")
                if name == "read-only-guard":
                    if failed or has_marker(console, "TITAN_RESCUE_VM_FAIL"):
                        raise RuntimeError("The expected successful guest reported failure.")
                else:
                    if passed or (name == "missing-disk" and ready):
                        raise RuntimeError("A negative case reached a forbidden success marker.")
                    expected_failure = False
                    if failed:
                        if name == "missing-disk":
                            expected_failure = has_marker(console, "TITAN_RESCUE_FAILED no-storage-before-deadline")
                            if time.monotonic() - started < 4.5:
                                raise RuntimeError("Missing-disk failure preceded the five-second discovery window.")
                        else:
                            expected_failure = (
                                has_marker(console, "TITAN_RESCUE_VM_FAIL sentinel-bytes-mismatch")
                                and has_marker(console, "TITAN_RESCUE_FAILED vm-test-returned")
                                and console.find(b"TITAN_RESCUE_VM_FAIL") < console.find(b"TITAN_RESCUE_FAILED")
                            )
                        if not expected_failure:
                            raise RuntimeError("The negative guest failed for an unexpected reason.")
                    if expected_failure and failure_seen is None:
                        failure_seen = time.monotonic()
                    if failure_seen is not None and time.monotonic() - failure_seen >= FAILURE_HOLD_SECONDS:
                        if process.poll() is not None:
                            raise RuntimeError("The failed guest exited instead of remaining alive.")
                        result["failure_hold_seconds"] = time.monotonic() - failure_seen
                        result["host_terminated"] = True
                        break
        if name == "read-only-guard":
            code = process.wait(timeout=max(0.1, TIMEOUT - (time.monotonic() - started)))
            if code != 0 or not has_marker(captured["stdout"], "TITAN_RESCUE_VM_PASS"):
                raise RuntimeError("The successful guest did not print PASS and power off with status 0.")
            if not has_marker(captured["stdout"], "TITAN_RESCUE_READY"):
                raise RuntimeError("The successful guest never reached READY.")
        elif not result["host_terminated"]:
            raise RuntimeError("The failed guest exited before the host could terminate it.")
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
    for name in ("qemu", "kernel", "initrd", "output"):
        parser.add_argument("--" + name, required=True)
    args = parser.parse_args(argv)
    previous_umask = os.umask(0o077)
    try:
        qemu = regular_input(args.qemu, executable=True)
        kernel, initrd = regular_input(args.kernel), regular_input(args.initrd)
        output = Path(args.output).expanduser().absolute()
        output.mkdir(mode=0o700)  # Refuse existing directories, files and symlinks.
        cases = []
        for name in ("read-only-guard", "wrong-sentinel", "missing-disk"):
            result = run_case(name, output, qemu, kernel, initrd)
            cases.append(result)
            print(f"{name}: {'passed' if result['passed'] else 'FAILED'}", flush=True)
        report = {"passed": all(case["passed"] for case in cases), "cases": cases,
                  "scope": "Synthetic x86_64 TCG guests only; no Titan hardware or recovery validation."}
        private_write(output / "summary.json", (json.dumps(report, indent=2) + "\n").encode())
        return 0 if report["passed"] else 1
    except (OSError, ValueError, KeyboardInterrupt) as error:
        print(f"VM check stopped: {error}", file=sys.stderr)
        return 1
    finally:
        os.umask(previous_umask)


if __name__ == "__main__":
    sys.exit(main())
