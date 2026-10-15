#!/usr/bin/env python3
"""Run the observation or return step of the proposed Titan entry trial.

This host helper sends only a fixed allowlist of standard read-only fastboot
`getvar` queries, or exactly one return command. It never enters fastboot,
sends images, or issues flash, erase, oem, flashing, boot or set_active
commands. Running it is part of a phone trial that needs explicit owner
authorization; see entry-return-trial.adoc.
"""

import argparse
import datetime
import json
import os
from pathlib import Path
import re
import selectors
import subprocess
import sys
import time

FORMAT = "titan-fastboot-trial-v1"
VARIABLES = (
    "product", "version-bootloader", "version-baseband", "secure", "unlocked",
    "is-userspace", "max-download-size", "current-slot", "slot-count",
    "partition-type:boot", "partition-size:boot",
    "partition-type:recovery", "partition-size:recovery",
    "partition-type:dtbo", "partition-size:dtbo",
)
RETURN_COMMANDS = ("reboot", "continue")
OUTPUT_LIMIT = 65536
COMMAND_TIMEOUT = 20.0
POLL_INTERVAL = 2.0
MAX_WAIT = 600.0
SERIAL = re.compile(r"[!-~]{1,64}")
PLACEHOLDER = "<selected-device>"


class TrialError(Exception):
    pass


def run_bounded(command, timeout=None, limit=None):
    """Run one argv without a shell; bound time and both output streams."""
    timeout = COMMAND_TIMEOUT if timeout is None else timeout
    limit = OUTPUT_LIMIT if limit is None else limit
    started = time.monotonic()
    deadline = started + timeout
    process = subprocess.Popen(command, stdin=subprocess.DEVNULL,
                               stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    streams = {"stdout": bytearray(), "stderr": bytearray()}
    status = "exited"
    try:
        with selectors.DefaultSelector() as selector:
            selector.register(process.stdout, selectors.EVENT_READ, "stdout")
            selector.register(process.stderr, selectors.EVENT_READ, "stderr")
            while selector.get_map() and status == "exited":
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    status = "timeout"
                    break
                for key, _ in selector.select(min(remaining, 0.5)):
                    chunk = os.read(key.fileobj.fileno(), 65536)
                    if not chunk:
                        selector.unregister(key.fileobj)
                        continue
                    streams[key.data] += chunk
                    if len(streams[key.data]) > limit:
                        status = "output-limit"
                        break
        if status == "exited":
            try:
                process.wait(timeout=max(0.0, deadline - time.monotonic()))
            except subprocess.TimeoutExpired:
                status = "timeout"
    finally:
        if process.poll() is None:
            process.kill()
        process.wait()
        process.stdout.close()
        process.stderr.close()
    return {
        "status": status,
        "exit": process.returncode if status == "exited" else None,
        "seconds": round(time.monotonic() - started, 3),
        "stdout": bytes(streams["stdout"][:limit]).decode("utf-8", "replace"),
        "stderr": bytes(streams["stderr"][:limit]).decode("utf-8", "replace"),
    }


def parse_devices(text):
    devices = []
    for line in text.splitlines():
        fields = line.split()
        if not fields:
            continue
        if len(fields) != 2 or not SERIAL.fullmatch(fields[0]):
            raise TrialError("Unrecognized fastboot device listing; nothing was queried.")
        devices.append((fields[0], fields[1]))
    return devices


def select_device(fastboot, steps, wait, poll=POLL_INTERVAL):
    """Wait for exactly one device in bootloader fastboot listing state."""
    deadline = time.monotonic() + wait
    while True:
        result = run_bounded(fastboot + ["devices"])
        steps.append({"argv": ["devices"], **result})
        if result["status"] != "exited" or result["exit"] != 0:
            raise TrialError("Listing fastboot devices failed; nothing was queried.")
        devices = parse_devices(result["stdout"])
        if len(devices) > 1:
            raise TrialError("More than one fastboot device is connected; disconnect the others.")
        if devices:
            serial, state = devices[0]
            if state != "fastboot":
                raise TrialError(f"The listed device is in state {state!r}, not 'fastboot'.")
            return serial
        if time.monotonic() + poll > deadline:
            raise TrialError("No fastboot device appeared within the waiting period.")
        time.sleep(poll)


def query_value(variable, result):
    if result["status"] != "exited" or result["exit"] != 0:
        return None
    prefix = variable + ":"
    for line in result["stderr"].splitlines() + result["stdout"].splitlines():
        if line.startswith(prefix):
            return line[len(prefix):].strip()
    return None


def inside_checkout(path):
    for parent in (path, *path.parents):
        if (parent / ".git").exists() or (parent / ".jj").exists():
            return True
    return False


def prepare_output(requested):
    """Create a new 0700 directory outside checkouts and the world-readable store."""
    output = Path(requested).expanduser()
    if not output.is_absolute():
        raise TrialError("The output directory must be an absolute path.")
    parent = output.parent.resolve(strict=True)
    output = parent / output.name
    if str(output) == "/nix/store" or str(output).startswith("/nix/store/"):
        raise TrialError("The output directory must be outside the Nix store.")
    if inside_checkout(parent):
        raise TrialError("The output directory must be outside every Git or jj checkout.")
    metadata = os.stat(parent)
    if metadata.st_uid != os.getuid():
        raise TrialError("The output parent must be owned by the current user.")
    os.mkdir(output, 0o700)
    os.chmod(output, 0o700)
    return output


def write_record(output, record):
    data = (json.dumps(record, indent=2, sort_keys=True) + "\n").encode("utf-8")
    pending = output / "trial.json.part"
    fd = os.open(pending, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        os.fchmod(fd, 0o600)
        view = memoryview(data)
        while view:
            view = view[os.write(fd, view):]
        os.fsync(fd)
    finally:
        os.close(fd)
    os.replace(pending, output / "trial.json")
    directory = os.open(output, os.O_RDONLY)
    try:
        os.fsync(directory)
    finally:
        os.close(directory)


def run_trial(fastboot, output, mode, command="reboot", wait=120.0, poll=POLL_INTERVAL):
    if mode not in ("observe", "return") or command not in RETURN_COMMANDS:
        raise TrialError("Unsupported trial step.")
    record = {"format": FORMAT, "mode": mode, "status": "incomplete",
              "created_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
              "fastboot": fastboot[-1], "steps": [], "variables": {}}
    steps = record["steps"]
    try:
        version = run_bounded(fastboot + ["--version"])
        steps.append({"argv": ["--version"], **version})
        if version["status"] != "exited" or version["exit"] != 0:
            raise TrialError("The fastboot executable did not report its version.")
        serial = select_device(fastboot, steps, wait, poll)
        record["device_serial_private"] = serial
        if mode == "return":
            result = run_bounded(fastboot + ["-s", serial, command])
            steps.append({"argv": ["-s", PLACEHOLDER, command], **result})
            if result["status"] != "exited" or result["exit"] != 0:
                raise TrialError(f"`fastboot {command}` did not complete successfully.")
        else:
            for variable in VARIABLES:
                result = run_bounded(fastboot + ["-s", serial, "getvar", variable])
                steps.append({"argv": ["-s", PLACEHOLDER, "getvar", variable], **result})
                if result["status"] != "exited":
                    raise TrialError(f"Query {variable!r} did not finish; later queries were skipped.")
                record["variables"][variable] = query_value(variable, result)
        record["status"] = "complete"
        return record
    except TrialError as error:
        record["error"] = str(error)
        raise
    finally:
        write_record(output, record)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=("observe", "return"))
    parser.add_argument("--output", required=True,
                        help="new private directory; its parent must exist")
    parser.add_argument("--fastboot", default="/opt/homebrew/bin/fastboot",
                        help="absolute path of the Platform-Tools fastboot executable")
    parser.add_argument("--command", choices=RETURN_COMMANDS, default="reboot",
                        help="return command; use 'continue' only if 'reboot' re-entered fastboot")
    parser.add_argument("--wait", type=float, default=120.0,
                        help="seconds to wait for the single fastboot device (at most 600)")
    args = parser.parse_args(argv)
    previous = os.umask(0o077)
    try:
        if args.mode == "observe" and args.command != "reboot":
            raise TrialError("--command applies only to the return step.")
        if not 0 <= args.wait <= MAX_WAIT:
            raise TrialError("--wait must be between 0 and 600 seconds.")
        executable = Path(args.fastboot)
        if not executable.is_absolute() or not os.access(executable, os.X_OK):
            raise TrialError("--fastboot must be an absolute path to an executable.")
        output = prepare_output(args.output)
        record = run_trial([str(executable)], output, args.mode, args.command, args.wait)
        if args.mode == "observe":
            answered = sum(value is not None for value in record["variables"].values())
            print(f"One fastboot device; {answered} of {len(VARIABLES)} variables answered.")
        else:
            print(f"`fastboot {args.command}` completed; confirm the return over ADB.")
        print(f"Private record: {output / 'trial.json'}")
        return 0
    except (TrialError, OSError) as error:
        print(f"Fastboot trial step stopped: {error}", file=sys.stderr)
        return 1
    finally:
        os.umask(previous)


if __name__ == "__main__":
    raise SystemExit(main())
