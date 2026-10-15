#!/usr/bin/env python3
"""Read the Titan USB probe's status lines on the Mac without writing to the phone.

The probe image binds a fixed ACM gadget and writes one bounded status line
every two seconds until it reboots at its deadline. This helper waits until
exactly one USB device carries the probe's fixed manufacturer, product and
serial strings, opens that device's modem port read-only in raw mode, validates
each complete line against the fixed format and saves them privately. Other
ports, such as the MediaTek preloader's brief port during a reset or Ubuntu
Touch's own gadget, which shares the pid.codes test ID, are never opened. It sends no
bytes to the phone. Running it is part of a temporary-boot trial that needs the
owner's explicit authorization; see temporary-boot-trial.adoc.
"""

import argparse
import datetime
import json
import os
from pathlib import Path
import re
import select
import subprocess
import sys
import termios
import time

FORMAT = "titan-usb-probe-report-v1"
LINE = re.compile(rb"TITAN_PROBE v1 seq=([1-9][0-9]{0,5}) uptime=(0|[1-9][0-9]{0,6}) "
                  rb"deadline=(0|[1-9][0-9]{0,6}) kernel=([A-Za-z0-9.+_-]{1,64}) storage=guarded usb=bound")
# The probe gadget's fixed descriptors (usb/owner.c). Vendor and product IDs
# alone are not enough: Ubuntu Touch's own gadget on this phone also uses
# 1209:0005, with different strings.
IDENTITY = {"idVendor": 0x1209, "idProduct": 0x0005, "USB Vendor Name": "Titan rescue experiment",
            "USB Product Name": "Titan read-only acquisition", "USB Serial Number": "TITAN-RESCUE-EXPERIMENT-0001"}
# macOS records some descriptor strings with "-" replaced by "_": on
# 2026-10-15 it showed the product as "Titan read_only acquisition". Each
# string may also appear under its kUSB*String key.
STRING_KEYS = {"USB Vendor Name": ("USB Vendor Name", "kUSBVendorString"),
               "USB Product Name": ("USB Product Name", "kUSBProductString"),
               "USB Serial Number": ("USB Serial Number", "kUSBSerialNumberString")}
CALLOUT = re.compile(r'"IOCalloutDevice" = "(/dev/cu\.usbmodem[A-Za-z0-9_.-]{1,64})"')
LINE_LIMIT = 256
BYTE_LIMIT = 65536
MAX_WAIT = 600.0


class ReportError(Exception):
    pass


def prepare_output(requested):
    """Create a new 0700 directory outside checkouts and the Nix store."""
    output = Path(requested).expanduser()
    if not output.is_absolute():
        raise ReportError("The output directory must be an absolute path.")
    parent = output.parent.resolve(strict=True)
    output = parent / output.name
    if str(output) == "/nix/store" or str(output).startswith("/nix/store/"):
        raise ReportError("The output directory must be outside the Nix store.")
    for directory in (parent, *parent.parents):
        if (directory / ".git").exists() or (directory / ".jj").exists():
            raise ReportError("The output directory must be outside every Git or jj checkout.")
    os.mkdir(output, 0o700)
    os.chmod(output, 0o700)
    return output


def ioreg_text():
    try:
        result = subprocess.run(["/usr/sbin/ioreg", "-r", "-c", "IOUSBHostDevice", "-l", "-w0"],
                                capture_output=True, timeout=20, check=False)
    except subprocess.TimeoutExpired as error:
        raise ReportError("The USB device registry could not be read in time.") from error
    if result.returncode != 0 or len(result.stdout) > 16 * 1024 * 1024:
        raise ReportError("The USB device registry could not be read.")
    return result.stdout.decode("utf-8", "replace")


def registry_objects(text):
    """Split ioreg output into (depth, object line, properties) in tree order."""
    objects = []
    for line in text.splitlines():
        marker = line.find("+-o ")
        if marker >= 0:
            objects.append([marker, line, []])
        elif objects:
            objects[-1][2].append(line)
    return objects


def probe_ports(text):
    """Return the modem ports of every USB device whose descriptors match the probe.

    Devices behind a hub appear nested inside the hub's entry, so each USB
    device is matched on its own properties and its ports are taken from its
    own descendants only."""
    objects, ports = registry_objects(text), []
    for index, (depth, line, properties) in enumerate(objects):
        if "<class IOUSBHostDevice" not in line:
            continue
        own = "\n".join(properties)
        numbers = {key: re.search(r'"%s" = (\d+)' % key, own) for key in ("idVendor", "idProduct")}
        if any(match is None or int(match.group(1)) != IDENTITY[key] for key, match in numbers.items()):
            continue
        normalized = lambda text: text.replace("_", "-")
        if not all(any(normalized(found) == normalized(value)
                       for name in STRING_KEYS[key] for found in re.findall(r'"%s" = "([^"]*)"' % name, own))
                   for key, value in IDENTITY.items() if isinstance(value, str)):
            continue
        descendants = []
        for child_depth, _, child_properties in objects[index + 1:]:
            if child_depth <= depth:
                break
            descendants.extend(child_properties)
        ports.append(sorted(set(CALLOUT.findall("\n".join(descendants)))))
    return ports


def wait_for_port(wait, poll=0.5, registry=ioreg_text):
    """Return the single modem port of the single probe device, ignoring all others."""
    deadline = time.monotonic() + wait
    while True:
        devices = probe_ports(registry())
        if len(devices) > 1 or any(len(ports) > 1 for ports in devices):
            raise ReportError("More than one probe device or port is present; nothing was read.")
        if devices and devices[0] and os.path.exists(devices[0][0]):
            return devices[0][0]
        if time.monotonic() + poll > deadline:
            raise ReportError("No probe device appeared within the waiting period.")
        time.sleep(poll)


def open_raw(port):
    fd = os.open(port, os.O_RDONLY | os.O_NOCTTY | os.O_NONBLOCK | os.O_CLOEXEC)
    try:
        attributes = termios.tcgetattr(fd)
        attributes[0] = 0                                  # iflag: no translation or flow control
        attributes[1] = 0                                  # oflag
        attributes[2] = termios.CS8 | termios.CREAD | termios.CLOCAL
        attributes[3] = 0                                  # lflag: no echo, canonical mode or signals
        termios.tcsetattr(fd, termios.TCSANOW, attributes)
    except BaseException:
        os.close(fd)
        raise
    return fd


def read_lines(fd, seconds, wanted):
    """Collect complete lines for at most `seconds` or until `wanted` valid lines."""
    deadline = time.monotonic() + seconds
    pending, total, valid, rejected = b"", 0, [], 0
    while time.monotonic() < deadline and len(valid) < wanted:
        ready, _, _ = select.select([fd], [], [], min(0.5, max(0.0, deadline - time.monotonic())))
        if not ready:
            continue
        try:
            chunk = os.read(fd, 4096)
        except BlockingIOError:
            continue
        except OSError as error:
            # The phone rebooting removes the port; keep what arrived.
            if valid:
                break
            raise ReportError("The USB modem port failed before any valid line arrived.") from error
        if not chunk:
            break
        total += len(chunk)
        if total > BYTE_LIMIT:
            raise ReportError("The port sent more than the bounded report allows.")
        pending += chunk
        while b"\n" in pending:
            line, pending = pending.split(b"\n", 1)
            line = line.strip(b"\r")
            if not line:
                continue
            match = LINE.fullmatch(line)
            if match is None:
                rejected += 1
                continue
            sequence, uptime, deadline_value, kernel = match.groups()
            valid.append({"seq": int(sequence), "uptime": int(uptime), "deadline": int(deadline_value),
                          "kernel": kernel.decode("ascii")})
        if len(pending) > LINE_LIMIT:
            raise ReportError("A report line exceeded its bound.")
    return valid, rejected, total


def write_record(output, record):
    data = (json.dumps(record, indent=2, sort_keys=True) + "\n").encode("ascii")
    fd = os.open(output / "report.json", os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        view = memoryview(data)
        while view:
            view = view[os.write(fd, view):]
        os.fsync(fd)
    finally:
        os.close(fd)


def consistent(lines):
    """Sequence numbers rise, the deadline is constant and uptime stays before it."""
    return (all(left["seq"] < right["seq"] and left["uptime"] <= right["uptime"]
                for left, right in zip(lines, lines[1:]))
            and len({line["deadline"] for line in lines}) == 1
            and len({line["kernel"] for line in lines}) == 1
            and all(line["uptime"] < line["deadline"] for line in lines))


def run(output, wait, seconds, wanted, port=None, registry=ioreg_text):
    record = {"format": FORMAT, "status": "incomplete",
              "created_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(), "lines": []}
    try:
        if port is None:
            port = wait_for_port(wait, registry=registry)
        record["port_private"] = port
        fd = open_raw(port)
        try:
            valid, rejected, total = read_lines(fd, seconds, wanted)
        finally:
            os.close(fd)
        record.update(lines=valid, rejected_lines=rejected, bytes=total)
        if len(valid) < wanted:
            raise ReportError(f"Only {len(valid)} of {wanted} valid report lines arrived.")
        # A line cut short by a full or absent host can arrive as a fragment;
        # fragments are counted, but the valid lines must agree.
        if not consistent(valid):
            raise ReportError("The valid report lines were inconsistent.")
        record["status"] = "complete"
        return record
    except ReportError as error:
        record["error"] = str(error)
        raise
    finally:
        write_record(output, record)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True, help="new private directory; its parent must exist")
    parser.add_argument("--wait", type=float, default=300.0,
                        help="seconds to wait for the probe's USB device to appear (at most 600)")
    parser.add_argument("--seconds", type=float, default=30.0, help="seconds to read once the port is open")
    parser.add_argument("--lines", type=int, default=5, help="valid lines to collect (1 to 20)")
    args = parser.parse_args(argv)
    previous = os.umask(0o077)
    try:
        if not 0 <= args.wait <= MAX_WAIT or not 1 <= args.seconds <= 120 or not 1 <= args.lines <= 20:
            raise ReportError("--wait, --seconds or --lines is outside its reviewed range.")
        output = prepare_output(args.output)
        record = run(output, args.wait, args.seconds, args.lines)
        first, last = record["lines"][0], record["lines"][-1]
        print(f"Probe report: {len(record['lines'])} valid lines ({record['rejected_lines']} fragments), "
              f"kernel {last['kernel']}, uptime {first['uptime']}-{last['uptime']} s, "
              f"reboot deadline at {last['deadline']} s.")
        print(f"Private record: {output / 'report.json'}")
        return 0
    except (ReportError, OSError, termios.error) as error:
        print(f"Probe report reading stopped: {error}", file=sys.stderr)
        return 1
    finally:
        os.umask(previous)


if __name__ == "__main__":
    raise SystemExit(main())
