#!/usr/bin/env python3
"""Receive the Titan's native-route diagnostics on the Mac (diag/README.adoc).

The diagnostic image, started from the recovery partition, streams a fixed
list of kernel and firmware state (command line, kernel log, the bootloader's
device tree, device-driver bindings, interrupts, processors, partitions, memory
map) as named sections over the TTR1 protocol on its fixed USB gadget. This helper waits for that gadget by its
fixed strings, receives the stream with the existing TTR1 receiver into a new
private directory, then splits it into one private file per section with an
index. The data includes device identifiers such as the serial number in the
command line, so it stays private. It sends only TTR1 protocol frames and never
writes to the phone's storage. Running it is part of a trial that needs the
owner's explicit authorization; see native-diag-trial.adoc.
"""

import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import sys

FORMAT = "titan-diagnostics-v1"
LABEL = "titan-diagnostics"
MAX_BYTES = 8388608
# The producer's fixed order (diag/producer.c), each with its byte limit and
# the file suffix it is saved under.
SECTIONS = (("cmdline", 4096, ".txt"), ("kmsg", 4 << 20, ".txt"), ("fdt", 2 << 20, ".dtb"),
            ("bindings", 256 << 10, ".txt"), ("interrupts", 256 << 10, ".txt"), ("cpuinfo", 64 << 10, ".txt"),
            ("partitions", 64 << 10, ".txt"), ("iomem", 256 << 10, ".txt"))
HEADER = re.compile(rb"section ([a-z]+) (?:(0|[1-9][0-9]{0,9})( truncated)?|(missing)|error (0|[1-9][0-9]{0,3}))\n")


class DiagnosticsError(Exception):
    pass


def load(name, filename, directory=None):
    path = (directory or Path(__file__).resolve().parent) / filename
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def parse(data):
    """Return [(name, bytes or None, truncated, errno or None)] from a complete diagnostic stream."""
    if not isinstance(data, bytes) or not data.startswith(b"TITAN-DIAG v1\n"):
        raise DiagnosticsError("The stream does not start with the diagnostic banner.")
    offset, result = len(b"TITAN-DIAG v1\n"), []
    for name, limit, _ in SECTIONS:
        match = HEADER.match(data, offset)
        if match is None or match.group(1).decode() != name:
            raise DiagnosticsError(f"Expected the {name} section header.")
        offset = match.end()
        if match.group(4) or match.group(5):
            result.append((name, None, False, None if match.group(4) else int(match.group(5))))
            continue
        length = int(match.group(2))
        if length > limit or offset + length > len(data):
            raise DiagnosticsError(f"The {name} section exceeds its limit or the stream.")
        result.append((name, data[offset:offset + length], bool(match.group(3)), None))
        offset += length
    if data[offset:] != b"end\n":
        raise DiagnosticsError("The stream does not end with the fixed trailer.")
    return result


def write_private(path, data):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    try:
        view = memoryview(data)
        while view:
            view = view[os.write(fd, view):]
        os.fsync(fd)
    finally:
        os.close(fd)


def split(payload, output):
    """Write each section of a received payload into a new private directory."""
    data = Path(payload).read_bytes()
    sections = parse(data)
    os.mkdir(output, 0o700)
    output = Path(output)
    index = {"format": FORMAT, "payload_bytes": len(data), "sections": []}
    for (name, content, truncated, error), (_, _, suffix) in zip(sections, SECTIONS):
        entry = {"name": name, "missing": content is None and error is None, "error": error, "truncated": truncated}
        if content is not None:
            write_private(output / (name + suffix), content)
            entry.update({"file": name + suffix, "bytes": len(content),
                          "sha256": hashlib.sha256(content).hexdigest()})
        index["sections"].append(entry)
    write_private(output / "index.json", (json.dumps(index, indent=2) + "\n").encode())
    return index


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True, help="new private directory; its parent must exist")
    parser.add_argument("--wait", type=float, default=600.0,
                        help="seconds to wait for the diagnostic gadget to appear (at most 600)")
    parser.add_argument("--timeout", type=float, default=300.0,
                        help="seconds allowed for the transfer once it starts (at most 900)")
    args = parser.parse_args(argv)
    previous = os.umask(0o077)
    try:
        if not 0 <= args.wait <= 600 or not 1 <= args.timeout <= 900:
            raise DiagnosticsError("--wait or --timeout is outside its reviewed range.")
        listener = load("titan_diag_listener", "read-probe-report.py")
        output = listener.prepare_output(args.output)
        port = listener.wait_for_port(args.wait)
        receiver = load("titan_diag_receiver", "receive.py", Path(__file__).resolve().parent.parent / "transport")
        code = receiver.main(["--tty", port, "--label", LABEL, "--max-bytes", str(MAX_BYTES),
                              "--output", str(output / "transfer"), "--timeout-seconds", str(args.timeout)])
        if code != 0:
            raise DiagnosticsError("The TTR1 transfer did not complete; see the transfer directory.")
        index = split(output / "transfer" / "payload.bin", output / "sections")
        for entry in index["sections"]:
            state = ("missing" if entry["missing"] else f"read error {entry['error']}" if entry["error"] is not None
                     else f"{entry['bytes']} bytes" + (", truncated" if entry["truncated"] else ""))
            print(f"  {entry['name']}: {state}")
        print(f"Private sections: {output / 'sections'}")
        return 0
    except (DiagnosticsError, OSError, ValueError) as error:
        print(f"Diagnostic reception stopped: {error}", file=sys.stderr)
        return 1
    except Exception as error:
        if type(error).__name__ in ("ReportError", "TransferError"):
            print(f"Diagnostic reception stopped: {error}", file=sys.stderr)
            return 1
        raise
    finally:
        os.umask(previous)


if __name__ == "__main__":
    raise SystemExit(main())
