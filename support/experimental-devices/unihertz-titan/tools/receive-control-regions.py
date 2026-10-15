#!/usr/bin/env python3
"""Receive and verify the Titan's offline control-region acquisition on the Mac.

The acquisition image, started from the recovery partition, streams sixteen
fixed control and calibration regions, raw and in table order, followed by a
text manifest with two independent SHA-256 passes per region, over the TTR1
protocol on its fixed USB gadget. This helper waits for that gadget by its fixed
strings, receives the stream with the existing TTR1 receiver into a new private
directory, then splits it into one private file per region and checks each
region against both passes and its fixed geometry. It sends only TTR1 protocol
frames and never writes to the phone's storage. Running it is part of an
acquisition trial that needs the owner's explicit authorization; see
control-acquisition-trial.adoc.
"""

import argparse
import datetime
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import stat
import sys

FORMAT = "titan-control-regions-v1"
LABEL = "control-regions-raw"
MAX_BYTES = 1073741824
MANIFEST_MAX = 8192
CHUNK = 1 << 20
EXT4_STATES = ("clean", "unclean-state", "journal-recovery-pending", "orphans-pending", "not-ext4")
# The producer's fixed table (control/producer.c): label, GPT number, start and
# sectors from the measured layout, and kind.
REGIONS = (
    ("boot_para", 1, 64, 2048, "raw"), ("para", 3, 67648, 1024, "raw"),
    ("expdb", 4, 68672, 40960, "raw"), ("frp", 5, 109632, 2048, "raw"),
    ("nvcfg", 6, 111680, 65536, "ext4"), ("nvdata", 7, 177216, 131072, "ext4"),
    ("metadata", 8, 308288, 65536, "raw"), ("protect1", 9, 373824, 16384, "ext4"),
    ("protect2", 10, 390208, 19392, "ext4"), ("seccfg", 11, 409600, 16384, "raw"),
    ("sec1", 12, 425984, 4096, "raw"), ("proinfo", 13, 430080, 6144, "raw"),
    ("nvram", 25, 829440, 131072, "raw"), ("cache", 35, 9142272, 884736, "raw"),
    ("otp", 37, 244164544, 88064, "raw"), ("flashinfo", 38, 244252608, 32768, "raw"),
)
HEX = re.compile(r"[0-9a-f]{64}")


class VerificationError(Exception):
    pass


def load(name, filename, directory=None):
    path = (directory or Path(__file__).resolve().parent) / filename
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def parse_manifest(data, regions):
    """Return one record per region from the producer's manifest, in table order."""
    try:
        text = data.decode("ascii")
    except UnicodeDecodeError as error:
        raise VerificationError("The manifest is not ASCII.") from error
    lines = text.split("\n")
    total = sum(sectors * 512 for _, _, _, sectors, _ in regions)
    if (len(lines) != len(regions) + 3 or lines[-1] != "" or lines[-2] != "end"
            or lines[0] != f"TITAN-CONTROL-REGIONS v1 regions={len(regions)} bytes={total}"):
        raise VerificationError("The manifest framing differs from the fixed format.")
    records = []
    for line, (label, number, start, sectors, kind) in zip(lines[1:-2], regions):
        fields = line.split(" ")
        expected = ["region", label, str(number), str(start), str(sectors), str(sectors * 512)]
        if len(fields) != 10 or fields[:6] != expected or fields[8] != kind:
            raise VerificationError(f"The manifest entry for {label} differs from the fixed table.")
        first, second, state = fields[6], fields[7], fields[9]
        if not HEX.fullmatch(first) or not HEX.fullmatch(second):
            raise VerificationError(f"The manifest digests for {label} are malformed.")
        if (kind == "raw") != (state == "-") or (kind == "ext4" and state not in EXT4_STATES):
            raise VerificationError(f"The manifest state for {label} is malformed.")
        records.append({"label": label, "first": first, "second": second, "kind": kind, "state": state})
    return records


def write_private(directory, name, data_source, size):
    """Copy size bytes from an open file into a new 0600 file; return its SHA-256."""
    fd = os.open(directory / name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    digest, remaining = hashlib.sha256(), size
    try:
        while remaining:
            chunk = data_source.read(min(CHUNK, remaining))
            if not chunk:
                raise VerificationError("The payload ended inside a region.")
            remaining -= len(chunk)
            digest.update(chunk)
            if any(chunk):
                view = memoryview(chunk)
                while view:
                    view = view[os.write(fd, view):]
            else:
                os.lseek(fd, len(chunk), os.SEEK_CUR)
        os.ftruncate(fd, size)
        os.fsync(fd)
    finally:
        os.close(fd)
    return digest.hexdigest()


def split_and_verify(payload, output, regions=REGIONS):
    """Split a received payload into region files and check them; return the report."""
    payload = Path(payload)
    metadata = os.lstat(payload)
    total = sum(sectors * 512 for _, _, _, sectors, _ in regions)
    if not stat.S_ISREG(metadata.st_mode) or not total < metadata.st_size <= total + MANIFEST_MAX:
        raise VerificationError("The payload is not a regular file of the expected size.")
    os.mkdir(output, 0o700)
    output = Path(output)
    with payload.open("rb") as stream:
        stream.seek(total)
        records = parse_manifest(stream.read(MANIFEST_MAX + 1), regions)
        stream.seek(0)
        report = {"format": FORMAT, "created_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
                  "payload_bytes": metadata.st_size, "region_bytes": total, "regions": {}}
        for record, (label, number, start, sectors, kind) in zip(records, regions):
            digest = write_private(output, label + ".img", stream, sectors * 512)
            if digest != record["first"]:
                raise VerificationError(f"Region {label} does not match the producer's first pass.")
            stable = record["first"] == record["second"]
            consistent = stable and (kind == "raw" or record["state"] == "clean")
            report["regions"][label] = {"file": label + ".img", "number": number, "start": start,
                "sectors": sectors, "bytes": sectors * 512, "sha256": digest, "second_pass_sha256": record["second"],
                "stable": stable, "kind": kind, "ext4_state": record["state"], "consistent": consistent}
    report["all_stable"] = all(item["stable"] for item in report["regions"].values())
    report["all_consistent"] = all(item["consistent"] for item in report["regions"].values())
    data = (json.dumps(report, indent=2, sort_keys=True) + "\n").encode("ascii")
    fd = os.open(output / "report.json", os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        os.write(fd, data)
        os.fsync(fd)
    finally:
        os.close(fd)
    return report


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True, help="new private directory; its parent must exist")
    parser.add_argument("--wait", type=float, default=600.0,
                        help="seconds to wait for the acquisition gadget to appear (at most 600)")
    parser.add_argument("--timeout", type=float, default=1800.0,
                        help="seconds allowed for the transfer once it starts (at most 3600)")
    args = parser.parse_args(argv)
    previous = os.umask(0o077)
    try:
        listener = load("titan_control_listener", "read-probe-report.py")
        if not 0 <= args.wait <= 600 or not 1 <= args.timeout <= 3600:
            raise VerificationError("--wait or --timeout is outside its reviewed range.")
        output = listener.prepare_output(args.output)
        port = listener.wait_for_port(args.wait)
        receiver = load("titan_control_receiver", "receive.py",
                        Path(__file__).resolve().parent.parent / "transport")
        code = receiver.main(["--tty", port, "--label", LABEL, "--max-bytes", str(MAX_BYTES),
                              "--output", str(output / "transfer"), "--timeout-seconds", str(args.timeout)])
        if code != 0:
            raise VerificationError("The TTR1 transfer did not complete; see the transfer directory.")
        report = split_and_verify(output / "transfer" / "payload.bin", output / "regions")
        regions = report["regions"].values()
        print(f"Received {len(report['regions'])} regions ({report['region_bytes']} bytes): "
              f"{sum(item['stable'] for item in regions)} stable across both passes, "
              f"{sum(item['consistent'] for item in regions)} consistent.")
        for label, item in report["regions"].items():
            if item["kind"] == "ext4" or not item["consistent"]:
                print(f"  {label}: {item['ext4_state'] if item['kind'] == 'ext4' else 'raw'}, "
                      f"{'stable' if item['stable'] else 'CHANGED between passes'}")
        print(f"Private report: {output / 'regions' / 'report.json'}")
        return 0
    except (VerificationError, OSError, ValueError) as error:
        print(f"Control-region reception stopped: {error}", file=sys.stderr)
        return 1
    except Exception as error:
        if type(error).__name__ in ("ReportError", "TransferError"):
            print(f"Control-region reception stopped: {error}", file=sys.stderr)
            return 1
        raise
    finally:
        os.umask(previous)


if __name__ == "__main__":
    raise SystemExit(main())
