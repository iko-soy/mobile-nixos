#!/usr/bin/env python3
"""Read-only checks of fixed kernel APIs, without mount/namespace/service changes.

Default ADB mode runs inline Python without creating phone files and saves its
report on this host. Explicit --local mode writes the report on the invoking
Linux aarch64 machine instead.
These are syscall availability/metadata checks, not a systemd or NixOS boot test.
"""

import argparse
import datetime
import errno
import importlib.util
import json
import os
from pathlib import Path
import platform
import shlex
import sys
import tempfile


# ARM64 uses asm-generic syscall numbers. Never issue these on another ABI.
SYSCALLS = {"name_to_handle_at": 264, "statx": 291, "pidfd_send_signal": 424,
            "pidfd_open": 434, "close_range": 436, "openat2": 437}
AT_FDCWD = -100
AT_NO_AUTOMOUNT = 0x800
AT_STATX_DONT_SYNC = 0x4000
STATX_BASIC_STATS = 0x7FF
STATX_MNT_ID = 0x1000
STATX_ATTR_MOUNT_ROOT = 0x2000
O_PATH = 0x200000
O_CLOEXEC = 0x80000


class ProbeError(Exception):
    pass


ctypes = None


def load_ctypes():
    # The ADB host only transports Python source and JSON. Importing ctypes can
    # initialize host libffi callbacks, so defer that dependency to raw probing.
    global ctypes, StatxTimestamp, Statx, FileHandle, OpenHow
    if ctypes is not None:
        return
    import ctypes as ctypes_module
    ctypes = ctypes_module

    class StatxTimestamp(ctypes.Structure):
        _fields_ = [("seconds", ctypes.c_int64), ("nanoseconds", ctypes.c_uint32),
                    ("reserved", ctypes.c_int32)]


    class Statx(ctypes.Structure):
        # The kernel ABI is 256 bytes; mount_id occupies originally reserved space.
        _fields_ = [
            ("mask", ctypes.c_uint32), ("block_size", ctypes.c_uint32),
            ("attributes", ctypes.c_uint64), ("links", ctypes.c_uint32),
            ("uid", ctypes.c_uint32), ("gid", ctypes.c_uint32),
            ("mode", ctypes.c_uint16), ("spare0", ctypes.c_uint16),
            ("inode", ctypes.c_uint64), ("size", ctypes.c_uint64),
            ("blocks", ctypes.c_uint64), ("attributes_mask", ctypes.c_uint64),
            ("atime", StatxTimestamp), ("btime", StatxTimestamp),
            ("ctime", StatxTimestamp), ("mtime", StatxTimestamp),
            ("rdev_major", ctypes.c_uint32), ("rdev_minor", ctypes.c_uint32),
            ("dev_major", ctypes.c_uint32), ("dev_minor", ctypes.c_uint32),
            ("mount_id", ctypes.c_uint64), ("spare", ctypes.c_uint64 * 13),
        ]


    class FileHandle(ctypes.Structure):
        _fields_ = [("handle_bytes", ctypes.c_uint32), ("handle_type", ctypes.c_int32),
                    ("handle", ctypes.c_ubyte * 128)]


    class OpenHow(ctypes.Structure):
        _fields_ = [("flags", ctypes.c_uint64), ("mode", ctypes.c_uint64),
                    ("resolve", ctypes.c_uint64)]


def check_architecture():
    if (platform.system() != "Linux" or platform.machine() != "aarch64"
            or sys.byteorder != "little"):
        raise ProbeError("Raw probes require Linux aarch64, little endian, with 64-bit pointers.")
    load_ctypes()
    if ctypes.sizeof(ctypes.c_void_p) != 8:
        raise ProbeError("Raw probes require Linux aarch64, little endian, with 64-bit pointers.")
    if (ctypes.sizeof(Statx) != 256 or Statx.attributes_mask.offset != 56
            or Statx.mount_id.offset != 144 or ctypes.sizeof(OpenHow) != 24
            or ctypes.sizeof(FileHandle) != 136):
        raise ProbeError("Unexpected ctypes ABI layout; no raw syscall was issued.")


def process_policy():
    # Read only selected fields; do not retain the raw status or its identifiers.
    selected = {"Seccomp": None, "NoNewPrivs": None}
    try:
        with open("/proc/self/status", encoding="ascii") as stream:
            data = stream.read(16385)
        if len(data) > 16384:
            return {"status": "unavailable", "fields": selected}
        for line in data.splitlines():
            key, separator, value = line.partition(":")
            if separator and key in selected and value.strip().isdigit():
                selected[key] = int(value.strip())
        return {"status": "read", "fields": selected}
    except (OSError, UnicodeError, ValueError):
        return {"status": "unavailable", "fields": selected}


def syscall(libc, name, *arguments):
    ctypes.set_errno(0)
    result = libc.syscall(ctypes.c_long(SYSCALLS[name]), *arguments)
    error = ctypes.get_errno() if result == -1 else 0
    return result, error


def result_record(result, error):
    if result >= 0:
        classification = "available"
    elif error == errno.ENOSYS:
        classification = "unavailable-or-filtered"
    elif error in (errno.EACCES, errno.EPERM):
        classification = "permission-or-policy-denied"
    elif error == errno.EOPNOTSUPP:
        classification = "operation-not-supported"
    elif error == errno.EINVAL:
        classification = "invalid-argument"
    else:
        classification = "other-error"
    return {"status": "success" if result >= 0 else "error", "errno": error,
            "errno_name": errno.errorcode.get(error, "UNKNOWN") if error else None,
            "classification": classification}


def probe_kernel_apis():
    check_architecture()
    libc = ctypes.CDLL(None, use_errno=True)
    libc.syscall.restype = ctypes.c_long
    # syscall() is variadic; every argument below has an explicit ctypes type.
    libc.syscall.argtypes = [ctypes.c_long]
    report = {
        "format": 1, "probe_completed": False,
        "abi": "linux-aarch64-little-endian-64",
        "process_policy": process_policy(),
        "meaning": "Availability and metadata only; not a systemd or NixOS boot compatibility result.",
        "probes": {},
    }
    probes = report["probes"]
    probes["statx"] = {}
    for path in ("/", "/proc", "/sys"):
        metadata = Statx()
        result, error = syscall(
            libc, "statx", ctypes.c_int(AT_FDCWD), ctypes.c_char_p(path.encode()),
            ctypes.c_uint(AT_NO_AUTOMOUNT | AT_STATX_DONT_SYNC),
            ctypes.c_uint(STATX_BASIC_STATS | STATX_MNT_ID), ctypes.byref(metadata),
        )
        record = result_record(result, error)
        if result == 0:
            record["metadata"] = {
                "returned_mask": metadata.mask,
                "attributes_mask": metadata.attributes_mask,
                "basic_stats_complete": metadata.mask & STATX_BASIC_STATS == STATX_BASIC_STATS,
                "mount_id_returned": bool(metadata.mask & STATX_MNT_ID),
                "mount_root_attribute_supported": bool(metadata.attributes_mask & STATX_ATTR_MOUNT_ROOT),
                "is_mount_root": (bool(metadata.attributes & STATX_ATTR_MOUNT_ROOT)
                                  if metadata.attributes_mask & STATX_ATTR_MOUNT_ROOT else None),
            }
        probes["statx"][path] = record

    # This obtains a reference to this probe process only; it never targets PID1.
    descriptor, error = syscall(libc, "pidfd_open", ctypes.c_int(os.getpid()), ctypes.c_uint(0))
    probes["pidfd_open"] = result_record(descriptor, error)
    if descriptor >= 0:
        try:
            # Signal 0 checks existence/permission; it does not deliver a signal.
            result, error = syscall(libc, "pidfd_send_signal", ctypes.c_int(descriptor),
                                    ctypes.c_int(0), ctypes.c_void_p(), ctypes.c_uint(0))
            probes["pidfd_send_signal_0"] = result_record(result, error)
        finally:
            os.close(descriptor)
    else:
        probes["pidfd_send_signal_0"] = {"status": "not-run", "reason": "pidfd_open failed"}

    # Reversed bounds must fail with EINVAL before closing any descriptor.
    result, error = syscall(libc, "close_range", ctypes.c_uint(1), ctypes.c_uint(0), ctypes.c_uint(0))
    probes["close_range_invalid_range"] = result_record(result, error)
    probes["close_range_invalid_range"]["expected_errno"] = "EINVAL"
    probes["close_range_invalid_range"]["entrypoint_recognized"] = result == -1 and error == errno.EINVAL

    handle = FileHandle()
    handle.handle_bytes = 128
    mount_id = ctypes.c_int()
    result, error = syscall(libc, "name_to_handle_at", ctypes.c_int(AT_FDCWD), ctypes.c_char_p(b"/"),
                            ctypes.byref(handle), ctypes.byref(mount_id), ctypes.c_int(0))
    # Never emit opaque file handles, mount IDs, inode numbers or process IDs.
    probes["name_to_handle_at"] = result_record(result, error)

    how = OpenHow(flags=O_PATH | O_CLOEXEC, mode=0, resolve=0)
    descriptor, error = syscall(libc, "openat2", ctypes.c_int(AT_FDCWD), ctypes.c_char_p(b"/"),
                                ctypes.byref(how), ctypes.c_size_t(ctypes.sizeof(how)))
    probes["openat2"] = result_record(descriptor, error)
    if descriptor >= 0:
        os.close(descriptor)
    report["probe_completed"] = True
    return report


def load_inventory():
    spec = importlib.util.spec_from_file_location(
        "titan_inventory", Path(__file__).with_name("collect-inventory.py"))
    inventory = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(inventory)
    return inventory


def prepare_output(inventory, requested):
    if requested is not None:
        return inventory.prepare_output(requested)
    state = Path(os.environ.get("XDG_STATE_HOME", Path.home() / ".local/state"))
    base = (state / "mobile-nixos/titan-kernel-apis").expanduser().resolve()
    if inventory.inside_git_checkout(base):
        raise ProbeError("Probe output must be outside every Git checkout.")
    base.mkdir(mode=0o700, parents=True, exist_ok=True)
    prefix = datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%dT%H%M%SZ-")
    return Path(tempfile.mkdtemp(prefix=prefix, dir=base))


def validate_report(report):
    # Avoid treating any arbitrary successful remote JSON as a completed probe.
    expected = {"statx", "pidfd_open", "pidfd_send_signal_0", "close_range_invalid_range",
                "name_to_handle_at", "openat2"}
    if (not isinstance(report, dict) or report.get("format") != 1
            or report.get("probe_completed") is not True
            or report.get("abi") != "linux-aarch64-little-endian-64"
            or not isinstance(report.get("probes"), dict)
            or set(report["probes"]) != expected
            or not isinstance(report["probes"]["statx"], dict)
            or set(report["probes"]["statx"]) != {"/", "/proc", "/sys"}):
        raise ProbeError("Remote probe report is incomplete or malformed.")
    records = [*report["probes"]["statx"].values(),
               *(report["probes"][name] for name in expected - {"statx"})]
    if any(not isinstance(record, dict) or record.get("status") not in {"success", "error", "not-run"}
           for record in records):
        raise ProbeError("Remote probe records are malformed.")
    return report


def summary(report):
    records = report["probes"]["statx"].values()
    complete_metadata = sum(
        record.get("status") == "success" and isinstance(record.get("metadata"), dict)
        and all(record["metadata"].get(field) is True for field in
                ("basic_stats_complete", "mount_id_returned", "mount_root_attribute_supported"))
        for record in records)
    labels = {"available", "unavailable-or-filtered", "permission-or-policy-denied",
              "operation-not-supported", "invalid-argument", "other-error"}
    lines = [f"statx: {complete_metadata}/3 paths returned basic stats, mount ID and mount-root attribute support"]
    for name in ("pidfd_open", "pidfd_send_signal_0", "name_to_handle_at", "openat2"):
        record = report["probes"][name]
        label = record.get("classification")
        lines.append(f"{name}: {label if label in labels else 'not-run or unknown'}")
    recognized = report["probes"]["close_range_invalid_range"].get("entrypoint_recognized") is True
    lines.append(f"close_range: {'recognized invalid-range check' if recognized else 'not established'}")
    lines.append("ENOSYS can also come from seccomp; inspect process_policy and the private report.")
    lines.append("These checks do not establish systemd or NixOS boot compatibility.")
    return "\n".join(lines)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    transport = parser.add_mutually_exclusive_group()
    transport.add_argument("--local", action="store_true", help="probe this Linux aarch64 machine and write the report here")
    transport.add_argument("--serial", help="ADB selector when multiple transports exist")
    transport.add_argument("--probe-stdout", action="store_true", help=argparse.SUPPRESS)
    parser.add_argument("--adb", default="adb", help="host ADB executable")
    parser.add_argument("--output", help="new private output directory outside Git")
    parser.add_argument("--timeout", type=int, default=30, help="seconds per ADB command")
    args = parser.parse_args(argv)
    if args.timeout <= 0:
        parser.error("--timeout must be positive")
    try:
        if args.probe_stdout:
            # ADB sends this source via python3 -B -c: no script is installed.
            print(json.dumps(probe_kernel_apis(), sort_keys=True))
            return 0
        inventory = load_inventory()
        if args.local:
            report = probe_kernel_apis()
        else:
            stdout, _, code, timed_out = inventory.run_command([args.adb, "devices", "-l"], args.timeout)
            if code != 0 or timed_out:
                raise ProbeError("ADB transport enumeration failed.")
            serial = inventory.select_usb_device(stdout.decode(), args.serial)
            inventory.check_adb_transport(args.adb, serial, args.timeout)
            command = "python3 -B -c " + shlex.quote(Path(__file__).read_text()) + " --probe-stdout"
            stdout, stderr, code, timed_out = inventory.run_probe(args.adb, serial, command, args.timeout)
            if code != 0 or timed_out or stderr:
                raise ProbeError("Remote Python probe failed; no compatibility result was accepted.")
            if len(stdout) > 65536:
                raise ProbeError("Remote probe report exceeded its expected size.")
            report = json.loads(stdout)
        validate_report(report)
        os.umask(0o077)
        output = prepare_output(inventory, args.output)
        report["collected_at_utc"] = datetime.datetime.now(datetime.timezone.utc).isoformat()
        report["transport"] = "local" if args.local else "adb"
        inventory.write_private(output / "report.json", (json.dumps(report, indent=2) + "\n").encode())
        print(summary(report))
        print(f"Private probe report: {output / 'report.json'}")
        return 0
    except (ProbeError, OSError, ValueError, UnicodeError) as error:
        print(f"Kernel API probe stopped: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
