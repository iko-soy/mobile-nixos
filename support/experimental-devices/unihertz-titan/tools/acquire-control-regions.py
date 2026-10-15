#!/usr/bin/env python3
"""Preserve the twelve unmounted control and calibration regions over normal-mode ADB.

Only twelve named GPT partitions are read: boot_para, para, expdb, frp,
metadata, seccfg, sec1, proinfo, nvram, cache, otp and flashinfo. No block
flags, mounts, boot mode or phone files are changed, and RPMB is not opened.
Raw writers such as modem or NVRAM services may still run in normal mode:
repeat agreement shows stability during the reads, not consistency, an atomic
snapshot or a recovery validation. The three process mount views do not
establish global quiescence.
"""

import argparse
import datetime
import importlib.util
import json
import os
from pathlib import Path
import re
import shlex
import sys


SPEC = importlib.util.spec_from_file_location(
    "titan_control_os_primitives", Path(__file__).with_name("acquire-os-partitions.py"))
os_partitions = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(os_partitions)
bootloaders = os_partitions.bootloaders
transport = os_partitions.transport
AcquisitionError = os_partitions.AcquisitionError
PublicationRetained = os_partitions.PublicationRetained
require = os_partitions.require
parsed_json = os_partitions.parsed_json
SparseSink = os_partitions.SparseSink
PrivateOutput = os_partitions.PrivateOutput
METADATA_LIMIT = os_partitions.METADATA_LIMIT

# Measured GPT positions of the regions that no host mount covered on
# 2026-10-14. The names are an acquisition allowlist; labels do not establish
# formats, and absence of a mount does not exclude raw writers.
TARGETS = {
    "boot_para": {"number": 1, "start": 64, "sectors": 2048, "bytes": 1048576},
    "para": {"number": 3, "start": 67648, "sectors": 1024, "bytes": 524288},
    "expdb": {"number": 4, "start": 68672, "sectors": 40960, "bytes": 20971520},
    "frp": {"number": 5, "start": 109632, "sectors": 2048, "bytes": 1048576},
    "metadata": {"number": 8, "start": 308288, "sectors": 65536, "bytes": 33554432},
    "seccfg": {"number": 11, "start": 409600, "sectors": 16384, "bytes": 8388608},
    "sec1": {"number": 12, "start": 425984, "sectors": 4096, "bytes": 2097152},
    "proinfo": {"number": 13, "start": 430080, "sectors": 6144, "bytes": 3145728},
    "nvram": {"number": 25, "start": 829440, "sectors": 131072, "bytes": 67108864},
    "cache": {"number": 35, "start": 9142272, "sectors": 884736, "bytes": 452984832},
    "otp": {"number": 37, "start": 244164544, "sectors": 88064, "bytes": 45088768},
    "flashinfo": {"number": 38, "start": 244252608, "sectors": 32768, "bytes": 16777216},
}
TOTAL_BYTES = 652738560


# Compose the reviewed OS guards rather than copying or relaxing them. Its
# TARGETS remain vendor/system: base_snapshot continues checking the complete
# map, the read-only vendor mounts and the dynamically identified Android view.
REMOTE_CODE = os_partitions.REMOTE_CODE + "\nbase_snapshot = snapshot\n" + (
    "CONTROL_TARGETS = " + repr(TARGETS) + "\n"
) + r'''
def snapshot(permission_only=False, descriptors=None):
    base, opened = base_snapshot(permission_only, descriptors)
    try:
        parent = base["disk"]["sysfs"]
        records, identities, expected_sizes = {}, {}, {}
        for label, expected in CONTROL_TARGETS.items():
            item = base["partitions"][expected["number"] - 1]
            require(item["name"] == label and all(item[key] == expected[key]
                for key in ("number", "start", "sectors")))
            name = "mmcblk0p" + str(expected["number"])
            path, directory = "/dev/" + name, "/sys/class/block/" + name
            require(os.path.realpath("/dev/disk/by-partlabel/" + label) == path
                    and os.path.realpath(directory) == parent + "/" + name)
            identities[name] = node(name, item["device_number"])
            expected_sizes[name] = expected["bytes"]
            empty_directory(directory + "/holders")
            empty_directory(directory + "/slaves", optional=True)
            records[label] = {"node": path, "bytes": expected["bytes"], **item}
        devices = {item["device_number"] for item in records.values()}
        require(len(devices) == 12 and not devices.intersection({base["disk"]["device_number"],
            base["targets"]["vendor"]["device_number"], base["targets"]["system"]["device_number"]}))
        forbidden = devices | {base["disk"]["device_number"], base["targets"]["system"]["device_number"]}
        vendor_device = base["targets"]["vendor"]["device_number"]
        mounts = {}
        for scope, path in (("self", "/proc/self/mountinfo"), ("pid1", "/proc/1/mountinfo")):
            mounts[scope] = mount_rows(path, vendor_device, forbidden,
                optional=permission_only and scope == "pid1")
        android, mounts["android"], _ = android_view(permission_only, vendor_device, forbidden,
            None if permission_only else opened)
        require(mounts == base["vendor_mounts"] and android == base["android_init"])
        permissions = {name: os.access("/dev/" + name, os.R_OK) for name in identities}
        if not permission_only:
            require(all(permissions.values()) and all(value is not None for value in mounts.values()))
            for name, identity in identities.items():
                if descriptors is None:
                    opened[name] = os.open("/dev/" + name,
                        os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW | os.O_CLOEXEC)
                metadata = os.fstat(opened[name])
                require(stat.S_ISBLK(metadata.st_mode)
                        and (metadata.st_dev, metadata.st_ino, metadata.st_rdev) == identity)
                require(ioctl_number(opened[name], 0x80081272, 8) == expected_sizes[name]
                        and ioctl_number(opened[name], 0x1268, 4) == 512
                        and ioctl_number(opened[name], 0x127b, 4) == 512)
        return {"format": "titan-control-region-guard-v1", "base": base, "targets": records,
            "permissions": permissions, "checks": {
                "self_mounts": mounts["self"] is not None, "pid1_mounts": mounts["pid1"] is not None,
                "android_mounts": mounts["android"] is not None, "holders_and_slaves_empty": True,
                "ioctl_geometry": not permission_only}}, opened
    except BaseException:
        if descriptors is None:
            for fd in opened.values(): os.close(fd)
        raise

def execute(mode, label):
    require(mode in ("permissions", "probe", "read", "hash"))
    require(label in CONTROL_TARGETS if mode in ("read", "hash") else label == "")
    before, descriptors = snapshot(mode == "permissions")
    try:
        if mode in ("permissions", "probe"):
            sys.stdout.buffer.write(json.dumps(before, sort_keys=True).encode("ascii") + b"\n")
        else:
            expected = CONTROL_TARGETS[label]
            fd = descriptors["mmcblk0p" + str(expected["number"])]
            require(os.lseek(fd, 0, os.SEEK_CUR) == 0)
            remaining, digest = expected["bytes"], hashlib.sha256()
            while remaining:
                chunk = os.read(fd, min(CHUNK_BYTES, remaining))
                require(chunk and len(chunk) <= remaining)
                remaining -= len(chunk)
                if mode == "read": sys.stdout.buffer.write(chunk)
                else: digest.update(chunk)
            after, _ = snapshot(False, descriptors)
            require(before == after)
            if mode == "hash":
                sys.stdout.buffer.write((json.dumps({"label": label, "bytes": expected["bytes"],
                    "sha256": digest.hexdigest()}, sort_keys=True) + "\n").encode("ascii"))
        sys.stdout.buffer.flush()
    finally:
        for fd in descriptors.values(): os.close(fd)
'''


def target_bytes(label):
    return TARGETS[label]["bytes"]


def remote_script(mode, label=""):
    if mode not in ("permissions", "probe", "read", "hash") or (
            label not in TARGETS if mode in ("read", "hash") else label != ""):
        raise ValueError("Only the fixed set of twelve control regions is supported.")
    program = REMOTE_CODE + (
        f"\ntry:\n    execute({mode!r}, {label!r})\n"
        "except BaseException:\n    sys.stderr.write('Fixed control-region guard or read refused.\\n')\n"
        "    sys.exit(23)\n")
    return "/usr/bin/python3 -I -S -B -c " + shlex.quote(program)


def validate_evidence(data, permission_only=False):
    report = parsed_json(data)
    try:
        require(set(report) == {"format", "base", "targets", "permissions", "checks"}
                and report["format"] == "titan-control-region-guard-v1")
        base = os_partitions.validate_evidence(
            (json.dumps(report["base"], sort_keys=True) + "\n").encode("ascii"), permission_only)
        require(set(report["targets"]) == set(TARGETS))
        expected_nodes = set()
        for label, expected in TARGETS.items():
            item = base["partitions"][expected["number"] - 1]
            require(item["name"] == label and all(item[key] == expected[key]
                for key in ("number", "start", "sectors")))
            name = "mmcblk0p" + str(expected["number"])
            expected_nodes.add(name)
            require(report["targets"][label] == {"node": "/dev/" + name, "bytes": expected["bytes"], **item})
        require(len({report["targets"][label]["device_number"] for label in TARGETS}) == len(TARGETS))
        require(set(report["permissions"]) == expected_nodes
                and all(type(value) is bool for value in report["permissions"].values()))
        checks = report["checks"]
        require(set(checks) == {"self_mounts", "pid1_mounts", "android_mounts", "holders_and_slaves_empty",
                                "ioctl_geometry"}
                and all(type(value) is bool for value in checks.values()))
        require(checks["self_mounts"] and checks["holders_and_slaves_empty"]
                and checks["ioctl_geometry"] is (not permission_only))
        for scope in ("self", "pid1", "android"):
            require(checks[scope + "_mounts"] is base["checks"][scope + "_mounts"])
        if not permission_only:
            require(all(checks.values()) and all(report["permissions"].values()),
                    "Control-region read permissions or process mount-view checks did not pass.")
    except (KeyError, TypeError, AttributeError) as error:
        raise AcquisitionError("Control-region metadata has an unexpected shape.") from error
    return report


def probe(remote, permission_only=False):
    data, count, _ = remote.run(remote_script("permissions" if permission_only else "probe"), METADATA_LIMIT)
    require(count == len(data), "Metadata byte count did not match.")
    return validate_evidence(data, permission_only)


def progress(message):
    print(message, file=sys.stderr, flush=True)


def acquire(remote, requested):
    baseline = probe(remote)
    sizes = {label: target_bytes(label) for label in TARGETS}
    output = PrivateOutput(requested, size_mapping=sizes)
    try:
        report = {"format": "titan-private-control-regions-v1", "status": "complete",
            "created_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "transport": "adb-shell-v2-no-pty-framed-status", "kernel_map": baseline,
            "scope": ("fixed twelve unmounted control and calibration GPT partitions in normal mode; "
                      "not a consistent copy, not userdata or the mounted calibration filesystems, no RPMB"),
            "helper_sources": transport.source_digests("acquire-control-regions.py", "acquire-os-partitions.py",
                                                       "acquire-bootloaders.py", "acquire-partitions.py",
                                                       "collect-inventory.py"),
            "mount_view_scope": ["acquisition process", "PID1", "identified Android init"],
            "bytes_preserved": sum(sizes.values()), "partitions": {},
            "validation": {"atomic_snapshot": False, "global_quiescence": False,
                "raw_writers_excluded": False, "authentication_performed": False,
                "restoration_tested": False, "device_changes_performed": False}}
        for label, expected in sizes.items():
            require(probe(remote) == baseline, "Kernel map or read safety changed before acquisition.")
            pending = label + ".img.part"
            progress(f"{label}: transferring {expected} bytes to private storage")
            with os.fdopen(output.create(pending), "wb") as stream:
                sink = SparseSink(stream, expected, output.budget)
                _, count, digest = remote.run(remote_script("read", label), expected, sink=sink)
                require(count == expected, "Control-region transfer byte count did not match the fixed profile.")
                sink.finish()
            progress(f"{label}: verifying saved logical bytes")
            require(output.saved_hash(pending, expected) == digest,
                    "Saved-file SHA-256 did not match the transfer.")
            require(probe(remote) == baseline, "Kernel map or read safety changed after acquisition.")
            progress(f"{label}: independent full phone reread for SHA-256")
            data, count, _ = remote.run(remote_script("hash", label), 256)
            require(count == len(data), "Phone digest byte count did not match.")
            repeated = parsed_json(data)
            require(repeated == {"label": label, "bytes": expected, "sha256": digest}
                    and re.fullmatch(r"[0-9a-f]{64}", digest) is not None,
                    "Independent bounded phone SHA-256 did not match; a writer may have changed the region.")
            require(probe(remote) == baseline, "Kernel map or read safety changed after the repeat read.")
            report["partitions"][label] = {"file": label + ".img", "bytes": expected, "sha256": digest,
                "transfer_sha256": digest, "readback_sha256": digest, "phone_repeat_sha256": digest,
                "zero_bytes_skipped": sink.zero_bytes,
                "storage": "raw logical image; zero-only chunks skipped by seeking, allocation left to the filesystem",
                "geometry": baseline["targets"][label]}
        require(probe(remote) == baseline, "Final kernel map or read safety changed.")
        progress("All twelve regions verified; publishing the private set and manifest")
        output.manifest(report)
        output.publish()
        return output.path, report
    finally:
        output.close()


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--adb", default="adb", help="host ADB executable")
    parser.add_argument("--serial", help="select one already-authorized USB ADB transport")
    parser.add_argument("--output", required=True, help="new private directory outside Git, jj and /nix; parent must exist")
    parser.add_argument("--timeout", type=int, default=1800, help="seconds per bounded remote operation (default: 1800)")
    parser.add_argument("--sudo", action="store_true", help="prompt secretly in this local terminal only if read access is missing")
    args = parser.parse_args(argv)
    if not 1 <= args.timeout <= 7200:
        parser.error("--timeout must be between 1 and 7200 seconds")
    remote = None
    previous_umask = os.umask(0o077)
    try:
        candidate = bootloaders.private_path(args.output)
        require(not os.path.lexists(candidate), "Output must be a new private directory.")
        devices, _, _ = transport.run_bounded([args.adb, "devices", "-l"], 65536, args.timeout)
        serial = transport.inventory.select_usb_device(devices.decode("ascii"), args.serial)
        remote = transport.Remote(args.adb, serial, args.timeout)
        remote.check_protocol()
        # The complete unprivileged metadata probe establishes this phone's map
        # and mount views before any credential is requested.
        permission = probe(remote, permission_only=True)
        missing = (not all(permission["permissions"].values()) or not all(permission["base"]["permissions"].values())
                   or not permission["checks"]["pid1_mounts"] or not permission["checks"]["android_mounts"])
        if missing:
            require(args.sudo, "Block or process mount-view read access is missing; rerun with --sudo in a local terminal.")
            remote.password = transport.prompt_password()
        output, report = acquire(remote, candidate)
        print(f"Verified twelve control/calibration regions: {report['bytes_preserved']} private logical bytes with saved-file and repeat phone SHA-256 agreement. Output: {output}")
        print("Normal-mode reads are not a consistent copy: raw writers were not excluded, and agreement is not atomic or a restoration test.")
        return 0
    except PublicationRetained as error:
        print(f"Control-region acquisition stopped after publication: {error}", file=sys.stderr)
        print("The published files were kept; this run is not reported as complete.", file=sys.stderr)
        return 1
    except AcquisitionError as error:
        print(f"Control-region acquisition stopped: {error}", file=sys.stderr)
        print("Any retained .part files are incomplete private evidence; no completed result is reported.", file=sys.stderr)
        return 1
    except (ValueError, OSError, UnicodeError, EOFError, KeyboardInterrupt):
        print("Control-region acquisition stopped during a local or transport operation; no completed result is reported.", file=sys.stderr)
        print("Any retained .part files are incomplete private evidence.", file=sys.stderr)
        return 1
    finally:
        if remote is not None: remote.password = None
        os.umask(previous_umask)


if __name__ == "__main__":
    raise SystemExit(main())
