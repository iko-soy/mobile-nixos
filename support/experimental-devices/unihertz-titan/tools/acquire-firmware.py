#!/usr/bin/env python3
"""Preserve a fixed firmware set and both eMMC boot areas over normal-mode ADB.

Only fourteen named GPT partitions and boot0/boot1 are read. No block flags,
mounts, boot mode or phone files are changed. Labels do not prove immutability:
repeat agreement is neither an atomic snapshot nor a recovery validation. The
three process mount views do not establish global quiescence.
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
    "titan_firmware_os_primitives", Path(__file__).with_name("acquire-os-partitions.py"))
os_partitions = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(os_partitions)
bootloaders = os_partitions.bootloaders
transport = os_partitions.transport
AcquisitionError = os_partitions.AcquisitionError
require = os_partitions.require
parsed_json = os_partitions.parsed_json
SparseSink = os_partitions.SparseSink
PrivateOutput = os_partitions.PrivateOutput
METADATA_LIMIT = os_partitions.METADATA_LIMIT
CHUNK_BYTES = os_partitions.CHUNK_BYTES

# Measured GPT positions; these names are an acquisition allowlist, not an
# assertion that firmware cannot write the regions while Android is running.
GPT_TARGETS = {
    "md1img": {"number": 14, "start": 436224, "sectors": 204800, "bytes": 104857600},
    "spmfw": {"number": 15, "start": 641024, "sectors": 2048, "bytes": 1048576},
    "scp1": {"number": 16, "start": 643072, "sectors": 12288, "bytes": 6291456},
    "scp2": {"number": 17, "start": 655360, "sectors": 12288, "bytes": 6291456},
    "sspm_1": {"number": 18, "start": 667648, "sectors": 2048, "bytes": 1048576},
    "sspm_2": {"number": 19, "start": 669696, "sectors": 2048, "bytes": 1048576},
    "cam_vpu1": {"number": 20, "start": 671744, "sectors": 30720, "bytes": 15728640},
    "cam_vpu2": {"number": 21, "start": 702464, "sectors": 30720, "bytes": 15728640},
    "cam_vpu3": {"number": 22, "start": 733184, "sectors": 30720, "bytes": 15728640},
    "gz1": {"number": 23, "start": 763904, "sectors": 32768, "bytes": 16777216},
    "gz2": {"number": 24, "start": 796672, "sectors": 32768, "bytes": 16777216},
    "logo": {"number": 29, "start": 1030144, "sectors": 16384, "bytes": 8388608},
    "tee1": {"number": 31, "start": 1062912, "sectors": 10240, "bytes": 5242880},
    "tee2": {"number": 32, "start": 1073152, "sectors": 24576, "bytes": 12582912},
}
BOOT_AREAS = {
    "boot0": {"name": "mmcblk0boot0", "device_number": "179:32", "sectors": 8192, "bytes": 4194304},
    "boot1": {"name": "mmcblk0boot1", "device_number": "179:64", "sectors": 8192, "bytes": 4194304},
}
TARGETS = {**GPT_TARGETS, **BOOT_AREAS}
TOTAL_BYTES = 235929600


# Compose the reviewed OS guards rather than copying or relaxing them. Its
# TARGETS remains vendor/system: base_snapshot continues checking the complete
# map, the read-only vendor mounts and the dynamically identified Android view.
REMOTE_CODE = os_partitions.REMOTE_CODE + "\nbase_snapshot = snapshot\n" + (
    "FIRMWARE_TARGETS = " + repr(GPT_TARGETS) + "\nBOOT_AREAS = " + repr(BOOT_AREAS) + "\n"
) + r'''
FIRMWARE_ALL = {**FIRMWARE_TARGETS, **BOOT_AREAS}

def snapshot(permission_only=False, descriptors=None):
    base, opened = base_snapshot(permission_only, descriptors)
    try:
        parent = base["disk"]["sysfs"]
        records, identities, expected_sizes = {}, {}, {}
        for label, expected in FIRMWARE_TARGETS.items():
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
        for label, expected in BOOT_AREAS.items():
            name = expected["name"]
            path, directory = "/dev/" + name, "/sys/class/block/" + name
            require(os.path.realpath(directory) == parent + "/" + name
                    and text(directory + "/dev") == expected["device_number"]
                    and text(directory + "/size") == str(expected["sectors"])
                    and text(directory + "/queue/logical_block_size") == "512"
                    and text(directory + "/queue/physical_block_size") == "512"
                    and text(directory + "/ro") == "1" and text(directory + "/force_ro") == "1")
            identities[name] = node(name, expected["device_number"])
            expected_sizes[name] = expected["bytes"]
            empty_directory(directory + "/holders")
            empty_directory(directory + "/slaves")
            records[label] = {"node": path, **expected, "sysfs": parent + "/" + name,
                "parent": parent, "logical_sector_bytes": 512, "physical_sector_bytes": 512,
                "ro": 1, "force_ro": 1}
        devices = {item["device_number"] for item in records.values()}
        require(len(devices) == 16 and not devices.intersection({base["disk"]["device_number"],
            base["targets"]["vendor"]["device_number"], base["targets"]["system"]["device_number"]}))
        require(not {item["device_number"] for item in BOOT_AREAS.values()}.intersection(
            item["device_number"] for item in base["partitions"]))
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
                if name in ("mmcblk0boot0", "mmcblk0boot1"):
                    # BLKROGET only. Neither force_ro nor block flags are set.
                    require(ioctl_number(opened[name], 0x125e, 4) == 1)
        return {"format": "titan-firmware-guard-v1", "base": base, "targets": records,
            "permissions": permissions, "checks": {
                "self_mounts": mounts["self"] is not None, "pid1_mounts": mounts["pid1"] is not None,
                "android_mounts": mounts["android"] is not None, "holders_and_slaves_empty": True,
                "ioctl_geometry": not permission_only, "boot_area_read_only": True}}, opened
    except BaseException:
        if descriptors is None:
            for fd in opened.values(): os.close(fd)
        raise

def execute(mode, label):
    require(mode in ("permissions", "probe", "read", "hash"))
    require(label in FIRMWARE_ALL if mode in ("read", "hash") else label == "")
    before, descriptors = snapshot(mode == "permissions")
    try:
        if mode in ("permissions", "probe"):
            sys.stdout.buffer.write(json.dumps(before, sort_keys=True).encode("ascii") + b"\n")
        else:
            expected = FIRMWARE_ALL[label]
            name = expected["name"] if label in BOOT_AREAS else "mmcblk0p" + str(expected["number"])
            fd = descriptors[name]
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
        raise ValueError("Only the fixed firmware set and eMMC boot areas are supported.")
    program = REMOTE_CODE + (
        f"\ntry:\n    execute({mode!r}, {label!r})\n"
        "except BaseException:\n    sys.stderr.write('Fixed firmware guard or read refused.\\n')\n"
        "    sys.exit(23)\n")
    return "/usr/bin/python3 -I -S -B -c " + shlex.quote(program)


def validate_evidence(data, permission_only=False):
    report = parsed_json(data)
    try:
        require(set(report) == {"format", "base", "targets", "permissions", "checks"}
                and report["format"] == "titan-firmware-guard-v1")
        base = os_partitions.validate_evidence(
            (json.dumps(report["base"], sort_keys=True) + "\n").encode("ascii"), permission_only)
        require(set(report["targets"]) == set(TARGETS))
        expected_nodes = set()
        for label, expected in GPT_TARGETS.items():
            item = base["partitions"][expected["number"] - 1]
            require(item["name"] == label and all(item[key] == expected[key]
                for key in ("number", "start", "sectors")))
            name = "mmcblk0p" + str(expected["number"])
            expected_nodes.add(name)
            require(report["targets"][label] == {"node": "/dev/" + name, "bytes": expected["bytes"], **item})
        parent = base["disk"]["sysfs"]
        known_devices = {item["device_number"] for item in base["partitions"]} | {base["disk"]["device_number"]}
        for label, expected in BOOT_AREAS.items():
            name = expected["name"]
            expected_nodes.add(name)
            require(expected["device_number"] not in known_devices)
            known_devices.add(expected["device_number"])
            item = report["targets"][label]
            require(all(type(item[key]) is int for key in (
                "sectors", "bytes", "logical_sector_bytes", "physical_sector_bytes", "ro", "force_ro")))
            require(item == {"node": "/dev/" + name, **expected, "sysfs": parent + "/" + name,
                "parent": parent, "logical_sector_bytes": 512, "physical_sector_bytes": 512,
                "ro": 1, "force_ro": 1})
        require(set(report["permissions"]) == expected_nodes
                and all(type(value) is bool for value in report["permissions"].values()))
        checks = report["checks"]
        require(set(checks) == {"self_mounts", "pid1_mounts", "android_mounts", "holders_and_slaves_empty",
                               "ioctl_geometry", "boot_area_read_only"}
                and all(type(value) is bool for value in checks.values()))
        require(checks["self_mounts"] and checks["holders_and_slaves_empty"] and checks["boot_area_read_only"]
                and checks["ioctl_geometry"] is (not permission_only))
        for scope in ("self", "pid1", "android"):
            require(checks[scope + "_mounts"] is base["checks"][scope + "_mounts"])
        if not permission_only:
            require(all(checks.values()) and all(report["permissions"].values()),
                    "Firmware read permissions or process mount-view checks did not pass.")
    except (KeyError, TypeError, AttributeError) as error:
        raise AcquisitionError("Firmware metadata has an unexpected shape.") from error
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
        report = {"format": "titan-private-firmware-v1", "status": "complete",
            "created_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "transport": "adb-shell-v2-no-pty-framed-status", "kernel_map": baseline,
            "scope": "fixed fourteen firmware GPT partitions and two eMMC boot areas; no calibration, control or RPMB",
            "mount_view_scope": ["acquisition process", "PID1", "identified Android init"],
            "bytes_preserved": sum(sizes.values()), "partitions": {},
            "validation": {"atomic_snapshot": False, "global_quiescence": False,
                "firmware_immutability_proven": False, "authentication_performed": False,
                "restoration_tested": False, "device_changes_performed": False}}
        for label, expected in sizes.items():
            require(probe(remote) == baseline, "Kernel map or read safety changed before acquisition.")
            pending = label + ".img.part"
            progress(f"{label}: transferring {expected} bytes to private storage")
            with os.fdopen(output.create(pending), "wb") as stream:
                sink = SparseSink(stream, expected, output.budget)
                _, count, digest = remote.run(remote_script("read", label), expected, sink=sink)
                require(count == expected, "Firmware transfer byte count did not match the fixed profile.")
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
                    "Independent bounded phone SHA-256 did not match.")
            require(probe(remote) == baseline, "Kernel map or read safety changed after the repeat read.")
            report["partitions"][label] = {"file": label + ".img", "bytes": expected, "sha256": digest,
                "transfer_sha256": digest, "readback_sha256": digest, "phone_repeat_sha256": digest,
                "zero_bytes_skipped": sink.zero_bytes,
                "storage": "raw logical image with zero-only chunks stored as holes where supported",
                "geometry": baseline["targets"][label]}
        require(probe(remote) == baseline, "Final kernel map or read safety changed.")
        progress("All sixteen images verified; publishing the private set and manifest")
        output.manifest(report)
        output.publish()
        return output.path, report
    finally:
        output.close()


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--adb", default="adb", help="host ADB executable")
    parser.add_argument("--serial", help="select one already-authorized ADB transport")
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
        devices, _, _ = transport.run_bounded([args.adb, "devices"], 65536, args.timeout)
        serial = transport.inventory.select_device(transport.inventory.parse_devices(devices.decode("ascii")), args.serial)
        remote = transport.Remote(args.adb, serial, args.timeout)
        remote.check_protocol()
        permission = probe(remote, permission_only=True)
        missing = (not all(permission["permissions"].values()) or not all(permission["base"]["permissions"].values())
                   or not permission["checks"]["pid1_mounts"] or not permission["checks"]["android_mounts"])
        if missing:
            require(args.sudo, "Block or process mount-view read access is missing; rerun with --sudo in a local terminal.")
            remote.password = transport.prompt_password()
        output, report = acquire(remote, candidate)
        print(f"Verified sixteen firmware/boot-area images: {report['bytes_preserved']} private logical bytes with saved-file and repeat phone SHA-256 agreement. Output: {output}")
        print("Observed agreement is not atomic, firmware immutability, authentication or a restoration test.")
        return 0
    except AcquisitionError as error:
        print(f"Firmware acquisition stopped: {error}", file=sys.stderr)
        print("Any retained .part files are incomplete private evidence; no completed result is reported.", file=sys.stderr)
        return 1
    except (ValueError, OSError, UnicodeError, EOFError, KeyboardInterrupt):
        print("Firmware acquisition stopped during a local or transport operation; no completed result is reported.", file=sys.stderr)
        print("Any retained .part files are incomplete private evidence.", file=sys.stderr)
        return 1
    finally:
        if remote is not None: remote.password = None
        os.umask(previous_umask)


if __name__ == "__main__":
    raise SystemExit(main())
