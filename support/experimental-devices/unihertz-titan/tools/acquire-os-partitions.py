#!/usr/bin/env python3
"""Preserve fixed vendor/system partitions through normal-mode USB ADB.

This reads existing storage without changing mounts, block flags or boot mode.
Repeated hashes record observed agreement, not an atomic snapshot or recovery
validation. The mount guard's explicitly recorded scope is not proof of global
quiescence or absence of raw firmware writers.
"""

import argparse
import datetime
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import shlex
import stat
import sys


SPEC = importlib.util.spec_from_file_location(
    "titan_os_bootloader_primitives", Path(__file__).with_name("acquire-bootloaders.py"))
bootloaders = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(bootloaders)
transport = bootloaders.transport
AcquisitionError = transport.AcquisitionError
TARGETS = {
    "vendor": {"number": 33, "start": 1097728, "sectors": 1753088, "bytes": 897581056},
    "system": {"number": 34, "start": 2850816, "sectors": 6291456, "bytes": 3221225472},
}
TOTAL_BYTES = 4118806528
DISK_SECTORS = 244285440
DISK_BYTES = 125074145280
METADATA_LIMIT = 65536
CHUNK_BYTES = 65536
SPACE_RESERVE = 64 * 1048576
SPACE_INTERVAL = 16 * 1048576


REMOTE_CODE = r'''
import fcntl
import hashlib
import json
import os
import re
import stat
import struct
import sys

DISK_SECTORS = 244285440
DISK_BYTES = 125074145280
TARGETS = {
    "vendor": {"number": 33, "start": 1097728, "sectors": 1753088, "bytes": 897581056},
    "system": {"number": 34, "start": 2850816, "sectors": 6291456, "bytes": 3221225472},
}
CHUNK_BYTES = 65536

def require(condition):
    if not condition:
        raise ValueError("fixed OS guard rejected")

def bounded_text(stream, limit):
    # proc seq_file and sysfs reads may return a short chunk before EOF, even
    # when that chunk ends at a newline. Only an empty read establishes EOF.
    chunks, total = [], 0
    while True:
        chunk = stream.read(min(65536, limit + 1 - total))
        require(isinstance(chunk, bytes))
        if not chunk: break
        total += len(chunk)
        require(total <= limit)
        chunks.append(chunk)
    data = b"".join(chunks)
    require(data.endswith(b"\n") and b"\0" not in data)
    return data.decode("ascii")[:-1]

def text(path, limit=4096):
    with open(path, "rb", buffering=0) as stream:
        return bounded_text(stream, limit)

def number(value, maximum=DISK_SECTORS):
    require(re.fullmatch(r"0|[1-9][0-9]{0,14}", value) is not None)
    result = int(value)
    require(result <= maximum)
    return result

def device_number(value):
    require(re.fullmatch(r"(?:0|[1-9][0-9]{0,8}):(?:0|[1-9][0-9]{0,8})", value) is not None)
    return tuple(int(part) for part in value.split(":"))

def node(name, expected):
    path = "/dev/" + name
    metadata = os.stat(path, follow_symlinks=False)
    require(stat.S_ISBLK(metadata.st_mode) and os.path.realpath(path) == path)
    require((os.major(metadata.st_rdev), os.minor(metadata.st_rdev)) == device_number(expected))
    return metadata.st_dev, metadata.st_ino, metadata.st_rdev

def empty_directory(path, optional=False):
    try:
        with os.scandir(path) as entries:
            require(next(entries, None) is None)
    except FileNotFoundError:
        require(optional)

def partition(directory, parent):
    name = directory.rsplit("/", 1)[1]
    index = number(text(directory + "/partition"), 38)
    require(index >= 1 and name == "mmcblk0p" + str(index))
    require(os.path.realpath(directory) == parent + "/" + name)
    fields = {}
    for line in text(directory + "/uevent").splitlines():
        key, separator, value = line.partition("=")
        require(separator == "=" and key and key not in fields)
        fields[key] = value
    require(fields.get("DEVNAME") == name and fields.get("DEVTYPE") == "partition"
            and fields.get("PARTN") == str(index))
    label = fields.get("PARTNAME", "")
    require(re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}", label) is not None)
    start, sectors = number(text(directory + "/start")), number(text(directory + "/size"))
    require(start >= 64 and sectors > 0 and start + sectors <= DISK_SECTORS - 64)
    device = text(directory + "/dev")
    node(name, device)
    return {"number": index, "name": label, "start": start, "sectors": sectors, "device_number": device}

def text_at(directory_fd, name, limit=4096):
    fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=directory_fd)
    with os.fdopen(fd, "rb", buffering=0) as stream:
        return bounded_text(stream, limit)

def process_stat(data):
    opening, closing = data.find(" ("), data.rfind(")")
    require(opening > 0 and closing > opening and data[closing + 1:closing + 2] == " ")
    pid, comm = number(data[:opening], 2147483647), data[opening + 2:closing]
    fields = data[closing + 2:].split()
    require(pid > 0 and len(fields) >= 20 and len(fields[0]) == 1)
    return {"pid": pid, "comm": comm, "ppid": number(fields[1], 2147483647),
            "start_time": number(fields[19], 2**64 - 1)}

def discover_android():
    candidates = []
    with os.scandir("/proc") as entries:
        for index, item in enumerate(entries):
            require(index < 4096)
            if not re.fullmatch(r"[1-9][0-9]{0,9}", item.name):
                continue
            try:
                path = "/proc/" + item.name
                if text(path + "/comm", 256) != "init": continue
                if text(path + "/cgroup") != "0::/lxc.payload.android": continue
                child = process_stat(text(path + "/stat"))
                require(child["pid"] == int(item.name) and child["comm"] == "init")
                parent_path = "/proc/" + str(child["ppid"])
                if text(parent_path + "/cgroup") != "0::/lxc.monitor.android": continue
                if text(parent_path + "/comm", 256) != "lxc-start": continue
                parent = process_stat(text(parent_path + "/stat"))
                require(parent["pid"] == child["ppid"] and parent["comm"] == "lxc-start")
                candidates.append((child, parent))
            except (FileNotFoundError, ProcessLookupError):
                # A disappearing unrelated process is not an identity match.
                continue
    require(len(candidates) == 1)
    return candidates[0]

def mount_rows(path, vendor_device, forbidden, optional=False, directory_fd=None):
    try:
        data = text(path, 262144) if directory_fd is None else text_at(directory_fd, "mountinfo", 262144)
    except PermissionError:
        require(optional)
        return None
    require(data)
    records = []
    for line in data.splitlines():
        fields = line.split()
        require(len(fields) >= 10 and fields.count("-") == 1)
        split = fields.index("-")
        require(split >= 6 and len(fields) == split + 4)
        device_number(fields[2])
        require(fields[2] not in forbidden)
        if fields[2] == vendor_device:
            mount_options, super_options = fields[5].split(","), fields[split + 3].split(",")
            require(mount_options.count("ro") == 1 and "rw" not in mount_options
                    and super_options.count("ro") == 1 and "rw" not in super_options
                    and fields[split + 1] == "ext4")
            # Numeric mount IDs and optional propagation fields are transient;
            # preserve the relevant mount identity/options instead.
            records.append({"root": fields[3], "mountpoint": fields[4],
                            "filesystem": "ext4", "mount_options": sorted(mount_options),
                            "super_options": sorted(super_options)})
    return sorted(records, key=lambda item: json.dumps(item, sort_keys=True))

def android_view(permission_only, vendor_device, forbidden, descriptors=None):
    opened = {} if descriptors is None else descriptors
    try:
        discovered_child, discovered_parent = discover_android()
        if descriptors is None:
            for key, identity in (("android_proc", discovered_child), ("monitor_proc", discovered_parent)):
                opened[key] = os.open("/proc/" + str(identity["pid"]),
                    os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
        def identities():
            child = process_stat(text_at(opened["android_proc"], "stat"))
            parent = process_stat(text_at(opened["monitor_proc"], "stat"))
            require(child["comm"] == "init" and parent["comm"] == "lxc-start"
                    and child["ppid"] == parent["pid"]
                    and text_at(opened["android_proc"], "comm", 256) == "init"
                    and text_at(opened["monitor_proc"], "comm", 256) == "lxc-start"
                    and text_at(opened["android_proc"], "cgroup") == "0::/lxc.payload.android"
                    and text_at(opened["monitor_proc"], "cgroup") == "0::/lxc.monitor.android")
            return child, parent
        child, parent = identities()
        require((child, parent) == (discovered_child, discovered_parent))
        namespaces = {}
        for proc, key in (("android_proc", "android_namespace"), ("monitor_proc", "monitor_namespace")):
            if descriptors is None:
                # Namespace descriptors are retained solely for identity. No
                # setns, unshare, mount or namespace mutation is performed.
                opened[key] = os.open("ns/mnt", os.O_RDONLY | os.O_CLOEXEC, dir_fd=opened[proc])
            held = os.fstat(opened[key])
            current = os.stat("ns/mnt", dir_fd=opened[proc])
            require((held.st_dev, held.st_ino) == (current.st_dev, current.st_ino))
            namespaces[key] = [held.st_dev, held.st_ino]
        rows = mount_rows("android-init", vendor_device, forbidden, optional=permission_only,
                          directory_fd=opened["android_proc"])
        if rows is None:
            raise PermissionError("Android process mount view is unavailable")
        require(identities() == (child, parent))
        for proc, key in (("android_proc", "android_namespace"), ("monitor_proc", "monitor_namespace")):
            current = os.stat("ns/mnt", dir_fd=opened[proc])
            require([current.st_dev, current.st_ino] == namespaces[key])
        report = {"pid": child["pid"], "start_time": child["start_time"],
                  "parent_pid": parent["pid"], "parent_start_time": parent["start_time"],
                  "parent_ppid": parent["ppid"], "namespace": namespaces["android_namespace"],
                  "parent_namespace": namespaces["monitor_namespace"]}
        if permission_only:
            for fd in opened.values(): os.close(fd)
            return report, rows, {}
        return report, rows, opened
    except BaseException as error:
        if descriptors is None:
            for fd in opened.values(): os.close(fd)
        if permission_only and isinstance(error, PermissionError):
            return None, None, {}
        raise

def ioctl_number(fd, request, size):
    result = fcntl.ioctl(fd, request, bytes(size))
    require(isinstance(result, bytes) and len(result) == size)
    return struct.unpack("<Q" if size == 8 else "<I", result)[0]

def snapshot(permission_only=False, descriptors=None):
    require(sys.platform == "linux" and sys.byteorder == "little"
            and os.uname().machine == "aarch64" and sys.maxsize == 2**63 - 1)
    disk = "/sys/class/block/mmcblk0"
    parent = os.path.realpath(disk)
    require(re.fullmatch(r"/sys/devices/[A-Za-z0-9_./:@+-]+/mmcblk0", parent) is not None)
    require(text(disk + "/device/type") == "MMC" and text(disk + "/removable") == "0"
            and text(disk + "/size") == str(DISK_SECTORS)
            and text(disk + "/queue/logical_block_size") == "512"
            and text(disk + "/queue/physical_block_size") == "512")
    disk_device = text(disk + "/dev")
    identities = {"mmcblk0": node("mmcblk0", disk_device)}
    empty_directory(disk + "/holders"); empty_directory(disk + "/slaves")
    names = []
    with os.scandir("/sys/class/block") as entries:
        for index, item in enumerate(entries):
            require(index < 256)
            if item.name.startswith("mmcblk0p"):
                require(re.fullmatch(r"mmcblk0p[1-9][0-9]?", item.name) is not None)
                names.append(item.name)
    require(len(names) == 38)
    parts = sorted((partition("/sys/class/block/" + name, parent) for name in names),
                   key=lambda item: item["number"])
    require([item["number"] for item in parts] == list(range(1, 39)))
    require(len({item["name"] for item in parts}) == 38
            and len({item["device_number"] for item in parts} | {disk_device}) == 39)
    ordered = sorted(parts, key=lambda item: item["start"])
    require(all(left["start"] + left["sectors"] <= right["start"]
                for left, right in zip(ordered, ordered[1:])))
    require(parts[0]["start"] == 64)
    for index, label, start, size in ((2, "recovery", None, 65536), (28, "boot", None, 65536),
            (30, "dtbo", None, 16384), (36, "userdata", 10027008, 234137536)):
        item = parts[index - 1]
        require(item["name"] == label and item["sectors"] == size
                and (start is None or item["start"] == start))
    target_records, expected_sizes = {}, {"mmcblk0": DISK_BYTES}
    for label, expected in TARGETS.items():
        index = expected["number"]
        item = parts[index - 1]
        name, path = "mmcblk0p" + str(index), "/dev/mmcblk0p" + str(index)
        require(item["name"] == label and all(item[key] == expected[key] for key in ("number", "start", "sectors")))
        require(os.path.realpath("/dev/disk/by-partlabel/" + label) == path)
        identities[name] = node(name, item["device_number"])
        expected_sizes[name] = expected["bytes"]
        empty_directory("/sys/class/block/" + name + "/holders")
        empty_directory("/sys/class/block/" + name + "/slaves", optional=True)
        target_records[label] = {"node": path, "bytes": expected["bytes"], **item}
    forbidden = {disk_device, target_records["system"]["device_number"]}
    mounts = {}
    for scope, path in (("self", "/proc/self/mountinfo"), ("pid1", "/proc/1/mountinfo")):
        mounts[scope] = mount_rows(path, target_records["vendor"]["device_number"], forbidden,
                                   optional=permission_only and scope == "pid1")
    # The measured normal-mode profile exposes vendor read-only in this view;
    # absence is a profile change, not evidence that another view is safe.
    require(bool(mounts["self"]))
    permissions = {name: os.access("/dev/" + name, os.R_OK) for name in identities}
    if not permission_only:
        require(all(permissions.values()) and all(value is not None for value in mounts.values()))
    android, mounts["android"], auxiliaries = android_view(permission_only,
        target_records["vendor"]["device_number"], forbidden, descriptors)
    result = {"format": "titan-os-partition-guard-v1", "disk": {"node": "/dev/mmcblk0",
        "type": "MMC", "removable": 0, "sectors": DISK_SECTORS, "bytes": DISK_BYTES,
        "logical_sector_bytes": 512, "physical_sector_bytes": 512,
        "device_number": disk_device, "sysfs": parent}, "partitions": parts,
        "targets": target_records, "permissions": permissions, "vendor_mounts": mounts, "android_init": android,
        "checks": {"self_mounts": mounts["self"] is not None, "pid1_mounts": mounts["pid1"] is not None,
                   "android_mounts": mounts["android"] is not None,
                   "holders_and_slaves_empty": True, "ioctl_geometry": not permission_only}}
    if permission_only:
        return result, {}
    opened = auxiliaries if descriptors is None else descriptors
    try:
        require(android is not None and mounts["android"] is not None)
        for name, identity in identities.items():
            if descriptors is None:
                opened[name] = os.open("/dev/" + name, os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW | os.O_CLOEXEC)
            metadata = os.fstat(opened[name])
            require(stat.S_ISBLK(metadata.st_mode)
                    and (metadata.st_dev, metadata.st_ino, metadata.st_rdev) == identity)
            require(ioctl_number(opened[name], 0x80081272, 8) == expected_sizes[name]
                    and ioctl_number(opened[name], 0x1268, 4) == 512
                    and ioctl_number(opened[name], 0x127b, 4) == 512)
        return result, opened
    except BaseException:
        if descriptors is None:
            for fd in opened.values(): os.close(fd)
        raise

def execute(mode, label):
    require(mode in ("permissions", "probe", "read", "hash"))
    require(label in TARGETS if mode in ("read", "hash") else label == "")
    before, descriptors = snapshot(mode == "permissions")
    try:
        if mode in ("permissions", "probe"):
            sys.stdout.buffer.write(json.dumps(before, sort_keys=True).encode("ascii") + b"\n")
        else:
            expected = TARGETS[label]
            fd = descriptors["mmcblk0p" + str(expected["number"])]
            require(os.lseek(fd, 0, os.SEEK_CUR) == 0)
            remaining, digest = expected["bytes"], hashlib.sha256()
            while remaining:
                chunk = os.read(fd, min(CHUNK_BYTES, remaining))
                require(chunk and len(chunk) <= remaining)
                remaining -= len(chunk)
                if mode == "read":
                    sys.stdout.buffer.write(chunk)
                else:
                    digest.update(chunk)
            after, _ = snapshot(False, descriptors)
            require(before == after)
            if mode == "hash":
                sys.stdout.buffer.write((json.dumps({"label": label, "bytes": expected["bytes"],
                    "sha256": digest.hexdigest()}, sort_keys=True) + "\n").encode("ascii"))
        sys.stdout.buffer.flush()
    finally:
        for fd in descriptors.values(): os.close(fd)
'''


def require(condition, message="OS partition metadata did not match the fixed profile."):
    if not condition:
        raise AcquisitionError(message)


def target_bytes(label):
    return TARGETS[label]["bytes"]


def remote_script(mode, label=""):
    if mode not in ("permissions", "probe", "read", "hash") or (
            label not in TARGETS if mode in ("read", "hash") else label != ""):
        raise ValueError("Only fixed vendor/system inspection and bounded reads are supported.")
    program = REMOTE_CODE + (
        f"\ntry:\n    execute({mode!r}, {label!r})\n"
        "except BaseException:\n    sys.stderr.write('Fixed OS partition guard or read refused.\\n')\n"
        "    sys.exit(23)\n")
    return "/usr/bin/python3 -I -S -B -c " + shlex.quote(program)


def parsed_json(data):
    require(len(data) <= METADATA_LIMIT and data.endswith(b"\n"), "Metadata was truncated or exceeded its bound.")
    def unique(pairs):
        result = {}
        for key, value in pairs:
            require(key not in result, "Duplicate metadata fields were received.")
            result[key] = value
        return result
    try:
        return json.loads(data.decode("ascii"), object_pairs_hook=unique)
    except (ValueError, UnicodeError) as error:
        raise AcquisitionError("Malformed OS partition metadata was received.") from error


def validate_evidence(data, permission_only=False):
    report = parsed_json(data)
    try:
        require(set(report) == {"format", "disk", "partitions", "targets", "permissions", "checks", "vendor_mounts", "android_init"})
        require(report["format"] == "titan-os-partition-guard-v1")
        disk = report["disk"]
        require(set(disk) == {"node", "type", "removable", "sectors", "bytes", "logical_sector_bytes",
                              "physical_sector_bytes", "device_number", "sysfs"})
        require(all(type(disk[key]) is int for key in ("removable", "sectors", "bytes",
                    "logical_sector_bytes", "physical_sector_bytes")))
        require({key: disk[key] for key in ("node", "type", "removable", "sectors", "bytes",
                    "logical_sector_bytes", "physical_sector_bytes")} == {
            "node": "/dev/mmcblk0", "type": "MMC", "removable": 0, "sectors": DISK_SECTORS,
            "bytes": DISK_BYTES, "logical_sector_bytes": 512, "physical_sector_bytes": 512})
        require(re.fullmatch(r"/sys/devices/[A-Za-z0-9_./:@+-]+/mmcblk0", disk["sysfs"]) is not None)
        parts = report["partitions"]
        require(type(parts) is list and len(parts) == 38)
        names, devices = set(), {disk["device_number"]}
        for index, item in enumerate(parts, 1):
            require(set(item) == {"number", "name", "start", "sectors", "device_number"})
            require(all(type(item[key]) is int for key in ("number", "start", "sectors")))
            require(item["number"] == index and 64 <= item["start"]
                    and 0 < item["sectors"] and item["start"] + item["sectors"] <= DISK_SECTORS - 64)
            require(re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}", item["name"]) is not None)
            require(item["name"] not in names and item["device_number"] not in devices)
            names.add(item["name"]); devices.add(item["device_number"])
        require(all(re.fullmatch(r"(?:0|[1-9][0-9]{0,8}):(?:0|[1-9][0-9]{0,8})", value)
                    for value in devices))
        ordered = sorted(parts, key=lambda item: item["start"])
        require(all(left["start"] + left["sectors"] <= right["start"]
                    for left, right in zip(ordered, ordered[1:])))
        require(parts[0]["start"] == 64)
        for index, label, start, size in ((2, "recovery", None, 65536), (28, "boot", None, 65536),
                (30, "dtbo", None, 16384), (36, "userdata", 10027008, 234137536)):
            item = parts[index - 1]
            require(item["name"] == label and item["sectors"] == size
                    and (start is None or item["start"] == start))
        require(set(report["targets"]) == set(TARGETS))
        for label, expected in TARGETS.items():
            item = parts[expected["number"] - 1]
            require(item["name"] == label and all(item[key] == expected[key] for key in ("number", "start", "sectors")))
            require(report["targets"][label] == {"node": f"/dev/mmcblk0p{expected['number']}", "bytes": expected["bytes"], **item})
        require(set(report["permissions"]) == {"mmcblk0", "mmcblk0p33", "mmcblk0p34"}
                and all(type(value) is bool for value in report["permissions"].values()))
        checks, mounts = report["checks"], report["vendor_mounts"]
        require(set(checks) == {"self_mounts", "pid1_mounts", "android_mounts", "holders_and_slaves_empty", "ioctl_geometry"}
                and all(type(value) is bool for value in checks.values()))
        require(set(mounts) == {"self", "pid1", "android"})
        require(bool(mounts["self"]), "The observed read-only vendor mount is absent from the acquisition process view.")
        for scope, records in mounts.items():
            require(checks[scope + "_mounts"] is (records is not None))
            if records is None:
                require(permission_only and scope in ("pid1", "android"))
                continue
            require(type(records) is list and len(records) <= 256)
            for item in records:
                require(set(item) == {"root", "mountpoint", "filesystem", "mount_options", "super_options"})
                require(item["filesystem"] == "ext4" and type(item["root"]) is str and type(item["mountpoint"]) is str)
                for key in ("mount_options", "super_options"):
                    options = item[key]
                    require(type(options) is list and all(type(value) is str for value in options)
                            and options.count("ro") == 1 and "rw" not in options)
        android = report["android_init"]
        if android is None:
            require(permission_only and mounts["android"] is None)
        else:
            require(mounts["android"] is not None and set(android) == {
                "pid", "start_time", "parent_pid", "parent_start_time", "parent_ppid", "namespace", "parent_namespace"})
            require(all(type(android[key]) is int and 0 <= android[key] < 2**64
                        for key in ("pid", "start_time", "parent_pid", "parent_start_time", "parent_ppid")))
            require(0 < android["pid"] <= 2147483647 and 0 < android["parent_pid"] <= 2147483647
                    and android["pid"] != android["parent_pid"] and android["parent_ppid"] <= 2147483647)
            for key in ("namespace", "parent_namespace"):
                pair = android[key]
                require(type(pair) is list and len(pair) == 2
                        and all(type(value) is int and 0 <= value < 2**64 for value in pair) and pair[1] > 0)
        require(checks["self_mounts"] and checks["holders_and_slaves_empty"]
                and checks["ioctl_geometry"] is (not permission_only))
        if not permission_only:
            require(checks["pid1_mounts"] and checks["android_mounts"] and all(report["permissions"].values()),
                    "Read permissions or process mount-view checks did not pass.")
    except (KeyError, TypeError, AttributeError) as error:
        raise AcquisitionError("OS partition metadata has an unexpected shape.") from error
    return report


def probe(remote, permission_only=False):
    data, count, _ = remote.run(remote_script("permissions" if permission_only else "probe"), METADATA_LIMIT)
    require(count == len(data), "Metadata byte count did not match.")
    return validate_evidence(data, permission_only)


class SpaceBudget:
    def __init__(self, directory_fd, remaining):
        self.fd, self.remaining, self.since_check = directory_fd, remaining, 0
        self.check()

    def check(self):
        space = os.fstatvfs(self.fd)
        require(space.f_bavail * space.f_frsize >= self.remaining + SPACE_RESERVE,
                "Insufficient free space for remaining full-size images plus the 64 MiB reserve.")
        self.since_check = 0

    def before_write(self, count):
        require(0 <= count <= self.remaining, "Output exceeded the fixed pair byte budget.")
        if self.since_check >= SPACE_INTERVAL:
            self.check()

    def consumed(self, count):
        self.remaining -= count
        self.since_check += count


class SparseSink:
    """Skip only entirely zero chunks; the logical byte stream is unchanged."""
    def __init__(self, stream, expected, budget):
        self.stream, self.expected, self.budget = stream, expected, budget
        self.position, self.zero_bytes = 0, 0

    def write(self, data):
        count = len(data)
        require(self.position + count <= self.expected, "Output exceeded the fixed partition byte count.")
        self.budget.before_write(count)
        if data.count(0) == count:
            self.stream.seek(count, os.SEEK_CUR)
            self.zero_bytes += count
        else:
            require(self.stream.write(data) == count, "Private image write was short.")
        self.position += count
        self.budget.consumed(count)
        return count

    def finish(self):
        require(self.position == self.expected and self.stream.tell() == self.expected,
                "Partition transfer did not contain its exact fixed byte count.")
        self.stream.truncate(self.expected)
        self.stream.flush()
        os.fsync(self.stream.fileno())


class PrivateOutput(bootloaders.PrivateOutput):
    """Reuse anchored creation/privacy; replace LK's whole-file readback/pair."""
    def __init__(self, requested):
        super().__init__(requested)
        try:
            self.budget = SpaceBudget(self.fd, sum(target_bytes(label) for label in TARGETS))
        except BaseException:
            self.close()
            raise

    def saved_hash(self, name, expected):
        before = os.stat(name, dir_fd=self.fd, follow_symlinks=False)
        require(bootloaders.inode(before) == self.owned[name] and stat.S_ISREG(before.st_mode),
                "Saved private file identity or type changed before readback.")
        fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC, dir_fd=self.fd)
        try:
            metadata = os.fstat(fd)
            require(bootloaders.file_identity(metadata) == bootloaders.file_identity(before)
                    and metadata.st_size == expected and metadata.st_uid == os.getuid()
                    and metadata.st_nlink == 1 and stat.S_IMODE(metadata.st_mode) == 0o600,
                    "Saved private file identity, size or privacy changed.")
            remaining, digest = expected, hashlib.sha256()
            while remaining:
                data = os.read(fd, min(1048576, remaining))
                require(data, "Saved image ended before its fixed byte count.")
                digest.update(data)
                remaining -= len(data)
            require(not os.read(fd, 1) and bootloaders.file_identity(os.fstat(fd)) == bootloaders.file_identity(metadata),
                    "Saved file changed during readback.")
            self.sizes[name], self.modified[name] = expected, metadata.st_mtime_ns
            return digest.hexdigest()
        finally:
            os.close(fd)

    def publish(self):
        self.recheck(); self.budget.check()
        try:
            for name in (*(label + ".img" for label in TARGETS), "manifest.json"):
                pending = name + ".part"
                os.link(pending, name, src_dir_fd=self.fd, dst_dir_fd=self.fd, follow_symlinks=False)
                self.owned[name] = self.owned[pending]
                self.published.append(name)
            os.fsync(self.fd)
            for name in self.published: os.unlink(name + ".part", dir_fd=self.fd)
            os.fsync(self.fd); os.fsync(self.parent_fd)
            self.recheck()
            for name in self.published:
                metadata = os.stat(name, dir_fd=self.fd, follow_symlinks=False)
                require(bootloaders.inode(metadata) == self.owned[name] and stat.S_ISREG(metadata.st_mode)
                        and metadata.st_uid == os.getuid() and metadata.st_nlink == 1
                        and stat.S_IMODE(metadata.st_mode) == 0o600 and metadata.st_size == self.sizes[name + ".part"]
                        and metadata.st_mtime_ns == self.modified[name + ".part"],
                        "Published file identity or privacy changed.")
        except BaseException:
            for name in self.published:
                try:
                    if bootloaders.inode(os.stat(name, dir_fd=self.fd, follow_symlinks=False)) == self.owned[name]:
                        os.unlink(name, dir_fd=self.fd)
                except OSError: pass
            raise


def acquire(remote, requested):
    baseline = probe(remote)
    output = PrivateOutput(requested)
    try:
        report = {"format": "titan-private-os-partitions-v1", "status": "complete",
            "created_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "transport": "adb-shell-v2-no-pty-framed-status", "kernel_map": baseline,
            "scope": "fixed vendor/system only; limited process mount views and repeated reads, not global quiescence",
            "mount_view_scope": ["acquisition process", "PID1", "identified Android init"],
            "bytes_preserved": sum(target_bytes(label) for label in TARGETS), "partitions": {},
            "validation": {"atomic_snapshot": False, "global_quiescence": False,
                           "authentication_performed": False, "restoration_tested": False,
                           "device_changes_performed": False}}
        for label in TARGETS:
            require(probe(remote) == baseline, "Kernel map or read safety changed before acquisition.")
            expected, pending = target_bytes(label), label + ".img.part"
            progress(f"{label}: transferring {expected} bytes to private storage")
            with os.fdopen(output.create(pending), "wb") as stream:
                sink = SparseSink(stream, expected, output.budget)
                _, count, digest = remote.run(remote_script("read", label), expected, sink=sink)
                require(count == expected, "Partition transfer byte count did not match the fixed profile.")
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
            report["partitions"][label] = {"file": label + ".img", "bytes": expected,
                "sha256": digest, "transfer_sha256": digest, "readback_sha256": digest,
                "phone_repeat_sha256": digest, "zero_bytes_skipped": sink.zero_bytes,
                "storage": "raw logical image with zero-only chunks stored as holes where supported",
                "geometry": baseline["targets"][label]}
        require(probe(remote) == baseline, "Final kernel map or read safety changed.")
        progress("Both partitions verified; publishing the private pair and manifest")
        output.manifest(report)
        output.publish()
        return output.path, report
    finally:
        output.close()


def progress(message):
    print(message, file=sys.stderr, flush=True)


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
        missing = (not all(permission["permissions"].values())
                   or not permission["checks"]["pid1_mounts"] or not permission["checks"]["android_mounts"])
        if missing:
            require(args.sudo, "Block or process mount-view read access is missing; rerun with --sudo in a local terminal.")
            remote.password = transport.prompt_password()
        output, report = acquire(remote, candidate)
        print(f"Verified vendor and system: {report['bytes_preserved']} private logical bytes with saved-file and repeat phone SHA-256 agreement. Output: {output}")
        print("Sparse storage preserves zero bytes; observed read agreement is not an atomic snapshot or restoration test.")
        return 0
    except AcquisitionError as error:
        print(f"OS partition acquisition stopped: {error}", file=sys.stderr)
        print("Any retained .part files are incomplete private evidence; no completed result is reported.", file=sys.stderr)
        return 1
    except (ValueError, OSError, UnicodeError, EOFError, KeyboardInterrupt):
        print("OS partition acquisition stopped during a local or transport operation; no completed result is reported.", file=sys.stderr)
        print("Any retained .part files are incomplete private evidence.", file=sys.stderr)
        return 1
    finally:
        if remote is not None: remote.password = None
        os.umask(previous_umask)


if __name__ == "__main__":
    raise SystemExit(main())
