#!/usr/bin/env python3
"""Preserve only the measured Titan's lk and lk2 through normal-mode USB ADB.

Each fixed 1 MiB partition is read twice: once for its private copy and once for
an independent phone SHA-256. Agreement records observed stability, not an atomic
snapshot, bootloader authentication, a calibration backup or tested restoration.
No phone file, block flag, mount, configuration, software or boot mode is changed.
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
    "titan_bootloader_transport", Path(__file__).with_name("acquire-partitions.py"))
transport = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(transport)
AcquisitionError = transport.AcquisitionError
IMAGE_BYTES = 1048576
DISK_SECTORS = 244285440
DISK_BYTES = 125074145280
METADATA_LIMIT = 32768
SPACE_RESERVE = 4 * 1048576
TARGETS = {"lk": (26, 960512), "lk2": (27, 962560)}

# This fixed program is sent in the command argument, never installed on the
# phone. Python isolated/no-site/no-bytecode mode suppresses Python environment,
# site customization and cache writes. Only metadata paths and three fixed block FDs
# are opened; stdout is either bounded metadata or one exact partition payload.
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
IMAGE_BYTES = 1048576
TARGETS = {"lk": (26, 960512), "lk2": (27, 962560)}

def require(condition):
    if not condition:
        raise ValueError("fixed guard rejected")

def text(path, limit=4096):
    with open(path, "rb", buffering=0) as stream:
        data = stream.read(limit + 1)
    require(len(data) <= limit and data.endswith(b"\n") and b"\0" not in data)
    return data.decode("ascii")[:-1]

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
    return (metadata.st_dev, metadata.st_ino, metadata.st_rdev)

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

def unmounted(path, forbidden, optional):
    try:
        data = text(path, 262144)
    except PermissionError:
        require(optional)
        return False
    require(data)
    for line in data.splitlines():
        fields = line.split()
        require(len(fields) >= 10 and "-" in fields[6:])
        device_number(fields[2])
        require(fields[2] not in forbidden)
    return True

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
    empty_directory(disk + "/holders")
    empty_directory(disk + "/slaves")
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
    target_records = {}
    for label, (index, start) in TARGETS.items():
        item = parts[index - 1]
        name = "mmcblk0p" + str(index)
        path = "/dev/" + name
        require(item["name"] == label and item["start"] == start and item["sectors"] == 2048)
        require(os.path.realpath("/dev/disk/by-partlabel/" + label) == path)
        identities[name] = node(name, item["device_number"])
        empty_directory("/sys/class/block/" + name + "/holders")
        empty_directory("/sys/class/block/" + name + "/slaves", optional=True)
        target_records[label] = {"node": path, "bytes": IMAGE_BYTES, **item}
    forbidden = {disk_device, *(item["device_number"] for item in target_records.values())}
    self_mounts = unmounted("/proc/self/mountinfo", forbidden, False)
    pid1_mounts = unmounted("/proc/1/mountinfo", forbidden, permission_only)
    permissions = {name: os.access("/dev/" + name, os.R_OK) for name in identities}
    result = {"format": "titan-bootloader-guard-v1", "disk": {"node": "/dev/mmcblk0",
        "type": "MMC", "removable": 0, "sectors": DISK_SECTORS, "bytes": DISK_BYTES,
        "logical_sector_bytes": 512, "physical_sector_bytes": 512,
        "device_number": disk_device, "sysfs": parent}, "partitions": parts,
        "targets": target_records, "permissions": permissions,
        "checks": {"self_mounts": self_mounts, "pid1_mounts": pid1_mounts,
                   "holders_and_slaves_empty": True, "ioctl_geometry": not permission_only}}
    if permission_only:
        return result, {}
    require(all(permissions.values()) and self_mounts and pid1_mounts)
    opened = {} if descriptors is None else descriptors
    try:
        for name, identity in identities.items():
            if descriptors is None:
                opened[name] = os.open("/dev/" + name, os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW | os.O_CLOEXEC)
            metadata = os.fstat(opened[name])
            require(stat.S_ISBLK(metadata.st_mode)
                    and (metadata.st_dev, metadata.st_ino, metadata.st_rdev) == identity)
            expected = DISK_BYTES if name == "mmcblk0" else IMAGE_BYTES
            require(ioctl_number(opened[name], 0x80081272, 8) == expected
                    and ioctl_number(opened[name], 0x1268, 4) == 512
                    and ioctl_number(opened[name], 0x127b, 4) == 512)
        return result, opened
    except BaseException:
        if descriptors is None:
            for fd in opened.values():
                os.close(fd)
        raise

def execute(mode, label):
    require(mode in ("permissions", "probe", "read", "hash"))
    require(label in TARGETS if mode in ("read", "hash") else label == "")
    before, descriptors = snapshot(mode == "permissions")
    try:
        if mode in ("permissions", "probe"):
            output = json.dumps(before, sort_keys=True).encode("ascii") + b"\n"
        else:
            name = "mmcblk0p" + str(TARGETS[label][0])
            fd = descriptors[name]
            require(os.lseek(fd, 0, os.SEEK_CUR) == 0)
            data = bytearray()
            while len(data) < IMAGE_BYTES:
                chunk = os.read(fd, min(65536, IMAGE_BYTES - len(data)))
                require(chunk)
                data.extend(chunk)
            after, _ = snapshot(False, descriptors)
            require(before == after)
            if mode == "read":
                output = bytes(data)
            else:
                output = (json.dumps({"label": label, "bytes": IMAGE_BYTES,
                    "sha256": hashlib.sha256(data).hexdigest()}, sort_keys=True) + "\n").encode("ascii")
        sys.stdout.buffer.write(output)
        sys.stdout.buffer.flush()
    finally:
        for fd in descriptors.values():
            os.close(fd)
'''


def remote_script(mode, label=""):
    if mode not in ("permissions", "probe", "read", "hash") or (
            label not in TARGETS if mode in ("read", "hash") else label != ""):
        raise ValueError("Only fixed lk/lk2 inspection and bounded reads are supported.")
    # Suppress raw Python exceptions: neither private metadata nor input from an
    # authentication helper is echoed by this program or the transport wrapper.
    program = REMOTE_CODE + (
        f"\ntry:\n    execute({mode!r}, {label!r})\n"
        "except BaseException:\n    sys.stderr.write('Fixed bootloader guard or read refused.\\n')\n"
        "    sys.exit(23)\n")
    return "/usr/bin/python3 -I -S -B -c " + shlex.quote(program)


def require(condition, message="Bootloader metadata did not match the fixed profile."):
    if not condition:
        raise AcquisitionError(message)


def parsed_json(data):
    def unique(pairs):
        result = {}
        for key, value in pairs:
            require(key not in result, "Duplicate metadata fields were received.")
            result[key] = value
        return result
    require(len(data) <= METADATA_LIMIT and data.endswith(b"\n"), "Metadata was truncated or exceeded its bound.")
    try:
        return json.loads(data.decode("ascii"), object_pairs_hook=unique)
    except (ValueError, UnicodeError) as error:
        raise AcquisitionError("Malformed bootloader metadata was received.") from error


def validate_evidence(data, permission_only=False):
    report = parsed_json(data)
    try:
        require(set(report) == {"format", "disk", "partitions", "targets", "permissions", "checks"})
        require(report["format"] == "titan-bootloader-guard-v1")
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
        for label, (index, start) in TARGETS.items():
            item = parts[index - 1]
            require(item["name"] == label and item["start"] == start and item["sectors"] == 2048)
            require(report["targets"][label] == {"node": f"/dev/mmcblk0p{index}", "bytes": IMAGE_BYTES, **item})
        require(set(report["permissions"]) == {"mmcblk0", "mmcblk0p26", "mmcblk0p27"}
                and all(type(value) is bool for value in report["permissions"].values()))
        checks = report["checks"]
        require(set(checks) == {"self_mounts", "pid1_mounts", "holders_and_slaves_empty", "ioctl_geometry"}
                and all(type(value) is bool for value in checks.values()))
        require(checks["self_mounts"] and checks["holders_and_slaves_empty"]
                and checks["ioctl_geometry"] is (not permission_only))
        if not permission_only:
            require(checks["pid1_mounts"] and all(report["permissions"].values()), "Read permissions or mount checks did not pass.")
    except (KeyError, TypeError, AttributeError) as error:
        raise AcquisitionError("Bootloader metadata has an unexpected shape.") from error
    return report


def probe(remote, permission_only=False):
    data, count, _ = remote.run(remote_script("permissions" if permission_only else "probe"), METADATA_LIMIT)
    require(count == len(data), "Metadata byte count did not match.")
    return validate_evidence(data, permission_only)


def private_path(value):
    path = Path(os.path.abspath(os.fspath(Path(value).expanduser())))
    path = path.parent.resolve(strict=True) / path.name
    require(path.name not in ("", ".", ".."), "A new named private output directory is required.")
    require(path != Path("/nix") and Path("/nix") not in path.parents,
            "Private bootloader copies must be outside /nix.")
    for parent in (path, *path.parents):
        require(not os.path.lexists(parent / ".git") and not os.path.lexists(parent / ".jj"),
                "Private bootloader copies must be outside every Git or jj checkout.")
    return path


def inode(metadata):
    return metadata.st_dev, metadata.st_ino


def file_identity(metadata):
    return (metadata.st_dev, metadata.st_ino, metadata.st_mode, metadata.st_uid,
            metadata.st_nlink, metadata.st_size, metadata.st_mtime_ns, metadata.st_ctime_ns)


class PrivateOutput:
    def __init__(self, requested):
        self.path = private_path(requested)
        self.parent_fd = self.fd = -1
        self.owned = {}
        self.sizes = {}
        self.modified = {}
        self.published = []
        require(not os.path.lexists(self.path), "Output must be a new private directory.")
        try:
            self.parent_fd = os.open(self.path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
            parent = os.fstat(self.parent_fd)
            self.parent_identity = inode(parent)
            require(parent.st_uid == os.getuid() and not stat.S_IMODE(parent.st_mode) & 0o022,
                    "Output parent must be owned by this user and not writable by group or others.")
            require(inode(os.stat(self.path.parent, follow_symlinks=False)) == self.parent_identity)
            space = os.fstatvfs(self.parent_fd)
            require(space.f_bavail * space.f_frsize >= 2 * IMAGE_BYTES + SPACE_RESERVE,
                    "Private output needs space for 2 MiB of images plus a 4 MiB reserve.")
            os.mkdir(self.path.name, 0o700, dir_fd=self.parent_fd)
            created = os.stat(self.path.name, dir_fd=self.parent_fd, follow_symlinks=False)
            self.fd = os.open(self.path.name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                              dir_fd=self.parent_fd)
            require(stat.S_ISDIR(created.st_mode) and created.st_uid == os.getuid()
                    and inode(os.fstat(self.fd)) == inode(created))
            os.fchmod(self.fd, 0o700)
            self.identity = inode(created)
            self.recheck()
            os.fsync(self.parent_fd)
        except BaseException:
            self.close()
            raise

    def recheck(self):
        metadata = os.stat(self.path.name, dir_fd=self.parent_fd, follow_symlinks=False)
        require(inode(metadata) == self.identity and stat.S_ISDIR(metadata.st_mode)
                and stat.S_IMODE(metadata.st_mode) == 0o700 and metadata.st_uid == os.getuid()
                and inode(os.stat(self.path.parent, follow_symlinks=False)) == self.parent_identity
                and private_path(self.path) == self.path, "Private output directory identity changed.")

    def create(self, name):
        fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                     0o600, dir_fd=self.fd)
        try:
            self.owned[name] = inode(os.fstat(fd))
            os.fchmod(fd, 0o600)
            return fd
        except BaseException:
            os.close(fd)
            raise

    def saved_hash(self, name, expected):
        before = os.stat(name, dir_fd=self.fd, follow_symlinks=False)
        require(inode(before) == self.owned[name] and stat.S_ISREG(before.st_mode),
                "Saved private file identity or type changed before readback.")
        fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC, dir_fd=self.fd)
        try:
            metadata = os.fstat(fd)
            require(file_identity(metadata) == file_identity(before) and inode(metadata) == self.owned[name]
                    and stat.S_ISREG(metadata.st_mode)
                    and metadata.st_size == expected and metadata.st_uid == os.getuid()
                    and metadata.st_nlink == 1 and stat.S_IMODE(metadata.st_mode) == 0o600,
                    "Saved private file identity, size or privacy changed.")
            data = bytearray()
            while len(data) <= expected:
                chunk = os.read(fd, min(65536, expected + 1 - len(data)))
                if not chunk:
                    break
                data.extend(chunk)
            require(len(data) == expected and file_identity(os.fstat(fd)) == file_identity(metadata),
                    "Saved file changed during readback.")
            self.sizes[name] = expected
            self.modified[name] = metadata.st_mtime_ns
            return hashlib.sha256(data).hexdigest()
        finally:
            os.close(fd)

    def manifest(self, report):
        data = (json.dumps(report, indent=2, sort_keys=True) + "\n").encode("ascii")
        with os.fdopen(self.create("manifest.json.part"), "wb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        require(self.saved_hash("manifest.json.part", len(data)) == hashlib.sha256(data).hexdigest())

    def publish(self):
        self.recheck()
        try:
            for name in ("lk.img", "lk2.img", "manifest.json"):
                pending = name + ".part"
                os.link(pending, name, src_dir_fd=self.fd, dst_dir_fd=self.fd, follow_symlinks=False)
                self.owned[name] = self.owned[pending]
                self.published.append(name)
            os.fsync(self.fd)
            for name in self.published:
                os.unlink(name + ".part", dir_fd=self.fd)
            os.fsync(self.fd)
            os.fsync(self.parent_fd)
            self.recheck()
            for name in self.published:
                metadata = os.stat(name, dir_fd=self.fd, follow_symlinks=False)
                require(inode(metadata) == self.owned[name] and stat.S_ISREG(metadata.st_mode)
                        and metadata.st_uid == os.getuid() and metadata.st_nlink == 1
                        and stat.S_IMODE(metadata.st_mode) == 0o600 and metadata.st_size == self.sizes[name + ".part"]
                        and metadata.st_mtime_ns == self.modified[name + ".part"],
                        "Published file identity or privacy changed.")
        except BaseException:
            for name in self.published:
                try:
                    if inode(os.stat(name, dir_fd=self.fd, follow_symlinks=False)) == self.owned[name]:
                        os.unlink(name, dir_fd=self.fd)
                except OSError:
                    pass
            raise

    def close(self):
        for attribute in ("fd", "parent_fd"):
            fd = getattr(self, attribute)
            if fd >= 0:
                os.close(fd)
                setattr(self, attribute, -1)


def acquire(remote, requested):
    baseline = probe(remote)
    output = PrivateOutput(requested)
    try:
        report = {"format": "titan-private-bootloaders-v1", "status": "complete",
            "created_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "transport": "adb-shell-v2-no-pty-framed-status", "kernel_map": baseline,
            "scope": "fixed lk and lk2 only; observed read agreement, not an atomic snapshot or recovery validation",
            "bytes_preserved": 2 * IMAGE_BYTES, "partitions": {},
            "validation": {"atomic_snapshot": False, "authentication_performed": False,
                           "restoration_tested": False, "device_changes_performed": False}}
        for label in TARGETS:
            require(probe(remote) == baseline, "Kernel map or read safety changed before acquisition.")
            pending = label + ".img.part"
            with os.fdopen(output.create(pending), "wb") as stream:
                _, count, digest = remote.run(remote_script("read", label), IMAGE_BYTES, sink=stream)
                require(count == IMAGE_BYTES, "Partition transfer did not contain exactly 1 MiB.")
                stream.flush()
                os.fsync(stream.fileno())
            require(output.saved_hash(pending, IMAGE_BYTES) == digest,
                    "Saved-file SHA-256 did not match the transfer.")
            require(probe(remote) == baseline, "Kernel map or read safety changed after acquisition.")
            data, count, _ = remote.run(remote_script("hash", label), 256)
            require(count == len(data), "Phone digest byte count did not match.")
            repeated = parsed_json(data)
            require(repeated == {"label": label, "bytes": IMAGE_BYTES, "sha256": digest}
                    and re.fullmatch(r"[0-9a-f]{64}", digest) is not None,
                    "Independent bounded phone SHA-256 did not match.")
            require(probe(remote) == baseline, "Kernel map or read safety changed after the repeat read.")
            report["partitions"][label] = {"file": label + ".img", "bytes": IMAGE_BYTES,
                "sha256": digest, "transfer_sha256": digest, "readback_sha256": digest,
                "phone_repeat_sha256": digest, "geometry": baseline["targets"][label]}
        require(probe(remote) == baseline, "Final kernel map or read safety changed.")
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
    parser.add_argument("--timeout", type=int, default=120, help="seconds per bounded remote operation")
    parser.add_argument("--sudo", action="store_true", help="prompt secretly in this local terminal only if read access is missing")
    args = parser.parse_args(argv)
    if not 1 <= args.timeout <= 600:
        parser.error("--timeout must be between 1 and 600 seconds")
    remote = None
    previous_umask = os.umask(0o077)
    try:
        # Validate the requested location before transport or credential work.
        candidate = private_path(args.output)
        require(not os.path.lexists(candidate), "Output must be a new private directory.")
        devices, _, _ = transport.run_bounded([args.adb, "devices"], 65536, args.timeout)
        serial = transport.inventory.select_device(transport.inventory.parse_devices(devices.decode("ascii")), args.serial)
        remote = transport.Remote(args.adb, serial, args.timeout)
        remote.check_protocol()
        # This also verifies isolated Python availability and complete metadata
        # before credentials; it opens no block device and reads no contents.
        permission = probe(remote, permission_only=True)
        missing = not all(permission["permissions"].values()) or not permission["checks"]["pid1_mounts"]
        if missing:
            require(args.sudo, "Block or PID1-mount read access is missing; rerun with --sudo in a local terminal.")
            remote.password = transport.prompt_password()
        output, _ = acquire(remote, candidate)
        print(f"Verified lk and lk2: 2097152 private bytes with saved-file and repeat phone SHA-256 agreement. Output: {output}")
        print("Observed read agreement only; no atomic snapshot or restoration test was established.")
        return 0
    except AcquisitionError as error:
        # These messages are fixed local text or numeric transport status; no
        # subprocess stderr, remote metadata, password or raw image is included.
        print(f"Bootloader acquisition stopped: {error}", file=sys.stderr)
        print("Any retained .part files are incomplete private evidence; no completed result is reported.", file=sys.stderr)
        return 1
    except (ValueError, OSError, UnicodeError, EOFError, KeyboardInterrupt):
        print("Bootloader acquisition stopped; no completed result is reported. Check local permissions and the fixed profile.", file=sys.stderr)
        print("If an output directory was created, any retained .part files are incomplete private evidence.", file=sys.stderr)
        return 1
    finally:
        if remote is not None:
            remote.password = None
        os.umask(previous_umask)


if __name__ == "__main__":
    raise SystemExit(main())
