#!/usr/bin/env python3
"""Preserve only the measured Titan's fixed, non-partition GPT edge windows.

Normal-mode reads do not establish a snapshot, filesystem consistency, a
calibration backup or a recovery path. Repeated map/byte agreement records
observed stability; it cannot eliminate the race between a guard and a read.
The measured Titan's zero disk GUID is an explicit profile exception, reported
as a warning; it supplies no unique disk identity. Other GPT checks remain strict.
No command changes block flags, mounts, partitions, software or boot mode.
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
import tempfile


def sibling(module, filename):
    spec = importlib.util.spec_from_file_location(module, Path(__file__).with_name(filename))
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


acquisition = sibling("titan_gpt_acquisition_transport", "acquire-partitions.py")
gpt = sibling("titan_gpt_validator", "inspect-gpt.py")
AcquisitionError = acquisition.AcquisitionError
DISK_BYTES = 125074145280
DISK_SECTORS = 244285440
SECTOR_BYTES = 512
EDGE_SECTORS = 64
EDGE_BYTES = EDGE_SECTORS * SECTOR_BYTES
TAIL_START = DISK_SECTORS - EDGE_SECTORS
PARTITION_COUNT = 38
MAP_LIMIT = 32768
ANCHORS = {2: ("recovery", None, 65536), 28: ("boot", None, 65536),
           30: ("dtbo", None, 16384), 36: ("userdata", 10027008, 234137536)}


def guard_script(emit=False, privileged=True):
    """Fixed sysfs/ioctl checks; no block contents are read by this guard.

    The unprivileged form omits only the read-permission and ioctl checks, so
    the identity of this phone's disk and partition map can be established
    before any sudo credential is requested or sent.
    """
    readable = " && [ -r /dev/mmcblk0 ]" if privileged else ""
    ioctls = f"""[ "$(/usr/sbin/blockdev --getsize64 /dev/mmcblk0)" = {DISK_BYTES} ] || exit 17
[ "$(/usr/sbin/blockdev --getss /dev/mmcblk0)" = 512 ] || exit 18
[ "$(/usr/sbin/blockdev --getpbsz /dev/mmcblk0)" = 512 ] || exit 19
""" if privileged else ""
    script = f"""set -eu
export LC_ALL=C
[ ! -L /dev/mmcblk0 ] && [ -b /dev/mmcblk0 ]{readable} || exit 10
[ "$(readlink -f /dev/mmcblk0)" = /dev/mmcblk0 ] || exit 11
[ "$(cat /sys/class/block/mmcblk0/device/type)" = MMC ] || exit 12
[ "$(cat /sys/class/block/mmcblk0/removable)" = 0 ] || exit 13
[ "$(cat /sys/class/block/mmcblk0/size)" = {DISK_SECTORS} ] || exit 14
[ "$(cat /sys/class/block/mmcblk0/queue/logical_block_size)" = 512 ] || exit 15
[ "$(cat /sys/class/block/mmcblk0/queue/physical_block_size)" = 512 ] || exit 16
{ioctls}disk_sysfs=$(readlink -f /sys/class/block/mmcblk0)
case "$disk_sysfs" in /sys/devices/*/mmcblk0) ;; *) exit 20;; esac
canonical_decimal() {{
    case "$1" in ''|*[!0-9]*|0?*) exit 30;; esac
    [ "${{#1}}" -le 10 ] || exit 30
}}
check_node() {{
    node_name=$1
    expected_device=$2
    [ ! -L "/dev/$node_name" ] && [ -b "/dev/$node_name" ] || exit 21
    [ "$(readlink -f "/dev/$node_name")" = "/dev/$node_name" ] || exit 22
    node_hex=$(stat -c '%t:%T' "/dev/$node_name")
    case "$node_hex" in ''|*[!0-9a-fA-F:]*|:*|*:) exit 23;; esac
    node_major=${{node_hex%:*}}
    node_minor=${{node_hex#*:}}
    case "$node_major:$node_minor" in *:*:*) exit 23;; esac
    [ "${{#node_major}}" -le 8 ] && [ "${{#node_minor}}" -le 8 ] || exit 23
    [ "$((0x$node_major)):$((0x$node_minor))" = "$expected_device" ] || exit 24
}}
disk_device=$(cat /sys/class/block/mmcblk0/dev)
check_node mmcblk0 "$disk_device"
disk_hex=$node_hex
[ "$(readlink -f /dev/disk/by-partlabel/boot)" = /dev/mmcblk0p28 ] || exit 25
[ "$(readlink -f /dev/disk/by-partlabel/recovery)" = /dev/mmcblk0p2 ] || exit 26
[ "$(readlink -f /dev/disk/by-partlabel/dtbo)" = /dev/mmcblk0p30 ] || exit 27
[ "$(readlink -f /dev/disk/by-partlabel/userdata)" = /dev/mmcblk0p36 ] || exit 28
emit={1 if emit else 0}
if [ "$emit" = 1 ]; then
    printf 'DISK\\t/dev/mmcblk0\\tMMC\\t0\\t{DISK_SECTORS}\\t{DISK_BYTES}\\t512\\t512\\t%s\\t%s\\t%s\\n' "$disk_sysfs" "$disk_device" "$disk_hex"
fi
partition_count=0
for directory in /sys/class/block/mmcblk0p*; do
    [ -d "$directory" ] || exit 29
    name=${{directory##*/}}
    number=$(cat "$directory/partition")
    canonical_decimal "$number"
    [ "$name" = "mmcblk0p$number" ] && [ "$number" -ge 1 ] && [ "$number" -le 38 ] || exit 31
    parent=$(readlink -f "$directory")
    [ "$parent" = "$disk_sysfs/$name" ] || exit 32
    start=$(cat "$directory/start")
    size=$(cat "$directory/size")
    canonical_decimal "$start"
    canonical_decimal "$size"
    [ "$start" -ge {EDGE_SECTORS} ] && [ "$start" -le {TAIL_START} ] || exit 34
    [ "$size" -gt 0 ] && [ "$size" -le {TAIL_START} ] || exit 35
    [ "$((start + size))" -le {TAIL_START} ] || exit 36
    label=$(awk -F= -v name="$name" -v number="$number" '
        ($1 == "DEVNAME" || $1 == "DEVTYPE" || $1 == "PARTN" || $1 == "PARTNAME") && NF != 2 {{ bad=1 }}
        $1 == "DEVNAME" {{ devname=$2; names++ }}
        $1 == "DEVTYPE" {{ devtype=$2; types++ }}
        $1 == "PARTN" {{ partn=$2; numbers++ }}
        $1 == "PARTNAME" {{ label=$2; labels++ }}
        END {{ if (bad || names != 1 || types != 1 || numbers != 1 || labels != 1 || devname != name || devtype != "partition" || partn != number) exit 1; print label }}' "$directory/uevent")
    case "$label" in ''|*[!A-Za-z0-9._-]*) exit 37;; esac
    case "$number" in
      1) [ "$start" = 64 ] || exit 38;;
      2) [ "$label" = recovery ] && [ "$size" = 65536 ] || exit 39;;
      28) [ "$label" = boot ] && [ "$size" = 65536 ] || exit 40;;
      30) [ "$label" = dtbo ] && [ "$size" = 16384 ] || exit 41;;
      36) [ "$label" = userdata ] && [ "$start" = 10027008 ] && [ "$size" = 234137536 ] || exit 42;;
    esac
    device=$(cat "$directory/dev")
    check_node "$name" "$device"
    partition_count=$((partition_count + 1))
    [ "$partition_count" -le 38 ] || exit 43
    if [ "$emit" = 1 ]; then
        printf 'PART\\t%s\\t%s\\t%s\\t%s\\t%s\\t%s\\n' "$number" "$label" "$start" "$size" "$device" "$node_hex"
    fi
done
[ "$partition_count" = 38 ] || exit 44
if [ "$emit" = 1 ]; then printf 'END\\t38\\n'; fi
"""
    return script


def read_script(region):
    if region not in ("front", "tail"):
        raise ValueError("Only the two fixed GPT edge windows are supported.")
    skip = 0 if region == "front" else TAIL_START
    return guard_script() + f"dd if=/dev/mmcblk0 bs=512 skip={skip} count=64 iflag=fullblock status=none\n"


def decimal(value, maximum=DISK_SECTORS):
    if not re.fullmatch(r"0|[1-9][0-9]*", value) or len(value) > 20 or int(value) > maximum:
        raise AcquisitionError("Kernel map contains invalid or overflowing numeric metadata.")
    return int(value)


def device_identity(decimal_pair, hexadecimal_pair):
    if not re.fullmatch(r"(?:0|[1-9][0-9]*):(?:0|[1-9][0-9]*)", decimal_pair):
        raise AcquisitionError("Kernel map contains an invalid device identity.")
    if not re.fullmatch(r"[0-9a-fA-F]{1,8}:[0-9a-fA-F]{1,8}", hexadecimal_pair):
        raise AcquisitionError("Block node has an invalid device identity.")
    if tuple(map(int, decimal_pair.split(":"))) != tuple(int(v, 16) for v in hexadecimal_pair.split(":")):
        raise AcquisitionError("Block node and sysfs device identities do not match.")


def validate_map(data):
    if len(data) > MAP_LIMIT or not data.endswith(b"\n"):
        raise AcquisitionError("Kernel map exceeded its bound or was truncated.")
    try:
        lines = data.decode("ascii").splitlines()
    except UnicodeError as error:
        raise AcquisitionError("Kernel map is not unambiguous ASCII metadata.") from error
    if len(lines) != PARTITION_COUNT + 2 or lines[-1] != "END\t38":
        raise AcquisitionError("Kernel partition map is incomplete or has unexpected records.")
    disk = lines[0].split("\t")
    if len(disk) != 11 or disk[:8] != ["DISK", "/dev/mmcblk0", "MMC", "0",
            str(DISK_SECTORS), str(DISK_BYTES), "512", "512"]:
        raise AcquisitionError("Measured eMMC identity or geometry did not match.")
    if not re.fullmatch(r"/sys/devices/[A-Za-z0-9_./:@+-]+/mmcblk0", disk[8]):
        raise AcquisitionError("Unexpected canonical eMMC sysfs location.")
    device_identity(disk[9], disk[10])
    partitions, numbers, names, devices = [], set(), set(), {disk[9]}
    for line in lines[1:-1]:
        fields = line.split("\t")
        if len(fields) != 7 or fields[0] != "PART":
            raise AcquisitionError("Malformed kernel partition record.")
        number, start, sectors = decimal(fields[1], 38), decimal(fields[3]), decimal(fields[4])
        name = fields[2]
        if (number < 1 or number in numbers or name in names or fields[5] in devices
                or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}", name)):
            raise AcquisitionError("Duplicate or invalid kernel partition identity.")
        device_identity(fields[5], fields[6])
        if start < EDGE_SECTORS or not sectors or start + sectors > TAIL_START:
            raise AcquisitionError("A fixed GPT window overlaps a mapped partition.")
        if number == 1 and start != 64:
            raise AcquisitionError("The measured first-partition anchor changed.")
        if number in ANCHORS:
            expected_name, expected_start, expected_size = ANCHORS[number]
            if name != expected_name or sectors != expected_size or (expected_start is not None and start != expected_start):
                raise AcquisitionError("A measured Titan partition anchor changed.")
        numbers.add(number); names.add(name); devices.add(fields[5])
        partitions.append({"number": number, "name": name, "first_lba": start,
                           "last_lba": start + sectors - 1, "sectors": sectors,
                           "device_number": fields[5]})
    if numbers != set(range(1, PARTITION_COUNT + 1)):
        raise AcquisitionError("Kernel partition numbers do not match the measured complete set.")
    ordered = sorted(partitions, key=lambda item: item["first_lba"])
    if any(left["last_lba"] >= right["first_lba"] for left, right in zip(ordered, ordered[1:])):
        raise AcquisitionError("Kernel partition map contains overlapping partitions.")
    return {"device": "/dev/mmcblk0", "disk_bytes": DISK_BYTES, "disk_sectors": DISK_SECTORS,
            "logical_sector_bytes": 512, "physical_sector_bytes": 512, "sysfs": disk[8],
            "device_number": disk[9], "partitions": sorted(partitions, key=lambda item: item["number"])}


def probe(remote):
    data, count, _ = remote.run(guard_script(emit=True), MAP_LIMIT)
    if count != len(data):
        raise AcquisitionError("Kernel map transport byte count did not match.")
    return validate_map(data), data


def cross_check(parsed, kernel):
    keys = ("number", "name", "first_lba", "last_lba", "sectors")
    expected = [tuple(partition[key] for key in keys) for partition in kernel["partitions"]]
    try:
        if any(partition["first_lba"] < EDGE_SECTORS or partition["last_lba"] >= TAIL_START
               for partition in parsed["partitions"]):
            raise AcquisitionError("A fixed GPT window overlaps a GPT partition.")
        observed = sorted(tuple(partition[key] for key in keys) for partition in parsed["partitions"])
    except (KeyError, TypeError) as error:
        raise AcquisitionError("GPT validator returned an incomplete partition inventory.") from error
    if observed != expected:
        raise AcquisitionError("Validated GPT and complete kernel partition map disagree.")


def sync_directory(output):
    descriptor = os.open(output, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def manifest_write(output, manifest, durable=True):
    descriptor, name = tempfile.mkstemp(prefix=".manifest-", suffix=".part", dir=output)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write((json.dumps(manifest, indent=2) + "\n").encode())
            stream.flush()
            if durable:
                os.fsync(stream.fileno())
        os.replace(name, output / "manifest.json")
        if durable:
            sync_directory(output)
    finally:
        if os.path.exists(name):
            os.unlink(name)


def prepare_output(requested):
    if requested is not None and Path(requested).expanduser().is_symlink():
        raise ValueError("Private GPT output must not be a symlink.")
    candidate = Path(requested).expanduser().resolve() if requested else (
        Path(os.environ.get("XDG_STATE_HOME", Path.home() / ".local/state")) / "mobile-nixos/titan-recovery").resolve()
    if any((parent / ".jj").exists() for parent in (candidate, *candidate.parents)):
        raise ValueError("Private GPT output must be outside jj checkouts.")
    return acquisition.prepare_output(requested)


def acquire(remote, requested):
    # Permissions, complete identity and edge bounds must pass before output exists.
    baseline, raw_map = probe(remote)
    output = prepare_output(requested)
    manifest = {"format": 1, "status": "incomplete", "transport": "adb-shell-v2-no-pty",
        "created_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "scope": "two fixed GPT edge windows only; not a snapshot, calibration or filesystem backup",
        "helper_sources": acquisition.source_digests("acquire-gpt.py", "acquire-partitions.py",
                                                     "collect-inventory.py", "inspect-gpt.py"),
        "validation_policy": {"allow_zero_disk_guid": True,
            "reason": "observed on the measured original Titan; zero supplies no unique disk identity"},
        "warnings": [], "edge_bytes": EDGE_BYTES, "kernel_map": baseline, "regions": {}}
    published, partials, first, second = [], [], {}, {}
    try:
        manifest_write(output, manifest)
        raw_path = output / "kernel-map.txt.part"
        acquisition.inventory.write_private(raw_path, raw_map)
        with raw_path.open("rb") as stream:
            os.fsync(stream.fileno())
            if stream.read(MAP_LIMIT + 1) != raw_map:
                raise AcquisitionError("Saved kernel map readback did not match.")
        partials.append((raw_path, output / "kernel-map.txt"))
        for repeated, collection in ((False, first), (True, second)):
            for region in ("front", "tail"):
                current, _ = probe(remote)
                if current != baseline:
                    raise AcquisitionError("Kernel partition map changed during GPT acquisition.")
                if repeated:
                    data, count, digest = remote.run(read_script(region), EDGE_BYTES)
                else:
                    path = output / f"gpt-{region}.bin.part"
                    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
                    with os.fdopen(descriptor, "wb") as stream:
                        identity = os.fstat(stream.fileno())
                        _, count, digest = remote.run(read_script(region), EDGE_BYTES, sink=stream)
                        stream.flush()
                        os.fsync(stream.fileno())
                    partials.append((path, output / f"gpt-{region}.bin"))
                    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
                    with os.fdopen(descriptor, "rb") as saved:
                        metadata = os.fstat(saved.fileno())
                        if (not stat.S_ISREG(metadata.st_mode) or
                            (metadata.st_dev, metadata.st_ino) != (identity.st_dev, identity.st_ino)):
                            raise AcquisitionError("Saved GPT window identity changed before readback.")
                        data = saved.read(EDGE_BYTES + 1)
                if count != EDGE_BYTES or len(data) != EDGE_BYTES or hashlib.sha256(data).hexdigest() != digest:
                    raise AcquisitionError("GPT window count or independent saved-byte SHA-256 did not match.")
                collection[region] = data
                if repeated:
                    if data != first[region]:
                        raise AcquisitionError("Independent repeated GPT window bytes changed.")
                    manifest["regions"][region]["repeat_sha256"] = digest
                else:
                    manifest["regions"][region] = {"file": f"gpt-{region}.bin.part", "bytes": EDGE_BYTES,
                        "start_sector": 0 if region == "front" else TAIL_START, "sha256": digest,
                        "transfer_sha256": digest, "readback_sha256": digest}
            try:
                parsed = gpt.validate_gpt(collection["front"], collection["tail"], DISK_BYTES,
                                          SECTOR_BYTES, allow_zero_disk_guid=True)
            except gpt.GPTError as error:
                raise AcquisitionError("GPT structure validation failed; no metadata is marked verified.") from error
            cross_check(parsed, baseline)
            manifest["warnings"] = parsed["warnings"]
            manifest_write(output, manifest)
        final_map, _ = probe(remote)
        if final_map != baseline:
            raise AcquisitionError("Final kernel partition map changed.")
        manifest["gpt"] = parsed
        for pending, destination in partials:
            os.link(pending, destination)
            published.append((pending, destination))
        for pending, _ in published:
            pending.unlink()
        sync_directory(output)
        for region in manifest["regions"]:
            manifest["regions"][region]["file"] = f"gpt-{region}.bin"
        manifest["status"] = "complete"
        manifest_write(output, manifest)
        return output, manifest
    except BaseException as error:
        for pending, destination in reversed(published):
            if not pending.exists():
                os.link(destination, pending)
            destination.unlink()
        manifest["status"] = "incomplete"
        for region in manifest["regions"]:
            manifest["regions"][region]["file"] = f"gpt-{region}.bin.part"
        manifest["error"] = "Acquisition or verification failed; retained files are incomplete private evidence."
        manifest.pop("gpt", None)
        manifest_write(output, manifest, durable=False)
        raise


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--adb", default="adb")
    parser.add_argument("--serial")
    parser.add_argument("--output")
    parser.add_argument("--timeout", type=int, default=120)
    parser.add_argument("--sudo", action="store_true")
    args = parser.parse_args(argv)
    if args.timeout <= 0:
        parser.error("--timeout must be positive")
    remote = None
    previous_umask = os.umask(0o077)
    try:
        devices, _, _ = acquisition.run_bounded([args.adb, "devices", "-l"], 65536, args.timeout)
        serial = acquisition.inventory.select_usb_device(devices.decode(), args.serial)
        remote = acquisition.Remote(args.adb, serial, args.timeout)
        remote.check_protocol()
        # Establish this disk and its complete partition map as the unprivileged
        # USB ADB user before any credential is requested or sent.
        remote.run(guard_script(privileged=False))
        if args.sudo:
            remote.password = acquisition.prompt_password()
        output, manifest = acquire(remote, args.output)
        print(f"Both fixed GPT windows preserved with matching readback and repeat checks; private output: {output}")
        if "zero-disk-guid" in manifest["warnings"]:
            print("Warning: the observed GPT disk GUID is zero; it cannot identify this disk uniquely.")
        return 0
    except (AcquisitionError, ValueError, OSError, UnicodeError, EOFError, KeyboardInterrupt) as error:
        print(f"GPT acquisition stopped: {error}", file=sys.stderr)
        return 1
    finally:
        if remote is not None:
            remote.password = None
        os.umask(previous_umask)


if __name__ == "__main__":
    sys.exit(main())
