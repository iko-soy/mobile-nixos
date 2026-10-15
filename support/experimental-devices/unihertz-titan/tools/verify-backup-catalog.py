#!/usr/bin/env python3
"""Verify the fixed private Titan backup catalog on this host, without a phone.

Matching unsigned manifests establishes local integrity and layout agreement,
not unique device identity, an atomic snapshot, or a tested restoration path.
No images are copied. Sparse images are hashed over all their logical bytes.
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


def load_module(name, filename):
    spec = importlib.util.spec_from_file_location(name, Path(__file__).with_name(filename))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


firmware = load_module("titan_catalog_firmware", "acquire-firmware.py")
gpt = load_module("titan_catalog_gpt", "inspect-gpt.py")
DISK_BYTES = 125074145280
DISK_SECTORS = 244285440
JSON_LIMIT = 262144
CHUNK_BYTES = 1048576
TOTAL_BYTES = 8727773184
SYSFS_DISK = "/sys/devices/platform/bootdevice/mmc_host/mmc0/mmc0:0001/block/mmcblk0"
EXPECTED_LAYOUT = (
    (1, "boot_para", 64, 2048), (2, "recovery", 2112, 65536),
    (3, "para", 67648, 1024), (4, "expdb", 68672, 40960),
    (5, "frp", 109632, 2048), (6, "nvcfg", 111680, 65536),
    (7, "nvdata", 177216, 131072), (8, "metadata", 308288, 65536),
    (9, "protect1", 373824, 16384), (10, "protect2", 390208, 19392),
    (11, "seccfg", 409600, 16384), (12, "sec1", 425984, 4096),
    (13, "proinfo", 430080, 6144), (14, "md1img", 436224, 204800),
    (15, "spmfw", 641024, 2048), (16, "scp1", 643072, 12288),
    (17, "scp2", 655360, 12288), (18, "sspm_1", 667648, 2048),
    (19, "sspm_2", 669696, 2048), (20, "cam_vpu1", 671744, 30720),
    (21, "cam_vpu2", 702464, 30720), (22, "cam_vpu3", 733184, 30720),
    (23, "gz1", 763904, 32768), (24, "gz2", 796672, 32768),
    (25, "nvram", 829440, 131072), (26, "lk", 960512, 2048),
    (27, "lk2", 962560, 2048), (28, "boot", 964608, 65536),
    (29, "logo", 1030144, 16384), (30, "dtbo", 1046528, 16384),
    (31, "tee1", 1062912, 10240), (32, "tee2", 1073152, 24576),
    (33, "vendor", 1097728, 1753088), (34, "system", 2850816, 6291456),
    (35, "cache", 9142272, 884736), (36, "userdata", 10027008, 234137536),
    (37, "otp", 244164544, 88064), (38, "flashinfo", 244252608, 32768),
)
PROFILE = {
    "installed": {"format": 1, "field": "partitions", "files": {
        "boot": ("boot.img", 33554432), "recovery": ("recovery.img", 33554432),
        "dtbo": ("dtbo.img", 8388608)}},
    "bootloader-preservation/installed": {"format": "titan-private-bootloaders-v1",
        "field": "partitions", "files": {"lk": ("lk.img", 1048576), "lk2": ("lk2.img", 1048576)}},
    "os-partition-preservation/installed": {"format": "titan-private-os-partitions-v1",
        "field": "partitions", "files": {"vendor": ("vendor.img", 897581056), "system": ("system.img", 3221225472)}},
    "firmware-preservation/installed": {"format": "titan-private-firmware-v1",
        "field": "partitions", "files": {label: (label + ".img", item["bytes"])
            for label, item in firmware.TARGETS.items()}},
    "gpt-preservation/verified": {"format": 1, "field": "regions", "files": {
        "front": ("gpt-front.bin", 32768), "tail": ("gpt-tail.bin", 32768)}},
    "rootfs-files": {"format": None, "field": "files", "files": {
        "ubuntu": ("ubuntu.img", 3758096384), "android-rootfs": ("android-rootfs.img", 537280512)}},
}
REMAINING_GPT = tuple(sorted({row[1] for row in EXPECTED_LAYOUT} - {
    label for name, profile in PROFILE.items() if profile["field"] == "partitions"
    for label in profile["files"]}))
LIMITATIONS = [
    "Unsigned historical manifests are integrity references, not authenticated provenance.",
    "No CID or serial binds these sets; matching layout and a zero GPT disk GUID do not establish unique device identity.",
    "Separate live acquisitions and repeat hashes do not establish an atomic snapshot or global quiescence.",
    "This catalog verifies one local collection; it does not create or establish an independent backup copy.",
    "The early boot/recovery/dtbo manifest records partition numbers and sizes, but no acquired start offsets.",
    "The historical LK acquisition preceded the mountinfo short-read fix; its mount-check attestations do not prove complete mount-view coverage.",
    "The rootfs manifest has no format or timestamp and only historical boolean repeat/readback attestations; the rootfs files are not a userdata backup.",
    "Supplementary inspection/fsck logs are not revalidated or treated as hash-bound filesystem checks by this catalog.",
    "Calibration, control partitions and consistent userdata remain incomplete; RPMB is not preserved here.",
    "No restore, bootloader entry/return, rescue boot, or emergency recovery procedure is validated.",
]


class CatalogError(Exception):
    pass


def require(condition, message="Backup catalog validation failed."):
    if not condition:
        raise CatalogError(message)


def parsed_json(data):
    require(type(data) is bytes and 0 < len(data) <= JSON_LIMIT, "Manifest exceeds its fixed bound.")

    def unique(pairs):
        result = {}
        for key, value in pairs:
            require(key not in result, "Manifest contains a duplicate key.")
            result[key] = value
        return result

    def invalid_constant(_):
        raise CatalogError("Manifest contains a non-JSON number.")

    try:
        result = json.loads(data.decode("utf-8"), object_pairs_hook=unique, parse_constant=invalid_constant)
        require(type(result) is dict, "Manifest must be an object.")
        return result
    except (ValueError, UnicodeError, RecursionError) as error:
        raise CatalogError("Manifest is not bounded valid JSON.") from error


def normalize_layout(rows, gpt_style=False):
    require(type(rows) is list and len(rows) == 38, "Partition map is incomplete.")
    result = []
    for row in rows:
        require(type(row) is dict)
        first = "first_lba" if gpt_style else "start"
        require(all(type(row[key]) is int for key in ("number", first, "sectors")))
        require(type(row["name"]) is str)
        if gpt_style:
            require(type(row["last_lba"]) is int and row["last_lba"] == row[first] + row["sectors"] - 1)
        result.append((row["number"], row["name"], row[first], row["sectors"]))
    require(tuple(result) == EXPECTED_LAYOUT, "Partition map differs from the fixed measured layout.")
    return result


def digest_record(record, fields):
    values = [record[key] for key in fields]
    require(all(type(value) is str and re.fullmatch(r"[0-9a-f]{64}", value) for value in values)
            and len(set(values)) == 1, "Recorded SHA-256 values do not agree.")
    return values[0]


def validate_manifests(manifests):
    """Validate recognized historical schemas; do not reassert their live guards."""
    try:
        require(type(manifests) is dict and set(manifests) == set(PROFILE))
        specs, maps, parents = [], [], []
        for name, profile in PROFILE.items():
            document = manifests[name]
            require(type(document) is dict and document["status"] == "complete")
            require(type(document["scope"]) is str and 0 < len(document["scope"]) <= 1024)
            if profile["format"] is None:
                require("format" not in document and "created_utc" not in document)
            else:
                require(type(document["format"]) is type(profile["format"])
                        and document["format"] == profile["format"])
                require(document["transport"] == ("adb-shell-v2-no-pty" if type(profile["format"]) is int
                        else "adb-shell-v2-no-pty-framed-status"))
                require(type(document["created_utc"]) is str and 0 < len(document["created_utc"]) <= 64)
            entries = document[profile["field"]]
            require(type(entries) is dict and set(entries) == set(profile["files"]), "Backup targets differ from the fixed set.")
            for label, (filename, size) in profile["files"].items():
                record = entries[label]
                require(type(record) is dict and record["file"] == filename
                        and type(record["bytes"]) is int and record["bytes"] == size,
                        "Backup filename or size differs from the fixed profile.")
                fields = ("sha256", "transfer_sha256", "readback_sha256", "phone_repeat_sha256")
                if name == "installed":
                    fields = ("sha256", "transfer_sha256", "phone_sha256")
                    pre = record["preflight"]
                    number, _, _, sectors = next(row for row in EXPECTED_LAYOUT if row[1] == label)
                    require(pre == {"label": label, "device": f"/dev/mmcblk0p{number}",
                        "mmc_type": "MMC", "partition": str(number), "sectors": str(sectors),
                        "bytes": str(size), "sysfs": SYSFS_DISK + f"/mmcblk0p{number}",
                        "sysfs_disk": SYSFS_DISK, "device_number": f"179:{number}",
                        "block_device": "true", "readable": "true", "unmounted": "true", "holders": "none"})
                elif name == "rootfs-files":
                    fields = ("sha256",)
                    require(record["source_hash_before_and_after_match"] is True
                            and record["saved_file_readback_match"] is True)
                elif name == "gpt-preservation/verified":
                    fields = ("sha256", "transfer_sha256", "readback_sha256", "repeat_sha256")
                    require(type(record["start_sector"]) is int
                            and record["start_sector"] == (0 if label == "front" else DISK_SECTORS - 64))
                else:
                    require(record["geometry"] == document["kernel_map"]["targets"][label])
                specs.append({"set": name, "label": label, "file": filename, "bytes": size,
                              "sha256": digest_record(record, fields)})
            if name in ("bootloader-preservation/installed", "os-partition-preservation/installed", "firmware-preservation/installed"):
                require(type(document["bytes_preserved"]) is int
                        and document["bytes_preserved"] == sum(size for _, size in profile["files"].values()))
                require(type(document["validation"]) is dict and document["validation"]
                        and all(value is False for value in document["validation"].values()))
                flags = {"atomic_snapshot", "authentication_performed", "device_changes_performed", "restoration_tested"}
                if name != "bootloader-preservation/installed":
                    flags.add("global_quiescence")
                if name == "firmware-preservation/installed":
                    flags.add("firmware_immutability_proven")
                require(set(document["validation"]) == flags)
                validator = {"bootloader-preservation/installed": firmware.bootloaders.validate_evidence,
                             "os-partition-preservation/installed": firmware.os_partitions.validate_evidence,
                             "firmware-preservation/installed": firmware.validate_evidence}[name]
                validator(json.dumps(document["kernel_map"]).encode("ascii") + b"\n")
                kernel = document["kernel_map"]
                if name == "firmware-preservation/installed":
                    kernel = kernel["base"]
                maps.append(normalize_layout(kernel["partitions"]))
                parents.append(kernel["disk"])
        require(len(specs) == 27 and sum(item["bytes"] for item in specs) == TOTAL_BYTES)
        require(all(parent == parents[0] for parent in parents)
                and parents[0]["sysfs"] == SYSFS_DISK, "Parent geometry or identity differs across captures.")
        document = manifests["gpt-preservation/verified"]
        require(type(document["edge_bytes"]) is int and document["edge_bytes"] == 32768
                and document["validation_policy"]["allow_zero_disk_guid"] is True
                and document["warnings"] == ["zero-disk-guid"])
        kernel = document["kernel_map"]
        require({key: kernel[key] for key in kernel if key != "partitions"} == {
            "device": "/dev/mmcblk0", "disk_bytes": DISK_BYTES, "disk_sectors": DISK_SECTORS,
            "logical_sector_bytes": 512, "physical_sector_bytes": 512,
            "sysfs": SYSFS_DISK, "device_number": parents[0]["device_number"]})
        require(all(type(kernel[key]) is int for key in ("disk_bytes", "disk_sectors", "logical_sector_bytes", "physical_sector_bytes")))
        maps.append(normalize_layout(kernel["partitions"], True))
        maps.append(normalize_layout(document["gpt"]["partitions"], True))
        require(all(item == maps[0] for item in maps))
        return {"payloads": specs, "layout": maps[0], "parent": parents[0]}
    except (KeyError, TypeError, AttributeError, StopIteration, ValueError, firmware.AcquisitionError) as error:
        raise CatalogError("Manifest schema or historical geometry does not match the fixed profile.") from error


def file_identity(metadata):
    return (metadata.st_dev, metadata.st_ino, metadata.st_mode, metadata.st_uid,
            metadata.st_nlink, metadata.st_size, metadata.st_mtime_ns, metadata.st_ctime_ns)


def directory_identity(metadata):
    return metadata.st_dev, metadata.st_ino, metadata.st_mode, metadata.st_uid


def check_regular(metadata, expected=None):
    require(stat.S_ISREG(metadata.st_mode) and metadata.st_uid == os.getuid()
            and stat.S_IMODE(metadata.st_mode) == 0o600 and metadata.st_nlink == 1,
            "Input must be an owned private regular file with one link.")
    if expected is not None:
        require(metadata.st_size == expected, "Input length differs from the fixed profile.")


class PrivateTree:
    """Retain directory handles, rejecting symlinks on every path component."""
    def __init__(self, requested):
        self.path = Path(os.path.abspath(os.fspath(Path(requested).expanduser())))
        require(self.path != Path("/") and not self.path.is_relative_to("/nix"),
                "Private backup paths must be outside /nix.")
        self.links, self.fds, self.children = [], [], {}
        try:
            fd = os.open("/", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
            self.fds.append(fd)
            self._outside_checkout(fd)
            for component in self.path.parts[1:]:
                fd = self._open_directory(fd, component, False)
            self.fd = fd
            self._private_directory(os.fstat(fd))
        except BaseException:
            self.close()
            raise

    @staticmethod
    def _private_directory(metadata):
        require(stat.S_ISDIR(metadata.st_mode) and metadata.st_uid == os.getuid()
                and stat.S_IMODE(metadata.st_mode) == 0o700, "Backup directories must be owned and mode 0700.")

    @staticmethod
    def _outside_checkout(fd):
        for name in (".git", ".jj"):
            try:
                os.stat(name, dir_fd=fd, follow_symlinks=False)
            except FileNotFoundError:
                continue
            raise CatalogError("Private backup paths must be outside every Git or jj checkout.")

    def _open_directory(self, parent, name, private):
        before = os.stat(name, dir_fd=parent, follow_symlinks=False)
        require(stat.S_ISDIR(before.st_mode), "Backup directory cannot be a symlink or another file type.")
        if private:
            self._private_directory(before)
        fd = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=parent)
        self.fds.append(fd)
        identity = directory_identity(before)
        require(directory_identity(os.fstat(fd)) == identity, "Directory changed while opening.")
        self._outside_checkout(fd)
        self.links.append((parent, name, fd, identity, private))
        return fd

    def directory(self, relative):
        require(relative in PROFILE, "Unknown backup set.")
        fd, prefix = self.fd, ""
        for component in relative.split("/"):
            prefix = prefix + "/" + component if prefix else component
            if prefix not in self.children:
                self.children[prefix] = self._open_directory(fd, component, True)
            fd = self.children[prefix]
        return fd

    def recheck(self):
        self._private_directory(os.fstat(self.fd))
        for parent, name, fd, identity, private in self.links:
            require(directory_identity(os.stat(name, dir_fd=parent, follow_symlinks=False)) == identity
                    and directory_identity(os.fstat(fd)) == identity, "Backup directory identity changed.")
            if private:
                self._private_directory(os.fstat(fd))
            self._outside_checkout(fd)

    def close(self):
        for fd in reversed(self.fds):
            os.close(fd)
        self.fds.clear()


class PrivateFile:
    def __init__(self, directory, name, expected=None):
        require(type(name) is str and re.fullmatch(r"[a-zA-Z0-9_.-]+", name)
                and name not in (".", ".."))
        self.directory, self.name, self.fd = directory, name, -1
        before = os.stat(name, dir_fd=directory, follow_symlinks=False)
        check_regular(before, expected)  # Refuse devices/FIFOs before opening.
        try:
            self.fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC, dir_fd=directory)
            self.metadata = os.fstat(self.fd)
            check_regular(self.metadata, expected)
            require(file_identity(self.metadata) == file_identity(before), "File changed while opening.")
        except BaseException:
            self.close()
            raise

    def recheck(self):
        require(file_identity(os.fstat(self.fd)) == file_identity(self.metadata)
                and file_identity(os.stat(self.name, dir_fd=self.directory, follow_symlinks=False))
                == file_identity(self.metadata), "Input changed during catalog verification.")

    def read_small(self, limit):
        require(0 < self.metadata.st_size <= limit, "Metadata exceeds its fixed bound.")
        os.lseek(self.fd, 0, os.SEEK_SET)
        chunks, remaining = [], self.metadata.st_size
        while remaining:
            chunk = os.read(self.fd, min(65536, remaining))
            require(chunk, "Metadata ended early.")
            chunks.append(chunk)
            remaining -= len(chunk)
        require(not os.read(self.fd, 1), "Metadata exceeds its recorded length.")
        self.recheck()
        return b"".join(chunks)

    def close(self):
        if self.fd >= 0:
            os.close(self.fd)
            self.fd = -1


def hash_payload(fd, expected_bytes):
    """Hash an already checked regular file in bounded chunks, including holes."""
    require(type(expected_bytes) is int and 0 < expected_bytes <= TOTAL_BYTES)
    require(os.lseek(fd, 0, os.SEEK_CUR) == 0, "Payload hashing must start at offset zero.")
    digest, remaining = hashlib.sha256(), expected_bytes
    while remaining:
        chunk = os.read(fd, min(CHUNK_BYTES, remaining))
        require(chunk, "Payload ended before its fixed byte count.")
        remaining -= len(chunk)
        digest.update(chunk)
    require(not os.read(fd, 1), "Payload exceeds its fixed byte count.")
    return digest.hexdigest()


class CatalogOutput:
    def __init__(self, requested):
        self.path = Path(os.path.abspath(os.fspath(Path(requested).expanduser())))
        require(self.path.name not in ("", ".", ".."))
        self.parent, self.fd, self.owned = None, -1, None
        try:
            self.parent = PrivateTree(self.path.parent)
            os.mkdir(self.path.name, 0o700, dir_fd=self.parent.fd)
            self.fd = self.parent._open_directory(self.parent.fd, self.path.name, True)
            self.parent.recheck()
            os.fsync(self.parent.fd)
        except BaseException:
            self.close()
            raise

    def publish(self, report, recheck_inputs):
        data = (json.dumps(report, indent=2, sort_keys=True) + "\n").encode("ascii")
        require(len(data) <= JSON_LIMIT, "Catalog exceeds its fixed bound.")
        fd = os.open("catalog.json.part", os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                     0o600, dir_fd=self.fd)
        linked, saved, published_identity = False, None, None
        try:
            os.fchmod(fd, 0o600)
            initial = os.fstat(fd)
            self.owned = (initial.st_dev, initial.st_ino)
            with os.fdopen(fd, "wb") as stream:
                fd = -1
                require(stream.write(data) == len(data), "Catalog write was incomplete.")
                stream.flush()
                os.fsync(stream.fileno())
            saved = PrivateFile(self.fd, "catalog.json.part", len(data))
            require((saved.metadata.st_dev, saved.metadata.st_ino) == self.owned,
                    "Partial catalog identity changed before readback.")
            require(hash_payload(saved.fd, len(data)) == hashlib.sha256(data).hexdigest(), "Catalog readback failed.")
            saved.recheck()
            self.parent.recheck()
            recheck_inputs()
            saved.recheck()
            os.link("catalog.json.part", "catalog.json", src_dir_fd=self.fd, dst_dir_fd=self.fd, follow_symlinks=False)
            linked = True
            # The final name is newly ours even if the pending path changed
            # during link(). Record that alias for identity-matched rollback,
            # and reject it before proceeding unless it is the held inode.
            linked_metadata = os.stat("catalog.json", dir_fd=self.fd, follow_symlinks=False)
            published_identity = linked_metadata.st_dev, linked_metadata.st_ino
            require(published_identity == self.owned, "Catalog identity changed at publication.")
            os.fsync(self.fd)
            os.unlink("catalog.json.part", dir_fd=self.fd)
            os.fsync(self.fd)
            os.fsync(self.parent.fd)
            self.parent.recheck()
            published = PrivateFile(self.fd, "catalog.json", len(data))
            try:
                require((published.metadata.st_dev, published.metadata.st_ino) == self.owned)
                require(hash_payload(published.fd, len(data)) == hashlib.sha256(data).hexdigest())
                published.recheck()
                recheck_inputs()
                self.parent.recheck()
            finally:
                published.close()
        except BaseException:
            if linked:
                try:
                    metadata = os.stat("catalog.json", dir_fd=self.fd, follow_symlinks=False)
                    if published_identity is not None and (metadata.st_dev, metadata.st_ino) == published_identity:
                        os.unlink("catalog.json", dir_fd=self.fd)
                        os.fsync(self.fd)
                except OSError:
                    pass
            raise
        finally:
            if saved is not None:
                saved.close()
            if fd >= 0:
                os.close(fd)

    def close(self):
        if self.parent is not None:
            self.parent.close()
            self.parent = None
        self.fd = -1


def verify_catalog(backup_root, output):
    """Verify all fixed sets, then exclusively publish one private catalog.json."""
    tree, destination, held = None, None, []
    try:
        tree = PrivateTree(backup_root)
        manifests, manifest_hashes = {}, {}
        for name in PROFILE:
            item = PrivateFile(tree.directory(name), "manifest.json")
            held.append(item)
            data = item.read_small(JSON_LIMIT)
            manifests[name] = parsed_json(data)
            manifest_hashes[name] = hashlib.sha256(data).hexdigest()
        validated = validate_manifests(manifests)
        destination = CatalogOutput(output)
        report = {"format": "titan-private-backup-catalog-v1", "status": "complete",
            "created_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "payload_count": 27, "logical_bytes": TOTAL_BYTES, "sets": {},
            "layout": [{"number": n, "name": name, "start": start, "sectors": sectors}
                       for n, name, start, sectors in validated["layout"]],
            "parent": validated["parent"], "remaining_gpt_names": list(REMAINING_GPT),
            "limitations": LIMITATIONS, "validation": {"local_payload_hashes": True,
                "layout_agreement": True, "gpt_reparsed": True, "unique_device_identity": False,
                "authenticated_provenance": False, "atomic_snapshot": False,
                "independent_backup_copy": False, "restore_ready": False}}
        for name in PROFILE:
            report["sets"][name] = {"manifest_file": name + "/manifest.json",
                "manifest_sha256": manifest_hashes[name], "historical_scope": manifests[name]["scope"],
                "historical_created_utc": manifests[name].get("created_utc"), "files": {}}
        edges = {}
        for spec in validated["payloads"]:
            name, label = spec["set"], spec["label"]
            print(f"Checking private payload {len(held) - len(PROFILE) + 1}/27.", file=sys.stderr)
            item = PrivateFile(tree.directory(name), spec["file"], spec["bytes"])
            held.append(item)
            actual = hash_payload(item.fd, spec["bytes"])
            require(actual == spec["sha256"], "Saved payload SHA-256 differs from its manifest.")
            item.recheck()
            report["sets"][name]["files"][label] = {"file": spec["file"], "expected_bytes": spec["bytes"],
                "actual_bytes": item.metadata.st_size, "allocated_bytes": item.metadata.st_blocks * 512,
                "expected_sha256": spec["sha256"], "actual_sha256": actual}
            if name == "gpt-preservation/verified":
                edges[label] = item.read_small(32768)
                require(hashlib.sha256(edges[label]).hexdigest() == actual, "GPT bytes changed before parsing.")
        try:
            inspection = gpt.validate_gpt(edges["front"], edges["tail"], DISK_BYTES, 512, allow_zero_disk_guid=True)
        except gpt.GPTError as error:
            raise CatalogError("Preserved GPT regions failed structural validation.") from error
        require(json.dumps(inspection, sort_keys=True) == json.dumps(manifests["gpt-preservation/verified"]["gpt"], sort_keys=True),
                "Reparsed GPT differs from its recorded report.")
        require(inspection["warnings"] == ["zero-disk-guid"])
        require(normalize_layout(inspection["partitions"], True) == validated["layout"])
        report["gpt"] = inspection

        def recheck_inputs():
            tree.recheck()
            for item in held:
                item.recheck()

        recheck_inputs()
        destination.publish(report, recheck_inputs)
        return report
    finally:
        for item in reversed(held):
            item.close()
        if destination is not None:
            destination.close()
        if tree is not None:
            tree.close()


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--backup-root", required=True, help="existing private root containing the six fixed sets")
    parser.add_argument("--output", required=True, help="fresh private output directory outside Git, jj and /nix; parent must exist")
    args = parser.parse_args(argv)
    previous_umask = os.umask(0o077)
    try:
        report = verify_catalog(args.backup_root, args.output)
        print(f"Verified {report['payload_count']} payloads; {report['logical_bytes']} logical bytes.")
        return 0
    except CatalogError as error:
        print(f"Backup catalog verification failed: {error}", file=sys.stderr)
        print("No completed catalog is reported.", file=sys.stderr)
        return 1
    except (OSError, ValueError, UnicodeError, EOFError, KeyboardInterrupt):
        print("Backup catalog verification failed; no completed catalog is reported.", file=sys.stderr)
        return 1
    finally:
        os.umask(previous_umask)


if __name__ == "__main__":
    raise SystemExit(main())
