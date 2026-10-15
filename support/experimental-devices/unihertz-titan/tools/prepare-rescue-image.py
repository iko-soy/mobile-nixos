#!/usr/bin/env python3
"""Prepare a private, unsigned Titan rescue envelope locally; never contact a phone.

Only the reviewed installed boot and USB rescue ramdisk hashes are accepted.
No private input is submitted to Nix, an external executable, or a repository.
The output has no AVB metadata and is not evidence of bootloader acceptance,
hardware bootability, storage consistency or a working recovery procedure.
"""

import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import stat
import struct
import sys


BOOT_BYTES = 33554432
BOOT_SHA256 = "6829a8bcaa696a6fe283184a874450357dd81e7e203eedaf79329bdc55745e83"
KERNEL_BYTES = 9537534
KERNEL_SHA256 = "f11ae9a7d90cdd9f1bad0b59b79b38c83ff9fd9f11133b119d480a60e9621787"
DTB_BYTES = 112135
DTB_SHA256 = "51a6baed284c9caaec627cf402c4925db133856a4eecbaa87cfefe070915ce69"
RAMDISK_BYTES = 3054712
RAMDISK_SHA256 = "27d2a3da8f23391a4d280eb37fd145a8f63b13a6a051b969a23bcac6ca6aed88"
SOURCE_CMDLINE = (
    "bootopt=64S3,32N2,64N2 buildvariant=user "
    "systempart=/dev/disk/by-partlabel/system halium_lvm_vg=ubports "
    "security=apparmor rodata=0 init=/init"
)
# rodata=0 is an inherited compatibility assumption, not proven necessary.
# Removing the UT selectors and naming this PID1 does not override any later
# bootloader command-line additions; those still require hardware review.
RESCUE_CMDLINE = (
    "bootopt=64S3,32N2,64N2 buildvariant=user security=apparmor rodata=0 "
    "rdinit=/init init=/init panic=0"
)
IMAGE_NAME = "UNTESTED-UNSIGNED-rescue.img"
MANIFEST_NAME = "manifest.json"
PAGE_SIZE = 2048
HEADER_SIZE = 1660
MKBOOTIMG_REV = "40a19c4c5ffe8b86c6c61318c8aa4ffe35d6e7ad"


class PreparationError(ValueError):
    """A fixed input, privacy or publication requirement was not met."""


def require(condition, message):
    if not condition:
        raise PreparationError(message)


def load_tool(filename, name):
    spec = importlib.util.spec_from_file_location(name, Path(__file__).with_name(filename))
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


boot_inspector = load_tool("inspect-boot-image.py", "titan_rescue_boot_inspector")


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def legacy_image_id(kernel, ramdisk, dtb):
    """Match pinned Lineage mkbootimg v2 ID, including its empty legacy-dt slot.

    This SHA-1 field is format compatibility metadata, never authentication.
    https://github.com/LineageOS/android_system_tools_mkbootimg/blob/
    40a19c4c5ffe8b86c6c61318c8aa4ffe35d6e7ad/mkbootimg.py
    """
    digest = hashlib.sha1(usedforsecurity=False)
    for payload in (kernel, ramdisk, b"", b"", b"", dtb):
        digest.update(payload)
        digest.update(struct.pack("<I", len(payload)))
    return digest.digest() + bytes(12)


def command_fields(command):
    encoded = command.encode("ascii")
    require(b"\0" not in encoded and len(encoded) <= 1534, "Invalid fixed command line.")
    return (encoded[:511] + b"\0").ljust(512, b"\0"), (encoded[511:] + b"\0").ljust(1024, b"\0")


def payload(data, info, name):
    region = info["segments"][name]
    return data[region["offset"]:region["end"]]


def validate_boot(data):
    require(type(data) is bytes and len(data) == BOOT_BYTES, "Installed boot byte count does not match the reviewed copy.")
    require(sha256(data) == BOOT_SHA256, "Installed boot SHA-256 does not match the reviewed copy.")
    try:
        info = boot_inspector.inspect_image(data)
        require(not boot_inspector.titan_errors(info), "Installed boot does not match the fixed Titan profile.")
    except boot_inspector.ImageFormatError as error:
        raise PreparationError("Installed boot geometry is invalid.") from error
    require(info["segments"]["second"]["size"] == 0 and info["load_addresses"]["second"] == 0
            and info["segments"]["recovery_dtbo"]["size"] == 0
            and info["recovery_dtbo_header_offset"] == 0,
            "Installed boot contains an unexpected secondary payload.")
    source_first, source_extra = command_fields(SOURCE_CMDLINE)
    require(data[48:64] == bytes(16) and data[64:576] == source_first and data[608:1632] == source_extra,
            "Installed boot board or command-line bytes differ from the reviewed profile.")
    require(data[HEADER_SIZE:PAGE_SIZE] == bytes(PAGE_SIZE - HEADER_SIZE), "Installed boot header padding is not canonical.")
    kernel, original_ramdisk, dtb = (payload(data, info, name) for name in ("kernel", "ramdisk", "dtb"))
    require(len(kernel) == KERNEL_BYTES and sha256(kernel) == KERNEL_SHA256,
            "Installed kernel differs from the reviewed payload.")
    require(len(dtb) == DTB_BYTES and sha256(dtb) == DTB_SHA256,
            "Installed DTB differs from the reviewed payload.")
    table = info["dtb"]
    require(table["format"] == "android-dt-table" and table["version"] == 0
            and table["header_size"] == 32 and table["entry_size"] == 32
            and table["page_size"] == PAGE_SIZE and table["total_size"] == len(dtb)
            and table["trailing_bytes"] == 0 and len(table["entries"]) == 1
            and table["entries"][0]["offset"] == 64,
            "Installed DTB table differs from the fixed profile.")
    require(data[576:608] == legacy_image_id(kernel, original_ramdisk, dtb),
            "Installed boot legacy image ID differs from the pinned assembler convention.")
    return info, kernel, dtb


def validate_ramdisk(data):
    require(type(data) is bytes and len(data) == RAMDISK_BYTES, "USB rescue ramdisk byte count differs from the reviewed build.")
    require(sha256(data) == RAMDISK_SHA256, "USB rescue ramdisk SHA-256 differs from the reviewed build.")
    inspector = load_tool("inspect-rescue-ramdisk.py", "titan_private_rescue_ramdisk_inspector")
    try:
        return inspector.inspect_ramdisk(data)
    except inspector.RamdiskFormatError as error:
        raise PreparationError("USB rescue ramdisk archive validation failed.") from error


def assemble_image(boot, ramdisk):
    """Return (raw envelope bytes, private manifest); no filesystem or subprocess I/O."""
    original, kernel, dtb = validate_boot(boot)
    ramdisk_report = validate_ramdisk(ramdisk)
    # Rebuild the narrow v2 envelope explicitly. No inherited padding, AVB or
    # authentication bytes are copied. Only reviewed payloads and fixed fields.
    header = bytearray(PAGE_SIZE)
    header[:8] = b"ANDROID!"
    struct.pack_into("<10I", header, 8, len(kernel), 0x40080000, len(ramdisk),
                     0x55000000, 0, 0, 0x54000000, PAGE_SIZE, 2, (10 << 25) | (25 << 4) | 8)
    first, extra = command_fields(RESCUE_CMDLINE)
    header[64:576] = first
    header[576:608] = legacy_image_id(kernel, ramdisk, dtb)
    header[608:1632] = extra
    struct.pack_into("<IQIIQ", header, 1632, 0, 0, HEADER_SIZE, len(dtb), 0x54000000)
    image = bytes(header)
    for section in (kernel, ramdisk, dtb):
        image += section + bytes((-len(section)) % PAGE_SIZE)
    require(len(image) <= BOOT_BYTES, "Rescue envelope exceeds the fixed boot partition capacity.")
    try:
        inspected = boot_inspector.inspect_image(image)
    except boot_inspector.ImageFormatError as error:
        raise PreparationError("Generated rescue envelope failed independent geometry inspection.") from error
    require(inspected["avb"] is None and len(image) == inspected["padded_payload_end"]
            and inspected["load_addresses"] == original["load_addresses"]
            and inspected["cmdline"] == RESCUE_CMDLINE
            and payload(image, inspected, "kernel") == kernel
            and payload(image, inspected, "dtb") == dtb
            and payload(image, inspected, "ramdisk") == ramdisk,
            "Generated rescue envelope failed preservation checks.")
    manifest = {
        "format": "titan-private-usb-rescue-envelope-v1",
        "status": "prepared-build-only",
        "inputs": {
            "installed_boot": {"bytes": len(boot), "sha256": sha256(boot)},
            "kernel": {"bytes": len(kernel), "sha256": sha256(kernel)},
            "dtb": {"bytes": len(dtb), "sha256": sha256(dtb)},
            "usb_ramdisk": ramdisk_report,
        },
        "image": {"file": IMAGE_NAME, "bytes": len(image), "sha256": sha256(image),
                  "legacy_image_id": image[576:608].hex(), "inspection": inspected},
        "policy": {
            "source_cmdline": SOURCE_CMDLINE, "rescue_cmdline": RESCUE_CMDLINE,
            "rodata_zero": "inherited compatibility assumption, not proven necessary",
            "mkbootimg_reference_revision": MKBOOTIMG_REV,
            "avb_metadata_included": False, "authentication_performed": False,
            "full_partition_image": False, "partition_capacity_bytes": BOOT_BYTES,
            "bootability_verified": False, "bootloader_acceptance_verified": False,
            "recovery_procedure_verified": False, "device_action_performed": False,
        },
    }
    return image, manifest


def private_path(value):
    path = Path(os.path.abspath(os.fspath(Path(value).expanduser())))
    require(path.name not in ("", ".", ".."), "A named local file or directory is required.")
    # Resolve parents only: the leaf must still be checked without following a
    # symlink. Every existing ancestor is considered for repository/store scope.
    path = path.parent.resolve(strict=True) / path.name
    require(path != Path("/nix") and Path("/nix") not in path.parents,
            "Private preparation paths must be outside the Nix store and its root.")
    for parent in (path.parent, *path.parent.parents):
        require(not os.path.lexists(parent / ".git") and not os.path.lexists(parent / ".jj"),
                "Private preparation paths must be outside every repository.")
    return path


def identity(metadata):
    return (metadata.st_dev, metadata.st_ino, metadata.st_size, metadata.st_mode,
            metadata.st_uid, metadata.st_nlink, metadata.st_mtime_ns, metadata.st_ctime_ns)


class PrivateInput:
    def __init__(self, path, expected_bytes):
        self.path = private_path(path)
        self.fd = -1
        try:
            self.metadata = os.stat(self.path, follow_symlinks=False)
            require(stat.S_ISREG(self.metadata.st_mode), "Inputs must be regular files, never devices or pipes.")
            require(self.metadata.st_uid == os.getuid() and self.metadata.st_nlink == 1
                    and stat.S_IMODE(self.metadata.st_mode) in (0o400, 0o600),
                    "Inputs must be privately owned files with mode 0400 or 0600 and one link.")
            require(self.metadata.st_size == expected_bytes, "Input byte count differs from the fixed reviewed artifact.")
            self.fd = os.open(self.path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
            require(identity(os.fstat(self.fd)) == identity(self.metadata), "Input identity changed while opening it.")
            parts, total = [], 0
            while True:
                chunk = os.read(self.fd, min(1048576, expected_bytes + 1 - total))
                if not chunk:
                    break
                parts.append(chunk)
                total += len(chunk)
                require(total <= expected_bytes, "Input grew beyond its fixed byte count.")
            require(total == expected_bytes, "Input ended before its fixed byte count.")
            self.data = b"".join(parts)
            self.recheck()
        except BaseException:
            self.close()
            raise

    def recheck(self):
        require(identity(os.fstat(self.fd)) == identity(self.metadata)
                and identity(os.stat(self.path, follow_symlinks=False)) == identity(self.metadata),
                "Input identity or metadata changed during preparation.")

    def close(self):
        if self.fd >= 0:
            os.close(self.fd)
            self.fd = -1


def write_private(directory_fd, name, data):
    fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                 0o600, dir_fd=directory_fd)
    try:
        os.fchmod(fd, 0o600)
        position = 0
        while position < len(data):
            amount = os.write(fd, memoryview(data)[position:position + 1048576])
            require(amount > 0, "Private output write did not make progress.")
            position += amount
        os.fsync(fd)
        metadata = os.fstat(fd)
    finally:
        os.close(fd)
    fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=directory_fd)
    try:
        require(identity(os.fstat(fd)) == identity(metadata), "Private output identity changed before readback.")
        digest, total = hashlib.sha256(), 0
        while True:
            chunk = os.read(fd, min(1048576, len(data) + 1 - total))
            if not chunk:
                break
            total += len(chunk)
            require(total <= len(data), "Private output grew during readback.")
            digest.update(chunk)
        require(total == len(data) and digest.hexdigest() == sha256(data)
                and identity(os.fstat(fd)) == identity(metadata), "Private output readback verification failed.")
    finally:
        os.close(fd)
    return metadata.st_dev, metadata.st_ino


def prepare(boot_path, ramdisk_path, output_path):
    output = private_path(output_path)
    require(not os.path.lexists(output), "Output must be a new private directory.")
    boot = ramdisk = None
    directory_fd = parent_fd = -1
    owned = {}
    try:
        boot = PrivateInput(boot_path, BOOT_BYTES)
        ramdisk = PrivateInput(ramdisk_path, RAMDISK_BYTES)
        image, manifest = assemble_image(boot.data, ramdisk.data)
        boot.recheck()
        ramdisk.recheck()
        parent_fd = os.open(output.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
        parent_metadata = os.fstat(parent_fd)
        parent_identity = (parent_metadata.st_dev, parent_metadata.st_ino)
        require(parent_metadata.st_uid == os.getuid() and not (stat.S_IMODE(parent_metadata.st_mode) & 0o022)
                and identity(os.stat(output.parent, follow_symlinks=False))[:2] == parent_identity,
                "Output parent must be owned by this user and not writable by group or others.")
        require(private_path(output) == output, "Output parent changed during preparation.")
        os.mkdir(output.name, 0o700, dir_fd=parent_fd)
        created_directory = os.stat(output.name, dir_fd=parent_fd, follow_symlinks=False)
        directory_fd = os.open(output.name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                               dir_fd=parent_fd)
        opened_directory = os.fstat(directory_fd)
        require(stat.S_ISDIR(created_directory.st_mode) and created_directory.st_uid == os.getuid()
                and identity(created_directory)[:2] == identity(opened_directory)[:2],
                "New output directory identity changed while opening it.")
        os.fchmod(directory_fd, 0o700)
        directory_identity = identity(os.fstat(directory_fd))[:2]
        os.fsync(parent_fd)
        report = (json.dumps(manifest, indent=2, sort_keys=True) + "\n").encode("utf-8")
        for name, data in ((IMAGE_NAME, image), (MANIFEST_NAME, report)):
            pending = name + ".partial"
            owned[pending] = write_private(directory_fd, pending, data)
        boot.recheck()
        ramdisk.recheck()
        require(identity(os.stat(output.name, dir_fd=parent_fd, follow_symlinks=False))[:2] == directory_identity
                and identity(os.stat(output.parent, follow_symlinks=False))[:2] == parent_identity
                and private_path(output) == output,
                "Output directory identity changed before publication.")
        for name in (IMAGE_NAME, MANIFEST_NAME):
            pending = name + ".partial"
            # Hard-link publication is exclusive; it never replaces a file.
            os.link(pending, name, src_dir_fd=directory_fd, dst_dir_fd=directory_fd, follow_symlinks=False)
            owned[name] = owned[pending]
            os.unlink(pending, dir_fd=directory_fd)
            del owned[pending]
        os.fsync(directory_fd)
        os.fsync(parent_fd)
        require(identity(os.stat(output.name, dir_fd=parent_fd, follow_symlinks=False))[:2] == directory_identity
                and identity(os.stat(output.parent, follow_symlinks=False))[:2] == parent_identity
                and private_path(output) == output,
                "Output directory identity changed during publication.")
        for name, expected_size in ((IMAGE_NAME, len(image)), (MANIFEST_NAME, len(report))):
            published = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
            require(identity(published)[:2] == owned[name] and stat.S_ISREG(published.st_mode)
                    and published.st_uid == os.getuid() and published.st_nlink == 1
                    and stat.S_IMODE(published.st_mode) == 0o600 and published.st_size == expected_size,
                    "Published output identity or privacy changed.")
        return manifest
    except BaseException:
        # Remove only outputs whose inode still matches this operation. A
        # partial output is never a completed rescue image or backup result.
        if directory_fd >= 0:
            for name, expected in owned.items():
                try:
                    metadata = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
                    if (metadata.st_dev, metadata.st_ino) == expected:
                        os.unlink(name, dir_fd=directory_fd)
                except OSError:
                    pass
        raise
    finally:
        if directory_fd >= 0:
            os.close(directory_fd)
        if parent_fd >= 0:
            os.close(parent_fd)
        if ramdisk is not None:
            ramdisk.close()
        if boot is not None:
            boot.close()


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--boot", required=True, type=Path, help="private reviewed installed boot copy (0400/0600)")
    parser.add_argument("--ramdisk", required=True, type=Path, help="private exact reviewed USB ramdisk copy (0400/0600)")
    parser.add_argument("--output", required=True, type=Path, help="new private directory outside Git/jj and /nix")
    args = parser.parse_args(argv)
    try:
        report = prepare(args.boot, args.ramdisk, args.output)
    except PreparationError as error:
        print(f"Preparation refused: {error}", file=sys.stderr)
        return 1
    except OSError:
        print("Preparation failed during a local file operation; no completed result is reported.", file=sys.stderr)
        return 1
    print(f"Prepared {IMAGE_NAME}: {report['image']['bytes']} bytes, SHA-256 {report['image']['sha256']}.")
    print("Unsigned build-only envelope; no device action or boot/recovery validation.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
