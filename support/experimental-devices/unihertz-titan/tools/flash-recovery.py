#!/usr/bin/env python3
"""Write one pinned image to the Titan's recovery partition with `fastboot flash`.

This host helper writes only the `recovery` partition, and only one of six
pinned full-partition images: the USB probe envelope, the same probe with the
repository-built kernel, the native route's first modern-kernel image or its
diagnostic image, or the offline control-region acquisition envelope, each
padded with zeros to the partition size, or the preserved original recovery
image that restores it. It
first sends fixed read-only identity queries, including the recovery
partition's size and type, from a verified read-only private copy that it
measures again afterwards. It never writes another partition and never issues
erase, boot, oem, flashing, set_active or any other command. Running it changes
the phone's storage and needs the owner's explicit authorization of the
procedure in recovery-route-trial.adoc, control-acquisition-trial.adoc,
repo-kernel-trial.adoc, native-boot-trial.adoc or native-diag-trial.adoc.
"""

import argparse
import datetime
import hashlib
import importlib.util
import os
from pathlib import Path
import stat
import sys

SPEC = importlib.util.spec_from_file_location(
    "titan_fastboot_flash_primitives", Path(__file__).with_name("observe-fastboot.py"))
trial = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(trial)
TrialError = trial.TrialError

FORMAT = "titan-fastboot-flash-recovery-v1"
PARTITION = "recovery"
PARTITION_BYTES = 33554432
# Each profile pins its source file and the exact full-partition bytes sent.
PROFILES = {
    # The second-version USB probe envelope (usb-probe/README.adoc), which
    # restarts into the bootloader, in the recovery layout that carries the
    # stock recovery-DTBO section; padded with zeros so that the whole
    # partition has one known content.
    "rescue-probe": {
        "source_bytes": 9768960,
        "source_sha256": "f37dd3b159226e7c9955ee87246a570b8075d6e95187d4f1406d456f5c0ce59d",
        "sha256": "a97cb154eb82a7241e155fbdb5c6bc804404ab1bb8082739aaa63835f1d96080",
    },
    # The same second-version probe ramdisk and recovery layout with the
    # repository-built kernel (kernel.nix) in place of the installed one.
    "repo-kernel-probe": {
        "source_bytes": 9764864,
        "source_sha256": "35fb8d6427b3b32809b48789235158fda460b5d6e6ecbf4ed703ed0f3694050f",
        "sha256": "e59463888dae6b7db6c64bbd2c84965d2ffce2a76a5b51a6cb5f0c426a5fc251",
    },
    # The native route's first modern-kernel image (native-boot-trial.adoc):
    # Linux 7.3-rc3, the Titan board tree and overlay and the modern probe,
    # assembled in Nix by the pinned mkbootimg (nativeProbeImage).
    "native-probe": {
        "source_bytes": 15712256,
        "source_sha256": "5945dad1ae4041224136a184e49f07abffdef14c63d3797cf43cb9191985da88",
        "sha256": "35a45a98f06d1a5fca462a6f2540e370189a26346ec727b892e9776ca2ba63b3",
    },
    # The native route's diagnostic image (diag/README.adoc): the same kernel,
    # tree and overlay with the diagnostic ramdisk (nativeDiagImage).
    "native-diag": {
        "source_bytes": 17606656,
        "source_sha256": "8a58da6ccf326fb6c8432e18a9d5c57b2a9c4b3bfcf44909a93df4c01f029bde",
        "sha256": "5a55f9d7a54c9f5bb757b32955f2488909457a042ba42509182fcacb7ec7c6ee",
    },
    # The offline control-region acquisition envelope (control/README.adoc),
    # which restarts into the bootloader after the transfer or at its deadline,
    # in the same recovery layout; padded with zeros like the probe.
    "control-acquisition": {
        "source_bytes": 13475840,
        "source_sha256": "41fd9c6bfb7f34f2351678eb52337ac6320672739d3109b0e8e0334b89d87b65",
        "sha256": "6729b1463f208f0ac73d3b950e3f8c3599f3343f99ce0addad4d5272ba421155",
    },
    # The installed stock recovery as preserved on 2026-10-14
    # (recovery-preparation.adoc); restores the partition byte for byte.
    "original-recovery": {
        "source_bytes": 33554432,
        "source_sha256": "4dd1c1f75cff6e8ec2d4606020f4c790ad3dc10545acc4ea0a11207d2d36be6d",
        "sha256": "4dd1c1f75cff6e8ec2d4606020f4c790ad3dc10545acc4ea0a11207d2d36be6d",
    },
}
# Read-only identity queries; values observed on 2026-10-15.
IDENTITY = ("product", "is-userspace", "unlocked", "max-download-size",
            "partition-size:" + PARTITION, "partition-type:" + PARTITION)
EXPECTED = {"product": "g61v71c2k_dfl_tee", "is-userspace": "no", "unlocked": "yes",
            "partition-type:" + PARTITION: "raw data"}
FLASH_TIMEOUT = 300.0
CHUNK = 1 << 20


def file_digest(path, limit):
    """Hash at most limit + 1 bytes of a regular file without following links."""
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            raise TrialError("The image is not a regular file.")
        digest, total = hashlib.sha256(), 0
        while total <= limit:
            chunk = os.read(fd, min(CHUNK, limit + 1 - total))
            if not chunk:
                break
            total += len(chunk)
            digest.update(chunk)
        return total, digest.hexdigest()
    finally:
        os.close(fd)


def prepare_image(source, output, profile):
    """Copy the pinned source into the private output, padded to the partition size."""
    expected = PROFILES[profile]
    path = Path(source).expanduser()
    if not path.is_absolute():
        raise TrialError("The image must be an absolute path.")
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    target = output / "image.img"
    try:
        metadata = os.fstat(fd)
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_size != expected["source_bytes"]:
            raise TrialError("The image is not a regular file of the pinned size; nothing was sent.")
        out = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
        try:
            source_digest, total = hashlib.sha256(), 0
            while True:
                chunk = os.read(fd, CHUNK)
                if not chunk:
                    break
                total += len(chunk)
                if total > expected["source_bytes"]:
                    raise TrialError("The image grew while it was copied; nothing was sent.")
                source_digest.update(chunk)
                view = memoryview(chunk)
                while view:
                    view = view[os.write(out, view):]
            if total != expected["source_bytes"] or source_digest.hexdigest() != expected["source_sha256"]:
                raise TrialError("The image does not match the pinned profile; nothing was sent.")
            padding = PARTITION_BYTES - total
            while padding:
                view = memoryview(bytes(min(CHUNK, padding)))
                padding -= len(view)
                while view:
                    view = view[os.write(out, view):]
            os.fsync(out)
        finally:
            os.close(out)
    except TrialError:
        if os.path.lexists(target):
            os.unlink(target)
        raise
    finally:
        os.close(fd)
    if file_digest(target, PARTITION_BYTES) != (PARTITION_BYTES, expected["sha256"]):
        os.unlink(target)
        raise TrialError("The padded image does not match the pinned partition content; nothing was sent.")
    os.chmod(target, 0o400)
    return target


def check_identity(variables):
    for name, value in EXPECTED.items():
        if variables.get(name) != value:
            raise TrialError(f"Bootloader variable {name!r} did not match the recorded value; nothing was sent.")
    # This bootloader reports partition sizes in hexadecimal without a prefix
    # (`2000000` for 32 MiB) and the download limit with one (`0x8000000`).
    sizes = {}
    for name, base in (("max-download-size", 0), ("partition-size:" + PARTITION, 16)):
        try:
            sizes[name] = int(variables.get(name) or "", base)
        except ValueError as error:
            raise TrialError(f"Bootloader variable {name!r} was not reported; nothing was sent.") from error
    if sizes["partition-size:" + PARTITION] != PARTITION_BYTES:
        raise TrialError("The recovery partition size differs from the recorded layout; nothing was sent.")
    if sizes["max-download-size"] < PARTITION_BYTES:
        raise TrialError("The image exceeds the reported maximum download size; nothing was sent.")


def run_flash(fastboot, output, profile, image, wait=120.0, poll=trial.POLL_INTERVAL):
    expected = PROFILES[profile]
    record = {"format": FORMAT, "profile": profile, "partition": PARTITION, "status": "incomplete",
              "created_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
              "fastboot": fastboot[-1], "image": {"bytes": PARTITION_BYTES, "sha256": expected["sha256"]},
              "steps": [], "variables": {}}
    steps = record["steps"]
    try:
        version = trial.run_bounded(fastboot + ["--version"])
        steps.append({"argv": ["--version"], **version})
        if version["status"] != "exited" or version["exit"] != 0:
            raise TrialError("The fastboot executable did not report its version.")
        serial = trial.select_device(fastboot, steps, wait, poll)
        record["device_serial_private"] = serial
        for variable in IDENTITY:
            result = trial.run_bounded(fastboot + ["-s", serial, "getvar", variable])
            steps.append({"argv": ["-s", trial.PLACEHOLDER, "getvar", variable], **result})
            if result["status"] != "exited":
                raise TrialError(f"Query {variable!r} did not finish; nothing was sent.")
            record["variables"][variable] = trial.query_value(variable, result)
        check_identity(record["variables"])
        if file_digest(image, PARTITION_BYTES) != (PARTITION_BYTES, expected["sha256"]):
            raise TrialError("The private image copy changed; nothing was sent.")
        result = trial.run_bounded(fastboot + ["-s", serial, "flash", PARTITION, str(image)],
                                   timeout=FLASH_TIMEOUT)
        steps.append({"argv": ["-s", trial.PLACEHOLDER, "flash", PARTITION, "<private-image-copy>"], **result})
        after = file_digest(image, PARTITION_BYTES)
        record["image_after_flash"] = {"bytes": after[0], "sha256": after[1]}
        if after != (PARTITION_BYTES, expected["sha256"]):
            raise TrialError("The private image copy changed while fastboot read it; what was written is unknown.")
        if result["status"] != "exited" or result["exit"] != 0:
            raise TrialError("`fastboot flash recovery` did not complete successfully; "
                             "the partition may be partly written.")
        record["status"] = "complete"
        return record
    except TrialError as error:
        record["error"] = str(error)
        raise
    finally:
        trial.write_record(output, record)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--profile", required=True, choices=sorted(PROFILES),
                        help="pinned recovery content approved for this step")
    parser.add_argument("--image", required=True, help="absolute path of the private source image")
    parser.add_argument("--output", required=True, help="new private directory; its parent must exist")
    parser.add_argument("--fastboot", default="/opt/homebrew/bin/fastboot",
                        help="absolute path of the Platform-Tools fastboot executable")
    parser.add_argument("--wait", type=float, default=120.0,
                        help="seconds to wait for the single fastboot device (at most 600)")
    args = parser.parse_args(argv)
    previous = os.umask(0o077)
    try:
        if not 0 <= args.wait <= trial.MAX_WAIT:
            raise TrialError("--wait must be between 0 and 600 seconds.")
        executable = Path(args.fastboot)
        if not executable.is_absolute() or not os.access(executable, os.X_OK):
            raise TrialError("--fastboot must be an absolute path to an executable.")
        output = trial.prepare_output(args.output)
        image = prepare_image(args.image, output, args.profile)
        run_flash([str(executable)], output, args.profile, image, args.wait)
        print(f"`fastboot flash recovery` completed for the {args.profile} profile; "
              "verify the partition from Ubuntu Touch.")
        print(f"Private record: {output / 'trial.json'}")
        return 0
    except (TrialError, OSError) as error:
        print(f"Recovery flash step stopped: {error}", file=sys.stderr)
        return 1
    finally:
        os.umask(previous)


if __name__ == "__main__":
    raise SystemExit(main())
