#!/usr/bin/env python3
"""Run the temporary-boot step of the proposed Titan RAM-boot trial.

This host helper sends exactly one pinned boot image with `fastboot boot`,
after fixed read-only identity queries. The image is loaded into RAM; neither
the helper nor the commands it sends write a partition, although the system it
boots may write storage as any normal boot does. It never flashes, erases or
issues oem, flashing, set_active or any other command. Running it changes the
phone's boot mode and needs the owner's explicit authorization of the
procedure in temporary-boot-trial.adoc.
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
    "titan_fastboot_trial_primitives", Path(__file__).with_name("observe-fastboot.py"))
trial = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(trial)
TrialError = trial.TrialError

FORMAT = "titan-fastboot-boot-v1"
# Each profile pins one reviewed image by exact size and SHA-256. The installed
# boot image is the phone's own known-good Ubuntu Touch boot partition, which
# matches the documented CI candidate; see recovery-preparation.adoc.
PROFILES = {
    "installed-boot": {
        "bytes": 33554432,
        "sha256": "6829a8bcaa696a6fe283184a874450357dd81e7e203eedaf79329bdc55745e83",
    },
    # Stage B: the installed kernel and DTB with the 2026-10-15 USB probe
    # ramdisk, packaged by prepare-rescue-image.py --ramdisk-profile usb-probe
    # and byte-identical to the pinned mkbootimg. See usb-probe/README.adoc.
    "rescue-probe": {
        "bytes": 9719808,
        "sha256": "e6da06fc1f6c47d4c4ae0edc8c1888e9dc628dbef9b8f8a01ae37768065704c8",
    },
}
# Read-only identity queries; values observed on 2026-10-15.
IDENTITY = ("product", "is-userspace", "unlocked", "max-download-size")
EXPECTED = {"product": "g61v71c2k_dfl_tee", "is-userspace": "no", "unlocked": "yes"}
BOOT_TIMEOUT = 180.0
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


def copy_image(source, output, profile):
    """Copy the image into the private output and verify the copy against its profile."""
    expected = PROFILES[profile]
    path = Path(source).expanduser()
    if not path.is_absolute():
        raise TrialError("The image must be an absolute path.")
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    target = output / "image.img"
    try:
        metadata = os.fstat(fd)
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_size != expected["bytes"]:
            raise TrialError("The image is not a regular file of the pinned size; nothing was sent.")
        out = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
        try:
            total = 0
            while True:
                chunk = os.read(fd, CHUNK)
                if not chunk:
                    break
                total += len(chunk)
                if total > expected["bytes"]:
                    raise TrialError("The image grew while it was copied; nothing was sent.")
                view = memoryview(chunk)
                while view:
                    view = view[os.write(out, view):]
            os.fsync(out)
        finally:
            os.close(out)
    finally:
        os.close(fd)
    if file_digest(target, expected["bytes"]) != (expected["bytes"], expected["sha256"]):
        os.unlink(target)
        raise TrialError("The image does not match the pinned profile; nothing was sent.")
    os.chmod(target, 0o400)
    return target


def check_identity(variables, size):
    for name, value in EXPECTED.items():
        if variables.get(name) != value:
            raise TrialError(f"Bootloader variable {name!r} did not match the recorded value; nothing was sent.")
    try:
        limit = int(variables.get("max-download-size") or "", 0)
    except ValueError as error:
        raise TrialError("The maximum download size was not reported; nothing was sent.") from error
    if limit < size:
        raise TrialError("The image exceeds the reported maximum download size; nothing was sent.")


def run_boot(fastboot, output, profile, image, wait=120.0, poll=trial.POLL_INTERVAL):
    expected = PROFILES[profile]
    record = {"format": FORMAT, "profile": profile, "status": "incomplete",
              "created_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
              "fastboot": fastboot[-1], "image": dict(expected), "steps": [], "variables": {}}
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
        check_identity(record["variables"], expected["bytes"])
        if file_digest(image, expected["bytes"]) != (expected["bytes"], expected["sha256"]):
            raise TrialError("The private image copy changed; nothing was sent.")
        result = trial.run_bounded(fastboot + ["-s", serial, "boot", str(image)], timeout=BOOT_TIMEOUT)
        steps.append({"argv": ["-s", trial.PLACEHOLDER, "boot", "<private-image-copy>"], **result})
        # Measure the copy again: a change while fastboot read it would leave
        # the bytes actually sent unknown.
        after = file_digest(image, expected["bytes"])
        record["image_after_boot"] = {"bytes": after[0], "sha256": after[1]}
        if after != (expected["bytes"], expected["sha256"]):
            raise TrialError("The private image copy changed while fastboot read it; what was sent is unknown.")
        if result["status"] != "exited" or result["exit"] != 0:
            raise TrialError("`fastboot boot` did not complete successfully.")
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
                        help="pinned image profile approved for this trial")
    parser.add_argument("--image", required=True, help="absolute path of the private image file")
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
        image = copy_image(args.image, output, args.profile)
        run_boot([str(executable)], output, args.profile, image, args.wait)
        print(f"`fastboot boot` completed for the {args.profile} profile; confirm the boot over ADB.")
        print(f"Private record: {output / 'trial.json'}")
        return 0
    except (TrialError, OSError) as error:
        print(f"Temporary boot step stopped: {error}", file=sys.stderr)
        return 1
    finally:
        os.umask(previous)


if __name__ == "__main__":
    raise SystemExit(main())
