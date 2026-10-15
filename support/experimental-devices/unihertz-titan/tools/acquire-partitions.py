#!/usr/bin/env python3
"""Read three measured Titan eMMC partitions through normal-mode ADB.

This is not a general block-device copier, a userdata backup, or a recovery
writer. It never installs software or changes the phone's boot mode. The optional
sudo password is requested on a local terminal and sent only on ADB stdin.
"""

import argparse
import datetime
import getpass
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import secrets
import selectors
import shlex
import subprocess
import sys
import tempfile
import time
import warnings


SPEC = importlib.util.spec_from_file_location(
    "titan_inventory", Path(__file__).with_name("collect-inventory.py")
)
inventory = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(inventory)

# These values apply only to the owner's measured original Titan eMMC layout.
PARTITIONS = {
    "boot": ("mmcblk0p28", 28, 33554432),
    "recovery": ("mmcblk0p2", 2, 33554432),
    "dtbo": ("mmcblk0p30", 30, 8388608),
}
MIB = 1048576


class AcquisitionError(Exception):
    pass


def identity_script(label):
    """Return identity checks that an unprivileged ADB shell can already run.

    They tie the label, block node, sysfs partition and size together, so a
    different phone or layout is rejected before any sudo credential is sent.
    """
    if label not in PARTITIONS:
        raise ValueError("Only boot, recovery and dtbo are supported.")
    device, number, size = PARTITIONS[label]
    return f"""set -eu
mmc_type=$(cat /sys/class/block/mmcblk0/device/type)
[ "$mmc_type" = MMC ] || exit 10
target=$(readlink -f /dev/disk/by-partlabel/{label})
[ "$target" = /dev/{device} ] || exit 11
[ ! -L /dev/{device} ] && [ -b /dev/{device} ] || exit 12
sysfs=$(readlink -f /sys/class/block/{device})
sysfs_disk=$(readlink -f /sys/class/block/mmcblk0)
[ "${{sysfs%/*}}" = "$sysfs_disk" ] || exit 13
partition=$(cat /sys/class/block/{device}/partition)
[ "$partition" = {number} ] || exit 14
sectors=$(cat /sys/class/block/{device}/size)
[ "$sectors" = {size // 512} ] || exit 15
device_number=$(cat /sys/class/block/{device}/dev)
node_hex=$(stat -c '%t:%T' /dev/{device})
case "$node_hex" in ''|*[!0-9a-fA-F:]*|:*|*:|*:*:*) exit 21;; esac
[ "${{#node_hex}}" -le 17 ] || exit 21
[ "$((0x${{node_hex%:*}})):$((0x${{node_hex#*:}}))" = "$device_number" ] || exit 21
"""


def guard_script(label):
    """Return fixed read-only checks immediately preceding every block read."""
    identity = identity_script(label)
    device, _, size = PARTITIONS[label]
    return identity + f"""[ -r /dev/{device} ] || exit 16
bytes=$(/usr/sbin/blockdev --getsize64 /dev/{device})
[ "$bytes" = {size} ] || exit 17
[ -r /proc/self/mountinfo ] && [ -r /proc/1/mountinfo ] || exit 18
awk -v device_number="$device_number" '$3 == device_number {{ mounted = 1 }} END {{ exit mounted ? 1 : 0 }}' /proc/self/mountinfo /proc/1/mountinfo || exit 19
for holder in /sys/class/block/{device}/holders/*; do
    [ ! -e "$holder" ] || exit 20
done
"""


def probe_script(label):
    return guard_script(label) + f"""printf '%s\\n' 'label={label}' "device=$target" "mmc_type=$mmc_type" "partition=$partition" "sectors=$sectors" "bytes=$bytes" "sysfs=$sysfs" "sysfs_disk=$sysfs_disk" "device_number=$device_number" 'block_device=true' 'readable=true' 'unmounted=true' 'holders=none'
"""


def read_script(label):
    device, _, size = PARTITIONS[label]
    # No output device, no redirection and no unbounded partition selection.
    return guard_script(label) + (
        f"dd if=/dev/{device} bs={MIB} count={size // MIB} "
        "iflag=fullblock status=none\n"
    )


def hash_script(label):
    device, _, _ = PARTITIONS[label]
    return guard_script(label) + f"sha256sum /dev/{device}\n"


def validate_evidence(label, data):
    try:
        lines = data.decode("ascii").splitlines()
        fields = dict(line.split("=", 1) for line in lines)
    except (UnicodeError, ValueError) as error:
        raise AcquisitionError("Malformed partition preflight output.") from error
    device, number, size = PARTITIONS[label]
    expected = {
        "label": label, "device": f"/dev/{device}", "mmc_type": "MMC",
        "partition": str(number), "sectors": str(size // 512), "bytes": str(size),
        "block_device": "true", "readable": "true", "unmounted": "true", "holders": "none",
    }
    if (len(lines) != len(fields) or set(fields) != set(expected) | {
            "sysfs", "sysfs_disk", "device_number"}):
        raise AcquisitionError("Unexpected partition preflight fields.")
    if any(fields[key] != value for key, value in expected.items()):
        raise AcquisitionError(f"{label}: partition geometry or read safety did not match.")
    disk = fields["sysfs_disk"]
    if (not disk.startswith("/sys/devices/") or not disk.endswith("/mmcblk0")
            or fields["sysfs"] != f"{disk}/{device}"
            or not re.fullmatch(r"[0-9]+:[0-9]+", fields["device_number"])):
        raise AcquisitionError(f"{label}: unexpected sysfs parent or device number.")
    return fields


def run_bounded(command, limit, timeout, *, sink=None, password=None, expected_exit=0,
                status_token=None):
    """Drain both pipes, enforce a wall-clock deadline and read at most limit+1.

    Remote stderr is deliberately never printed or persisted: even an unexpected
    authentication helper cannot cause a password to appear in our diagnostics.
    """
    deadline = time.monotonic() + timeout
    process = subprocess.Popen(
        command, stdin=subprocess.PIPE if password is not None else subprocess.DEVNULL,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE,
    )
    chunks, diagnostics, total, stderr_total = [], [], 0, 0
    digest = hashlib.sha256()
    try:
        if password is not None:
            try:
                process.stdin.write(password + b"\n")
                process.stdin.flush()
            except BrokenPipeError:
                pass
            finally:
                try:
                    process.stdin.close()
                except BrokenPipeError:
                    pass
        with selectors.DefaultSelector() as selector:
            selector.register(process.stdout, selectors.EVENT_READ, "stdout")
            selector.register(process.stderr, selectors.EVENT_READ, "stderr")
            while selector.get_map():
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise AcquisitionError("ADB operation timed out; partial image discarded.")
                for key, _ in selector.select(min(remaining, 1)):
                    allowance = limit - total if key.data == "stdout" else 16384 - stderr_total
                    chunk = os.read(key.fileobj.fileno(), min(65536, allowance + 1))
                    if not chunk:
                        selector.unregister(key.fileobj)
                        continue
                    if key.data == "stderr":
                        stderr_total += len(chunk)
                        if stderr_total > 16384:
                            raise AcquisitionError("ADB diagnostic output exceeded its safety bound.")
                        diagnostics.append(chunk)
                        continue
                    total += len(chunk)
                    if total > limit:
                        raise AcquisitionError("ADB output exceeded the expected byte count.")
                    digest.update(chunk)
                    if sink is None:
                        chunks.append(chunk)
                    else:
                        sink.write(chunk)
        try:
            code = process.wait(timeout=max(0, deadline - time.monotonic()))
        except subprocess.TimeoutExpired as error:
            raise AcquisitionError("ADB operation timed out; partial image discarded.") from error
        if status_token is not None:
            stderr = b"".join(diagnostics)
            token = status_token.encode("ascii")
            trailer = re.search(rb"\n" + re.escape(token) + rb":([0-9]{1,3})\n\Z", stderr)
            if not trailer or stderr.count(token) != 1 or int(trailer.group(1)) > 255:
                raise AcquisitionError("Missing or malformed remote exit-status trailer; no image accepted.")
            remote_code = int(trailer.group(1))
            # Some Ubuntu Touch adbd versions advertise shell_v2 but return host
            # status 0 even when the remote shell failed. Require the trailer,
            # and reject independent transport errors as well.
            if code not in (0, remote_code):
                raise AcquisitionError(f"ADB transport failed (exit {code}); no image accepted.")
            code = remote_code
        if code != expected_exit:
            raise AcquisitionError(f"ADB operation failed (exit {code}); no image accepted.")
        return b"".join(chunks), total, digest.hexdigest()
    finally:
        if process.poll() is None:
            process.kill()
        process.wait()
        process.stdout.close()
        process.stderr.close()


class Remote:
    def __init__(self, adb, serial, timeout, password=None):
        self.adb, self.serial, self.timeout, self.password = adb, serial, timeout, password

    def run(self, script, limit=16384, *, sink=None, expected_exit=0):
        invocation = "sh -c " + shlex.quote(script)
        if self.password is not None:
            invocation = "sudo -S -p '' -- " + invocation
        token = "TITAN_ACQUIRE_STATUS_" + secrets.token_hex(16)
        # The wrapper is outside sudo so failed authentication also receives a
        # status. The unpredictable marker is on stderr, never the image stream.
        invocation = (invocation + "; result=$?; printf '\\n" + token
                      + ":%s\\n' \"$result\" >&2; exit \"$result\"")
        return run_bounded(
            [self.adb, "-s", self.serial, "shell", "-T", invocation],
            limit, self.timeout, sink=sink, password=self.password, expected_exit=expected_exit,
            status_token=token,
        )

    def check_protocol(self):
        features, _, _ = run_bounded(
            [self.adb, "-s", self.serial, "features"], 16384, self.timeout,
        )
        if "shell_v2" not in re.split(r"[\s,]+", features.decode("ascii").strip()):
            raise AcquisitionError("ADB shell_v2 is required to verify remote exit status.")
        # Check before requesting sudo credentials: binary bytes and stderr must
        # stay separate, and framed status must survive even if adbd loses it.
        binary, _, _ = self.run("printf '\\000\\015\\012\\377'; exit 42", limit=4, expected_exit=42)
        if binary != b"\x00\r\n\xff":
            raise AcquisitionError("ADB did not preserve the binary probe bytes.")


def prepare_output(requested):
    if requested is not None:
        return inventory.prepare_output(requested)
    state = Path(os.environ.get("XDG_STATE_HOME", Path.home() / ".local/state"))
    base = (state / "mobile-nixos/titan-recovery").expanduser().resolve()
    if inventory.inside_git_checkout(base):
        raise ValueError("Backup output must be outside every Git or jj checkout and the Nix store.")
    base.mkdir(mode=0o700, parents=True, exist_ok=True)
    prefix = datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%dT%H%M%SZ-installed-")
    return Path(tempfile.mkdtemp(prefix=prefix, dir=base))


def write_manifest(output, manifest):
    pending = output / "manifest.json.part"
    inventory.write_private(pending, (json.dumps(manifest, indent=2) + "\n").encode())
    os.replace(pending, output / "manifest.json")


def acquire_one(remote, output, label):
    expected = PARTITIONS[label][2]
    evidence = validate_evidence(label, remote.run(probe_script(label))[0])
    pending, destination = output / f"{label}.img.part", output / f"{label}.img"
    if destination.exists():
        raise AcquisitionError("Refusing to overwrite an existing image.")
    created = False
    try:
        descriptor = os.open(pending, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        created = True
        with os.fdopen(descriptor, "wb") as stream:
            _, actual, digest = remote.run(read_script(label), expected, sink=stream)
            if actual != expected:
                raise AcquisitionError(f"{label}: expected {expected} bytes, received {actual}.")
            stream.flush()
            os.fsync(stream.fileno())
        saved_digest = hashlib.sha256()
        with pending.open("rb") as saved:
            for _ in range(expected // MIB):
                chunk = saved.read(MIB)
                if len(chunk) != MIB:
                    raise AcquisitionError(f"{label}: saved image readback was short.")
                saved_digest.update(chunk)
            if saved.read(1):
                raise AcquisitionError(f"{label}: saved image readback exceeded its byte count.")
        if saved_digest.hexdigest() != digest:
            raise AcquisitionError(f"{label}: saved image readback SHA-256 did not match the transfer.")
        # The phone hash performs a fresh guarded read independent of the transfer.
        validate_evidence(label, remote.run(probe_script(label))[0])
        result = remote.run(hash_script(label), 256)[0]
        device = PARTITIONS[label][0]
        matched = re.fullmatch(rb"([0-9a-f]{64})  /dev/" + device.encode() + rb"\n", result)
        if not matched or matched.group(1).decode() != digest:
            raise AcquisitionError(f"{label}: independent phone SHA-256 did not match.")
        # Link publication is atomic and, unlike rename, cannot overwrite a file
        # that appeared after our initial check.
        os.link(pending, destination)
        pending.unlink()
        return {"file": destination.name, "bytes": actual, "sha256": saved_digest.hexdigest(),
                "transfer_sha256": digest,
                "phone_sha256": digest, "preflight": evidence}
    finally:
        if created and pending.exists():
            pending.unlink()


def source_digests(*names):
    """Return SHA-256 digests of the exact helper sources writing a manifest.

    Recording them binds a private manifest to the reviewed code that produced
    it, so later fixes cannot be confused with an earlier acquisition.
    """
    here = Path(__file__).resolve().parent
    return {name: hashlib.sha256((here / name).read_bytes()).hexdigest() for name in names}


def prompt_password():
    if not sys.stdin.isatty() or not sys.stderr.isatty():
        raise AcquisitionError("--sudo requires a local interactive terminal; no password accepted from files or pipes.")
    try:
        # isatty alone does not establish that termios can disable echo. Python
        # otherwise warns and falls back to reading a visibly echoed password.
        with warnings.catch_warnings():
            warnings.simplefilter("error", getpass.GetPassWarning)
            password = getpass.getpass("Phone sudo password (sent only over authorized USB ADB): ")
    except getpass.GetPassWarning as error:
        raise AcquisitionError("Cannot disable password echo; no password was read. Use a working local terminal.") from error
    if not password or "\n" in password or "\r" in password or len(password.encode()) > 1024:
        raise AcquisitionError("A nonempty single-line password of at most 1024 bytes is required.")
    return password.encode()


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--adb", default="adb", help="host ADB executable")
    parser.add_argument("--serial", help="select the Titan when multiple ADB transports exist")
    parser.add_argument("--output", help="new private directory outside every Git or jj checkout")
    parser.add_argument("--timeout", type=int, default=120, help="seconds per remote operation (default: 120)")
    parser.add_argument("--sudo", action="store_true", help="prompt in this terminal for the phone's sudo password")
    args = parser.parse_args(argv)
    if args.timeout <= 0:
        parser.error("--timeout must be positive")
    output, remote = None, None
    # Newly created parent directories and files are private as well.
    previous_umask = os.umask(0o077)
    try:
        devices, _, _ = run_bounded([args.adb, "devices", "-l"], 65536, args.timeout)
        serial = inventory.select_usb_device(devices.decode(), args.serial)
        remote = Remote(args.adb, serial, args.timeout)
        remote.check_protocol()
        # Establish this Titan's partition identity as the unprivileged USB ADB
        # user before any credential is requested or sent.
        for label in PARTITIONS:
            remote.run(identity_script(label))
        if args.sudo:
            remote.password = prompt_password()
        # Fail before creating an output directory if any partition is unreadable.
        for label in PARTITIONS:
            validate_evidence(label, remote.run(probe_script(label))[0])
        output = prepare_output(args.output)
        manifest = {
            "format": 1, "status": "incomplete", "transport": "adb-shell-v2-no-pty",
            "created_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "scope": "boot, recovery and dtbo only; not a userdata or calibration backup",
            "helper_sources": source_digests("acquire-partitions.py", "collect-inventory.py"),
            "partitions": {},
        }
        write_manifest(output, manifest)
        print(f"Writing private partition images to {output}")
        for label in PARTITIONS:
            manifest["partitions"][label] = acquire_one(remote, output, label)
            write_manifest(output, manifest)
            print(f"{label}: exact byte count and independent phone SHA-256 verified")
        manifest["status"] = "complete"
        write_manifest(output, manifest)
        print(f"Verified all three images; private manifest: {output / 'manifest.json'}")
        return 0
    except (AcquisitionError, ValueError, OSError, UnicodeError, EOFError, KeyboardInterrupt) as error:
        # No subprocess stdout/stderr or password is included in these errors.
        print(f"Acquisition stopped: {error}", file=sys.stderr)
        if output is not None:
            print(f"The incomplete manifest and any already verified images remain at {output}", file=sys.stderr)
        return 1
    finally:
        if remote is not None:
            remote.password = None
        os.umask(previous_umask)


if __name__ == "__main__":
    sys.exit(main())
