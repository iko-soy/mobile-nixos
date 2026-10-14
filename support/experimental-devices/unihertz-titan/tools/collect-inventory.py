#!/usr/bin/env python3
"""Collect a read-only Titan baseline locally or over ADB/SSH, without elevating privileges."""

import argparse
import datetime
import json
import math
import os
from pathlib import Path
import re
import secrets
import shlex
import subprocess
import sys
import tempfile


# These commands are fixed, not assembled from device output or user input.
# Keep probes separate: an unavailable interface must not hide other evidence.
PROBES = {
    "kernel.txt": "uname -r; uname -m; cat /proc/version",
    "os-release.txt": "cat /etc/os-release",
    "active-system-manager.txt": "cat /proc/1/comm; systemctl --system show --property=Version --value",
    "device-tree.txt": r"""
for field in model compatible; do
    printf '%s=' "$field"
    if [ -r "/proc/device-tree/$field" ]; then
        tr '\000' '\n' < "/proc/device-tree/$field"
    else
        printf 'unavailable\n'
    fi
done
""",
    "android-properties.txt": r"""
if command -v getprop >/dev/null 2>&1; then
    getter=getprop
elif [ -x /system/bin/getprop ]; then
    getter=/system/bin/getprop
elif [ -x /android/system/bin/getprop ]; then
    getter=/android/system/bin/getprop
else
    printf 'getprop unavailable in this shell\n' >&2
    exit 1
fi
for key in ro.product.manufacturer ro.product.model ro.product.device \
    ro.product.board ro.board.platform ro.hardware ro.build.fingerprint \
    ro.build.version.release ro.build.version.security_patch \
    ro.vendor.build.fingerprint ro.boot.flash.locked \
    ro.boot.verifiedbootstate ro.boot.vbmeta.device_state; do
    printf '%s=' "$key"
    "$getter" "$key"
done
""",
    "config.gz": "cat /proc/config.gz",
    "partitions.txt": r"""
cat /proc/partitions
for block in /sys/class/block/*; do
    [ -d "$block" ] || continue
    printf '\nblock=%s\n' "${block##*/}"
    for field in size partition queue/logical_block_size; do
        if [ -r "$block/$field" ]; then
            printf '%s=' "$field"
            cat "$block/$field"
        fi
    done
done
for directory in /dev/disk/by-partlabel /dev/block/by-name \
    /dev/block/bootdevice/by-name /dev/block/platform/*/by-name \
    /dev/block/platform/*/*/by-name; do
    [ -d "$directory" ] || continue
    printf '\npartition-labels=%s\n' "$directory"
    ls -l "$directory"
done
""",
    "storage.txt": r"""
for block in /sys/class/block/mmcblk[0-9] /sys/class/block/sd[a-z]; do
    [ -d "$block" ] || continue
    name=${block##*/}
    for field in type name model vendor; do
        if [ -r "$block/device/$field" ]; then
            printf '%s.%s=' "$name" "$field"
            cat "$block/device/$field"
        fi
    done
done
for host in /sys/class/scsi_host/host*; do
    [ -r "$host/proc_name" ] || continue
    printf '%s.proc_name=' "${host##*/}"
    cat "$host/proc_name"
done
""",
    "mounts.txt": "cat /proc/mounts; cat /proc/filesystems",
    "mountinfo.txt": "cat /proc/self/mountinfo",
    "loop-backing-files.txt": r"""
for block in /sys/class/block/loop*; do
    [ -d "$block" ] || continue
    printf '\nblock=%s\n' "${block##*/}"
    for field in loop/backing_file ro; do
        if [ -r "$block/$field" ]; then
            printf '%s=' "$field"
            cat "$block/$field"
        fi
    done
done
""",
    "userdata-space.txt": "df -Pk /userdata",
    "system-image-channel.txt": "cat /etc/system-image/channel.ini",
    "system-image-channel-config.txt": "cat /etc/system-image/config.d/01_channel.ini",
    "memory.txt": "cat /proc/meminfo; cat /proc/iomem",
    # Input Phys/Uniq fields can contain Bluetooth addresses or USB serials.
    "input.txt": "sed '/^[PU]: /d' /proc/bus/input/devices",
    "display.txt": r"""
for device in /sys/class/graphics/fb* /sys/class/drm/card*-*; do
    [ -d "$device" ] || continue
    printf '\ndevice=%s\n' "${device##*/}"
    for field in name virtual_size bits_per_pixel modes status; do
        if [ -r "$device/$field" ]; then
            printf '%s=\n' "$field"
            cat "$device/$field"
        fi
    done
done
""",
    "usb.txt": r"""
for device in /sys/class/android_usb/android* /sys/class/udc/* \
    /sys/kernel/config/usb_gadget/*; do
    [ -d "$device" ] || continue
    printf '\ndevice=%s\n' "$device"
    for field in state functions idVendor idProduct UDC current_speed maximum_speed; do
        if [ "$field" = functions ] && [ -d "$device/$field" ]; then
            printf '%s=\n' "$field"
            for function in "$device/$field"/*; do
                [ -e "$function" ] || continue
                printf '%s\n' "${function##*/}"
            done
        elif [ -f "$device/$field" ] && [ -r "$device/$field" ]; then
            printf '%s=' "$field"
            cat "$device/$field"
        fi
    done
done
""",
    "power.txt": r"""
for device in /sys/class/power_supply/*; do
    [ -d "$device" ] || continue
    printf '\ndevice=%s\n' "${device##*/}"
    for field in type status health technology present online capacity \
        voltage_now current_now temp charge_full charge_full_design charge_counter; do
        if [ -r "$device/$field" ]; then
            printf '%s=' "$field"
            cat "$device/$field"
        fi
    done
done
""",
    "network-audio.txt": r"""
for device in /sys/class/net/*; do
    [ -d "$device" ] || continue
    printf '\nnetwork=%s\n' "${device##*/}"
    if [ -r "$device/operstate" ]; then cat "$device/operstate"; fi
done
cat /proc/asound/cards
""",
}

PRIVATE_PROBES = {
    "cmdline.txt": "cat /proc/cmdline",
    "dmesg.txt": "dmesg",
}

# Exercise binary output, separate stderr, and a nonzero remote status before
# collecting through ADB. Some Ubuntu Touch adbd versions advertise shell_v2 but
# report zero for failed commands, so a feature check alone is insufficient.
ADB_CHECK_SCRIPT = r"printf '\000\015\012\377'; printf 'titan-inventory-check\n' >&2; exit 7"


def parse_devices(output):
    """Parse `adb devices` without persisting or printing transport serials."""
    devices = {}
    for line in output.splitlines():
        if not line.strip() or line.startswith(("List of devices", "*")):
            continue
        fields = line.split()
        if len(fields) >= 2:
            devices[fields[0]] = fields[1]
    return devices


def select_device(devices, serial):
    if serial is None:
        if not devices:
            raise ValueError("No ADB device found. Connect the Titan and enable ADB first.")
        if len(devices) != 1:
            raise ValueError(
                "Multiple ADB transports found. Run adb devices locally, then select "
                "the Titan with --serial."
            )
        serial = next(iter(devices))
    if serial not in devices:
        raise ValueError("The selected ADB transport is not connected.")
    if devices[serial] != "device":
        raise ValueError(
            "The selected ADB transport is not ready. Check its authorization/status "
            "with adb devices locally."
        )
    return serial


def inside_git_checkout(path):
    path = path.resolve()
    for parent in (path, *path.parents):
        marker = parent / ".git"
        if marker.is_file() or (marker / "HEAD").is_file():
            return True
    return False


def prepare_output(requested):
    """Create a new private directory; never reuse existing or repository paths."""
    if requested:
        output = Path(requested).expanduser().resolve()
        if inside_git_checkout(output):
            raise ValueError("Inventory output must be outside every Git checkout.")
        output.parent.mkdir(parents=True, exist_ok=True)
        output.mkdir(mode=0o700)
    else:
        state = Path(os.environ.get("XDG_STATE_HOME", Path.home() / ".local/state"))
        base = (state / "mobile-nixos/titan-inventory").expanduser().resolve()
        if inside_git_checkout(base):
            raise ValueError("Default state directory is in Git; choose --output outside it.")
        base.mkdir(mode=0o700, parents=True, exist_ok=True)
        timestamp = datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%dT%H%M%SZ-")
        output = Path(tempfile.mkdtemp(prefix=timestamp, dir=base))
    return output


def run_probe(adb, serial, script, timeout):
    # shell_v2 keeps binary stdout and stderr separate. Pass one complete shell
    # command; exec-out has different quoting and cannot report remote status.
    # Also frame the status explicitly: the Titan's Ubuntu Touch adbd reports
    # zero even for `exit 7`, despite advertising shell_v2.
    marker = "__TITAN_INVENTORY_STATUS_" + secrets.token_hex(16) + ":"
    wrapper = (
        "sh -c " + shlex.quote(script)
        + "; status=$?; printf '\\n" + marker + "%s\\n' \"$status\" >&2; exit \"$status\""
    )
    command = [adb, "-s", serial, "shell", "-T", "-n", wrapper]
    stdout, stderr, code, timed_out = run_command(command, timeout)
    if timed_out:
        return stdout, stderr, code, True
    match = re.search(rb"\n" + marker.encode() + rb"([0-9]{1,3})\n\Z", stderr)
    if match is None or int(match[1]) > 255:
        return stdout, stderr + b"\nADB remote exit-status trailer missing or invalid.\n", None, False
    remote_code = int(match[1])
    stderr = stderr[:match.start()]
    if code not in (0, remote_code):
        return stdout, stderr + b"\nADB transport failed after receiving remote status.\n", code, False
    return stdout, stderr, remote_code, False


def check_adb_transport(adb, serial, timeout):
    stdout, _, code, timed_out = run_command([adb, "-s", serial, "features"], timeout)
    if code != 0 or timed_out or b"shell_v2" not in stdout.splitlines():
        raise ValueError("ADB shell_v2 is required to preserve binary stdout and separate stderr.")
    if run_probe(adb, serial, ADB_CHECK_SCRIPT, timeout) != (
        b"\x00\r\n\xff", b"titan-inventory-check\n", 7, False,
    ):
        raise ValueError("ADB binary-output, stderr, or remote-status check failed; no inventory was collected.")


def validate_ssh_host(host):
    # Permit normal SSH aliases, DNS/IPv4 and IPv6 destinations, optionally with
    # a user. Reject options, whitespace, URIs and shell/config metacharacters.
    if not re.fullmatch(
        r"(?:[A-Za-z0-9_][A-Za-z0-9_.-]*@)?"
        r"(?:[A-Za-z0-9_][A-Za-z0-9_.:-]*|\[[A-Fa-f0-9:.]+\])",
        host,
    ):
        raise ValueError("--ssh requires a hostname/IP or user@host; use --ssh-port for the port.")
    return host


def run_ssh_probe(host, port, script, timeout, config=None):
    validate_ssh_host(host)
    command = [
        "ssh", "-n", "-T", "-o", "BatchMode=yes",
        "-o", "StrictHostKeyChecking=yes", "-o", "ConnectTimeout=10",
    ]
    if config is not None:
        # Keep the path as one argv value; OpenSSH reads it, never a host shell.
        command.extend(["-F", config])
    command.extend(["-p", str(port), "--", host, "sh -c " + shlex.quote(script)])
    return run_command(command, timeout)


def run_local_probe(script, timeout):
    # The same fixed probes run under the invoking user, with no elevation.
    return run_command(["sh", "-c", script], timeout)


def run_command(command, timeout):
    try:
        result = subprocess.run(command, capture_output=True, timeout=timeout, check=False)
        return result.stdout, result.stderr, result.returncode, False
    except subprocess.TimeoutExpired as error:
        return error.stdout or b"", error.stderr or b"", None, True


def write_private(path, data):
    # `x` also prevents accidentally overwriting a file on a repeated invocation.
    with path.open("xb") as handle:
        os.chmod(path, 0o600)
        handle.write(data)


def key_values(data):
    return dict(
        line.split("=", 1)
        for line in data.decode("utf-8", errors="replace").splitlines()
        if "=" in line
    )


def summarize(outputs):
    properties = key_values(outputs.get("android-properties.txt", b""))
    tree = key_values(outputs.get("device-tree.txt", b""))
    storage = key_values(outputs.get("storage.txt", b""))
    evidence = {
        key: value.strip()
        for key, value in storage.items()
        if re.fullmatch(r"mmcblk\d+\.type|host\d+\.proc_name", key)
    }
    emmc = any(key.endswith(".type") and value == "MMC" for key, value in evidence.items())
    ufs = any(
        key.endswith(".proc_name") and "ufs" in value.lower()
        for key, value in evidence.items()
    )
    if emmc and ufs:
        variant = "ambiguous: both MMC and UFS evidence; inspect storage.txt"
    elif emmc:
        variant = "eMMC (MMC device type; confirm against internal partition map)"
    elif ufs:
        variant = "UFS (UFS SCSI host driver; confirm against internal partition map)"
    else:
        variant = "unknown; inspect storage.txt and partitions.txt"
    kernel = outputs.get("kernel.txt", b"").decode("utf-8", errors="replace").splitlines()
    return {
        "kernel_release": kernel[0] if kernel else "unavailable",
        "model": properties.get("ro.product.model") or tree.get("model", "unavailable"),
        "android_device": properties.get("ro.product.device", "unavailable"),
        "storage_variant_hint": variant,
        "storage_evidence": evidence,
    }


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    transport = parser.add_mutually_exclusive_group()
    transport.add_argument("--serial", help="ADB transport selector (required with multiple devices)")
    transport.add_argument("--ssh", metavar="USER@HOST", help="collect over SSH instead of ADB")
    transport.add_argument("--local", action="store_true", help="collect on this machine; run on the Titan itself")
    parser.add_argument("--ssh-port", type=int, help="SSH port (default: 22; requires --ssh)")
    parser.add_argument("--ssh-config", metavar="PATH", help="private OpenSSH configuration file (requires --ssh)")
    parser.add_argument("--adb", default="adb", help="ADB executable (default: adb)")
    parser.add_argument("--output", help="new private output directory outside any Git checkout")
    parser.add_argument("--timeout", type=float, default=20, help="seconds per command (default: 20)")
    parser.add_argument(
        "--include-private-logs", action="store_true",
        help="also collect dmesg and kernel cmdline, which can contain unique identifiers",
    )
    args = parser.parse_args(argv)
    if not math.isfinite(args.timeout) or args.timeout <= 0:
        parser.error("--timeout must be finite and greater than zero")
    if args.ssh_port is not None and (args.ssh is None or not 1 <= args.ssh_port <= 65535):
        parser.error("--ssh-port requires --ssh and a port from 1 to 65535")
    if args.ssh_config is not None and (args.ssh is None or not args.ssh_config):
        parser.error("--ssh-config requires --ssh and a nonempty path")

    # Protect newly created parent directories and files as well as the leaf.
    os.umask(0o077)
    try:
        if args.local:
            collect = lambda script: run_local_probe(script, args.timeout)
        elif args.ssh is not None:
            validate_ssh_host(args.ssh)
            collect = lambda script: run_ssh_probe(
                args.ssh, args.ssh_port or 22, script, args.timeout, args.ssh_config,
            )
            _, _, code, timed_out = collect("true")
            if code != 0 or timed_out:
                raise ValueError(
                    "SSH connection check failed. Verify the host key and key-based login "
                    "with ssh first; the collector cannot prompt for passwords or new host keys."
                )
        else:
            result = subprocess.run(
                [args.adb, "devices"], capture_output=True, timeout=args.timeout, check=False,
            )
            if result.returncode:
                raise ValueError("adb devices failed; run that command locally to diagnose it.")
            serial = select_device(parse_devices(result.stdout.decode("utf-8", errors="replace")), args.serial)
            check_adb_transport(args.adb, serial, args.timeout)
            collect = lambda script: run_probe(args.adb, serial, script, args.timeout)
        output = prepare_output(args.output)
    except (OSError, ValueError, subprocess.TimeoutExpired) as error:
        parser.exit(1, f"Inventory not started: {error}\n")

    print(f"Writing private inventory to {output}")
    print("Review files before sharing. Nothing is uploaded; no root/reboot/flash commands are run.")
    probes = dict(PROBES)
    if args.include_private_logs:
        probes.update(PRIVATE_PROBES)
    outputs = {}
    report = {
        "collected_at_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "transport": "local" if args.local else "ssh" if args.ssh is not None else "adb",
        "private_logs_requested": args.include_private_logs,
        "probes": {},
    }
    incomplete = 0
    for name, script in probes.items():
        try:
            stdout, stderr, code, timed_out = collect(script)
        except OSError as error:
            # Do not print the command line: it contains the selected transport ID.
            stdout, stderr, code, timed_out = b"", str(error).encode(), None, False
        write_private(output / name, stdout)
        if stderr:
            write_private(output / f"{name}.stderr", stderr)
        outputs[name] = stdout
        report["probes"][name] = {
            "command": script.strip(), "exit_code": code, "timed_out": timed_out,
            "stdout_bytes": len(stdout), "stderr_bytes": len(stderr),
        }
        if code != 0 or stderr or not stdout:
            incomplete += 1
            print(f"  {name}: unavailable, empty, or needs review (see report.json/stderr)")
        else:
            print(f"  {name}: collected")
    summary = summarize(outputs)
    report["complete"] = incomplete == 0
    report["probes_needing_review"] = incomplete
    write_private(output / "report.json", (json.dumps(report, indent=2) + "\n").encode())
    write_private(output / "summary.json", (json.dumps(summary, indent=2) + "\n").encode())
    print(f"Collection finished; {incomplete} probe(s) need review. Start with {output / 'summary.json'}.")
    print("A completed collection does not confirm working hardware, an unlocked bootloader, or recovery.")
    return 1 if incomplete else 0


if __name__ == "__main__":
    sys.exit(main())
