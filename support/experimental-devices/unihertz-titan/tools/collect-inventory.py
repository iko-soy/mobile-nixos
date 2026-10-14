#!/usr/bin/env python3
"""Collect a read-only Titan baseline locally or over ADB/SSH, without elevating privileges."""

import argparse
import datetime
import json
import math
import os
from pathlib import Path
import re
import shlex
import subprocess
import sys
import tempfile


# These commands are fixed, not assembled from device output or user input.
# Keep probes separate: an unavailable interface must not hide other evidence.
PROBES = {
    "kernel.txt": "uname -r; uname -m; cat /proc/version",
    "os-release.txt": "cat /etc/os-release",
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
        if [ -r "$device/$field" ]; then
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
    # ADB joins command arguments into a remote shell command. Quote the complete
    # static script for `sh -c`; subprocess itself never invokes a host shell.
    command = [adb, "-s", serial, "exec-out", "sh", "-c", shlex.quote(script)]
    return run_command(command, timeout)


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


def run_ssh_probe(host, port, script, timeout):
    validate_ssh_host(host)
    command = [
        "ssh", "-n", "-T", "-o", "BatchMode=yes",
        "-o", "StrictHostKeyChecking=yes", "-o", "ConnectTimeout=10",
        "-p", str(port), "--", host, "sh -c " + shlex.quote(script),
    ]
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

    # Protect newly created parent directories and files as well as the leaf.
    os.umask(0o077)
    try:
        if args.local:
            collect = lambda script: run_local_probe(script, args.timeout)
        elif args.ssh is not None:
            validate_ssh_host(args.ssh)
            collect = lambda script: run_ssh_probe(args.ssh, args.ssh_port or 22, script, args.timeout)
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
    write_private(output / "report.json", (json.dumps(report, indent=2) + "\n").encode())
    write_private(output / "summary.json", (json.dumps(summary, indent=2) + "\n").encode())
    print(f"Collection finished; {incomplete} probe(s) need review. Start with {output / 'summary.json'}.")
    print("A completed collection does not confirm working hardware, an unlocked bootloader, or recovery.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
