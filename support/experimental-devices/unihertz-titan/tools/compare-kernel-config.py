#!/usr/bin/env python3
"""Compare private runtime and reference kernel configurations on the host.

Only the boolean/tristate settings in the Titan README and inventory driver
audit are reported.
Configuration strings, comments and input paths are never included in results.
This is not a kernel API audit or evidence of userspace compatibility/bootability.
"""

import argparse
import gzip
import hashlib
import io
import json
from pathlib import Path
import re
import sys
import zlib


# Bound both file reads and decompression; a kernel configuration is much smaller.
MAX_CONFIG_BYTES = 8 * 1024 * 1024
SETTING = re.compile(r"CONFIG_([A-Za-z0-9_]+)=(.*)")
UNSET = re.compile(r"# CONFIG_([A-Za-z0-9_]+) is not set")
VALUE = re.compile(r'y|m|n|-?[0-9]+|0[xX][0-9a-fA-F]+|"(?:[^"\\]|\\.)*"')

# Keep this a narrow, explicit list rather than publishing arbitrary config
# values. In particular, string settings may contain private paths or keys.
AUDITED_SETTINGS = tuple(sorted((
    "ANDROID_PARANOID_NETWORK", "BINFMT_ELF", "BLK_DEV_INITRD", "BT",
    "CGROUPS", "CGROUP_PIDS", "COMPAT", "CONFIGFS_FS", "DEVTMPFS",
    "DEVTMPFS_MOUNT", "EXT4_FS", "EXT4_FS_POSIX_ACL", "FHANDLE",
    "FRAMEBUFFER_CONSOLE", "FW_LOADER_USER_HELPER", "FW_LOADER_USER_HELPER_FALLBACK",
    "INPUT_EVDEV", "INPUT_UINPUT", "IPC_NS", "KEYBOARD_MTK", "MODULES",
    "MTK_AW9523", "MTK_COMBO_BT", "MTK_FB", "MTK_SND_SOC_NEW_ARCH",
    "MTK_TOUCHPAD", "MTK_TOUCHPAD_SYNAPTICS",
    "NAMESPACES", "NET_NS", "NF_TABLES", "PID_NS", "RD_GZIP", "RD_XZ",
    "SECCOMP", "SECCOMP_FILTER", "SND_SOC", "TMPFS", "TMPFS_POSIX_ACL", "TMPFS_XATTR",
    "TOUCHSCREEN_MTK", "TOUCHSCREEN_MTK_SYNAPTICS", "TUN", "USB_CONFIGFS",
    "USB_MTK_HDRC", "USB_MTU3", "USB_MTU3_DUAL_ROLE", "USB_MTU3_PLAT_PHONE",
    "USER_NS", "UTS_NS", "VT",
)))
SCOPE = (
    "Configuration comparison only; kernel APIs, backports, installed modules, "
    "userspace compatibility and bootability are not verified. "
    "Unknown means the setting is absent, not disabled. Review before sharing."
)


class ConfigError(ValueError):
    """Invalid or unavailable input; messages must not contain private data."""


def parse_config(data):
    """Parse generated Kconfig syntax without evaluating or exposing values."""
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        raise ConfigError("configuration is not UTF-8 text") from None
    if "\0" in text:
        raise ConfigError("configuration contains a NUL byte")
    settings = {}
    for number, line in enumerate(text.splitlines(), 1):
        line = line.strip()
        if not line:
            continue
        unset = UNSET.fullmatch(line)
        setting = SETTING.fullmatch(line)
        if unset:
            name, value = unset.group(1), "n"
        elif setting and VALUE.fullmatch(setting.group(2)):
            name, value = setting.groups()
        elif line.startswith("#") and not line.startswith("# CONFIG_"):
            continue
        else:
            raise ConfigError(f"invalid configuration syntax at line {number}")
        if name in settings:
            raise ConfigError(f"duplicate configuration setting at line {number}")
        if name in AUDITED_SETTINGS and value not in ("y", "m", "n"):
            raise ConfigError(f"expected a boolean/tristate setting at line {number}")
        settings[name] = value
    if not settings:
        raise ConfigError("configuration contains no settings")
    return settings


def load_config(path):
    """Read plain/gzip config; the hash always covers decompressed file bytes."""
    path = Path(path)
    try:
        with path.open("rb") as handle:
            data = handle.read(MAX_CONFIG_BYTES + 1)
    except OSError:
        raise ConfigError("cannot read configuration file") from None
    if len(data) > MAX_CONFIG_BYTES:
        raise ConfigError("configuration file exceeds the size limit")
    if data.startswith(b"\x1f\x8b"):
        try:
            with gzip.GzipFile(fileobj=io.BytesIO(data)) as handle:
                data = handle.read(MAX_CONFIG_BYTES + 1)
        except (OSError, EOFError, zlib.error):
            raise ConfigError("invalid or truncated gzip configuration") from None
        if len(data) > MAX_CONFIG_BYTES:
            raise ConfigError("decompressed configuration exceeds the size limit")
    elif path.suffix == ".gz":
        raise ConfigError("configuration named .gz is not gzip data")
    return {
        "sha256": hashlib.sha256(data).hexdigest(),
        "settings": parse_config(data),
    }


def compare_configs(reference, runtime):
    """Return aggregate differences and allowlisted values, never raw configs."""
    before, after = reference["settings"], runtime["settings"]
    shared = before.keys() & after.keys()
    settings = {}
    for name in AUDITED_SETTINGS:
        original, running = before.get(name, "unknown"), after.get(name, "unknown")
        status = "unknown" if "unknown" in (original, running) else (
            "same" if original == running else "different"
        )
        settings["CONFIG_" + name] = {
            "reference": original, "runtime": running, "comparison": status,
        }
    return {
        "scope": SCOPE,
        "compatibility_verified": False,
        "bootability_verified": False,
        "inputs": {
            label: {"decompressed_sha256": config["sha256"],
                    "setting_count": len(config["settings"])}
            for label, config in (("reference", reference), ("runtime", runtime))
        },
        "comparison": {
            "identical_config_bytes": reference["sha256"] == runtime["sha256"],
            "same_parsed_settings": before == after,
            "changed_setting_count": sum(before[name] != after[name] for name in shared),
            "reference_only_setting_count": len(before.keys() - after.keys()),
            "runtime_only_setting_count": len(after.keys() - before.keys()),
        },
        "settings": settings,
    }


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, epilog=(
        "Missing settings remain unknown. Exit 0 means comparison completed, "
        "including differences; exit 1 means an input could not be interpreted. "
        "No device commands are run and no files are written."
    ))
    parser.add_argument("--reference", type=Path, required=True,
                        help="reference kernel output's config, plain or gzip")
    parser.add_argument("--runtime", type=Path, required=True,
                        help="private collected config.gz or decompressed configuration")
    parser.add_argument("--json", action="store_true", help="emit machine-readable comparison")
    args = parser.parse_args(argv)
    configs = {}
    for label, path in (("reference", args.reference), ("runtime", args.runtime)):
        try:
            configs[label] = load_config(path)
        except ConfigError as error:
            # Do not expose the input path, invalid line or underlying exception.
            print(f"Cannot compare {label} configuration: {error}", file=sys.stderr)
            return 1
    report = compare_configs(**configs)
    if args.json:
        print(json.dumps(report, indent=2, sort_keys=True))
    else:
        print(SCOPE)
        for label, info in report["inputs"].items():
            print(f"{label.capitalize()} SHA-256 (decompressed): {info['decompressed_sha256']}")
        print("Overall: " + ", ".join(f"{key}={value}" for key, value in report["comparison"].items()))
        for name, values in report["settings"].items():
            print(f"{name}: reference={values['reference']} runtime={values['runtime']} "
                  f"({values['comparison']})")
    return 0


if __name__ == "__main__":
    sys.exit(main())
