#!/usr/bin/env python3
"""Run the RAM NixOS stage 0 and an x86_64 build of its NixOS system in TCG.

Each case boots the VM build of stage 0 with QEMU's restricted user network
(172.16.42.0/24, host forwarding only) in place of the USB gadget network:

* valid: a short push and a same-size push with one changed byte are
  rejected, the pinned squashfs is accepted, NixOS boots to "running" with no
  failed unit, root on tmpfs and the store on an overlay, SSH accepts the test
  key, only loop and zram devices exist, the deadline timer is armed and kept
  on isolation, and NixOS then restarts by itself at that deadline;
* hard: with that timer stopped over SSH, stage 0's hard deadline process,
  still running in NixOS, restarts the guest at its own deadline;
* storage: with a blank disk attached, stage 0 reports the refusal on its
  status port, restarts before networking and leaves the disk unchanged;
* deadline: with nothing pushed, stage 0 restarts at its own deadline.
"""

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import selectors
import signal
import socket
import subprocess
import sys
import time

LOG_LIMIT = 16 * 1024 * 1024
STAGE0_DEADLINE = 150
NIXOS_DEADLINE = 480
HARD_DEADLINE = 600
CMDLINE = "console=ttyS0,115200 rdinit=/init panic=5 loglevel=4 nbd.nbds_max=0 systemd.crash_action=reboot titan_ram_vm=1"


def free_port():
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        return probe.getsockname()[1]


def private_write(path, data):
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "wb") as stream:
        stream.write(data)


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


class Guest:
    def __init__(self, args, directory, disk=None):
        self.push_port, self.ssh_port = free_port(), free_port()
        self.console = bytearray()
        self.started = time.monotonic()
        network = (f"user,id=net0,net=172.16.42.0/24,host=172.16.42.2,dhcpstart=172.16.42.20,restrict=on,"
                   f"hostfwd=tcp:127.0.0.1:{self.push_port}-172.16.42.1:7000,"
                   f"hostfwd=tcp:127.0.0.1:{self.ssh_port}-172.16.42.1:22")
        command = [args.qemu, "-machine", "q35,accel=tcg", "-cpu", "max", "-m", "1536", "-smp", "2",
                   "-nodefaults", "-no-user-config", "-display", "none", "-monitor", "none",
                   "-serial", "stdio", "-no-reboot", "-kernel", args.kernel, "-initrd", args.initrd,
                   "-append", CMDLINE,
                   "-netdev", network, "-device", "virtio-net-pci,netdev=net0"]
        if disk is not None:
            command += ["-drive", f"file={disk},if=none,format=raw,id=disk0", "-device", "virtio-blk-pci,drive=disk0"]
        self.process = subprocess.Popen(command, cwd=directory, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                        stderr=subprocess.STDOUT, start_new_session=True)
        self.selector = selectors.DefaultSelector()
        self.selector.register(self.process.stdout, selectors.EVENT_READ)

    def pump(self, timeout=0.2):
        for key, _ in self.selector.select(timeout):
            chunk = os.read(key.fileobj.fileno(), 65536)
            if not chunk:
                self.selector.unregister(key.fileobj)
                continue
            if len(self.console) + len(chunk) > LOG_LIMIT:
                raise RuntimeError("The guest console exceeded its bound.")
            self.console.extend(chunk)

    def lines(self):
        return self.console.replace(b"\r", b"").decode(errors="replace").split("\n")

    def wait_for(self, pattern, timeout):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            self.pump()
            for line in self.lines():
                if re.search(pattern, line):
                    return line
            if self.process.poll() is not None and not self.selector.get_map():
                break
        raise RuntimeError(f"Timed out waiting for {pattern!r}.")

    def wait_exit(self, timeout):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            self.pump()
            if self.process.poll() is not None:
                while self.selector.get_map():
                    self.pump()
                return time.monotonic() - self.started
        raise RuntimeError("The guest did not restart in time.")

    def stop(self):
        if self.process.poll() is None:
            for sig in (signal.SIGTERM, signal.SIGKILL):
                try:
                    os.killpg(self.process.pid, sig)
                    self.process.wait(timeout=5)
                    break
                except (ProcessLookupError, subprocess.TimeoutExpired):
                    continue
        self.selector.close()
        self.process.stdout.close()


def push(port, source=None, data=None, attempts=60):
    """Send one stream to stage 0, retrying while nothing listens yet."""
    for _ in range(attempts):
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=10) as connection:
                if source is not None:
                    with open(source, "rb") as stream:
                        while chunk := stream.read(1 << 20):
                            connection.sendall(chunk)
                else:
                    connection.sendall(data)
                connection.shutdown(socket.SHUT_WR)
                # The guest closes once it has read the stream.
                connection.settimeout(120)
                while connection.recv(4096):
                    pass
                return
        except (ConnectionError, socket.timeout):
            time.sleep(1)
    raise RuntimeError("Stage 0 never accepted the stream.")


def ssh(args, port, command, timeout=120):
    return subprocess.run([args.ssh, "-F", "/dev/null", "-i", args.key_file, "-p", str(port),
                           "-o", "StrictHostKeyChecking=no", "-o", "UserKnownHostsFile=/dev/null",
                           "-o", "BatchMode=yes", "-o", "ConnectTimeout=10", "-o", "LogLevel=ERROR",
                           "root@127.0.0.1", command], capture_output=True, timeout=timeout)


CHECKS = r"""
echo "running=$(systemctl is-system-running --wait)"
echo "root=$(findmnt -n -o FSTYPE /)"
echo "store=$(findmnt -n -o FSTYPE /nix/store)"
echo "block=$(ls /sys/class/block | tr '\n' ' ')"
echo "address=$(ip -4 -o addr show dev eth0 | awk '{print $4}')"
echo "sshd=$(systemctl is-active sshd)"
echo "networkd=$(systemctl is-active systemd-networkd)"
echo "timer=$(systemctl is-active titan-deadline.timer)"
echo "isolate=$(systemctl show -p IgnoreOnIsolate --value titan-deadline.timer)"
echo "failed=$(systemctl --failed --no-legend --plain | awk '{print $1}' | tr '\n' ' ')"
echo "cmdline=$(cat /proc/cmdline)"
echo "storage_rule=$(grep -c 'SUBSYSTEM=="block".*systemctl --no-block reboot' /etc/udev/rules.d/99-local.rules)"
echo "hard_deadline=$(grep -lx titan-deadline /proc/[0-9]*/comm 2>/dev/null | wc -l)"
echo "manager=$(grep -E '^(CrashAction|RuntimeWatchdogSec|RebootWatchdogSec)=' /etc/systemd/system.conf | sort | tr '\n' ' ')"
echo "watchdog_open=$(ls -l /proc/[0-9]*/fd 2>/dev/null | grep -c '/dev/watchdog')"
"""


def boot_nixos(args, guest, directory, corrupt):
    guest.wait_for(r"TITAN_RAM waiting-for-system .*attempt=1", 180)
    attempt = 1
    if corrupt:
        time.sleep(2)
        push(guest.push_port, data=b"\0" * (1 << 20))
        guest.wait_for(r"TITAN_RAM system-rejected bytes=1048576", 120)
        guest.wait_for(r"TITAN_RAM waiting-for-system .*attempt=2", 60)
        flipped = directory / "flipped.img"
        data = bytearray(Path(args.system).read_bytes())
        data[len(data) // 2] ^= 1
        flipped.write_bytes(data)
        time.sleep(2)
        push(guest.push_port, source=flipped)
        guest.wait_for(rf"TITAN_RAM system-rejected bytes={len(data)}", 300)
        guest.wait_for(r"TITAN_RAM waiting-for-system .*attempt=3", 60)
        flipped.unlink()
        attempt = 3
    time.sleep(2)
    push(guest.push_port, source=args.system)
    guest.wait_for(r"TITAN_RAM system-verified", 300)
    guest.wait_for(r"TITAN_RAM starting-nixos", 120)
    deadline = time.monotonic() + 600
    while True:
        guest.pump()
        try:
            if ssh(args, guest.ssh_port, "true", timeout=60).returncode == 0:
                return attempt
        except subprocess.TimeoutExpired:
            pass
        if time.monotonic() > deadline or guest.process.poll() is not None:
            raise RuntimeError("SSH never accepted the test key.")
        time.sleep(5)


def restart_second(guest):
    restart = re.search(r"\[\s*(\d+)\.\d+\] reboot: Restarting system", "\n".join(guest.lines()))
    return None if restart is None else int(restart.group(1))


def case_valid(args, directory, result):
    guest = Guest(args, directory)
    try:
        boot_nixos(args, guest, directory, corrupt=True)
        checks = ssh(args, guest.ssh_port, CHECKS, timeout=300)
        values = dict(line.split("=", 1) for line in checks.stdout.decode().splitlines() if "=" in line)
        result["checks"] = values
        expected = {"running": "running", "failed": "", "root": "tmpfs", "store": "overlay",
                    "address": "172.16.42.1/24", "sshd": "active", "networkd": "active", "timer": "active",
                    "isolate": "yes", "storage_rule": "1", "hard_deadline": "1", "watchdog_open": "0",
                    "manager": "CrashAction=reboot RebootWatchdogSec=off RuntimeWatchdogSec=off "}
        wrong = {k: values.get(k) for k, v in expected.items() if values.get(k) != v}
        if any(not name.startswith(("loop", "zram")) for name in values.get("block", "").split()):
            wrong["block"] = values.get("block")
        if "titan_ram_vm=1" not in values.get("cmdline", ""):
            wrong["cmdline"] = values.get("cmdline")
        if wrong:
            raise RuntimeError(f"Unexpected guest state: {wrong}")
        # Leave the session alone: NixOS must restart by itself at its deadline.
        elapsed = guest.wait_exit(NIXOS_DEADLINE + 300)
        second = restart_second(guest)
        if second is None or not NIXOS_DEADLINE - 5 <= second <= NIXOS_DEADLINE + 60:
            raise RuntimeError("NixOS did not restart at its deadline.")
        result.update({"passed": True, "restart_seconds": second, "elapsed_seconds": round(elapsed)})
    finally:
        guest.stop()
        private_write(directory / "console.log", bytes(guest.console))


def case_hard(args, directory, result):
    guest = Guest(args, directory)
    try:
        boot_nixos(args, guest, directory, corrupt=False)
        stopped = ssh(args, guest.ssh_port, "systemctl stop titan-deadline.timer && "
                      "systemctl is-active titan-deadline.timer; grep -lx titan-deadline /proc/[0-9]*/comm | wc -l",
                      timeout=120)
        result["after_stop"] = stopped.stdout.decode().split()
        if result["after_stop"] != ["inactive", "1"]:
            raise RuntimeError(f"Unexpected state after stopping the timer: {result['after_stop']}")
        guest.wait_exit(HARD_DEADLINE + 300)
        second = restart_second(guest)
        if second is None or not HARD_DEADLINE <= second <= HARD_DEADLINE + 30:
            raise RuntimeError("The hard deadline did not restart the guest.")
        result.update({"passed": True, "restart_seconds": second})
    finally:
        guest.stop()
        private_write(directory / "console.log", bytes(guest.console))


def case_storage(args, directory, result):
    disk = directory / "blank.raw"
    with disk.open("xb") as stream:
        stream.truncate(16 * 1024 * 1024)
    before = digest(disk)
    guest = Guest(args, directory, disk=disk.name)
    try:
        guest.wait_for(r"TITAN_RAM usb-bound", 180)
        guest.wait_for(r"TITAN_RAM restart reason=storage-present-vda", 60)
        guest.wait_exit(60)
        if any("network-up" in line or "storage-none" in line for line in guest.lines()):
            raise RuntimeError("Stage 0 continued past the storage check.")
        if digest(disk) != before:
            raise RuntimeError("The guest changed the disk.")
        result["passed"] = True
    finally:
        guest.stop()
        private_write(directory / "console.log", bytes(guest.console))


def case_deadline(args, directory, result):
    guest = Guest(args, directory)
    try:
        guest.wait_for(r"TITAN_RAM waiting-for-system", 180)
        guest.wait_for(r"TITAN_RAM deadline", STAGE0_DEADLINE + 120)
        guest.wait_exit(60)
        restart = re.search(r"\[\s*(\d+)\.\d+\] reboot: Restarting system", "\n".join(guest.lines()))
        if restart is None or int(restart.group(1)) < STAGE0_DEADLINE:
            raise RuntimeError("Stage 0 restarted before its deadline.")
        result.update({"passed": True, "restart_seconds": int(restart.group(1))})
    finally:
        guest.stop()
        private_write(directory / "console.log", bytes(guest.console))


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("qemu", "kernel", "initrd", "system", "ssh", "key", "output"):
        parser.add_argument("--" + name, required=True)
    args = parser.parse_args(argv)
    previous = os.umask(0o077)
    try:
        output = Path(args.output).absolute()
        output.mkdir(mode=0o700)
        args.key_file = str(output / "test-key")
        private_write(args.key_file, Path(args.key).read_bytes())
        cases = []
        for name, function in (("storage", case_storage), ("deadline", case_deadline), ("valid", case_valid),
                               ("hard", case_hard)):
            directory = output / name
            directory.mkdir(mode=0o700)
            result = {"case": name, "passed": False}
            try:
                function(args, directory, result)
            except (OSError, RuntimeError, subprocess.SubprocessError) as error:
                result["error"] = str(error)
                console = (directory / "console.log").read_bytes() if (directory / "console.log").exists() else b""
                lines = [line for line in console.decode(errors="replace").replace("\r", "").split("\n") if line.strip()]
                print(f"{name}: {error}\n" + "\n".join(lines[-80:]), file=sys.stderr, flush=True)
            print(f"{name}: {'passed' if result['passed'] else 'FAILED'}", flush=True)
            private_write(directory / "result.json", (json.dumps(result, indent=2) + "\n").encode())
            cases.append(result)
        passed = all(case["passed"] for case in cases)
        private_write(output / "summary.json", (json.dumps(
            {"passed": passed, "cases": cases,
             "scope": "Synthetic x86_64 TCG guest with QEMU user networking; no Titan hardware or USB gadget data path."},
            indent=2) + "\n").encode())
        return 0 if passed else 1
    finally:
        os.umask(previous)


if __name__ == "__main__":
    raise SystemExit(main())
