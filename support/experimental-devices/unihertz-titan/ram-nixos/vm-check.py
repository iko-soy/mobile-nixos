#!/usr/bin/env python3
"""Run the RAM NixOS stage 0 and an x86_64 build of its NixOS system in QEMU.

Each case boots the VM build of stage 0 with QEMU's restricted user network
(172.16.42.0/24, host forwarding only) in place of the USB gadget network. The
cases run at the same time, each in its own guest, under KVM when /dev/kvm is
usable and TCG otherwise; most of their time is spent waiting for deadlines:

* valid: a short push and a same-size push with one changed byte are
  rejected, the pinned squashfs is accepted, NixOS boots to "running" with no
  failed unit, root on tmpfs and the store on an overlay, SSH accepts the test
  key, only loop and zram devices exist, the session deadline is the default
  and its check armed and kept on isolation, the tools are present and no
  trim timer exists; titan-session refuses malformed or out-of-range times,
  holds a long one to the cap, then moves the end to a minute from now, and
  NixOS restarts by itself at that new deadline;
* hard: with the deadline check stopped over SSH, stage 0's hard deadline
  process, still running in NixOS, restarts the guest at its own deadline;
* kexec: titan-kexec refuses a kernel or a replacement tree with the wrong
  hash and an unknown option, loads the pinned kernel and initramfs with
  --nosmp, and `systemctl kexec` starts them (the tree-replacing path itself
  needs a device tree, so only the phone exercises it); stage 0 runs again,
  takes a second push, NixOS boots on one of the guest's two CPUs with
  `nosmp` and the appended marker on its command line, and the session
  deadline then restarts the guest;
* storage: with a blank disk attached, stage 0 reports the refusal on its
  status port, restarts before networking and leaves the disk unchanged;
* deadline: with nothing pushed, stage 0 restarts at its own deadline.
"""

import argparse
import concurrent.futures
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
import threading
import time

LOG_LIMIT = 16 * 1024 * 1024
# Kernel log timestamps and the boot-time clock the deadlines use can differ
# by a few milliseconds; whole seconds are compared with this allowance.
CLOCK_SLACK = 2
STAGE0_DEADLINE = 150
NIXOS_DEFAULT = 480
HARD_DEADLINE = 840
SESSION_CAP = HARD_DEADLINE - 300
CMDLINE = ("console=ttyS0,115200 rdinit=/init panic=5 loglevel=4 nbd.nbds_max=0 systemd.crash_action=reboot "
           "panic_on_oops=1 titan_ram_vm=1")


PORTS_LOCK = threading.Lock()
PORTS_GIVEN = set()


def free_port():
    # Cases start guests concurrently; never hand out the same port twice.
    with PORTS_LOCK:
        while True:
            with socket.socket() as probe:
                probe.bind(("127.0.0.1", 0))
                port = probe.getsockname()[1]
            if port not in PORTS_GIVEN:
                PORTS_GIVEN.add(port)
                return port


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
        command = [args.qemu, "-machine", f"q35,accel={args.accel}", "-cpu", "max", "-m", "1536", "-smp", "2",
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

    def wait_for_count(self, pattern, count, timeout):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            self.pump()
            if sum(1 for line in self.lines() if re.search(pattern, line)) >= count:
                return
            if self.process.poll() is not None and not self.selector.get_map():
                break
        raise RuntimeError(f"Timed out waiting for {count} of {pattern!r}.")

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


def ssh_argv(args, port, command):
    return [args.ssh, "-F", "/dev/null", "-i", args.key_file, "-p", str(port),
            "-o", "StrictHostKeyChecking=no", "-o", "UserKnownHostsFile=/dev/null",
            "-o", "BatchMode=yes", "-o", "ConnectTimeout=10", "-o", "LogLevel=ERROR",
            "root@127.0.0.1", command]


def ssh(args, port, command, timeout=120, stdin=None):
    return subprocess.run(ssh_argv(args, port, command), capture_output=True, timeout=timeout, stdin=stdin)


def wait_ssh(args, guest, timeout=600):
    deadline = time.monotonic() + timeout
    while True:
        guest.pump()
        try:
            if ssh(args, guest.ssh_port, "true", timeout=60).returncode == 0:
                return
        except subprocess.TimeoutExpired:
            pass
        if time.monotonic() > deadline or guest.process.poll() is not None:
            raise RuntimeError("SSH never accepted the test key.")
        time.sleep(5)


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
echo "session=$(titan-session status)"
echo "fstrim=$(systemctl list-timers --all --no-legend | grep -c fstrim)"
echo "tools=$(for t in dtc file less strace htop tmux ethtool iperf3 lsof pv i2cdetect; do command -v $t >/dev/null && echo $t; done | wc -l)"
echo "writers=$(ls /nix/store/*/bin/i2cset /nix/store/*/bin/i2cget /nix/store/*/bin/i2ctransfer /nix/store/*/bin/i2cdump 2>/dev/null | wc -l)"
echo "i2c_id=$(titan-i2c-id >/dev/null 2>&1; echo $?)"
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
    wait_ssh(args, guest)
    return attempt


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
                    "fstrim": "0", "tools": "11", "writers": "0", "i2c_id": "2",
                    "manager": "CrashAction=reboot RebootWatchdogSec=off RuntimeWatchdogSec=off "}
        wrong = {k: values.get(k) for k, v in expected.items() if values.get(k) != v}
        if any(not name.startswith(("loop", "zram")) for name in values.get("block", "").split()):
            wrong["block"] = values.get("block")
        if "titan_ram_vm=1" not in values.get("cmdline", ""):
            wrong["cmdline"] = values.get("cmdline")
        if f"restart at {NIXOS_DEFAULT}s of uptime" not in values.get("session", ""):
            wrong["session"] = values.get("session")
        if not any(line.startswith("TITAN_RAM storage-none block=") and "zram0" in line for line in guest.lines()):
            wrong["stage0_block_line"] = "missing"
        if wrong:
            raise RuntimeError(f"Unexpected guest state: {wrong}")
        refused = ssh(args, guest.ssh_port, "for m in 0 241 abc 0010 1234; do titan-session end-in $m >/dev/null 2>&1; "
                      "echo -n \"$? \"; done; titan-session status", timeout=60).stdout.decode()
        result["refused"] = refused
        if not refused.startswith("2 2 2 2 2 ") or f"restart at {NIXOS_DEFAULT}s" not in refused:
            raise RuntimeError(f"titan-session accepted a bad time or changed the deadline: {refused!r}")
        capped = ssh(args, guest.ssh_port, "titan-session end-in 240", timeout=60).stdout.decode()
        if f"restart at {SESSION_CAP}s of uptime" not in capped:
            raise RuntimeError(f"titan-session did not hold a long time to the cap: {capped!r}")
        moved = ssh(args, guest.ssh_port, "titan-session end-in 1", timeout=60).stdout.decode()
        match = re.search(r"restart at (\d+)s of uptime", moved)
        if match is None:
            raise RuntimeError(f"titan-session did not set a deadline: {moved!r}")
        deadline = int(match.group(1))
        result["moved_deadline"] = deadline
        # The moved restart must be distinguishable from the default one.
        if deadline + 90 >= NIXOS_DEFAULT:
            raise RuntimeError(f"The moved deadline {deadline}s is too close to the default to tell apart.")
        # Leave the session alone: NixOS must restart by itself at that deadline.
        elapsed = guest.wait_exit(deadline + 300)
        second = restart_second(guest)
        if second is None or not deadline - CLOCK_SLACK <= second <= deadline + 90:
            raise RuntimeError("NixOS did not restart at the moved deadline.")
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
        if second is None or not HARD_DEADLINE - CLOCK_SLACK <= second <= HARD_DEADLINE + 30:
            raise RuntimeError("The hard deadline did not restart the guest.")
        result.update({"passed": True, "restart_seconds": second})
    finally:
        guest.stop()
        private_write(directory / "console.log", bytes(guest.console))


def case_kexec(args, directory, result):
    guest = Guest(args, directory)
    try:
        boot_nixos(args, guest, directory, corrupt=False)
        kernel_sha256, initrd_sha256 = digest(args.kernel), digest(args.initrd)
        for local, remote in ((args.kernel, "/run/kexec/kernel"), (args.initrd, "/run/kexec/initrd")):
            with open(local, "rb") as stream:
                copied = ssh(args, guest.ssh_port, f"mkdir -p /run/kexec && cat > {remote}", timeout=300, stdin=stream)
            if copied.returncode != 0:
                raise RuntimeError(f"Copying {remote} failed.")
        refused = ssh(args, guest.ssh_port, f"titan-kexec /run/kexec/kernel {'0' * 64} /run/kexec/initrd "
                      f"{initrd_sha256} titan_kexec=1; echo \"exit=$? loaded=$(cat /sys/kernel/kexec_loaded)\"",
                      timeout=120).stdout.decode()
        if "exit=1" not in refused or "FAILED" not in refused or "loaded=0" not in refused:
            raise RuntimeError(f"titan-kexec did not refuse a kernel with the wrong hash: {refused!r}")
        refused_dtb = ssh(args, guest.ssh_port, f"titan-kexec --dtb /run/kexec/initrd {'0' * 64} /run/kexec/kernel "
                          f"{kernel_sha256} /run/kexec/initrd {initrd_sha256} titan_kexec=1; "
                          f"echo \"exit=$? loaded=$(cat /sys/kernel/kexec_loaded)\"", timeout=120).stdout.decode()
        if "exit=1" not in refused_dtb or "FAILED" not in refused_dtb or "loaded=0" not in refused_dtb:
            raise RuntimeError(f"titan-kexec did not refuse a tree with the wrong hash: {refused_dtb!r}")
        marker = ssh(args, guest.ssh_port, f"titan-kexec /run/kexec/kernel {kernel_sha256} /run/kexec/initrd "
                     f"{initrd_sha256} panic=0; echo \"exit=$? loaded=$(cat /sys/kernel/kexec_loaded)\"",
                     timeout=120).stdout.decode()
        if "exit=2" not in marker or "loaded=0" not in marker:
            raise RuntimeError(f"titan-kexec accepted an APPEND that is not a titan_ marker: {marker!r}")
        option = ssh(args, guest.ssh_port, f"titan-kexec --smp /run/kexec/kernel {kernel_sha256} /run/kexec/initrd "
                     f"{initrd_sha256}; echo \"exit=$? loaded=$(cat /sys/kernel/kexec_loaded)\"",
                     timeout=120).stdout.decode()
        if "exit=2" not in option or "loaded=0" not in option:
            raise RuntimeError(f"titan-kexec accepted an unknown option: {option!r}")
        cpus = ssh(args, guest.ssh_port, "nproc", timeout=60).stdout.decode().split()
        result["cpus_before_kexec"] = cpus
        if cpus != ["2"]:
            raise RuntimeError(f"The guest did not start with two CPUs: {cpus!r}")
        loaded = ssh(args, guest.ssh_port, f"titan-kexec --nosmp /run/kexec/kernel {kernel_sha256} /run/kexec/initrd "
                     f"{initrd_sha256} titan_kexec=1 && cat /sys/kernel/kexec_loaded", timeout=300).stdout.decode()
        result["loaded"] = loaded.split()
        if "loaded; systemctl kexec starts it" not in loaded or loaded.split()[-1:] != ["1"]:
            raise RuntimeError(f"titan-kexec did not load the pinned payload: {loaded!r}")
        try:
            ssh(args, guest.ssh_port, "systemctl kexec", timeout=30)
        except subprocess.TimeoutExpired:
            pass
        guest.wait_for_count(r"TITAN_RAM stage0 start", 2, 300)
        guest.wait_for_count(r"TITAN_RAM waiting-for-system .*attempt=1", 2, 180)
        time.sleep(2)
        push(guest.push_port, source=args.system)
        guest.wait_for_count(r"TITAN_RAM starting-nixos", 2, 300)
        wait_ssh(args, guest)
        after = ssh(args, guest.ssh_port, "cat /proc/cmdline; nproc; cut -d. -f1 /proc/uptime; "
                    "grep -lx titan-deadline /proc/[0-9]*/comm | wc -l", timeout=60).stdout.decode().split()
        result["after_kexec"] = after[-3:]
        result["gadget_detached_before_kexec"] = any("Detach the USB gadget before kexec" in line for line in guest.lines())
        if any(token not in after for token in ("titan_kexec=1", "titan_ram_vm=1", "panic_on_oops=1", "nosmp")):
            raise RuntimeError(f"The kexec'd kernel lacks the expected command line: {after!r}")
        if after[-3] != "1":
            raise RuntimeError(f"The kexec'd kernel did not stay on one CPU: {after[-3:]}")
        if not after[-2].isdigit() or int(after[-2]) > 600 or after[-1] != "1":
            raise RuntimeError(f"The kexec'd system did not restart its uptime or hard deadline: {after[-2:]}")
        moved = ssh(args, guest.ssh_port, "titan-session end-in 1", timeout=60).stdout.decode()
        match = re.search(r"restart at (\d+)s of uptime", moved)
        if match is None:
            raise RuntimeError(f"titan-session did not set a deadline: {moved!r}")
        deadline = int(match.group(1))
        guest.wait_exit(deadline + 300)
        second = restart_second(guest)
        if second is None or not deadline - CLOCK_SLACK <= second <= deadline + 90:
            raise RuntimeError("The kexec'd NixOS did not restart at its session deadline.")
        result.update({"passed": True, "restart_seconds": second, "moved_deadline": deadline})
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
        if restart is None or int(restart.group(1)) < STAGE0_DEADLINE - CLOCK_SLACK:
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
        args.accel = "kvm" if os.access("/dev/kvm", os.R_OK | os.W_OK) else "tcg"
        print(f"accelerator: {args.accel}", flush=True)

        def run(name, function):
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
            return result

        functions = (("storage", case_storage), ("deadline", case_deadline), ("valid", case_valid),
                     ("hard", case_hard), ("kexec", case_kexec))
        with concurrent.futures.ThreadPoolExecutor(max_workers=len(functions)) as pool:
            cases = list(pool.map(lambda case: run(*case), functions))
        passed = all(case["passed"] for case in cases)
        private_write(output / "summary.json", (json.dumps(
            {"passed": passed, "cases": cases, "accelerator": args.accel,
             "scope": "Synthetic x86_64 guest with QEMU user networking; no Titan hardware or USB gadget data path."},
            indent=2) + "\n").encode())
        return 0 if passed else 1
    finally:
        os.umask(previous)


if __name__ == "__main__":
    raise SystemExit(main())
