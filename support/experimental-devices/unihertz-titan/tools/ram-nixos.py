#!/usr/bin/env python3
"""Push the RAM NixOS system to the Titan and wait for SSH (ram-nixos/README.adoc).

The RAM NixOS recovery image's stage 0 brings up a USB network (the phone is
172.16.42.1 and leases the Mac 172.16.42.2), listens on TCP port 7000, and
starts NixOS only from a squashfs whose size and SHA-256 match the values
pinned in the image. This helper checks the local squashfs against the
expected size and hash before connecting, waits until stage 0 accepts the
connection from the Mac's leased address 172.16.42.2, so that nothing can reach
another network's 172.16.42.1, streams the file once and checks that the bytes
sent are the verified ones. It records the image's status lines from its USB serial port
while it works, then waits for the phone's SSH banner and prints the command
for the dedicated key. It only reads the status port and writes nothing to the
phone's storage. Running it is part of a trial that needs the owner's explicit
authorization; see native-ram-trial.adoc.
"""

import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import socket
import sys
import threading
import time

HOST = "172.16.42.1"
SOURCE = "172.16.42.2"
PORT = 7000
IDENTITY = {"idVendor": 0x1209, "idProduct": 0x0005, "USB Vendor Name": "Titan rescue experiment",
            "USB Product Name": "Titan RAM NixOS", "USB Serial Number": "TITAN-RAM-NIXOS-0001"}
STATUS_LINE = re.compile(rb"TITAN_RAM [ -~]{1,200}")


class PushError(Exception):
    pass


def load_listener(directory=None):
    """A private copy of the probe listener's helpers, matching this gadget."""
    path = (directory or Path(__file__).resolve().parent) / "read-probe-report.py"
    spec = importlib.util.spec_from_file_location("titan_ram_listener", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    module.IDENTITY = dict(IDENTITY)
    return module


def verify(path, sha256, size):
    digest, total = hashlib.sha256(), 0
    with open(path, "rb") as stream:
        while chunk := stream.read(1 << 20):
            digest.update(chunk)
            total += len(chunk)
    if total != size or digest.hexdigest() != sha256:
        raise PushError("The local squashfs does not match the pinned size and SHA-256; nothing was sent.")


def connect(host, port, source, wait, poll=1.0, opener=socket.create_connection, clock=time.monotonic,
            sleep=time.sleep):
    """Bound to the leased source address, so this fails until the USB link has it."""
    deadline = clock() + wait
    while True:
        try:
            return opener((host, port), timeout=5, source_address=(source, 0))
        except OSError:
            if clock() + poll > deadline:
                raise PushError(f"Stage 0 did not accept a connection on {host}:{port} in time.")
            sleep(poll)


def send(connection, path, sha256, size, timeout=300):
    digest, total = hashlib.sha256(), 0
    connection.settimeout(timeout)
    with open(path, "rb") as stream:
        while chunk := stream.read(1 << 20):
            connection.sendall(chunk)
            digest.update(chunk)
            total += len(chunk)
    connection.shutdown(socket.SHUT_WR)
    # Stage 0 sends nothing and may close its side early; whether it accepted
    # the stream shows in its status lines and in SSH answering.
    while connection.recv(4096):
        pass
    if total != size or digest.hexdigest() != sha256:
        raise PushError("The file changed while it was sent.")
    return total


def wait_ssh(host, source, wait, poll=2.0, opener=socket.create_connection, clock=time.monotonic,
             sleep=time.sleep):
    deadline = clock() + wait
    while True:
        try:
            with opener((host, 22), timeout=5, source_address=(source, 0)) as connection:
                connection.settimeout(10)
                if connection.recv(64).startswith(b"SSH-2.0-"):
                    return
        except OSError:
            pass
        if clock() + poll > deadline:
            raise PushError("SSH did not answer in time.")
        sleep(poll)


class StatusReader(threading.Thread):
    """Records the image's status lines; it never writes to the port."""

    def __init__(self, listener, log, wait):
        super().__init__(daemon=True)
        self.listener, self.log, self.wait = listener, log, wait
        self.lines, self.stop = [], threading.Event()

    def run(self):
        try:
            port = self.listener.wait_for_port(self.wait)
            fd = self.listener.open_raw(port)
        except Exception as error:
            self.lines.append(f"status port unavailable: {error}")
            return
        pending = b""
        try:
            while not self.stop.is_set() and len(self.lines) < 1000:
                try:
                    chunk = os.read(fd, 4096)
                except BlockingIOError:
                    time.sleep(0.2)
                    continue
                except OSError:
                    break
                if not chunk:
                    time.sleep(0.2)
                    continue
                pending = (pending + chunk)[-4096:]
                while b"\n" in pending:
                    line, pending = pending.split(b"\n", 1)
                    match = STATUS_LINE.search(line)
                    if match:
                        text = match.group(0).decode("ascii")
                        self.lines.append(text)
                        with open(self.log, "a") as stream:
                            stream.write(f"{time.strftime('%H:%M:%S')} {text}\n")
                        print(f"  {text}", flush=True)
        finally:
            os.close(fd)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--system", required=True, help="the RAM NixOS store squashfs")
    parser.add_argument("--sha256", required=True, help="the SHA-256 pinned in the image")
    parser.add_argument("--bytes", required=True, type=int, help="the size pinned in the image")
    parser.add_argument("--output", required=True, help="new private directory; its parent must exist")
    parser.add_argument("--key", required=True, help="the dedicated private key, for the printed command")
    parser.add_argument("--host", default=HOST)
    parser.add_argument("--source", default=SOURCE, help="the Mac's address on the USB link")
    parser.add_argument("--wait", type=float, default=600.0, help="seconds to wait for stage 0 (at most 900)")
    parser.add_argument("--ssh-wait", type=float, default=600.0, help="seconds to wait for SSH (at most 900)")
    parser.add_argument("--no-status", action="store_true", help="do not read the status port")
    args = parser.parse_args(argv)
    previous = os.umask(0o077)
    try:
        if not re.fullmatch(r"[0-9a-f]{64}", args.sha256) or args.bytes <= 0:
            raise PushError("--sha256 or --bytes is malformed.")
        if not 1 <= args.wait <= 900 or not 1 <= args.ssh_wait <= 900:
            raise PushError("--wait or --ssh-wait is outside its reviewed range.")
        verify(args.system, args.sha256, args.bytes)
        os.mkdir(args.output, 0o700)
        output = Path(args.output)
        reader = None
        if not args.no_status:
            reader = StatusReader(load_listener(), output / "status.log", args.wait)
            reader.start()
        started = time.monotonic()
        print(f"Waiting for stage 0 on {args.host}:{PORT}...", flush=True)
        with connect(args.host, PORT, args.source, args.wait) as connection:
            sent = send(connection, args.system, args.sha256, args.bytes)
        pushed = time.monotonic() - started
        print(f"Sent {sent} bytes in {pushed:.0f} s; waiting for SSH...", flush=True)
        wait_ssh(args.host, args.source, args.ssh_wait)
        record = {"host": args.host, "bytes": sent, "sha256": args.sha256, "push_seconds": round(pushed, 1),
                  "ssh_seconds": round(time.monotonic() - started, 1)}
        if reader is not None:
            reader.stop.set()
            record["status_lines"] = list(reader.lines)
        with open(output / "session.json", "x") as stream:
            json.dump(record, stream, indent=2)
        print("SSH is up. Log in with:")
        print(f"  ssh -i {args.key} -o IdentitiesOnly=yes -o BindAddress={args.source} "
              f"-o UserKnownHostsFile={output / 'known_hosts'} -o StrictHostKeyChecking=accept-new root@{args.host}")
        return 0
    except (PushError, OSError, ValueError) as error:
        print(f"RAM NixOS push stopped: {error}", file=sys.stderr)
        return 1
    finally:
        os.umask(previous)


if __name__ == "__main__":
    raise SystemExit(main())
