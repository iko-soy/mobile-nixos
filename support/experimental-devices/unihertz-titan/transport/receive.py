#!/usr/bin/env python3
"""Receive the off-device TTR1 prototype; no discovery, commands or phone setup."""

import argparse
import contextlib
import fcntl
import hashlib
import json
import math
import os
from pathlib import Path
import re
import secrets
import select
import socket
import stat
import struct
import sys
import tempfile
import termios
import time
import tty


HEADER = struct.Struct("!4sB3sII32s")
HELLO, BEGIN, DATA, END, ACK, COMPLETE, ERROR = range(1, 8)
FRAME_LIMIT = 32768
BYTE_LIMIT = 1 << 40
FREE_RESERVE = 64 * 1024 * 1024
REPORT_RESERVE = 65536
UINT64_MAX = (1 << 64) - 1


class TransferError(Exception):
    pass


def check_deadline(deadline):
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise TransferError("Transfer deadline expired.")
    return remaining


def wait_fd(fd, writing, deadline):
    while True:
        try:
            readable, writable, _ = select.select(
                [] if writing else [fd], [fd] if writing else [], [], check_deadline(deadline),
            )
            if readable or writable:
                return
        except InterruptedError:
            continue


def read_exact(fd, count, deadline):
    data = bytearray()
    while len(data) < count:
        wait_fd(fd, False, deadline)
        try:
            part = os.read(fd, count - len(data))
        except (InterruptedError, BlockingIOError):
            continue
        if not part:
            raise TransferError("Transport disconnected before the exchange completed.")
        data.extend(part)
    return bytes(data)


def write_transport(fd, data, deadline):
    view = memoryview(data)
    while view:
        wait_fd(fd, True, deadline)
        try:
            count = os.write(fd, view)
        except (InterruptedError, BlockingIOError):
            continue
        if count <= 0:
            raise TransferError("Transport write made no progress.")
        view = view[count:]


def send_frame(fd, kind, sequence, nonce, payload, deadline):
    write_transport(fd, HEADER.pack(b"TTR1", kind, bytes(3), sequence, len(payload), nonce) + payload, deadline)


def read_frame(fd, nonce, sequence, allowed, deadline):
    magic, kind, reserved, actual_sequence, length, actual_nonce = HEADER.unpack(read_exact(fd, HEADER.size, deadline))
    if magic != b"TTR1" or reserved != bytes(3) or actual_nonce != nonce:
        raise TransferError("Invalid frame magic, reserved bytes or session nonce.")
    if actual_sequence != sequence or kind not in (*allowed, ERROR):
        raise TransferError("Unexpected frame type or sequence.")
    if length > FRAME_LIMIT:
        raise TransferError("Frame payload exceeds the protocol bound.")
    payload = read_exact(fd, length, deadline)
    if kind == ERROR:
        if len(payload) != 4 or struct.unpack("!I", payload)[0] == 0:
            raise TransferError("Malformed remote error frame.")
        raise TransferError(f"Sender reported error code {struct.unpack('!I', payload)[0]}.")
    return kind, payload


def validate_arguments(label, max_bytes, timeout_seconds):
    if not isinstance(label, str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}", label):
        raise ValueError("Label must be 1-64 ASCII letters/digits/dot/underscore/hyphen, beginning with a letter or digit.")
    if not isinstance(max_bytes, int) or isinstance(max_bytes, bool) or not 1 <= max_bytes <= BYTE_LIMIT:
        raise ValueError("The local byte limit must be between 1 and 1099511627776.")
    if not math.isfinite(timeout_seconds) or timeout_seconds <= 0:
        raise ValueError("Timeout must be finite and positive.")


def validate_transport(fd):
    metadata = os.fstat(fd)
    if fcntl.fcntl(fd, fcntl.F_GETFL) & os.O_ACCMODE != os.O_RDWR:
        raise ValueError("Transport descriptor must be open for reading and writing.")
    if stat.S_ISSOCK(metadata.st_mode):
        endpoint = socket.socket(fileno=fd)
        try:
            if endpoint.getsockopt(socket.SOL_SOCKET, socket.SO_TYPE) != socket.SOCK_STREAM:
                raise ValueError("Transport socket must be a stream socket.")
        finally:
            endpoint.detach()
    elif not (stat.S_ISCHR(metadata.st_mode) and os.isatty(fd)):
        raise ValueError("Transport descriptor must be a stream socket or character TTY.")


def cleanup_warning(error):
    # Cleanup must not contradict a transfer result already recorded durably.
    try:
        print(f"Transport cleanup warning (transfer outcome unchanged): {error}", file=sys.stderr)
    except OSError:
        pass


def prepare_output(requested):
    requested = Path(requested).expanduser()
    if requested.is_symlink():
        raise ValueError("Output must not be a symlink.")
    output = requested.resolve()
    for parent in (output, *output.parents):
        marker = parent / ".git"
        if marker.is_file() or (marker / "HEAD").is_file() or (parent / ".jj").is_dir():
            raise ValueError("Private transfer output must be outside Git/jj checkouts.")
    output.mkdir(mode=0o700)
    return output


def sync_directory(output):
    descriptor = os.open(output, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def write_report(output, report, durable=True):
    descriptor, name = tempfile.mkstemp(prefix=".report-", suffix=".partial", dir=output)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write((json.dumps(report, indent=2) + "\n").encode())
            stream.flush()
            if durable:
                os.fsync(stream.fileno())
        os.replace(name, output / "report.json")
        if durable:
            sync_directory(output)
    finally:
        if os.path.exists(name):
            os.unlink(name)


def check_space(output, incoming=0):
    info = os.statvfs(output)
    if info.f_bavail * info.f_frsize < FREE_RESERVE + REPORT_RESERVE + incoming:
        raise TransferError("Insufficient free storage to preserve the 64 MiB reserve.")


def write_file(fd, payload, deadline):
    view = memoryview(payload)
    while view:
        check_deadline(deadline)
        try:
            count = os.write(fd, view)
        except InterruptedError:
            continue
        if count <= 0:
            raise TransferError("Saving the payload made no progress.")
        view = view[count:]


def sync_payload(fd, output, deadline):
    check_deadline(deadline)
    os.fsync(fd)
    sync_directory(output)
    check_deadline(deadline)


def readback(path, original, total, expected_hash, deadline):
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode) or (metadata.st_dev, metadata.st_ino) != original:
            raise TransferError("Saved payload identity changed before readback.")
        digest, remaining = hashlib.sha256(), total
        while remaining:
            check_deadline(deadline)
            data = os.read(descriptor, min(65536, remaining))
            if not data:
                raise TransferError("Independent payload readback was short.")
            digest.update(data)
            remaining -= len(data)
        if os.read(descriptor, 1) or digest.digest() != expected_hash:
            raise TransferError("Independent payload byte count or SHA-256 did not match.")
        check_deadline(deadline)
    finally:
        os.close(descriptor)


def receive(fd, *, label, max_bytes, output, timeout_seconds=90):
    """Run one exchange on an existing socket/TTY fd; preserve incomplete bytes."""
    validate_arguments(label, max_bytes, timeout_seconds)
    validate_transport(fd)
    deadline = time.monotonic() + timeout_seconds
    output = prepare_output(output)
    partial, destination = output / "payload.partial", output / "payload.bin"
    report = {"protocol": 1, "label": label, "status": "incomplete", "readback_verified": False,
              "completed": False, "bytes_received": 0, "local_byte_limit": max_bytes}
    saved, original_blocking, published = None, None, False
    try:
        saved = os.open(partial, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        metadata = os.fstat(saved)
        if not stat.S_ISREG(metadata.st_mode):
            raise TransferError("Staging output is not a regular file.")
        original = (metadata.st_dev, metadata.st_ino)
        write_report(output, report)
        check_space(output)
        original_blocking = os.get_blocking(fd)
        os.set_blocking(fd, False)
        nonce, encoded_label = secrets.token_bytes(32), label.encode("ascii")
        send_frame(fd, HELLO, 0, nonce, struct.pack("!QH", max_bytes, len(encoded_label)) + encoded_label, deadline)
        _, begin = read_frame(fd, nonce, 0, (BEGIN,), deadline)
        if len(begin) < 19:
            raise TransferError("Truncated BEGIN payload.")
        effective, source_kind, declared, label_length = struct.unpack("!QBQH", begin[:19])
        if begin[19:] != encoded_label or label_length != len(encoded_label):
            raise TransferError("BEGIN label does not match the independent local label.")
        if not 1 <= effective <= max_bytes or source_kind not in (0, 1):
            raise TransferError("Invalid effective limit or source kind.")
        if (source_kind == 0 and declared > effective) or (source_kind == 1 and declared != UINT64_MAX):
            raise TransferError("Invalid source length or declared length exceeds the effective limit.")
        report.update({"effective_byte_limit": effective, "source_kind": source_kind,
                       "declared_bytes": declared if source_kind == 0 else None})
        digest, total, sequence = hashlib.sha256(), 0, 1
        while True:
            kind, payload = read_frame(fd, nonce, sequence, (DATA, END), deadline)
            if kind == END:
                break
            if not payload or sequence == 0xFFFFFFFF:
                raise TransferError("Empty DATA or forbidden sequence wrap.")
            if total + len(payload) > effective:
                raise TransferError("DATA exceeds the effective local byte limit.")
            if source_kind == 0 and total + len(payload) > declared:
                raise TransferError("DATA exceeds the declared regular-file length.")
            check_space(output, len(payload))
            write_file(saved, payload, deadline)
            digest.update(payload)
            total += len(payload)
            report["bytes_received"] = total
            sequence += 1
        if len(payload) != 40:
            raise TransferError("END must contain exactly 40 bytes.")
        claimed_total, claimed_hash = struct.unpack("!Q32s", payload)
        if claimed_total != total or claimed_hash != digest.digest() or (source_kind == 0 and total != declared):
            raise TransferError("END count/hash or declared regular-file length did not match.")
        report["sha256"] = digest.hexdigest()
        sync_payload(saved, output, deadline)
        readback(partial, original, total, digest.digest(), deadline)
        report.update({"readback_verified": True, "status": "awaiting-complete"})
        write_report(output, report)
        send_frame(fd, ACK, sequence, nonce, payload, deadline)
        _, receipt = read_frame(fd, nonce, sequence, (COMPLETE,), deadline)
        if receipt != payload:
            raise TransferError("COMPLETE did not match the verified END payload.")
        check_deadline(deadline)
        check_space(output)
        os.set_blocking(fd, original_blocking)
        original_blocking = None
        # Exclusive link+unlink provides rename semantics without overwriting a
        # destination that appeared after output creation.
        os.link(partial, destination)
        published = True
        sync_directory(output)
        partial.unlink()
        sync_directory(output)
        report.update({"status": "complete", "completed": True})
        write_report(output, report)
        return report
    except BaseException as error:
        if published:
            if not partial.exists():
                os.link(destination, partial)
            destination.unlink()
        report.update({"status": "incomplete", "completed": False,
                       "error": str(error) or type(error).__name__})
        if saved is not None:
            report["stored_bytes"] = os.fstat(saved).st_size
        # Best effort remains readable when the originating error was fsync.
        write_report(output, report, durable=False)
        raise
    finally:
        if saved is not None:
            try:
                os.close(saved)
            except OSError as error:
                cleanup_warning(error)
        if original_blocking is not None:
            try:
                os.set_blocking(fd, original_blocking)
            except OSError as error:
                cleanup_warning(error)


@contextlib.contextmanager
def open_tty(path):
    path = Path(path).expanduser()
    if not stat.S_ISCHR(path.lstat().st_mode):
        raise ValueError("--tty must name a character TTY directly, not a symlink or block device.")
    descriptor = os.open(path, os.O_RDWR | os.O_NOCTTY | os.O_NONBLOCK | os.O_NOFOLLOW)
    original, exclusive = None, False
    try:
        if not stat.S_ISCHR(os.fstat(descriptor).st_mode) or not os.isatty(descriptor):
            raise ValueError("--tty is not a terminal device.")
        fcntl.ioctl(descriptor, termios.TIOCEXCL)
        exclusive = True
        original = termios.tcgetattr(descriptor)
        tty.setraw(descriptor, termios.TCSANOW)
        raw = termios.tcgetattr(descriptor)
        for flag in ("IXON", "IXOFF", "IXANY"):
            raw[0] &= ~getattr(termios, flag, 0)
        for flag in ("CRTSCTS", "CNEW_RTSCTS", "CCTS_OFLOW", "CRTS_IFLOW", "CDTR_IFLOW",
                     "CDSR_OFLOW", "CCAR_OFLOW", "MDMBUF"):
            raw[2] &= ~getattr(termios, flag, 0)
        raw[2] |= termios.CREAD | termios.CLOCAL
        termios.tcsetattr(descriptor, termios.TCSANOW, raw)
        yield descriptor
    finally:
        if original is not None:
            try:
                termios.tcsetattr(descriptor, termios.TCSANOW, original)
            except (OSError, termios.error) as error:
                cleanup_warning(error)
        if exclusive:
            try:
                fcntl.ioctl(descriptor, termios.TIOCNXCL)
            except OSError as error:
                cleanup_warning(error)
        try:
            os.close(descriptor)
        except OSError as error:
            cleanup_warning(error)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--tty", required=True)
    parser.add_argument("--label", required=True)
    parser.add_argument("--max-bytes", type=int, required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument("--timeout-seconds", type=float, default=90)
    args = parser.parse_args(argv)
    try:
        validate_arguments(args.label, args.max_bytes, args.timeout_seconds)
        with open_tty(args.tty) as descriptor:
            receive(descriptor, label=args.label, max_bytes=args.max_bytes,
                    output=args.output, timeout_seconds=args.timeout_seconds)
        print(f"Transfer completed and independently verified: {args.output}")
        return 0
    except (OSError, termios.error, ValueError, TransferError, KeyboardInterrupt) as error:
        print(f"Transfer incomplete: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
