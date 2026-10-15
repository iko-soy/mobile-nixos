"""Synthetic sockets/files/pipes/PTYs only; optionally exercise the built C sender."""

import contextlib
import errno
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import select
import socket
import stat
import struct
import subprocess
import sys
import tempfile
import termios
import threading
import time
import unittest
from unittest.mock import patch


SPEC = importlib.util.spec_from_file_location("transport_receiver", Path(__file__).with_name("receive.py"))
receiver = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(receiver)
HEADER = struct.Struct("!4sB3sII32s")
LABEL = b"fixture-1"
LIMIT = 131072
PATTERN = bytes(range(256)) * 257


def exact(peer, length):
    data = bytearray()
    while len(data) < length:
        chunk = peer.recv(length - len(data))
        if not chunk:
            raise EOFError("fixture peer disconnected")
        data.extend(chunk)
    return bytes(data)


def frame(peer):
    magic, kind, reserved, sequence, length, nonce = HEADER.unpack(exact(peer, 48))
    assert magic == b"TTR1" and reserved == bytes(3) and length <= 32768
    return kind, sequence, nonce, exact(peer, length)


def packet(kind, sequence, nonce, payload=b"", *, magic=b"TTR1", reserved=bytes(3), length=None):
    return HEADER.pack(magic, kind, reserved, sequence, len(payload) if length is None else length, nonce) + payload


def hello(peer):
    kind, sequence, nonce, payload = frame(peer)
    assert (kind, sequence) == (1, 0)
    maximum, length = struct.unpack("!QH", payload[:10])
    assert maximum == LIMIT and payload[10:] == LABEL and length == len(LABEL)
    return nonce


def begin(nonce, size, *, effective=LIMIT, source_kind=0, label=LABEL):
    return packet(2, 0, nonce, struct.pack("!QBQH", effective, source_kind, size, len(label)) + label)


def send_fragmented(peer, data):
    sizes, offset, index = (1, 7, 19, 251), 0, 0
    while offset < len(data):
        amount = sizes[index % len(sizes)]
        peer.sendall(data[offset:offset + amount])
        offset += amount
        index += 1


def normal_peer(peer, payload=PATTERN, *, receipt="complete", observed=None, fragmented=False):
    nonce = hello(peer)
    send = (lambda data: send_fragmented(peer, data)) if fragmented else peer.sendall
    send(begin(nonce, len(payload)))
    sequence = 1
    for offset in range(0, len(payload), 16000):
        send(packet(3, sequence, nonce, payload[offset:offset + 16000]))
        sequence += 1
    end = struct.pack("!Q32s", len(payload), hashlib.sha256(payload).digest())
    send(packet(4, sequence, nonce, end))
    if receipt == "expect-no-ack":
        if observed is not None:
            observed.append(peer.recv(1))
        return
    acknowledgement = frame(peer)
    assert acknowledgement == (5, sequence, nonce, end)
    if observed is not None:
        observed.append(acknowledgement)
    if receipt == "complete":
        send(packet(6, sequence, nonce, end))
    elif receipt == "wrong":
        send(packet(6, sequence, nonce, bytes(40)))
    elif receipt == "stale":
        send(packet(6, sequence, bytes(32), end))


def reject_after(build):
    """Send one invalid sequence, then hold the peer open until the receiver closes.

    Holding the connection prevents a disconnect or deadline from satisfying a
    negative case: the receiver must reject the bytes themselves.
    """
    def handler(peer):
        peer.sendall(build(hello(peer)))
        try:
            while peer.recv(65536):
                pass
        except ConnectionResetError:
            # Linux resets a Unix stream socket closed with unread input; any
            # frame queued before that close is still delivered first.
            pass
    return handler


def exchange(output, handler, *, timeout=2):
    host, peer = socket.socketpair()
    peer.settimeout(3)
    peer_errors = []

    def serve():
        try:
            handler(peer)
        except BaseException as error:
            peer_errors.append(error)
        finally:
            peer.close()

    thread = threading.Thread(target=serve, daemon=True)
    thread.start()
    report = error = None
    try:
        report = receiver.receive(host.fileno(), label=LABEL.decode(), max_bytes=LIMIT,
                                  output=output, timeout_seconds=timeout)
    except (receiver.TransferError, OSError) as caught:
        error = caught
    finally:
        host.close()
        thread.join(4)
    if thread.is_alive():
        raise AssertionError("Fixture peer did not stop")
    if peer_errors:
        raise AssertionError(f"Fixture peer failed: {peer_errors}")
    return report, error


@contextlib.contextmanager
def bridged_terminals():
    """Model two serial endpoints with independent terminal line disciplines."""
    host_master, host_slave = os.openpty()
    sender_master, sender_slave = os.openpty()
    stopped, errors = threading.Event(), []
    for descriptor in (host_master, sender_master):
        os.set_blocking(descriptor, False)

    def relay():
        queued = {host_master: bytearray(), sender_master: bytearray()}
        other = {host_master: sender_master, sender_master: host_master}
        deadline = time.monotonic() + 5
        try:
            while not stopped.is_set():
                if time.monotonic() >= deadline:
                    raise AssertionError("Synthetic terminal bridge exceeded its deadline")
                readable, writable, _ = select.select(
                    [fd for fd in queued if len(queued[other[fd]]) < 65536],
                    [fd for fd, pending in queued.items() if pending], [], 0.02,
                )
                for descriptor in readable:
                    try:
                        data = os.read(descriptor, 32768)
                    except BlockingIOError:
                        continue
                    if not data:
                        raise AssertionError("Synthetic terminal bridge disconnected")
                    queued[other[descriptor]].extend(data)
                for descriptor in writable:
                    try:
                        count = os.write(descriptor, queued[descriptor])
                    except BlockingIOError:
                        continue
                    if count <= 0:
                        raise AssertionError("Synthetic terminal bridge made no progress")
                    del queued[descriptor][:count]
        except BaseException as error:
            errors.append(error)

    worker = threading.Thread(target=relay, daemon=True)
    worker.start()
    try:
        yield os.ttyname(host_slave), sender_slave
    finally:
        stopped.set()
        worker.join(1)
        for descriptor in (host_master, host_slave, sender_master, sender_slave):
            os.close(descriptor)
        if worker.is_alive() or errors:
            raise AssertionError(f"Synthetic terminal bridge failed: {errors}")


class ReceiverTests(unittest.TestCase):
    def test_fragmentation_all_bytes_empty_stream_and_private_publication(self):
        for data in (PATTERN, b""):
            with self.subTest(length=len(data)), tempfile.TemporaryDirectory() as temporary:
                output = Path(temporary) / "transfer"
                report, error = exchange(output, lambda peer: normal_peer(peer, data, fragmented=True), timeout=5)
                self.assertIsNone(error)
                self.assertTrue(report["completed"])
                self.assertTrue(report["readback_verified"])
                self.assertEqual((output / "payload.bin").read_bytes(), data)
                self.assertFalse((output / "payload.partial").exists())
                self.assertEqual(report["sha256"], hashlib.sha256(data).hexdigest())
                self.assertEqual(stat.S_IMODE(output.stat().st_mode), 0o700)
                for path in output.iterdir():
                    self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)

    def assert_incomplete(self, output, *, verified=False):
        report = json.loads((output / "report.json").read_text())
        self.assertEqual(report["status"], "incomplete")
        self.assertFalse(report["completed"])
        self.assertEqual(report["readback_verified"], verified)
        self.assertTrue((output / "payload.partial").is_file())
        self.assertFalse((output / "payload.bin").exists())
        return report

    def test_invalid_headers_and_begin_fields_fail_without_resynchronization(self):
        variants = [
            (lambda n: packet(2, 0, n, magic=b"BAD!"), "Invalid frame magic, reserved bytes or session nonce."),
            (lambda n: packet(2, 0, n, reserved=b"\0\1\0"), "Invalid frame magic, reserved bytes or session nonce."),
            (lambda n: packet(2, 0, bytes(32)), "Invalid frame magic, reserved bytes or session nonce."),
            (lambda n: packet(2, 1, n), "Unexpected frame type or sequence."),
            (lambda n: packet(99, 0, n), "Unexpected frame type or sequence."),
            (lambda n: packet(2, 0, n, length=32769), "Frame payload exceeds the protocol bound."),
            (lambda n: packet(2, 0, n, b"short"), "Truncated BEGIN payload."),
            (lambda n: begin(n, 0, effective=LIMIT + 1), "Invalid effective limit or source kind."),
            (lambda n: begin(n, 0, effective=0), "Invalid effective limit or source kind."),
            (lambda n: begin(n, LIMIT + 1), "Invalid source length or declared length exceeds the effective limit."),
            (lambda n: begin(n, 0, source_kind=2), "Invalid effective limit or source kind."),
            (lambda n: begin(n, 0, source_kind=1), "Invalid source length or declared length exceeds the effective limit."),
            (lambda n: begin(n, 0, label=b"wrong"), "BEGIN label does not match the independent local label."),
            (lambda n: packet(7, 0, n, struct.pack("!I", 0)), "Malformed remote error frame."),
        ]
        for index, (variant, expected) in enumerate(variants):
            with self.subTest(case=index), tempfile.TemporaryDirectory() as temporary:
                output = Path(temporary) / "transfer"
                _, error = exchange(output, reject_after(variant))
                self.assertIsInstance(error, receiver.TransferError)
                self.assertEqual(str(error), expected)
                self.assertEqual(self.assert_incomplete(output)["stored_bytes"], 0)

    def test_data_sequence_lengths_limits_hashes_and_declared_length(self):
        variants = [
            (lambda n: begin(n, 1) + packet(3, 2, n, b"x"), "Unexpected frame type or sequence.", 0),
            (lambda n: begin(n, 1) + packet(3, 1, n), "Empty DATA or forbidden sequence wrap.", 0),
            (lambda n: begin(n, 1) + packet(3, 1, n, length=32769), "Frame payload exceeds the protocol bound.", 0),
            (lambda n: begin(n, receiver.UINT64_MAX, source_kind=1, effective=1) + packet(3, 1, n, b"xx"),
             "DATA exceeds the effective local byte limit.", 0),
            (lambda n: begin(n, 1) + packet(3, 1, n, b"xx"), "DATA exceeds the declared regular-file length.", 0),
            (lambda n: begin(n, 0) + packet(4, 1, n, bytes(39)), "END must contain exactly 40 bytes.", 0),
            (lambda n: begin(n, 0) + packet(4, 1, n, struct.pack("!Q32s", 1, hashlib.sha256(b"").digest())), "END count/hash or declared regular-file length did not match.", 0),
            (lambda n: begin(n, 0) + packet(4, 1, n, bytes(40)), "END count/hash or declared regular-file length did not match.", 0),
            (lambda n: begin(n, 2) + packet(3, 1, n, b"x")
             + packet(4, 2, n, struct.pack("!Q32s", 1, hashlib.sha256(b"x").digest())), "END count/hash or declared regular-file length did not match.", 1),
            (lambda n: begin(n, 0) + packet(7, 1, n, struct.pack("!I", 5)), "Sender reported error code 5.", 0),
        ]
        for index, (variant, expected, stored) in enumerate(variants):
            with self.subTest(case=index), tempfile.TemporaryDirectory() as temporary:
                output = Path(temporary) / "transfer"
                _, error = exchange(output, reject_after(variant))
                self.assertIsInstance(error, receiver.TransferError)
                self.assertEqual(str(error), expected)
                self.assertEqual(self.assert_incomplete(output)["stored_bytes"], stored)

    def test_data_frame_that_would_consume_the_free_space_reserve_is_refused(self):
        class Space:
            f_frsize = 1
            f_bavail = receiver.FREE_RESERVE + receiver.REPORT_RESERVE + 100

        with tempfile.TemporaryDirectory() as temporary, \
                patch.object(receiver.os, "statvfs", return_value=Space()):
            output = Path(temporary) / "transfer"
            _, error = exchange(output, reject_after(lambda n: begin(n, 101) + packet(3, 1, n, b"x" * 101)))
            self.assertIsInstance(error, receiver.TransferError)
            self.assertEqual(str(error), "Insufficient free storage to preserve the 64 MiB reserve.")
            self.assertEqual(self.assert_incomplete(output)["stored_bytes"], 0)

    def test_early_eof_and_absolute_timeout_preserve_staging(self):
        handlers = (
            lambda peer: peer.sendall(packet(2, 0, hello(peer))[:23]),
            lambda peer: peer.sendall(begin((n := hello(peer)), 20) + packet(3, 1, n, b"x", length=20)),
            lambda peer: (hello(peer), time.sleep(0.15)),
        )
        for index, handler in enumerate(handlers):
            with self.subTest(case=index), tempfile.TemporaryDirectory() as temporary:
                output = Path(temporary) / "transfer"
                _, error = exchange(output, handler, timeout=0.05)
                self.assertIsNotNone(error)
                self.assert_incomplete(output)

    def test_lost_stale_or_incorrect_completion_never_publishes_verified_bytes(self):
        for receipt in ("lost", "wrong", "stale"):
            with self.subTest(receipt=receipt), tempfile.TemporaryDirectory() as temporary:
                output = Path(temporary) / "transfer"
                ack = []
                _, error = exchange(output, lambda peer: normal_peer(peer, receipt=receipt, observed=ack))
                self.assertIsNotNone(error)
                self.assertEqual(len(ack), 1)
                self.assert_incomplete(output, verified=True)
                self.assertEqual((output / "payload.partial").read_bytes(), PATTERN)

    def test_fsync_or_readback_failure_sends_no_ack(self):
        for stage in ("sync_payload", "readback"):
            with self.subTest(stage=stage), tempfile.TemporaryDirectory() as temporary:
                output = Path(temporary) / "transfer"
                observed = []
                with patch.object(receiver, stage, side_effect=OSError("fixture storage failure")):
                    _, error = exchange(output, lambda peer: normal_peer(peer, receipt="expect-no-ack", observed=observed))
                self.assertIsNotNone(error)
                self.assertEqual(observed, [b""])
                self.assert_incomplete(output)

    def test_payload_full_flush_precedes_ack_and_only_unsupported_falls_back(self):
        # Simulate the macOS F_FULLFSYNC request on every host and record which
        # descriptors are flushed, by inode, relative to the observed ACK.
        command = getattr(receiver.fcntl, "F_FULLFSYNC", 51)
        real_fcntl, real_fsync = receiver.fcntl.fcntl, receiver.os.fsync
        for mode in ("full", "unsupported", "media-failure"):
            with self.subTest(mode=mode), tempfile.TemporaryDirectory() as temporary:
                output = Path(temporary) / "transfer"
                events = []

                def payload_inode():
                    partial = output / "payload.partial"
                    return partial.stat().st_ino if partial.exists() else None

                def fake_fcntl(fd, cmd, *args):
                    if cmd != command:
                        return real_fcntl(fd, cmd, *args)
                    inode = os.fstat(fd).st_ino
                    events.append(("full", inode))
                    if mode == "unsupported":
                        raise OSError(errno.ENOTSUP, "fixture: unsupported")
                    if mode == "media-failure" and inode == payload_inode():
                        raise OSError(errno.EIO, "fixture: media flush failed")
                    return 0

                def fake_fsync(fd):
                    events.append(("fsync", os.fstat(fd).st_ino))
                    return real_fsync(fd)

                observed = events if mode != "media-failure" else []
                receipt = "expect-no-ack" if mode == "media-failure" else "complete"
                with patch.object(receiver.fcntl, "F_FULLFSYNC", command, create=True), \
                        patch.object(receiver.fcntl, "fcntl", side_effect=fake_fcntl), \
                        patch.object(receiver.os, "fsync", side_effect=fake_fsync):
                    report, error = exchange(output, lambda peer: normal_peer(peer, receipt=receipt, observed=observed))
                if mode == "media-failure":
                    self.assertIsInstance(error, OSError)
                    self.assertEqual(error.errno, errno.EIO)
                    self.assertEqual(observed, [b""])
                    self.assert_incomplete(output)
                    continue
                self.assertIsNone(error)
                self.assertTrue(report["completed"])
                payload = (output / "payload.bin").stat().st_ino
                directory = output.stat().st_ino
                ack = next(index for index, event in enumerate(events) if event[0] == 5)
                kind = "full" if mode == "full" else "fsync"
                self.assertIn((kind, payload), events[:ack])
                self.assertIn((kind, directory), events[:ack])
                if mode == "full":
                    self.assertNotIn(("fsync", payload), events)

    def test_independent_readback_detects_actual_saved_file_corruption(self):
        original = receiver.readback

        def corrupt(path, *args):
            with path.open("r+b") as stream:
                stream.write(b"corrupt")
            return original(path, *args)

        with tempfile.TemporaryDirectory() as temporary, patch.object(receiver, "readback", side_effect=corrupt):
            output = Path(temporary) / "transfer"
            observed = []
            _, error = exchange(output, lambda peer: normal_peer(peer, receipt="expect-no-ack", observed=observed))
            self.assertIsNotNone(error)
            self.assertEqual(observed, [b""])
            self.assert_incomplete(output)

    def test_existing_output_git_paths_and_invalid_limits_are_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            existing = base / "existing"
            existing.mkdir()
            (existing / "keep").write_bytes(b"unchanged")
            with self.assertRaises(FileExistsError):
                receiver.prepare_output(existing)
            self.assertEqual((existing / "keep").read_bytes(), b"unchanged")
            (base / ".git").write_text("gitdir: /fixture")
            with self.assertRaisesRegex(ValueError, "Git"):
                receiver.prepare_output(base / "new")
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            (base / ".jj").mkdir()
            with self.assertRaisesRegex(ValueError, "jj"):
                receiver.prepare_output(base / "new")
        for label, limit, timeout in (("../path", 1, 1), ("", 1, 1), ("ok", 0, 1),
                                      ("ok", receiver.BYTE_LIMIT + 1, 1), ("ok", 1, float("nan"))):
            with self.subTest(label=label, limit=limit, timeout=timeout), self.assertRaises(ValueError):
                receiver.validate_arguments(label, limit, timeout)

    def test_free_space_is_incremental_not_entire_advertised_limit(self):
        class Space:
            f_bavail = receiver.FREE_RESERVE + receiver.REPORT_RESERVE + 32768
            f_frsize = 1

        with patch.object(receiver.os, "statvfs", return_value=Space()):
            receiver.check_space(Path("/"), 32768)
            with self.assertRaises(receiver.TransferError):
                receiver.check_space(Path("/"), 32769)

    def test_receiver_rejects_non_stream_transport_before_creating_output_or_writing(self):
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            source = base / "untouched"
            source.write_bytes(b"keep")
            regular = os.open(source, os.O_RDWR)
            null = os.open("/dev/null", os.O_RDWR)
            reader, writer = os.pipe()
            datagram = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
            try:
                for descriptor in (regular, null, reader, writer, datagram.fileno()):
                    with self.subTest(descriptor=descriptor), self.assertRaises(ValueError):
                        receiver.receive(descriptor, label="fixture", max_bytes=1,
                                         output=base / "forbidden", timeout_seconds=1)
                    self.assertFalse((base / "forbidden").exists())
                self.assertEqual(source.read_bytes(), b"keep")
            finally:
                for descriptor in (regular, null, reader, writer):
                    os.close(descriptor)
                datagram.close()

    def test_transport_restoration_failure_prevents_publication(self):
        original = receiver.os.set_blocking

        def fail_restore(descriptor, enabled):
            if enabled:
                raise OSError("fixture restoration failure")
            original(descriptor, enabled)

        with tempfile.TemporaryDirectory() as temporary, patch.object(receiver.os, "set_blocking", side_effect=fail_restore):
            output = Path(temporary) / "transfer"
            with contextlib.redirect_stderr(io.StringIO()) as diagnostics:
                _, error = exchange(output, normal_peer)
            self.assertIsInstance(error, OSError)
            self.assert_incomplete(output, verified=True)
            self.assertIn("cleanup warning", diagnostics.getvalue())

    def test_tty_cleanup_warning_does_not_replace_completed_body(self):
        master, slave = os.openpty()
        original = termios.tcgetattr(slave)
        try:
            terminal = receiver.open_tty(os.ttyname(slave))
            terminal.__enter__()
            with contextlib.redirect_stderr(io.StringIO()) as diagnostics:
                with patch.object(receiver.termios, "tcsetattr", side_effect=OSError("fixture restoration failure")):
                    terminal.__exit__(None, None, None)
            self.assertIn("transfer outcome unchanged", diagnostics.getvalue())
            termios.tcsetattr(slave, termios.TCSANOW, original)
        finally:
            os.close(master)
            os.close(slave)

    def test_tty_requires_explicit_terminal_and_restores_raw_settings(self):
        with self.assertRaises(ValueError), receiver.open_tty("/dev/null"):
            pass
        master, slave = os.openpty()
        try:
            configured = termios.tcgetattr(slave)
            configured[0] |= termios.IXON | termios.IXOFF | getattr(termios, "IXANY", 0)
            configured[2] |= getattr(termios, "CRTSCTS", 0)
            termios.tcsetattr(slave, termios.TCSANOW, configured)
            original = termios.tcgetattr(slave)
            with receiver.open_tty(os.ttyname(slave)) as descriptor:
                raw = termios.tcgetattr(descriptor)
                self.assertFalse(raw[3] & (termios.ICANON | termios.ECHO))
                self.assertFalse(raw[0] & (termios.IXON | termios.IXOFF | getattr(termios, "IXANY", 0)))
                self.assertFalse(raw[2] & getattr(termios, "CRTSCTS", 0))
                self.assertEqual(raw[2] & (termios.CLOCAL | termios.CREAD), termios.CLOCAL | termios.CREAD)
            restored = termios.tcgetattr(slave)
            # Darwin may set the transient pending-input flag when canonical
            # mode is restored; it is not a persistent terminal configuration.
            restored[3] &= ~getattr(termios, "PENDIN", 0)
            original[3] &= ~getattr(termios, "PENDIN", 0)
            self.assertEqual(restored, original)
        finally:
            os.close(master)
            os.close(slave)


SENDER = os.environ.get("TITAN_TRANSPORT_SENDER")
EMULATOR = os.environ.get("TITAN_TRANSPORT_EMULATOR")


@unittest.skipUnless(SENDER, "Set TITAN_TRANSPORT_SENDER to exercise the compiled sender")
class SenderTests(unittest.TestCase):
    def command(self, source, transport, status=None):
        command = ([EMULATOR] if EMULATOR else []) + [SENDER, "--input-fd", str(source),
                   "--transport-fd", str(transport), "--label", LABEL.decode(),
                   "--max-bytes", str(LIMIT), "--timeout-seconds", "2"]
        if status is not None:
            command += ["--status-fd", str(status)]
        return command

    def run_sender(self, *, pty=False, pipe_status=None):
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            source_path = base / "source"
            source_path.write_bytes(PATTERN)
            source = os.open(source_path, os.O_RDONLY)
            producer = status_reader = None
            if pipe_status is not None:
                os.close(source)
                source, writer = os.pipe()
                status_reader, status_writer = os.pipe()

                def produce():
                    try:
                        view = memoryview(PATTERN)
                        while view:
                            view = view[os.write(writer, view):]
                    finally:
                        os.close(writer)
                    try:
                        os.write(status_writer, pipe_status)
                    finally:
                        os.close(status_writer)

                producer = threading.Thread(target=produce, daemon=True)
                producer.start()
            host = peer = None
            terminals = contextlib.ExitStack()
            terminal = contextlib.nullcontext()
            if pty:
                host_path, transport = terminals.enter_context(bridged_terminals())
                terminal = receiver.open_tty(host_path)
            else:
                host, peer = socket.socketpair()
                transport = peer.fileno()
            descriptors = [source, transport] + ([status_reader] if status_reader is not None else [])
            process = None
            try:
                with terminal as terminal_fd:
                    if pty:
                        inherited = termios.tcgetattr(transport)
                        inherited[0] |= termios.IXON | termios.IXOFF | getattr(termios, "IXANY", 0)
                        inherited[3] |= termios.ICANON | termios.ECHO
                        termios.tcsetattr(transport, termios.TCSANOW, inherited)
                    process = subprocess.Popen(self.command(source, transport, status_reader), pass_fds=descriptors,
                                               stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                    if peer is not None:
                        peer.close()
                    if pty:
                        # Observe child raw setup before sending binary HELLO.
                        # Separate PTYs keep its later terminal restoration from
                        # changing the receiver's independent line discipline.
                        ready_by = time.monotonic() + 1
                        while os.get_blocking(transport):
                            self.assertIsNone(process.poll(), "Sender exited before PTY setup")
                            self.assertLess(time.monotonic(), ready_by, "Sender did not prepare PTY")
                            time.sleep(0.001)
                        raw = termios.tcgetattr(transport)
                        self.assertFalse(raw[3] & (termios.ICANON | termios.ECHO))
                        self.assertFalse(raw[0] & (termios.IXON | termios.IXOFF | getattr(termios, "IXANY", 0)))
                    output = base / "received"
                    error = None
                    try:
                        receiver.receive(terminal_fd if pty else host.fileno(), label=LABEL.decode(),
                                         max_bytes=LIMIT, output=output, timeout_seconds=3)
                    except (receiver.TransferError, OSError) as caught:
                        error = caught
                    stdout, stderr = process.communicate(timeout=4)
                    if pty:
                        self.assertTrue(termios.tcgetattr(transport)[3] & termios.ICANON)
                        self.assertFalse(termios.tcgetattr(terminal_fd)[3] & termios.ICANON)
                    if pipe_status is None or pipe_status == b"TPST" + bytes(4):
                        self.assertIsNone(error, stderr)
                        self.assertEqual(process.returncode, 0, stderr)
                        self.assertEqual((output / "payload.bin").read_bytes(), PATTERN)
                    else:
                        self.assertIsNotNone(error)
                        self.assertNotEqual(process.returncode, 0)
                        self.assertFalse((output / "payload.bin").exists())
                    self.assertEqual(stdout, b"")
            finally:
                if process is not None and process.poll() is None:
                    process.kill()
                    process.wait()
                os.close(source)
                if status_reader is not None:
                    os.close(status_reader)
                if host is not None:
                    host.close()
                if peer is not None:
                    peer.close()
                terminals.close()
                if producer is not None:
                    producer.join(2)
                    self.assertFalse(producer.is_alive())

    def test_regular_socket_roundtrip(self):
        self.run_sender()

    def test_all_256_bytes_over_raw_pty(self):
        self.run_sender(pty=True)

    def test_fifo_requires_exact_successful_producer_status(self):
        for status in (b"TPST" + bytes(4), b"TPST" + struct.pack("!I", 7), b"", b"TPST" + bytes(4) + b"x"):
            with self.subTest(status=status):
                self.run_sender(pipe_status=status)

    def test_sender_rejects_character_and_tty_sources_without_reading_them(self):
        master, slave = os.openpty()
        readonly_slave = os.open(os.ttyname(slave), os.O_RDONLY | os.O_NOCTTY | os.O_NONBLOCK)
        null = os.open("/dev/null", os.O_RDONLY)
        try:
            for source in (null, readonly_slave):
                with self.subTest(source=source):
                    host, peer = socket.socketpair()
                    try:
                        process = subprocess.run(self.command(source, peer.fileno()), pass_fds=[source, peer.fileno()],
                                                 capture_output=True, timeout=4)
                        self.assertNotEqual(process.returncode, 0)
                        self.assertEqual(process.stdout, b"")
                    finally:
                        host.close()
                        peer.close()
        finally:
            os.close(null)
            os.close(readonly_slave)
            os.close(master)
            os.close(slave)

    def test_sender_bad_handshake_bad_ack_and_lost_ack(self):
        for mode in ("bad-hello", "bad-ack", "lost-ack"):
            with self.subTest(mode=mode), tempfile.TemporaryDirectory() as temporary:
                source_path = Path(temporary) / "source"
                source_path.write_bytes(b"hello")
                source = os.open(source_path, os.O_RDONLY)
                host, peer = socket.socketpair()
                host.settimeout(4)
                process = subprocess.Popen(self.command(source, peer.fileno()), pass_fds=[source, peer.fileno()],
                                           stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                peer.close()
                try:
                    nonce = bytes(range(32))
                    greeting = struct.pack("!QH", LIMIT, len(LABEL)) + LABEL
                    host.sendall(packet(1, 0, nonce, greeting, magic=b"BAD!" if mode == "bad-hello" else b"TTR1"))
                    if mode != "bad-hello":
                        self.assertEqual(frame(host)[0], 2)
                        while (received := frame(host))[0] != 4:
                            self.assertEqual(received[0], 3)
                        if mode == "bad-ack":
                            host.sendall(packet(5, received[1], nonce, bytes(40)))
                        else:
                            host.close()
                    stdout, stderr = process.communicate(timeout=4)
                    # ERR_PROTOCOL, not a deadline or I/O failure after streaming.
                    self.assertEqual(process.returncode, 3, stderr)
                    self.assertEqual(stdout, b"")
                    if mode == "bad-hello":
                        try:
                            answered = host.recv(1)
                        except ConnectionResetError:
                            # The sender closed with the rejected HELLO unread.
                            answered = b""
                        self.assertEqual(answered, b"", "sender answered an invalid HELLO")
                finally:
                    if process.poll() is None:
                        process.kill()
                        process.wait()
                    host.close()
                    os.close(source)


if __name__ == "__main__":
    unittest.main()
