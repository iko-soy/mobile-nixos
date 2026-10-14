"""Linux-only synthetic ext4/FIFO tests; never open a device or phone source."""

import hashlib
import importlib.util
import json
import os
from pathlib import Path
import select
import shutil
import signal
import socket
import struct
import subprocess
import sys
import tempfile
import threading
import time
import unittest


PRODUCER = os.environ.get("TITAN_PRODUCER")
EMULATOR = os.environ.get("TITAN_PRODUCER_EMULATOR")
SENDER = os.environ.get("TITAN_TRANSPORT_SENDER")
SENDER_EMULATOR = os.environ.get("TITAN_TRANSPORT_EMULATOR")
PRODUCTION = os.environ.get("TITAN_PRODUCTION_PRODUCER")
PRODUCTION_EMULATOR = os.environ.get("TITAN_PRODUCTION_EMULATOR")
BANNER = b"e2image 1.47.4 (6-Mar-2025)\n"
SUCCESS = b"TPST" + bytes(4)
IMAGE_BYTES = 16 * 1024 * 1024
LIMIT = 32 * 1024 * 1024
PAYLOAD = bytes(range(256)) * 257 + b"Titan synthetic ext4 fixture\n"


def launch(binary, emulator):
    return ([emulator] if emulator else []) + [binary]


def command(binary, emulator, source, output, status, *, maximum=LIMIT, timeout=2, programs=None):
    result = launch(binary, emulator) + ["--input-fd", str(source), "--output-fd", str(output),
              "--status-fd", str(status), "--max-bytes", str(maximum), "--timeout-seconds", str(timeout)]
    if programs is not None:
        result += ["--e2image", str(programs[0]), "--zstd", str(programs[1])]
    return result


def finish(process, timeout=5):
    try:
        stdout, stderr = process.communicate(timeout=timeout)
    except subprocess.TimeoutExpired:
        process.kill()
        process.communicate()
        raise AssertionError("Fixture process exceeded its external deadline")
    if stdout:
        raise AssertionError("Supervisor/sender unexpectedly wrote to stdout")
    if len(stderr) > 16384:
        raise AssertionError("Supervisor/sender diagnostics exceeded fixture bound")
    return process.returncode, stderr


@unittest.skipUnless(sys.platform.startswith("linux") and PRODUCER,
                     "Set TITAN_PRODUCER on Linux to run synthetic supervisor tests")
class ProducerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.scratch = tempfile.TemporaryDirectory(prefix="titan-producer-fixtures-")
        cls.base = Path(cls.scratch.name)
        cls.image = cls.base / "source.ext4"
        cls.known = cls.base / "known.bin"
        cls.known.write_bytes(PAYLOAD)
        with cls.image.open("wb") as stream:
            stream.truncate(IMAGE_BYTES)
        subprocess.run(["mke2fs", "-q", "-F", "-t", "ext4", "-E",
                        "lazy_itable_init=0,lazy_journal_init=0", str(cls.image)],
                       check=True, capture_output=True, timeout=20)
        subprocess.run(["debugfs", "-w", "-R", f"write {cls.known} /known.bin", str(cls.image)],
                       check=True, capture_output=True, timeout=10)
        checked = subprocess.run(["e2fsck", "-fn", str(cls.image)], capture_output=True, timeout=10)
        if checked.returncode:
            raise AssertionError(f"Synthetic source failed e2fsck: {checked.stderr!r}")
        source = os.environ.get("TITAN_TRANSPORT_SOURCE")
        if source:
            spec = importlib.util.spec_from_file_location("producer_test_receiver", Path(source) / "receive.py")
            cls.receiver = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(cls.receiver)
        else:
            cls.receiver = None

    @classmethod
    def tearDownClass(cls):
        cls.scratch.cleanup()

    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="case-", dir=self.base)
        self.addCleanup(self.temporary.cleanup)
        self.case = Path(self.temporary.name)
        self.source = self.case / "source.ext4"
        shutil.copyfile(self.image, self.source)
        self.pids = self.case / "children.jsonl"
        self.addCleanup(self.kill_fixture_children)

    def child_records(self):
        if not self.pids.exists():
            return []
        return [json.loads(line) for line in self.pids.read_text().splitlines()]

    def kill_fixture_children(self):
        for record in self.child_records():
            try:
                current = Path(f"/proc/{record['pid']}/stat").read_text().rsplit(")", 1)[1].split()
                if current[19] == record["started"]:
                    os.kill(record["pid"], signal.SIGKILL)
            except (ProcessLookupError, FileNotFoundError):
                pass

    def assert_children_gone(self):
        deadline = time.monotonic() + 1
        while True:
            alive = []
            for record in self.child_records():
                status = Path(f"/proc/{record['pid']}/stat")
                try:
                    # A reparented killed grandchild may await the fixture
                    # environment's PID1 reaper; it must not still be running.
                    current = status.read_text().rsplit(")", 1)[1].split()
                    if current[19] == record["started"] and current[0] != "Z":
                        alive.append(record["pid"])
                except FileNotFoundError:
                    pass
            if not alive:
                return
            if time.monotonic() >= deadline:
                self.fail(f"Supervisor left running fixture children: {alive}")
            time.sleep(0.01)

    def program(self, name, body):
        path = self.case / name
        # Fixed paths are embedded in test executables, never passed through
        # environment variables or accepted by a production supervisor.
        prelude = f"""#!{sys.executable}
import json, os, signal, subprocess, sys, time
fds = {{}}
for entry in os.listdir('/proc/self/fd'):
    try: fds[entry] = os.readlink('/proc/self/fd/' + entry)
    except OSError: pass
with open({str(self.pids)!r}, 'a') as stream:
    started = open('/proc/self/stat').read().rsplit(')', 1)[1].split()[19]
    stream.write(json.dumps({{'pid': os.getpid(), 'started': started, 'fds': fds}}) + '\\n')
def emit(data):
    while data:
        data = data[os.write(1, data):]
"""
        path.write_text(prelude + body + "\n")
        path.chmod(0o700)
        return path

    def programs(self, *, image_body=None, zstd_body=None):
        if image_body is None:
            image_body = f"os.write(2, {BANNER!r})\nemit(b'fixture compressed bytes')"
        if zstd_body is None:
            zstd_body = "while True:\n    data = os.read(0, 65536)\n    if not data: break\n    emit(data)"
        return self.program("fake-e2image", image_body), self.program("fake-zstd", zstd_body)

    def direct(self, programs, *, maximum=LIMIT, timeout=1, consume=True, close_consumer=False,
               source_flags=os.O_RDONLY, change=None, extra_fd=None, binary=None, emulator=None,
               argument_change=None, observe=None):
        source = os.open(self.source, source_flags)
        data_read, data_write = os.pipe()
        status_read, status_write = os.pipe()
        if change:
            change(source, data_write, status_write)
        inherited = [source, data_write, status_write] + ([extra_fd] if extra_fd is not None else [])
        arguments = command(binary or PRODUCER, emulator if binary else EMULATOR,
                            source, data_write, status_write, maximum=maximum,
                            timeout=timeout, programs=programs)
        if argument_change:
            argument_change(arguments, source, data_write, status_write)
        process = subprocess.Popen(arguments, pass_fds=inherited,
                                   stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        for descriptor in (source, data_write, status_write):
            os.close(descriptor)
        captured = {data_read: bytearray(), status_read: bytearray()}
        active = [status_read] + ([data_read] if consume else [])
        if close_consumer:
            os.close(data_read)
            active = [status_read]
        began = time.monotonic()
        try:
            while active or process.poll() is None:
                self.assertLess(time.monotonic() - began, 5, "Supervisor failed to stop")
                readable, _, _ = select.select(active, [], [], 0.02)
                for descriptor in readable:
                    chunk = os.read(descriptor, 65536)
                    if not chunk:
                        active.remove(descriptor)
                    else:
                        captured[descriptor].extend(chunk)
                        self.assertLessEqual(len(captured[descriptor]), LIMIT + 65536)
                if observe:
                    observe(bytes(captured[status_read]))
            code, diagnostics = finish(process)
            self.assert_children_gone()
            return code, bytes(captured[data_read]), bytes(captured[status_read]), diagnostics
        finally:
            if process.poll() is None:
                process.kill()
                process.wait()
            for descriptor in (data_read, status_read):
                if descriptor == data_read and close_consumer:
                    continue
                os.close(descriptor)

    def pipeline(self, programs, *, maximum=LIMIT):
        if not SENDER or self.receiver is None:
            self.skipTest("Sender and TITAN_TRANSPORT_SOURCE are needed for full pipeline tests")
        source = os.open(self.source, os.O_RDONLY)
        data_read, data_write = os.pipe()
        status_read, status_write = os.pipe()
        receipt_read, receipt_write = os.pipe()
        host, peer = socket.socketpair()
        supervisor = subprocess.Popen(command(PRODUCER, EMULATOR, source, data_write, status_write,
                                               maximum=maximum, timeout=4, programs=programs),
                                      pass_fds=[source, data_write, status_write], stdin=subprocess.DEVNULL,
                                      stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        sender = subprocess.Popen(launch(SENDER, SENDER_EMULATOR) + ["--input-fd", str(data_read),
                                  "--transport-fd", str(peer.fileno()), "--status-fd", str(receipt_read),
                                  "--label", "producer-fixture", "--max-bytes", str(LIMIT),
                                  "--timeout-seconds", "6"], pass_fds=[data_read, peer.fileno(), receipt_read],
                                  stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        peer.close()
        for descriptor in (source, data_read, data_write, status_write, receipt_read):
            os.close(descriptor)
        status = bytearray()
        relay_errors = []

        def relay_status():
            try:
                while True:
                    chunk = os.read(status_read, 16)
                    if not chunk:
                        break
                    status.extend(chunk)
                    if len(status) > 8:
                        raise AssertionError("Producer status exceeded eight bytes")
                    os.write(receipt_write, chunk)
            except BrokenPipeError:
                pass
            except BaseException as error:
                relay_errors.append(error)
            finally:
                os.close(status_read)
                os.close(receipt_write)

        relay = threading.Thread(target=relay_status, daemon=True)
        relay.start()
        output = self.case / "received"
        error = None
        try:
            try:
                self.receiver.receive(host.fileno(), label="producer-fixture", max_bytes=LIMIT,
                                      output=output, timeout_seconds=7)
            except (self.receiver.TransferError, OSError) as caught:
                error = caught
            producer_code, producer_diagnostics = finish(supervisor)
            sender_code, sender_diagnostics = finish(sender)
            relay.join(1)
            self.assertFalse(relay.is_alive())
            self.assertFalse(relay_errors, relay_errors)
            self.assert_children_gone()
            return output, error, producer_code, sender_code, bytes(status), producer_diagnostics + sender_diagnostics
        finally:
            host.close()
            for process in (supervisor, sender):
                if process.poll() is None:
                    process.kill()
                    process.wait()
            relay.join(1)

    def assert_failure_status(self, status):
        self.assertNotEqual(status, SUCCESS)
        if status:
            self.assertEqual(len(status), 8)
            self.assertEqual(status[:4], b"TPST")
            self.assertNotEqual(struct.unpack("!I", status[4:])[0], 0)

    def test_real_ext4_supervisor_sender_receiver_and_restore(self):
        programs = (os.environ["TITAN_E2IMAGE"], os.environ["TITAN_ZSTD"])
        before = hashlib.sha256(self.source.read_bytes()).digest()
        output, error, producer_code, sender_code, status, diagnostics = self.pipeline(programs)
        self.assertIsNone(error, diagnostics)
        self.assertEqual((producer_code, sender_code, status), (0, 0, SUCCESS), diagnostics)
        restored = self.case / "restored.ext4"
        subprocess.run([programs[1], "-d", "--sparse", "-q", "-f", str(output / "payload.bin"),
                        "-o", str(restored)], check=True, capture_output=True, timeout=10)
        self.assertEqual(restored.stat().st_size, IMAGE_BYTES)
        checked = subprocess.run(["e2fsck", "-fn", str(restored)], capture_output=True, timeout=10)
        self.assertEqual(checked.returncode, 0, checked.stdout + checked.stderr)
        recovered = self.case / "recovered.bin"
        subprocess.run(["debugfs", "-R", f"dump /known.bin {recovered}", str(restored)],
                       check=True, capture_output=True, timeout=10)
        self.assertEqual(recovered.read_bytes(), PAYLOAD)
        self.assertEqual(hashlib.sha256(self.source.read_bytes()).digest(), before)

    def test_child_failures_and_diagnostics_never_publish_host_payload(self):
        cases = [
            (f"os.write(2, {BANNER!r}); emit(b'data'); sys.exit(7)", None),
            (f"os.write(2, {BANNER!r} + b'Read error at block 123\\n'); emit(b'data')", None),
            (None, "emit(b'data'); sys.exit(9)"),
            (None, "os.write(2, b'warning\\n'); emit(b'data')"),
        ]
        for index, (image_body, zstd_body) in enumerate(cases):
            with self.subTest(case=index):
                programs = self.programs(image_body=image_body, zstd_body=zstd_body)
                output, error, producer_code, sender_code, status, diagnostics = self.pipeline(programs)
                self.assertIsNotNone(error, diagnostics)
                self.assertNotEqual(producer_code, 0)
                self.assertNotEqual(sender_code, 0)
                self.assert_failure_status(status)
                self.assertFalse((output / "payload.bin").exists())
                self.assertFalse(json.loads((output / "report.json").read_text())["completed"])
                shutil.rmtree(output)

    def test_exact_banner_and_bounded_diagnostics(self):
        for diagnostic in (b"", BANNER + b"\0", BANNER + BANNER, b"wrong version\n", b"x" * 131072):
            with self.subTest(length=len(diagnostic)):
                programs = self.programs(image_body=f"os.write(2, {diagnostic!r}); emit(b'data')")
                code, _, status, _ = self.direct(programs)
                self.assertNotEqual(code, 0)
                self.assert_failure_status(status)
        programs = self.programs(zstd_body="os.write(2, b'x' * 131072); emit(b'data')")
        code, _, status, _ = self.direct(programs)
        self.assertNotEqual(code, 0)
        self.assert_failure_status(status)

    def test_output_limit_and_closed_or_stalled_consumer_fail_boundedly(self):
        programs = self.programs(image_body=f"os.write(2, {BANNER!r}); emit(b'x' * 1048576)")
        for options in ({"maximum": 1}, {"consume": False}, {"close_consumer": True}):
            with self.subTest(options=options):
                code, output, status, _ = self.direct(programs, **options)
                self.assertNotEqual(code, 0)
                self.assert_failure_status(status)
                if "maximum" in options:
                    self.assertLessEqual(len(output), options["maximum"])

    def test_timeout_kills_stalled_children_and_descendants(self):
        descendant = f"import json,os,time; started=open('/proc/self/stat').read().rsplit(')',1)[1].split()[19]; open({str(self.pids)!r},'a').write(json.dumps({{'pid':os.getpid(),'started':started,'fds':{{}}}})+'\\n'); time.sleep(30)"
        programs = self.programs(image_body=f"os.write(2, {BANNER!r})\nsubprocess.Popen([sys.executable, '-c', {descendant!r}])\ntime.sleep(30)")
        code, _, status, _ = self.direct(programs)
        self.assertNotEqual(code, 0)
        self.assert_failure_status(status)
        self.assertGreaterEqual(len(self.child_records()), 3, "Fixture descendant never started")

    def test_success_status_waits_for_child_exit_after_output_eof(self):
        ready, release = self.case / "zstd-output-closed", self.case / "release-zstd"
        body = ("while True:\n    data = os.read(0, 65536)\n    if not data: break\n    emit(data)\n"
                f"os.close(1)\nopen({str(ready)!r}, 'w').close()\n"
                f"while not os.path.exists({str(release)!r}): time.sleep(0.005)")
        observed = []

        def observe(status):
            if ready.exists() and not release.exists():
                self.assertEqual(status, b"", "Status arrived before zstd had exited")
                if not observed:
                    observed.append(time.monotonic())
                elif time.monotonic() - observed[0] > 0.15:
                    release.touch()

        code, _, status, diagnostics = self.direct(self.programs(zstd_body=body), timeout=2, observe=observe)
        self.assertTrue(observed, "Fixture never reached the output-EOF gate")
        self.assertEqual((code, status), (0, SUCCESS), diagnostics)

    def test_wrong_descriptor_roles_and_aliases_are_rejected_before_children(self):
        for kind in ("regular-output", "aliased-status", "fifo-source"):
            with self.subTest(kind=kind):
                def change(arguments, source, output, _status):
                    option, descriptor = {"regular-output": ("--output-fd", source),
                                          "aliased-status": ("--status-fd", output),
                                          "fifo-source": ("--input-fd", output)}[kind]
                    arguments[arguments.index(option) + 1] = str(descriptor)
                code, output, status, _ = self.direct(self.programs(), argument_change=change)
                self.assertNotEqual(code, 0)
                self.assertEqual(output, b"")
                self.assert_failure_status(status)
                self.assertEqual(self.child_records(), [])

    def test_dirty_geometry_offsets_and_writable_source_are_rejected(self):
        programs = self.programs()
        for kind in ("dirty", "recovery", "orphan", "orphan-present", "geometry", "offset", "writable"):
            with self.subTest(kind=kind):
                shutil.copyfile(self.image, self.source)
                if kind in ("dirty", "recovery", "orphan", "orphan-present", "geometry"):
                    with self.source.open("r+b") as stream:
                        offset, value = {"dirty": (1024 + 58, b"\x02\0"),
                                         "recovery": (1024 + 96, None),
                                         "orphan": (1024 + 232, struct.pack("<I", 1)),
                                         "orphan-present": (1024 + 100, None),
                                         "geometry": (1024 + 4, struct.pack("<I", 1))}[kind]
                        stream.seek(offset)
                        if value is None:
                            flag = 4 if kind == "recovery" else 0x10000
                            value = struct.pack("<I", struct.unpack("<I", stream.read(4))[0] | flag)
                            stream.seek(offset)
                        stream.write(value)
                change = (lambda fd, _out, _status: os.lseek(fd, 1, os.SEEK_SET)) if kind == "offset" else None
                code, _, status, _ = self.direct(programs, change=change,
                    source_flags=os.O_RDWR if kind == "writable" else os.O_RDONLY)
                self.assertNotEqual(code, 0)
                self.assert_failure_status(status)
                self.assertEqual(self.child_records(), [], "Invalid source reached a pipeline child")

    def test_source_changed_during_pipeline_is_rejected(self):
        body = f"os.write(2, {BANNER!r})\nwith open({str(self.source)!r}, 'r+b') as stream:\n    stream.seek(4096); stream.write(b'changed')\nemit(b'data')"
        code, _, status, _ = self.direct(self.programs(image_body=body))
        self.assertNotEqual(code, 0)
        self.assert_failure_status(status)

    def test_children_do_not_inherit_unrelated_descriptors(self):
        unrelated = self.case / "private-unrelated-file"
        unrelated.write_bytes(b"synthetic unrelated descriptor")
        descriptor = os.open(unrelated, os.O_RDONLY)
        try:
            code, _, status, diagnostics = self.direct(self.programs(), extra_fd=descriptor)
        finally:
            os.close(descriptor)
        self.assertEqual((code, status), (0, SUCCESS), diagnostics)
        self.assertGreaterEqual(len(self.child_records()), 2)
        for record in self.child_records():
            self.assertNotIn(str(unrelated), record["fds"].values())

    @unittest.skipUnless(PRODUCTION, "Set TITAN_PRODUCTION_PRODUCER to test production CLI isolation")
    def test_production_binary_rejects_test_only_program_overrides(self):
        for forbidden in ("--e2image", "--zstd"):
            with self.subTest(option=forbidden):
                def retain_one_override(arguments, *_descriptors):
                    remove = "--zstd" if forbidden == "--e2image" else "--e2image"
                    index = arguments.index(remove)
                    del arguments[index:index + 2]
                code, output, status, _ = self.direct(self.programs(), binary=PRODUCTION,
                    emulator=PRODUCTION_EMULATOR, argument_change=retain_one_override)
                self.assertNotEqual(code, 0)
                self.assertEqual(output, b"")
                self.assert_failure_status(status)
                self.assertEqual(self.child_records(), [])


if __name__ == "__main__":
    unittest.main()
