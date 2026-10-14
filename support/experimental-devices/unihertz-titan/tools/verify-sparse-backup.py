#!/usr/bin/env python3
"""Validate a local zstd-compressed raw ext4 image without mounting or repairing it.

This host-only check cannot establish that an archive came from an inactive or
consistent source. A clean filesystem check is not proof of application-level
consistency, complete calibration preservation, or a working restore procedure.
"""

import argparse
import datetime
import hashlib
import importlib.util
import json
import math
import os
from pathlib import Path
import selectors
import shutil
import signal
import stat
import struct
import subprocess
import sys
import tempfile
import time


SPEC = importlib.util.spec_from_file_location(
    "titan_inventory", Path(__file__).with_name("collect-inventory.py")
)
inventory = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(inventory)

CHUNK = 65536
SPARSE_BLOCK = 4096
ZERO_BLOCK = bytes(SPARSE_BLOCK)
LOG_LIMIT = 1048576
# Three bounded diagnostic streams plus atomic manifests and filesystem rounding.
OUTPUT_OVERHEAD = 4 * LOG_LIMIT
SPARSE_PROBE_BYTES = 32 * 1024 * 1024
LIMITATION = (
    "Read-only e2fsck -fn does not replay a journal or repair errors. Dirty, "
    "recovery-required, or repair-required images are rejected. Passing this "
    "check does not prove an inactive source, application consistency, complete "
    "device preservation, or successful restoration."
)


class ValidationError(Exception):
    pass


def free_bytes(directory):
    info = os.statvfs(directory)
    return info.f_bavail * info.f_frsize


def check_storage(directory, descriptor, allocation_budget, minimum_free, reserve=0):
    if os.fstat(descriptor).st_blocks * 512 > allocation_budget:
        raise ValidationError("Sparse image exceeded the physical allocation budget.")
    if free_bytes(directory) < minimum_free + reserve + OUTPUT_OVERHEAD:
        raise ValidationError("Insufficient free storage to preserve the requested reserve.")


def write_all(descriptor, data):
    view = memoryview(data)
    while view:
        written = os.write(descriptor, view)
        if written <= 0:
            raise ValidationError("Writing the private sparse image made no progress.")
        view = view[written:]


def check_sparse_support(directory, minimum_free):
    """Bound the worst-case scratch allocation before testing actual storage.

    The size is a probe bound, not a universal filesystem threshold. On the
    tested Mac, 8/16 MiB gaps allocated densely but 32 MiB gaps stayed sparse.
    Test both operations used by the writer, on the chosen output filesystem.
    """
    if free_bytes(directory) < minimum_free + OUTPUT_OVERHEAD + SPARSE_PROBE_BYTES:
        raise ValidationError("Insufficient free space for the bounded 32 MiB sparse-capability probe.")
    descriptor, name = tempfile.mkstemp(prefix=".sparse-probe-", dir=directory)
    evidence = {"maximum_scratch_bytes": SPARSE_PROBE_BYTES}
    try:
        for method in ("seek_write", "trailing_truncate"):
            os.ftruncate(descriptor, 0)
            os.lseek(descriptor, 0, os.SEEK_SET)
            write_all(descriptor, b"x" * SPARSE_BLOCK)
            if method == "seek_write":
                os.lseek(descriptor, SPARSE_PROBE_BYTES - SPARSE_BLOCK, os.SEEK_SET)
                write_all(descriptor, b"y" * SPARSE_BLOCK)
            else:
                os.ftruncate(descriptor, SPARSE_PROBE_BYTES)
            os.fsync(descriptor)
            allocated = os.fstat(descriptor).st_blocks * 512
            if allocated > LOG_LIMIT:
                raise ValidationError(
                    "The output filesystem did not preserve a sparse zero gap; "
                    "choose storage with verified sparse-file support."
                )
            evidence[method + "_allocated_bytes"] = allocated
        return evidence
    finally:
        os.close(descriptor)
        os.unlink(name)


class SparseWriter:
    """Skip runs of zero 4 KiB blocks, with bounded carry and write sizes."""

    def __init__(self, descriptor, directory, expected, allocation_budget, minimum_free):
        self.descriptor, self.directory = descriptor, directory
        self.expected, self.allocation_budget = expected, allocation_budget
        self.minimum_free = minimum_free
        self.pending = b""
        self.logical_bytes = self.data_bytes = 0
        self.digest = hashlib.sha256()

    def _segment(self, data, zero):
        if zero:
            os.lseek(self.descriptor, len(data), os.SEEK_CUR)
            return
        # Both data submitted to the filesystem and actual allocated blocks must
        # fit the budget. Allocation is also checked after writes and fsync.
        if self.data_bytes + len(data) > self.allocation_budget:
            raise ValidationError("Sparse image exceeded the data-write allocation budget.")
        reserve = ((len(data) + SPARSE_BLOCK - 1) // SPARSE_BLOCK) * SPARSE_BLOCK
        check_storage(self.directory, self.descriptor, self.allocation_budget,
                      self.minimum_free, reserve)
        write_all(self.descriptor, data)
        self.data_bytes += len(data)
        check_storage(self.directory, self.descriptor, self.allocation_budget, self.minimum_free)

    def feed(self, data):
        if self.logical_bytes + len(data) > self.expected:
            raise ValidationError("Decoded image exceeded its expected logical byte count.")
        self.logical_bytes += len(data)
        self.digest.update(data)
        data = self.pending + data
        complete = len(data) - len(data) % SPARSE_BLOCK
        start, previous_zero = 0, None
        for offset in range(0, complete, SPARSE_BLOCK):
            zero = data[offset:offset + SPARSE_BLOCK] == ZERO_BLOCK
            if previous_zero is not None and zero != previous_zero:
                self._segment(data[start:offset], previous_zero)
                start = offset
            previous_zero = zero
        if complete:
            self._segment(data[start:complete], previous_zero)
        self.pending = data[complete:]

    def finish(self):
        if self.logical_bytes != self.expected:
            raise ValidationError(
                f"Decoded image was short: expected {self.expected} bytes, received {self.logical_bytes}."
            )
        if self.pending:
            self._segment(self.pending, not any(self.pending))
            self.pending = b""
        # Seeking past trailing zeros alone does not extend the logical file.
        os.ftruncate(self.descriptor, self.expected)
        os.fsync(self.descriptor)
        check_storage(self.directory, self.descriptor, self.allocation_budget, self.minimum_free)


def run_stream(command, timeout, *, source=None, consume=None, stdout_limit=LOG_LIMIT):
    """Bound both pipe streams and elapsed time; never invoke a host shell."""
    deadline = time.monotonic() + timeout
    process = subprocess.Popen(
        command, stdin=source if source is not None else subprocess.DEVNULL,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, start_new_session=True,
    )
    stdout, stderr, stdout_count, stderr_count = [], [], 0, 0
    finished = False
    try:
        with selectors.DefaultSelector() as selector:
            selector.register(process.stdout, selectors.EVENT_READ, "stdout")
            selector.register(process.stderr, selectors.EVENT_READ, "stderr")
            while selector.get_map():
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise ValidationError("Host command timed out; no image accepted.")
                for key, _ in selector.select(min(remaining, 1)):
                    count = stdout_count if key.data == "stdout" else stderr_count
                    limit = stdout_limit if key.data == "stdout" else LOG_LIMIT
                    data = os.read(key.fileobj.fileno(), min(CHUNK, limit - count + 1))
                    if not data:
                        selector.unregister(key.fileobj)
                        continue
                    if count + len(data) > limit:
                        raise ValidationError("Host command output exceeded its byte bound.")
                    if key.data == "stdout":
                        stdout_count += len(data)
                        if consume is None:
                            stdout.append(data)
                        else:
                            consume(data)
                    else:
                        stderr_count += len(data)
                        stderr.append(data)
        try:
            code = process.wait(timeout=max(0, deadline - time.monotonic()))
        except subprocess.TimeoutExpired as error:
            raise ValidationError("Host command timed out; no image accepted.") from error
        finished = True
        return b"".join(stdout), b"".join(stderr), code
    finally:
        # Also stop a helper's children if they inherited pipes and timed out.
        if not finished:
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
        process.wait()
        process.stdout.close()
        process.stderr.close()


def reread_hash(descriptor, expected, timeout):
    deadline = time.monotonic() + timeout
    os.lseek(descriptor, 0, os.SEEK_SET)
    digest, remaining = hashlib.sha256(), expected
    while remaining:
        if time.monotonic() >= deadline:
            raise ValidationError("Sparse image readback timed out.")
        data = os.read(descriptor, min(CHUNK, remaining))
        if not data:
            raise ValidationError("Sparse image readback was short.")
        digest.update(data)
        remaining -= len(data)
    if os.read(descriptor, 1):
        raise ValidationError("Sparse image readback exceeded its expected logical size.")
    return digest.hexdigest()


def ext4_geometry(descriptor, expected):
    superblock = os.pread(descriptor, 1024, 1024)
    if len(superblock) != 1024 or struct.unpack_from("<H", superblock, 56)[0] != 0xEF53:
        raise ValidationError("No complete ext4 superblock at the raw filesystem offset.")
    blocks_low = struct.unpack_from("<I", superblock, 4)[0]
    first_data_block, log_block_size = struct.unpack_from("<II", superblock, 20)
    state = struct.unpack_from("<H", superblock, 58)[0]
    incompat = struct.unpack_from("<I", superblock, 96)[0]
    ro_compat = struct.unpack_from("<I", superblock, 100)[0]
    last_orphan = struct.unpack_from("<I", superblock, 232)[0]
    if log_block_size > 6:
        raise ValidationError("Unsupported ext4 block size.")
    block_size = 1024 << log_block_size
    blocks_high = struct.unpack_from("<I", superblock, 336)[0]
    if not incompat & 0x80 and blocks_high:
        raise ValidationError("Ext4 high block count is set without the 64-bit feature.")
    blocks = blocks_low | ((blocks_high << 32) if incompat & 0x80 else 0)
    if not blocks or blocks * block_size != expected:
        raise ValidationError("Ext4 geometry does not match the expected filesystem logical bytes.")
    if first_data_block != (1 if block_size == 1024 else 0):
        raise ValidationError("Unexpected ext4 first-data-block geometry.")
    if not incompat & 0x40:
        raise ValidationError("This validator requires an ext4 filesystem with the extents feature.")
    if state != 1 or incompat & 0x4 or ro_compat & 0x10000 or last_orphan:
        raise ValidationError("Ext4 is dirty, error-marked, or requires journal/orphan recovery. " + LIMITATION)
    return {
        "block_size": block_size, "block_count": blocks, "logical_bytes": blocks * block_size,
        "state": state, "incompat_features": f"0x{incompat:08x}",
        "ro_compat_features": f"0x{ro_compat:08x}",
        "journal_recovery_required": False, "last_orphan": last_orphan,
    }


def executable(requested):
    resolved = shutil.which(requested)
    if resolved is None:
        raise ValidationError(f"Required host executable is unavailable: {requested}")
    return resolved


def open_archive(path):
    # O_NONBLOCK prevents a substituted FIFO from blocking before fstat rejects
    # it. O_NOFOLLOW rejects symlinks; zstd receives this open descriptor on stdin.
    descriptor = os.open(path, os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW)
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode):
            raise ValidationError("The compressed archive must be an existing regular file.")
        return descriptor, metadata
    except BaseException:
        os.close(descriptor)
        raise


def prepare_output(requested):
    if requested is not None:
        return inventory.prepare_output(requested)
    state = Path(os.environ.get("XDG_STATE_HOME", Path.home() / ".local/state"))
    base = (state / "mobile-nixos/titan-sparse-validation").expanduser().resolve()
    if inventory.inside_git_checkout(base):
        raise ValueError("Validation output must be outside every Git checkout.")
    base.mkdir(mode=0o700, parents=True, exist_ok=True)
    prefix = datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%dT%H%M%SZ-")
    return Path(tempfile.mkdtemp(prefix=prefix, dir=base))


def write_manifest(output, manifest):
    descriptor, name = tempfile.mkstemp(prefix=".manifest-", suffix=".part", dir=output)
    pending = Path(name)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write((json.dumps(manifest, indent=2) + "\n").encode())
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(pending, output / "manifest.json")
    finally:
        if pending.exists():
            pending.unlink()


def validate_archive(archive, output, *, expected, allocation_budget, minimum_free,
                     timeout, zstd, e2fsck, source, source_metadata):
    manifest = {
        "format": 1, "status": "incomplete", "stage": "sparse-preflight",
        "created_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "archive": str(archive), "archive_bytes": source_metadata.st_size,
        "expected_logical_bytes": expected, "max_allocated_bytes": allocation_budget,
        "min_free_bytes": minimum_free, "timeout_seconds_per_phase": timeout,
        "reserved_output_overhead_bytes": OUTPUT_OVERHEAD,
        "limitation": LIMITATION,
    }
    pending, destination = output / "filesystem.img.part", output / "filesystem.img"
    descriptor, created = None, False
    try:
        write_manifest(output, manifest)
        if destination.exists():
            raise ValidationError("Refusing to overwrite an existing image.")
        descriptor = os.open(pending, os.O_RDWR | os.O_CREAT | os.O_EXCL, 0o600)
        created = True
        if expected < SPARSE_PROBE_BYTES and allocation_budget < expected:
            raise ValidationError("Images below 32 MiB require an allocation budget covering their full logical size.")
        manifest["sparse_preflight"] = check_sparse_support(output, minimum_free)
        # Presizing avoids repeated short EOF extensions, which can allocate
        # zero gaps densely even on a filesystem that supports sparse files.
        os.ftruncate(descriptor, expected)
        os.fsync(descriptor)
        check_storage(output, descriptor, allocation_budget, minimum_free)
        manifest["stage"] = "decompress"
        write_manifest(output, manifest)
        writer = SparseWriter(descriptor, output, expected, allocation_budget, minimum_free)
        _, diagnostics, code = run_stream(
            [zstd, "-d", "-c"], timeout, source=source, consume=writer.feed,
            stdout_limit=expected,
        )
        inventory.write_private(output / "zstd.stderr", diagnostics)
        manifest["zstd_exit_code"] = code
        if code != 0:
            raise ValidationError(f"zstd decompression failed (exit {code}); see private zstd.stderr.")
        if diagnostics:
            raise ValidationError("zstd produced diagnostics; inspect private zstd.stderr before accepting the image.")
        after = os.fstat(source)
        if (after.st_size, after.st_mtime_ns, after.st_ctime_ns) != (
            source_metadata.st_size, source_metadata.st_mtime_ns, source_metadata.st_ctime_ns,
        ):
            raise ValidationError("The compressed archive changed during decompression.")
        writer.finish()
        manifest.update({"stage": "readback", "decoded_sha256": writer.digest.hexdigest(),
                         "data_bytes_written": writer.data_bytes})
        write_manifest(output, manifest)
        digest = reread_hash(descriptor, expected, timeout)
        if digest != writer.digest.hexdigest():
            raise ValidationError("Sparse image readback SHA-256 did not match the decoded stream.")
        manifest["readback_sha256"] = digest
        manifest["ext4"] = ext4_geometry(descriptor, expected)
        manifest["stage"] = "e2fsck"
        write_manifest(output, manifest)
        before_check = os.fstat(descriptor)
        stdout, stderr, code = run_stream([e2fsck, "-fn", str(pending)], timeout)
        inventory.write_private(output / "e2fsck.stdout", stdout)
        inventory.write_private(output / "e2fsck.stderr", stderr)
        manifest["e2fsck_exit_code"] = code
        if code != 0:
            raise ValidationError(f"Read-only e2fsck failed (exit {code}); see private check logs. " + LIMITATION)
        # e2fsck prints its version on stderr on successful checks. Preserve it,
        # but require a successful full check and no modification of the image.
        after_check = os.fstat(descriptor)
        if (after_check.st_size, after_check.st_mtime_ns, after_check.st_ctime_ns) != (
            before_check.st_size, before_check.st_mtime_ns, before_check.st_ctime_ns,
        ):
            raise ValidationError("The filesystem image changed during its read-only check.")
        check_storage(output, descriptor, allocation_budget, minimum_free)
        manifest["allocated_bytes"] = after_check.st_blocks * 512
        manifest["file"] = destination.name
        os.close(descriptor)
        descriptor = None
        # Exclusive hard-link publication cannot overwrite a path created after
        # the initial destination check, and exposes only a fully checked image.
        os.link(pending, destination)
        pending.unlink()
        manifest.update({"status": "complete", "stage": "complete"})
        write_manifest(output, manifest)
        return manifest
    except BaseException as error:
        manifest.update({"status": "failed", "error": str(error) or type(error).__name__})
        write_manifest(output, manifest)
        raise
    finally:
        if descriptor is not None:
            os.close(descriptor)
        if created and pending.exists():
            pending.unlink()


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, epilog=LIMITATION)
    parser.add_argument("archive", help="existing regular zstd-compressed raw ext4 image (no symlinks)")
    parser.add_argument("--output", help="new private directory outside every Git checkout")
    parser.add_argument("--expected-bytes", type=int, required=True, help="exact filesystem logical byte count")
    parser.add_argument("--max-allocated-bytes", type=int, required=True,
                        help="maximum data written and physical blocks allocated to the sparse image")
    parser.add_argument("--min-free-bytes", type=int, required=True,
                        help="free-space reserve; also needs 4 MiB for logs/manifests and temporarily 32 MiB for a sparse probe")
    parser.add_argument("--timeout", type=float, default=3600, help="seconds per phase (default: 3600)")
    parser.add_argument("--zstd", default="zstd", help="existing host zstd executable")
    parser.add_argument("--e2fsck", default="e2fsck", help="existing host e2fsck executable")
    args = parser.parse_args(argv)
    if args.expected_bytes < 4096 or args.expected_bytes % 1024:
        parser.error("--expected-bytes must be at least 4096 and a multiple of 1024")
    if args.max_allocated_bytes <= 0 or args.min_free_bytes < 0:
        parser.error("--max-allocated-bytes must be positive and --min-free-bytes nonnegative")
    if args.expected_bytes < SPARSE_PROBE_BYTES and args.max_allocated_bytes < args.expected_bytes:
        parser.error("Images below 32 MiB require --max-allocated-bytes >= --expected-bytes")
    if not math.isfinite(args.timeout) or args.timeout <= 0:
        parser.error("--timeout must be finite and positive")
    source, output = None, None
    previous_umask = os.umask(0o077)
    try:
        archive = Path(args.archive).expanduser().absolute()
        source, metadata = open_archive(archive)
        zstd, e2fsck = executable(args.zstd), executable(args.e2fsck)
        output = prepare_output(args.output)
        validate_archive(
            archive, output, expected=args.expected_bytes, allocation_budget=args.max_allocated_bytes,
            minimum_free=args.min_free_bytes, timeout=args.timeout, zstd=zstd, e2fsck=e2fsck,
            source=source, source_metadata=metadata,
        )
        print(f"Verified sparse image and private manifest: {output}")
        print(LIMITATION)
        return 0
    except (ValidationError, OSError, ValueError, KeyboardInterrupt) as error:
        print(f"Validation stopped: {error}", file=sys.stderr)
        if output is not None:
            print(f"Private failure manifest and available diagnostics: {output}", file=sys.stderr)
        return 1
    finally:
        if source is not None:
            os.close(source)
        os.umask(previous_umask)


if __name__ == "__main__":
    sys.exit(main())
