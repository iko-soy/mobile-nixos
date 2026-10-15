"""Host-only catalog regressions using synthetic private files, never backups."""

import copy
import contextlib
import hashlib
import importlib.util
import json
import io
import os
from pathlib import Path
import stat
import tempfile
import unittest
from unittest import mock
import uuid


HERE = Path(__file__).resolve().parent


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


tool = load("titan_backup_catalog_test", HERE.parent / "verify-backup-catalog.py")
gpt_fixtures = load("titan_catalog_gpt_fixture", HERE / "test_gpt_acquisition.py")
firmware_fixtures = load("titan_catalog_firmware_fixture", HERE / "test_firmware_acquisition.py")
bootloader_fixtures = load("titan_catalog_lk_fixture", HERE / "test_bootloader_acquisition.py")


def encoded(value):
    return (json.dumps(value, sort_keys=True) + "\n").encode("ascii")


def private_write(path, data):
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "wb") as stream:
        stream.write(data)


class Fixture:
    """Real fixed geometry and GPT; synthetic hashes for large sparse files.

    Only the image hashing call is replaced in workflow tests. Schema, file
    metadata/permissions, publication and the actual GPT parser remain active.
    The independent HashTests exercise actual contents and streaming bounds.
    """

    def __init__(self, root):
        self.root = root
        self.manifests, self.payloads, self.hashes = {}, {}, {}
        self.real_hash = tool.hash_payload
        self.by_labels = {frozenset(profile["files"]): path for path, profile in tool.PROFILE.items()}
        self.boot = self.by_labels[frozenset(("boot", "recovery", "dtbo"))]
        self.gpt = self.by_labels[frozenset(("front", "tail"))]
        self.lk = self.by_labels[frozenset(("lk", "lk2"))]
        self.os = self.by_labels[frozenset(("vendor", "system"))]
        self.rootfs = self.by_labels[frozenset(("ubuntu", "android-rootfs"))]
        self.firmware = next(path for path, profile in tool.PROFILE.items() if len(profile["files"]) == 16)
        self.gpt_fixture = gpt_fixtures.Fixture()
        self.gpt_fixture.partitions = [dict(number=n, name=name, start=start, size=sectors)
                                      for n, name, start, sectors in tool.EXPECTED_LAYOUT]
        self.gpt_fixture.disk_guid = uuid.UUID(int=0)
        self.front, self.tail = self.gpt_fixture.captures()
        self.raw_map = self.gpt_fixture.map()
        self.layout = firmware_fixtures.base_evidence()
        self.fix_layout(self.layout)
        self.root.mkdir(mode=0o700)
        for relative, profile in tool.PROFILE.items():
            directory = self.root / relative
            directory.mkdir(mode=0o700, parents=True)
            for ancestor in (directory, *directory.parents):
                if ancestor == self.root: break
                ancestor.chmod(0o700)
            for label, (name, size) in profile["files"].items():
                path = directory / name
                if relative == self.gpt:
                    data = self.front if label == "front" else self.tail
                    private_write(path, data)
                    digest = hashlib.sha256(data).hexdigest()
                else:
                    private_write(path, b"SYNTHETIC-CATALOG-FIXTURE\n")
                    with path.open("r+b") as stream: stream.truncate(size)
                    digest = hashlib.sha256((relative + "/" + label).encode()).hexdigest()
                self.payloads[relative, label] = path
                metadata = path.stat()
                self.hashes[metadata.st_dev, metadata.st_ino] = digest
            self.manifests[relative] = self.manifest(relative, profile)
        private_write(self.root / self.gpt / "kernel-map.txt", self.raw_map)
        self.write_manifests()

    def fix_layout(self, report):
        report["disk"]["sysfs"] = tool.SYSFS_DISK
        for record, (number, name, start, sectors) in zip(report["partitions"], tool.EXPECTED_LAYOUT):
            record.update(number=number, name=name, start=start, sectors=sectors)
        for target in report["targets"].values():
            target.update(report["partitions"][target["number"] - 1])

    def records(self, relative, fields):
        result = {}
        for label, (name, size) in tool.PROFILE[relative]["files"].items():
            metadata = self.payloads[relative, label].stat()
            digest = self.hashes[metadata.st_dev, metadata.st_ino]
            result[label] = {"file": name, "bytes": size, **dict.fromkeys(fields, digest)}
        return result

    def manifest(self, relative, profile):
        common = {"status": "complete", "scope": "Synthetic fixture only"}
        if relative == self.rootfs:
            records = self.records(relative, ("sha256",))
            for record in records.values():
                record.update(source_hash_before_and_after_match=True, saved_file_readback_match=True)
            return {**common, "files": records}
        common.update(format=profile["format"], created_utc="2026-01-01T00:00:00+00:00",
                      transport="adb-shell-v2-no-pty")
        if relative == self.boot:
            records = self.records(relative, ("sha256", "transfer_sha256", "phone_sha256"))
            for label, record in records.items():
                part = next(part for part in self.layout["partitions"] if part["name"] == label)
                node = "mmcblk0p" + str(part["number"])
                disk = self.layout["disk"]["sysfs"]
                record["preflight"] = {"label": label, "device": "/dev/" + node, "mmc_type": "MMC",
                    "partition": str(part["number"]), "sectors": str(part["sectors"]), "bytes": str(record["bytes"]),
                    "sysfs": disk + "/" + node, "sysfs_disk": disk, "device_number": part["device_number"],
                    "block_device": "true", "readable": "true", "unmounted": "true", "holders": "none"}
            return {**common, "partitions": records}
        if relative == self.gpt:
            records = self.records(relative, ("sha256", "transfer_sha256", "readback_sha256", "repeat_sha256"))
            for label, record in records.items(): record["start_sector"] = 0 if label == "front" else 244285376
            parsed = gpt_fixtures.tool.gpt.validate_gpt(self.front, self.tail, 125074145280,
                                                        allow_zero_disk_guid=True)
            return {**common, "edge_bytes": 32768, "regions": records,
                "validation_policy": {"allow_zero_disk_guid": True,
                    "reason": "Synthetic zero disk GUID supplies no unique identity"},
                "warnings": ["zero-disk-guid"], "gpt": parsed,
                "kernel_map": gpt_fixtures.tool.validate_map(self.raw_map)}
        records = self.records(relative, ("sha256", "transfer_sha256", "readback_sha256", "phone_repeat_sha256"))
        if relative == self.lk:
            evidence = bootloader_fixtures.evidence(); self.fix_layout(evidence)
        elif relative == self.os:
            evidence = copy.deepcopy(self.layout)
        else:
            evidence = firmware_fixtures.evidence()
            evidence["base"] = copy.deepcopy(self.layout)
            for target in evidence["targets"].values():
                if "number" in target: target.update(self.layout["partitions"][target["number"] - 1])
                else:
                    target.update(parent=tool.SYSFS_DISK, sysfs=tool.SYSFS_DISK + "/" + target["name"])
        validation = dict.fromkeys(("atomic_snapshot", "authentication_performed", "restoration_tested",
                                    "device_changes_performed"), False)
        if relative != self.lk: validation["global_quiescence"] = False
        if relative == self.firmware: validation["firmware_immutability_proven"] = False
        for label, record in records.items():
            record["geometry"] = copy.deepcopy(evidence["targets"][label])
            if relative != self.lk:
                record.update(zero_bytes_skipped=0,
                              storage="raw logical image with zero-only chunks stored as holes where supported")
        result = {**common, "transport": "adb-shell-v2-no-pty-framed-status",
                  "kernel_map": evidence, "bytes_preserved": sum(r["bytes"] for r in records.values()),
                  "partitions": records, "validation": validation}
        if relative != self.lk:
            result["mount_view_scope"] = ["acquisition process", "PID1", "identified Android init"]
        return result

    def write_manifests(self):
        for relative, report in self.manifests.items():
            path = self.root / relative / "manifest.json"
            if path.exists(): path.write_bytes(encoded(report))
            else: private_write(path, encoded(report))

    def synthetic_hash(self, fd, expected):
        metadata = os.fstat(fd)
        if metadata.st_size != expected:
            raise tool.CatalogError("Synthetic stream byte count mismatch")
        key = metadata.st_dev, metadata.st_ino
        return self.hashes[key] if key in self.hashes else self.real_hash(fd, expected)


class ManifestTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="titan-catalog-schema-", dir="/tmp")
        self.addCleanup(self.temp.cleanup)
        self.fixture = Fixture(Path(self.temp.name).resolve() / "backup")

    def test_fixed_profile_counts_bytes_and_real_gpt_geometry(self):
        report = tool.validate_manifests(self.fixture.manifests)
        self.assertEqual(len(report["payloads"]), 27)
        self.assertEqual(sum(row["bytes"] for row in report["payloads"]), 8727773184)
        self.assertEqual(tuple(map(tuple, report["layout"])), tool.EXPECTED_LAYOUT)
        self.assertEqual(len(report["layout"]), 38)
        self.assertEqual(set(tool.REMAINING_GPT), {"boot_para", "para", "expdb", "frp", "nvcfg",
            "nvdata", "metadata", "protect1", "protect2", "seccfg", "sec1", "proinfo", "nvram",
            "cache", "userdata", "otp", "flashinfo"})

    def test_missing_incomplete_unknown_schema_targets_paths_and_digests_rejected(self):
        f = self.fixture
        faults = {
            "missing_set": lambda m: m.pop(f.rootfs),
            "unexpected_set": lambda m: m.update(unexpected={}),
            "incomplete": lambda m: m[f.gpt].update(status="incomplete"),
            "format": lambda m: m[f.lk].update(format="titan-private-bootloaders-v99"),
            "format_bool": lambda m: m[f.boot].update(format=True),
            "scope_missing": lambda m: m[f.boot].pop("scope"),
            "scope_type": lambda m: m[f.rootfs].update(scope={"unexpected": "object"}),
            "timestamp_type": lambda m: m[f.lk].update(created_utc=123),
            "missing_target": lambda m: m[f.os]["partitions"].pop("system"),
            "extra_target": lambda m: m[f.os]["partitions"].update(userdata={}),
            "path_traversal": lambda m: m[f.boot]["partitions"]["boot"].update(file="../boot.img"),
            "absolute_path": lambda m: m[f.boot]["partitions"]["boot"].update(file="/tmp/boot.img"),
            "wrong_size": lambda m: m[f.os]["partitions"]["vendor"].update(bytes=897581055),
            "boolean_size": lambda m: m[f.os]["partitions"]["vendor"].update(bytes=True),
            "digest_mismatch": lambda m: m[f.lk]["partitions"]["lk"].update(phone_repeat_sha256="0" * 64),
            "uppercase_digest": lambda m: m[f.rootfs]["files"]["ubuntu"].update(sha256="A" * 64),
            "rootfs_attestation": lambda m: m[f.rootfs]["files"]["ubuntu"].update(saved_file_readback_match=1),
            "false_validation": lambda m: m[f.firmware]["validation"].update(atomic_snapshot=True),
            "zero_guid_opt_out": lambda m: m[f.gpt]["validation_policy"].update(allow_zero_disk_guid=False),
            "zero_guid_warning": lambda m: m[f.gpt].update(warnings=[]),
        }
        for fault, mutate in faults.items():
            manifests = copy.deepcopy(f.manifests); mutate(manifests)
            with self.subTest(fault=fault), self.assertRaises(tool.CatalogError):
                tool.validate_manifests(manifests)

    def test_layout_and_geometry_disagreement_rejected_but_volatile_fields_allowed(self):
        f = self.fixture
        faults = {
            "map_start": lambda m: m[f.lk]["kernel_map"]["partitions"][2].update(start=67649),
            "map_name": lambda m: m[f.os]["kernel_map"]["partitions"][2].update(name="different"),
            "bool_number": lambda m: m[f.os]["kernel_map"]["partitions"][0].update(number=True),
            "parent": lambda m: m[f.lk]["kernel_map"]["disk"].update(sysfs="/sys/devices/other/mmcblk0"),
            "record_geometry": lambda m: m[f.os]["partitions"]["vendor"]["geometry"].update(start=1097729),
            "gpt_map": lambda m: m[f.gpt]["gpt"]["partitions"][0].update(sectors=2049),
            "gpt_kernel": lambda m: m[f.gpt]["kernel_map"]["partitions"][0].update(first_lba=65),
        }
        for fault, mutate in faults.items():
            manifests = copy.deepcopy(f.manifests); mutate(manifests)
            with self.subTest(fault=fault), self.assertRaises(tool.CatalogError):
                tool.validate_manifests(manifests)
        manifests = copy.deepcopy(f.manifests)
        manifests[f.os]["created_utc"] = "2026-02-01T00:00:00+00:00"
        manifests[f.firmware]["kernel_map"]["base"]["android_init"].update(pid=52, start_time=200)
        manifests[f.os]["kernel_map"]["vendor_mounts"]["android"][0]["mountpoint"] = "/synthetic/vendor-alias"
        self.assertEqual(len(tool.validate_manifests(manifests)["payloads"]), 27)


class WorkflowTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="titan-catalog-workflow-", dir="/tmp")
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name).resolve()
        self.sequence = 0
        self.fresh()

    def fresh(self):
        self.sequence += 1
        self.fixture = Fixture(self.base / f"backup-{self.sequence}")
        self.output = self.base / f"catalog-{self.sequence}"

    def verify(self, hash_fn=None, root=None):
        with mock.patch.object(tool, "hash_payload", side_effect=hash_fn or self.fixture.synthetic_hash):
            with contextlib.redirect_stderr(io.StringIO()):
                return tool.verify_catalog(root or self.fixture.root, self.output)

    def assert_unpublished(self):
        self.assertFalse((self.output / "catalog.json").exists())
        if self.output.exists():
            self.assertEqual(stat.S_IMODE(self.output.stat().st_mode), 0o700)
            for path in self.output.iterdir():
                self.assertTrue(path.name.endswith(".part"))
                self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)

    def test_complete_catalog_is_private_and_preserves_coverage_limitations(self):
        report = self.verify()
        self.assertEqual(report, json.loads((self.output / "catalog.json").read_bytes()))
        self.assertEqual(report["status"], "complete")
        self.assertEqual(report["payload_count"], 27)
        self.assertEqual(report["logical_bytes"], 8727773184)
        self.assertEqual(set(report["remaining_gpt_names"]), set(tool.REMAINING_GPT))
        self.assertEqual(report["gpt"]["warnings"], ["zero-disk-guid"])
        self.assertEqual(report["gpt"]["disk_guid"], str(uuid.UUID(int=0)))
        self.assertEqual(report["validation"], {"local_payload_hashes": True, "layout_agreement": True,
            "gpt_reparsed": True, "unique_device_identity": False, "authenticated_provenance": False,
            "atomic_snapshot": False, "independent_backup_copy": False, "restore_ready": False})
        limitations = " ".join(report["limitations"])
        for phrase in ("unsigned", "short-read", "not a userdata backup", "RPMB", "No restore"):
            self.assertIn(phrase.lower(), limitations.lower())
        self.assertEqual(stat.S_IMODE(self.output.stat().st_mode), 0o700)
        self.assertEqual(stat.S_IMODE((self.output / "catalog.json").stat().st_mode), 0o600)
        self.assertEqual((self.output / "catalog.json").stat().st_nlink, 1)
        self.assertEqual([p.name for p in self.output.iterdir()], ["catalog.json"])
        self.assertNotIn(str(self.base), json.dumps(report))

    def test_short_grown_missing_and_hash_mismatched_payloads_never_publish(self):
        for fault in ("short", "extra", "missing", "digest"):
            self.fresh(); f = self.fixture; path = f.payloads[f.rootfs, "ubuntu"]
            if fault in ("short", "extra"):
                with path.open("r+b") as stream: stream.truncate(path.stat().st_size + (-1 if fault == "short" else 1))
            elif fault == "missing": path.unlink()
            else:
                metadata = path.stat(); f.hashes[metadata.st_dev, metadata.st_ino] = "0" * 64
            with self.subTest(fault=fault), self.assertRaises((tool.CatalogError, OSError)):
                self.verify()
            self.assert_unpublished()

    def test_duplicate_json_and_private_error_values_do_not_escape_cli(self):
        f = self.fixture; path = f.root / f.boot / "manifest.json"
        path.write_bytes(b'{"status":"complete","status":"complete","private":"PRIVATE_TEST_VALUE"}\n')
        stderr, stdout = io.StringIO(), io.StringIO()
        with contextlib.redirect_stderr(stderr), contextlib.redirect_stdout(stdout):
            result = tool.main(["--backup-root", str(f.root), "--output", str(self.output)])
        self.assertEqual(result, 1)
        self.assertNotIn("PRIVATE_TEST_VALUE", stderr.getvalue() + stdout.getvalue())
        self.assertNotIn(str(f.root), stderr.getvalue() + stdout.getvalue())
        self.assert_unpublished()

    def test_real_gpt_parser_rejects_torn_edge_and_recorded_report_disagreement(self):
        for fault in ("torn", "report"):
            self.fresh(); f = self.fixture
            if fault == "report":
                f.manifests[f.gpt]["gpt"]["primary"]["header_crc32"] ^= 1
            else:
                path = f.payloads[f.gpt, "front"]
                data = bytearray(path.read_bytes()); data[1024 + 40] ^= 1
                path.write_bytes(data)
                digest = hashlib.sha256(data).hexdigest(); metadata = path.stat()
                f.hashes[metadata.st_dev, metadata.st_ino] = digest
                record = f.manifests[f.gpt]["regions"]["front"]
                for field in ("sha256", "transfer_sha256", "readback_sha256", "repeat_sha256"):
                    record[field] = digest
            f.write_manifests()
            with self.subTest(fault=fault), self.assertRaises(tool.CatalogError): self.verify()
            self.assert_unpublished()
        with self.assertRaises(gpt_fixtures.tool.gpt.GPTError):
            gpt_fixtures.tool.gpt.validate_gpt(f.front, f.tail, 125074145280)

    def test_nonprivate_symlink_hardlink_fifo_and_nonprivate_directory_rejected(self):
        for fault in ("file_mode", "manifest_mode", "symlink", "hardlink", "fifo", "directory_mode"):
            self.fresh(); f = self.fixture; path = f.payloads[f.boot, "boot"]
            if fault == "file_mode": path.chmod(0o640)
            elif fault == "manifest_mode": (f.root / f.boot / "manifest.json").chmod(0o644)
            elif fault == "directory_mode": (f.root / f.boot).chmod(0o750)
            elif fault == "hardlink": os.link(path, f.root / "second-link")
            elif fault == "symlink":
                renamed = path.with_name("target"); path.rename(renamed); path.symlink_to(renamed)
            else: path.unlink(); os.mkfifo(path, 0o600)
            with self.subTest(fault=fault), self.assertRaises((tool.CatalogError, OSError)): self.verify()
            self.assert_unpublished()

    def test_existing_output_and_unsafe_ancestry_are_refused(self):
        self.output.mkdir(mode=0o700); sentinel = self.output / "sentinel"
        private_write(sentinel, b"keep")
        with self.assertRaises((tool.CatalogError, OSError)): self.verify()
        self.assertEqual(sentinel.read_bytes(), b"keep")
        for marker in (".git", ".jj"):
            self.fresh(); parent = self.base / ("unsafe-" + marker[1:])
            parent.mkdir(mode=0o700); (parent / marker).mkdir(mode=0o700)
            self.output = parent / "catalog"
            with self.subTest(marker=marker), self.assertRaises(tool.CatalogError): self.verify()
            self.assertFalse(self.output.exists())
        self.fresh(); alias = self.base / "alias"; alias.symlink_to(self.fixture.root, target_is_directory=True)
        with self.assertRaises(tool.CatalogError): self.verify(root=alias)
        self.assert_unpublished()
        with self.assertRaises(tool.CatalogError): tool.PrivateTree("/nix")

    def test_changed_manifest_and_already_hashed_file_are_caught_before_publication(self):
        for fault in ("manifest_mutation", "manifest_replacement", "payload_mutation", "payload_replacement"):
            self.fresh(); f = self.fixture; calls = 0

            def alter(fd, expected):
                nonlocal calls
                result = f.synthetic_hash(fd, expected); calls += 1
                if calls == 2:
                    path = f.root / f.boot / "manifest.json" if fault.startswith("manifest") else f.payloads[f.boot, "boot"]
                    if fault.endswith("replacement"):
                        replacement = path.with_name(path.name + ".replacement")
                        private_write(replacement, b"replacement")
                        with replacement.open("r+b") as stream: stream.truncate(path.stat().st_size)
                        os.replace(replacement, path)
                    else:
                        with path.open("r+b") as stream: stream.write(b"X")
                return result

            with self.subTest(fault=fault), self.assertRaises(tool.CatalogError): self.verify(alter)
            self.assert_unpublished()

    def test_source_set_root_and_output_directory_swaps_are_caught(self):
        for fault in ("set_symlink", "root_rename", "output_symlink"):
            self.fresh(); f = self.fixture; changed = False

            def alter(fd, expected):
                nonlocal changed
                result = f.synthetic_hash(fd, expected)
                if not changed:
                    changed = True
                    path = f.root / f.boot if fault == "set_symlink" else f.root if fault == "root_rename" else self.output
                    saved = path.with_name(path.name + "-saved")
                    path.rename(saved)
                    if fault == "root_rename": path.mkdir(mode=0o700)
                    else: path.symlink_to(saved, target_is_directory=True)
                return result

            with self.subTest(fault=fault), self.assertRaises(tool.CatalogError): self.verify(alter)
            self.assert_unpublished()

    def test_late_publication_failure_or_source_change_removes_completed_catalog(self):
        original = os.link
        for fault in ("link_failure", "late_source_change"):
            self.fresh(); f = self.fixture

            def link(source, destination, **kwargs):
                if destination == "catalog.json":
                    if fault == "link_failure": raise OSError("Synthetic publication failure")
                    with f.payloads[f.boot, "boot"].open("r+b") as stream: stream.write(b"X")
                return original(source, destination, **kwargs)

            with mock.patch.object(tool.os, "link", side_effect=link):
                with self.subTest(fault=fault), self.assertRaises((tool.CatalogError, OSError)): self.verify()
            self.assert_unpublished()

    def test_catalog_staging_inode_replacement_never_leaves_a_completed_catalog(self):
        original_file = tool.PrivateFile
        original_link = os.link
        for fault in ("before_readback", "after_readback", "before_link"):
            self.fresh(); f = self.fixture; replaced = False

            def replace_pending():
                nonlocal replaced
                if replaced: return
                replaced = True
                pending = self.output / "catalog.json.part"
                other = self.output / "replacement.part"
                private_write(other, pending.read_bytes())
                os.replace(other, pending)

            def opening(directory, name, expected=None):
                if fault == "before_readback" and name == "catalog.json.part": replace_pending()
                return original_file(directory, name, expected)

            def hashing(fd, expected):
                result = f.synthetic_hash(fd, expected)
                metadata = os.fstat(fd)
                if fault == "after_readback" and (metadata.st_dev, metadata.st_ino) not in f.hashes:
                    replace_pending()
                return result

            def linking(source, destination, **kwargs):
                if fault == "before_link" and destination == "catalog.json": replace_pending()
                return original_link(source, destination, **kwargs)

            with mock.patch.object(tool, "PrivateFile", side_effect=opening):
                with mock.patch.object(tool.os, "link", side_effect=linking):
                    with self.subTest(fault=fault), self.assertRaises(tool.CatalogError): self.verify(hashing)
            self.assertTrue(replaced)
            self.assert_unpublished()

    def test_durability_failure_after_link_or_partial_unlink_rolls_back_final_name(self):
        original_sync = os.fsync
        for fault in ("after_link", "after_partial_unlink"):
            self.fresh(); failed = False

            def sync(fd):
                nonlocal failed
                final = self.output / "catalog.json"
                pending = self.output / "catalog.json.part"
                if (not failed and final.exists() and
                        (fault == "after_link" or not pending.exists())):
                    failed = True
                    raise OSError("Synthetic post-publication durability failure")
                return original_sync(fd)

            with mock.patch.object(tool.os, "fsync", side_effect=sync):
                with self.subTest(fault=fault), self.assertRaises(OSError): self.verify()
            self.assertTrue(failed)
            self.assert_unpublished()


class HashTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="titan-catalog-hash-", dir="/tmp")
        self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name).resolve() / "payload"

    def hash(self, expected):
        with self.path.open("rb", buffering=0) as stream:
            return tool.hash_payload(stream.fileno(), expected)

    def test_hash_streams_all_bytes_with_bounded_reads_and_handles_short_reads(self):
        data = bytes(range(256)) * 8193 + b"\0end"
        private_write(self.path, data)
        read, requests = os.read, []

        def short_read(fd, count):
            requests.append(count)
            return read(fd, min(count, 8191))

        with mock.patch.object(tool.os, "read", side_effect=short_read):
            self.assertEqual(self.hash(len(data)), hashlib.sha256(data).hexdigest())
        self.assertGreater(len(requests), 2)
        self.assertLessEqual(max(requests), 1048576)

    def test_hash_rejects_truncation_extra_bytes_and_read_errors(self):
        private_write(self.path, bytes(range(256)))
        for count in (255, 257):
            with self.subTest(expected=count), self.assertRaises(tool.CatalogError):
                self.hash(count)
        with mock.patch.object(tool.os, "read", side_effect=OSError("synthetic read failure")):
            with self.assertRaises((tool.CatalogError, OSError)):
                self.hash(256)

    def test_growth_during_hash_is_detected_by_the_final_eof_check(self):
        private_write(self.path, b"original")
        original_read, changed = os.read, False

        def read(fd, count):
            nonlocal changed
            data = original_read(fd, count)
            if not changed:
                changed = True
                with self.path.open("ab") as stream: stream.write(b"extra")
            return data

        with mock.patch.object(tool.os, "read", side_effect=read), self.assertRaises(tool.CatalogError):
            self.hash(8)

    def test_json_rejects_duplicate_keys_and_non_json_values(self):
        self.assertEqual(tool.parsed_json(b'{"a": {"b": 1}}\n'), {"a": {"b": 1}})
        for data in (b'{"a":1,"a":1}', b'{"a":{"b":1,"b":2}}',
                     b'{"a":NaN}', b'{"a":Infinity}', b'[]', b'\xff', b'{} trailing',
                     b" " * (tool.JSON_LIMIT + 1)):
            with self.subTest(data=data), self.assertRaises(tool.CatalogError):
                tool.parsed_json(data)


if __name__ == "__main__":
    unittest.main()
