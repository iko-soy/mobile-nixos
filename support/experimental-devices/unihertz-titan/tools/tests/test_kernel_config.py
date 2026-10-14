"""Exercise config evidence and privacy with synthetic host-side inputs."""

import contextlib
import gzip
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch


SCRIPT = Path(__file__).resolve().parents[1] / "compare-kernel-config.py"
SPEC = importlib.util.spec_from_file_location("kernel_config", SCRIPT)
kernel_config = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(kernel_config)


class ConfigComparisonTests(unittest.TestCase):
    def compare(self, reference, runtime):
        with tempfile.TemporaryDirectory() as directory:
            before, after = Path(directory) / "reference", Path(directory) / "runtime"
            before.write_bytes(reference)
            after.write_bytes(runtime)
            return kernel_config.compare_configs(
                kernel_config.load_config(before), kernel_config.load_config(after),
            )

    def test_gzip_and_plain_hash_the_same_decompressed_config(self):
        data = b'# Generated config\nCONFIG_FHANDLE=y\n# CONFIG_BT is not set\n'
        report = self.compare(data, gzip.compress(data, mtime=123))
        digest = hashlib.sha256(data).hexdigest()
        self.assertEqual(report["inputs"]["reference"]["decompressed_sha256"], digest)
        self.assertEqual(report["inputs"]["runtime"]["decompressed_sha256"], digest)
        self.assertTrue(report["comparison"]["identical_config_bytes"])
        self.assertTrue(report["comparison"]["same_parsed_settings"])
        self.assertFalse(report["compatibility_verified"])
        self.assertFalse(report["bootability_verified"])

    def test_missing_disabled_and_modular_settings_stay_distinct(self):
        report = self.compare(
            b'# CONFIG_FHANDLE is not set\nCONFIG_BT=m\nCONFIG_MODULES=y\n',
            b'CONFIG_FHANDLE=n\nCONFIG_BT=y\nCONFIG_TUN=y\n',
        )
        settings = report["settings"]
        self.assertEqual(settings["CONFIG_FHANDLE"], {
            "reference": "n", "runtime": "n", "comparison": "same",
        })
        self.assertEqual(settings["CONFIG_BT"], {
            "reference": "m", "runtime": "y", "comparison": "different",
        })
        self.assertEqual(settings["CONFIG_MODULES"]["runtime"], "unknown")
        self.assertEqual(settings["CONFIG_TUN"]["reference"], "unknown")
        # Even two missing values are not evidence of an agreed disabled option.
        self.assertEqual(settings["CONFIG_TMPFS"]["comparison"], "unknown")
        self.assertEqual(report["comparison"]["changed_setting_count"], 1)
        self.assertEqual(report["comparison"]["reference_only_setting_count"], 1)
        self.assertEqual(report["comparison"]["runtime_only_setting_count"], 1)

    def test_comments_and_unset_notation_affect_bytes_but_not_settings(self):
        report = self.compare(
            b'# builder: private-comment\n# CONFIG_BT is not set\n',
            b'CONFIG_BT=n\n',
        )
        self.assertFalse(report["comparison"]["identical_config_bytes"])
        self.assertTrue(report["comparison"]["same_parsed_settings"])
        self.assertNotIn("private-comment", json.dumps(report))

    def test_arbitrary_values_are_counted_but_not_published(self):
        report = self.compare(
            b'CONFIG_FHANDLE=y\nCONFIG_PRIVATE_TOKEN="private-secret-one"\n'
            b'CONFIG_PRIVATE_COUNT=64\nCONFIG_PRIVATE_ADDRESS=0xff\n',
            b'CONFIG_FHANDLE=y\nCONFIG_PRIVATE_TOKEN="private-secret-two"\n'
            b'CONFIG_PRIVATE_COUNT=-1\nCONFIG_PRIVATE_ADDRESS=0x10\n',
        )
        self.assertEqual(report["comparison"]["changed_setting_count"], 3)
        encoded = json.dumps(report)
        for forbidden in ("PRIVATE_TOKEN", "private-secret", "PRIVATE_COUNT", "PRIVATE_ADDRESS"):
            self.assertNotIn(forbidden, encoded)


class ConfigInputTests(unittest.TestCase):
    def test_malformed_and_duplicate_configs_are_rejected_without_disclosure(self):
        invalid = (
            b'', b'# only a comment\n', b'private-malformed-line\n',
            b'CONFIG_FHANDLE=private-secret\n', b'CONFIG_FHANDLE="private-secret"\n',
            b'CONFIG_OTHER="private-secret\n', b'# CONFIG_FHANDLE is not se\n',
            b'CONFIG_FHANDLE=y\nCONFIG_FHANDLE=n\n',
            b'CONFIG_FHANDLE=y\nCONFIG_FHANDLE=y\n',
            b'# CONFIG_BT is not set\nCONFIG_BT=y\n',
            b'CONFIG_OTHER="private-secret\0"\n', b'CONFIG_OTHER="\xff"\n',
        )
        for data in invalid:
            with self.subTest(data=data), self.assertRaises(kernel_config.ConfigError) as error:
                kernel_config.parse_config(data)
            self.assertNotIn("private-", str(error.exception))

    def test_bad_gzip_crc_truncation_and_misnamed_plaintext_fail(self):
        good = gzip.compress(b'CONFIG_FHANDLE=y\n', mtime=0)
        damaged_crc = good[:-8] + bytes([good[-8] ^ 1]) + good[-7:]
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "config.gz"
            for data in (good[:-4], damaged_crc, b'CONFIG_FHANDLE=y\n', b''):
                with self.subTest(data=data):
                    path.write_bytes(data)
                    with self.assertRaises(kernel_config.ConfigError):
                        kernel_config.load_config(path)

    def test_bounded_plain_reads_and_gzip_decompression(self):
        with tempfile.TemporaryDirectory() as directory, patch.object(
            kernel_config, "MAX_CONFIG_BYTES", 128,
        ):
            path = Path(directory) / "config"
            oversized = b'# ' + b'x' * 512 + b'\nCONFIG_FHANDLE=y\n'
            for data in (oversized, gzip.compress(oversized)):
                with self.subTest(compressed=data.startswith(b'\x1f\x8b')):
                    path.write_bytes(data)
                    with self.assertRaisesRegex(kernel_config.ConfigError, "size limit"):
                        kernel_config.load_config(path)

    def test_valid_escaped_strings_and_numeric_values_parse(self):
        settings = kernel_config.parse_config(
            b'CONFIG_STRING="a \\"quote\\" and \\\\ slash"\n'
            b'CONFIG_INT=-42\nCONFIG_HEX=0xFE\nCONFIG_TRISTATE=m\n'
        )
        self.assertEqual(len(settings), 4)
        self.assertEqual(settings["TRISTATE"], "m")


class ConfigCliTests(unittest.TestCase):
    def invoke(self, arguments):
        stdout, stderr = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            code = kernel_config.main(arguments)
        return code, stdout.getvalue(), stderr.getvalue()

    def test_json_and_text_report_differences_without_paths_or_private_values(self):
        with tempfile.TemporaryDirectory() as directory:
            reference = Path(directory) / "private-reference-path"
            runtime = Path(directory) / "private-runtime-path.gz"
            reference.write_bytes(b'CONFIG_FHANDLE=n\nCONFIG_LOCALVERSION="private-build"\n')
            runtime.write_bytes(gzip.compress(b'CONFIG_FHANDLE=y\nCONFIG_LOCALVERSION="private-other"\n'))
            before = {path: path.read_bytes() for path in (reference, runtime)}
            arguments = ["--reference", str(reference), "--runtime", str(runtime)]
            for extra in ([], ["--json"]):
                with self.subTest(extra=extra):
                    code, stdout, stderr = self.invoke(arguments + extra)
                    self.assertEqual(code, 0)
                    self.assertEqual(stderr, "")
                    self.assertNotIn("private-", stdout)
                    self.assertNotIn(directory, stdout)
                    if extra:
                        report = json.loads(stdout)
                        self.assertEqual(report["settings"]["CONFIG_FHANDLE"]["comparison"], "different")
                    else:
                        self.assertIn("CONFIG_FHANDLE: reference=n runtime=y (different)", stdout)
            self.assertEqual(set(Path(directory).iterdir()), set(before))
            for path, data in before.items():
                self.assertEqual(path.read_bytes(), data)

    def test_missing_or_invalid_input_emits_no_partial_report_or_private_details(self):
        with tempfile.TemporaryDirectory() as directory:
            reference = Path(directory) / "private-reference-path"
            runtime = Path(directory) / "private-runtime-path"
            reference.write_bytes(b'CONFIG_FHANDLE=y\n')
            for data in (None, b'CONFIG_FHANDLE="private-secret"\n'):
                if data is not None:
                    runtime.write_bytes(data)
                code, stdout, stderr = self.invoke([
                    "--reference", str(reference), "--runtime", str(runtime), "--json",
                ])
                self.assertEqual(code, 1)
                self.assertEqual(stdout, "")
                self.assertIn("runtime configuration", stderr)
                self.assertNotIn("private-", stderr)
                self.assertNotIn(directory, stderr)


if __name__ == "__main__":
    unittest.main()
