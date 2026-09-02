#!/usr/bin/env python3

from __future__ import annotations

import os
import stat
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPOSITORY_ROOT / "scripts"))

import no_source_write_suite as suite  # noqa: E402


class NoSourceWriteSuiteTests(unittest.TestCase):
    @unittest.skipIf(os.geteuid() == 0, "synthetic chmod preflight is unsafe as root")
    def test_full_harness_attempts_leave_source_unchanged(self) -> None:
        harness = suite.NoSourceWriteHarness.create()

        result = harness.run_all()

        self.assertTrue(result["source_unchanged"])
        self.assertEqual("synthetic_contract_preflight", result["evidence_level"])
        self.assertFalse(result["integration_proof_complete"])
        for name, attempt in result["attempts"].items():
            self.assertTrue(attempt["passed"], name)

    @unittest.skipIf(os.geteuid() == 0, "synthetic chmod preflight is unsafe as root")
    def test_refuses_source_outside_harness_root(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            other_root = Path(tmp) / "other-root"
            other_root.mkdir()
            source = Path(tmp) / "source.fixture"
            source.write_bytes(b"not the fixture")

            with self.assertRaisesRegex(suite.UnsafeFixtureError, "under the harness root"):
                suite.NoSourceWriteHarness.from_existing(other_root, source)

    @unittest.skipIf(os.geteuid() == 0, "synthetic chmod preflight is unsafe as root")
    def test_refuses_wrong_hash_even_under_harness_root(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = root / "source.fixture"
            image, _ = suite.fixture_builder.build_image()
            corrupted = bytearray(image)
            corrupted[-1] ^= 0xFF
            source.write_bytes(corrupted)
            source.chmod(stat.S_IRUSR | stat.S_IRGRP | stat.S_IROTH)

            with self.assertRaisesRegex(suite.UnsafeFixtureError, "hash"):
                suite.NoSourceWriteHarness.from_existing(root, source)

    @unittest.skipIf(os.geteuid() == 0, "synthetic chmod preflight is unsafe as root")
    def test_refuses_wrong_filename(self) -> None:
        harness = suite.NoSourceWriteHarness.create()
        wrong_name = harness.root / "source.raw"
        wrong_name.write_bytes(harness.source_path.read_bytes())

        with self.assertRaisesRegex(suite.UnsafeFixtureError, "filename"):
            suite.NoSourceWriteHarness.from_existing(harness.root, wrong_name)

    @unittest.skipIf(os.geteuid() == 0, "synthetic chmod preflight is unsafe as root")
    def test_each_named_attempt_is_present(self) -> None:
        result = suite.NoSourceWriteHarness.create().run_all()

        self.assertEqual(
            {
                "malicious_adapter_attempt",
                "compromised_api_payload",
                "same_disk_scratch",
                "symlink_swap",
                "device_renumber",
                "scanner_restart",
                "minimal_scan",
            },
            set(result["attempts"]),
        )

    @unittest.skipIf(os.geteuid() == 0, "synthetic chmod preflight is unsafe as root")
    def test_refuses_symlink_hardlink_and_writable_fixture(self) -> None:
        harness = suite.NoSourceWriteHarness.create()

        link = harness.root / "source-link.fixture"
        link.symlink_to(harness.source_path)
        with self.assertRaisesRegex(suite.UnsafeFixtureError, "symlink"):
            suite.NoSourceWriteHarness.from_existing(harness.root, link)

        hardlink = harness.root / "source.fixture"
        harness.source_path.rename(harness.root / "original.fixture")
        os.link(harness.root / "original.fixture", hardlink)
        with self.assertRaisesRegex(suite.UnsafeFixtureError, "private regular"):
            suite.NoSourceWriteHarness.from_existing(harness.root, hardlink)

        hardlink.unlink()
        (harness.root / "original.fixture").rename(hardlink)
        hardlink.chmod(stat.S_IRUSR | stat.S_IWUSR)
        with self.assertRaisesRegex(suite.UnsafeFixtureError, "write permission"):
            suite.NoSourceWriteHarness.from_existing(harness.root, hardlink)

    def test_refuses_root_execution_before_creating_fixture(self) -> None:
        with mock.patch.object(suite.os, "geteuid", return_value=0):
            with self.assertRaisesRegex(suite.UnsafeFixtureError, "must not run as root"):
                suite.NoSourceWriteHarness.create()


if __name__ == "__main__":
    unittest.main()
