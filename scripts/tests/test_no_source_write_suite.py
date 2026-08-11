#!/usr/bin/env python3

from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path

REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPOSITORY_ROOT / "scripts"))

import no_source_write_suite as suite  # noqa: E402


class NoSourceWriteSuiteTests(unittest.TestCase):
    def test_full_harness_attempts_leave_source_unchanged(self) -> None:
        harness = suite.NoSourceWriteHarness.create()

        result = harness.run_all()

        self.assertTrue(result["source_unchanged"])
        for name, attempt in result["attempts"].items():
            self.assertTrue(attempt["passed"], name)

    def test_refuses_source_outside_harness_root(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            other_root = Path(tmp) / "other-root"
            other_root.mkdir()
            source = Path(tmp) / "source.fixture"
            source.write_bytes(b"not the fixture")

            with self.assertRaisesRegex(suite.UnsafeFixtureError, "under the harness root"):
                suite.NoSourceWriteHarness.from_existing(other_root, source)

    def test_refuses_wrong_hash_even_under_harness_root(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = root / "source.fixture"
            source.write_bytes(b"not the fixture")

            with self.assertRaisesRegex(suite.UnsafeFixtureError, "hash"):
                suite.NoSourceWriteHarness.from_existing(root, source)

    def test_refuses_wrong_filename(self) -> None:
        harness = suite.NoSourceWriteHarness.create()
        wrong_name = harness.root / "source.raw"
        wrong_name.write_bytes(harness.source_path.read_bytes())

        with self.assertRaisesRegex(suite.UnsafeFixtureError, "filename"):
            suite.NoSourceWriteHarness.from_existing(harness.root, wrong_name)

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


if __name__ == "__main__":
    unittest.main()
