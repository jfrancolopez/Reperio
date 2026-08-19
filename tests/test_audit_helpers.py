#!/usr/bin/env python3

from __future__ import annotations

import unittest
from typing import Any

from worker.audit_helpers import (
    AUDIT_HELPER_VERSION,
    AuditHelperError,
    adapter_for,
    build_invocation,
    detect_format,
    redact_material,
    run_helper,
    supported_formats,
)


class AdapterTests(unittest.TestCase):
    def test_supported_pairs(self) -> None:
        pairs = {
            "zip": "zip2john",
            "7z": "7z2john",
            "rar": "rar2john",
            "pdf": "pdf2john",
            "office": "office2john",
            "key": "key2john",
            "bitcoin_wallet": "bitcoin2john",
            "ethereum_wallet": "ethereum2john",
            "gpg": "gpg2john",
        }
        for format, helper in pairs.items():
            adapter = adapter_for(format)
            self.assertEqual(helper, adapter.helper)
            self.assertEqual("john", adapter.engine)

    def test_unsupported_format_rejected(self) -> None:
        with self.assertRaisesRegex(AuditHelperError, "no allowed adapter"):
            adapter_for("mystery")

    def test_metadata_normalized(self) -> None:
        meta = adapter_for("pdf").metadata()
        self.assertEqual("pdf2john/john", meta["mode"])
        self.assertEqual("copied_target_only", meta["input"])
        self.assertEqual("secret", meta["output_classification"])


class DetectTests(unittest.TestCase):
    def test_detected_from_format(self) -> None:
        self.assertEqual("zip", detect_format({"format": "zip"}))

    def test_detected_from_container(self) -> None:
        self.assertEqual("pdf", detect_format({"container": "pdf", "format": "other"}))

    def test_wrong_detection_is_explicit(self) -> None:
        with self.assertRaisesRegex(AuditHelperError, "no supported format"):
            detect_format({"format": "unknown"})


class InvocationTests(unittest.TestCase):
    def test_copied_target_only(self) -> None:
        invocation = build_invocation(
            format="zip", copied_target_path="/scratch/job-1/copy.zip", scratch_dir="/scratch/job-1"
        )
        self.assertEqual("reperio-2john", invocation["argv"][0])
        self.assertEqual("zip2john", invocation["argv"][1])
        self.assertEqual("/scratch/job-1/copy.zip", invocation["argv"][2])

    def test_source_path_rejected(self) -> None:
        with self.assertRaisesRegex(AuditHelperError, "copied scratch target"):
            build_invocation(
                format="zip",
                copied_target_path="/dev/sdb1/secret.zip",
                scratch_dir="/scratch/job-1",
            )

    def test_not_downloadable_by_default(self) -> None:
        invocation = build_invocation(
            format="zip", copied_target_path="/scratch/job-1/copy.zip", scratch_dir="/scratch/job-1"
        )
        self.assertFalse(invocation["downloadable_by_default"])
        self.assertEqual("secret", invocation["output_classification"])


class RunTests(unittest.TestCase):
    def test_successful_run(self) -> None:
        invocation = build_invocation(
            format="zip", copied_target_path="/scratch/job-1/copy.zip", scratch_dir="/scratch/job-1"
        )
        outcome = run_helper(
            invocation, lambda req: {"returncode": 0, "material": "hash:$pkzip2$abc"}
        )
        self.assertEqual("ok", outcome["status"])
        self.assertTrue(outcome["classified"])
        self.assertFalse(outcome["downloadable_by_default"])

    def test_timeout(self) -> None:
        invocation = build_invocation(
            format="zip", copied_target_path="/scratch/job-1/copy.zip", scratch_dir="/scratch/job-1"
        )
        outcome = run_helper(invocation, lambda req: {"timed_out": True})
        self.assertEqual("timed_out", outcome["status"])
        self.assertTrue(outcome["redacted"])

    def test_crash(self) -> None:
        invocation = build_invocation(
            format="zip", copied_target_path="/scratch/job-1/copy.zip", scratch_dir="/scratch/job-1"
        )

        def broken(req: Any) -> dict[str, Any]:
            raise RuntimeError("boom")

        outcome = run_helper(invocation, broken)
        self.assertEqual("crashed", outcome["status"])

    def test_nonzero_exit(self) -> None:
        invocation = build_invocation(
            format="zip", copied_target_path="/scratch/job-1/copy.zip", scratch_dir="/scratch/job-1"
        )
        outcome = run_helper(invocation, lambda req: {"returncode": 2})
        self.assertEqual("failed", outcome["status"])

    def test_secret_redaction(self) -> None:
        invocation = build_invocation(
            format="zip", copied_target_path="/scratch/job-1/copy.zip", scratch_dir="/scratch/job-1"
        )
        outcome = run_helper(
            invocation, lambda req: {"returncode": 0, "material": "password=supersecret12345"}
        )
        self.assertNotIn("supersecret12345", outcome["material"])
        self.assertIn("[redacted]", outcome["material"])

    def test_redact_material(self) -> None:
        redacted = redact_material("secret=abcdefghij12345 wallet=wallet-abcdef123456")
        self.assertNotIn("abcdefghij12345", redacted)
        self.assertNotIn("wallet-abcdef123456", redacted)


class VersionTests(unittest.TestCase):
    def test_version_constant(self) -> None:
        self.assertEqual("audit-helper-v1", AUDIT_HELPER_VERSION)

    def test_supported_formats(self) -> None:
        self.assertIn("zip", supported_formats())
        self.assertNotIn("mystery", supported_formats())


if __name__ == "__main__":
    unittest.main()
