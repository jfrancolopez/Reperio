#!/usr/bin/env python3

from __future__ import annotations

import json
import tempfile
import threading
import unittest
from pathlib import Path

from hostd import safety_audit


class HostdSafetyAuditTests(unittest.TestCase):
    def test_appends_and_verifies_ordered_records(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "safety.jsonl"
            audit = safety_audit.SafetyAuditLog(path)

            first = audit.append("device_resolution", {"source_id": "source_abc"})
            second = audit.append("read_only_verification", {"prepared": True})
            state = safety_audit.verify_audit_log(path)

        self.assertEqual(1, first["sequence"])
        self.assertEqual(2, second["sequence"])
        self.assertEqual(3, state["next_sequence"])
        self.assertEqual(second["record_hash"], state["last_hash"])

    def test_redacts_credentials_tokens_and_sampled_bytes(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "safety.jsonl"
            audit = safety_audit.SafetyAuditLog(path)

            audit.append(
                "destination_separation",
                {
                    "credential_ref": "env:SECRET",
                    "operator_token": "abc123",
                    "nested": {"sample_bytes": "raw-sector"},
                    "safe_fact": "8:1",
                },
            )
            record = safety_audit.verify_audit_log(path)["records"][0]

        encoded = json.dumps(record, sort_keys=True)
        self.assertNotIn("env:SECRET", encoded)
        self.assertNotIn("abc123", encoded)
        self.assertNotIn("raw-sector", encoded)
        self.assertIn("8:1", encoded)

    def test_tampered_log_is_detected(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "safety.jsonl"
            audit = safety_audit.SafetyAuditLog(path)
            audit.append("mount_holder_check", {"safe": True})
            record = json.loads(path.read_text(encoding="utf-8"))
            record["payload"]["safe"] = False
            path.write_text(json.dumps(record, sort_keys=True) + "\n", encoding="utf-8")

            with self.assertRaisesRegex(safety_audit.AuditVerificationError, "hash mismatch"):
                safety_audit.verify_audit_log(path)

    def test_truncated_log_is_detected(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "safety.jsonl"
            audit = safety_audit.SafetyAuditLog(path)
            audit.append("read_only_verification", {"prepared": True})
            path.write_text(path.read_text(encoding="utf-8")[:20], encoding="utf-8")

            with self.assertRaisesRegex(safety_audit.AuditVerificationError, "invalid JSON"):
                safety_audit.verify_audit_log(path)

    def test_concurrent_appends_preserve_sequence_ordering(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "safety.jsonl"
            audit = safety_audit.SafetyAuditLog(path)

            threads = [
                threading.Thread(
                    target=audit.append, args=("scanner_sandbox_profile", {"index": index})
                )
                for index in range(20)
            ]
            for thread in threads:
                thread.start()
            for thread in threads:
                thread.join()
            state = safety_audit.verify_audit_log(path)

        self.assertEqual(list(range(1, 21)), [record["sequence"] for record in state["records"]])

    def test_rotation_continuation_can_start_from_verified_existing_log(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "safety.jsonl"
            safety_audit.SafetyAuditLog(path).append("device_resolution", {"source_id": "source_1"})
            safety_audit.SafetyAuditLog(path).append("system_disk_decision", {"denied": False})

            state = safety_audit.verify_audit_log(path)

        self.assertEqual(3, state["next_sequence"])


if __name__ == "__main__":
    unittest.main()
