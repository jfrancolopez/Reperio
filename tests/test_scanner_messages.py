from __future__ import annotations

import json
import unittest

from scanner import messages


class ScannerMessageTests(unittest.TestCase):
    def test_golden_messages_decode_for_all_required_types(self) -> None:
        samples = [
            messages.encode_message("hello", 0, {"worker_id": "worker_1", "scanner_version": "0"}),
            messages.encode_message("capabilities", 1, {"capabilities": ["source-validation"]}),
            messages.encode_message(
                "stage_start", 2, {"stage": "validate", "idempotency_key": "k"}
            ),
            messages.encode_message(
                "finding_batch",
                3,
                {"stage": "validate", "batch_id": "b1", "findings": [{"finding_id": "f1"}]},
            ),
            messages.encode_message(
                "progress", 4, {"stage": "validate", "completed": 1, "total": 2}
            ),
            messages.encode_message("checkpoint", 5, {"stage": "validate", "checkpoint_id": "c1"}),
            messages.encode_message(
                "warning", 6, {"stage": "validate", "code": "slow", "message": "slow read"}
            ),
            messages.encode_message(
                "error",
                7,
                {"stage": "validate", "code": "io", "message": "read failed", "retryable": True},
            ),
            messages.encode_message("pause_ack", 8, {"stage": "validate", "reason": "operator"}),
            messages.encode_message("complete", 9, {"stage": "validate", "status": "completed"}),
        ]

        decoded = messages.decode_stream(samples)

        self.assertEqual(10, len(decoded))
        self.assertEqual("hello", decoded[0].message_type)
        self.assertEqual(3, decoded[3].sequence)
        self.assertEqual(("finding_batch", 3, "b1"), decoded[3].replay_key)

    def test_version_mismatch_is_rejected_without_raw_output(self) -> None:
        line = b'{"protocol_version":999,"type":"hello","sequence":0,"payload":{}}\n'

        with self.assertRaises(messages.ScannerMessageError) as captured:
            messages.decode_line(line)

        self.assertIn("unsupported", str(captured.exception))
        self.assertNotIn("999", str(captured.exception))

    def test_truncated_batch_is_rejected(self) -> None:
        line = messages.encode_message(
            "progress", 1, {"stage": "validate", "completed": 1, "total": 2}
        ).rstrip(b"\n")

        with self.assertRaisesRegex(messages.ScannerMessageError, "truncated"):
            messages.decode_line(line)

    def test_oversized_field_is_rejected(self) -> None:
        with self.assertRaisesRegex(messages.ScannerMessageError, "maximum"):
            messages.encode_message(
                "warning",
                1,
                {
                    "stage": "validate",
                    "code": "oversized",
                    "message": "x" * (messages.MAX_FIELD_CHARS + 1),
                },
            )

    def test_invalid_encoding_is_rejected(self) -> None:
        with self.assertRaisesRegex(messages.ScannerMessageError, "UTF-8"):
            messages.decode_line(b"\xff\n")

    def test_duplicate_replay_is_ignored(self) -> None:
        line = messages.encode_message(
            "finding_batch",
            3,
            {"stage": "validate", "batch_id": "batch_1", "findings": [{"finding_id": "f1"}]},
        )

        decoded = messages.decode_stream([line, line])

        self.assertEqual(1, len(decoded))

    def test_unsafe_worker_output_cannot_inject_logs_or_sql(self) -> None:
        payload = {
            "protocol_version": messages.PROTOCOL_VERSION,
            "type": "warning",
            "sequence": 1,
            "payload": {"stage": "validate", "code": "bad", "message": "ok\nDROP TABLE jobs"},
        }

        with self.assertRaisesRegex(messages.ScannerMessageError, "unsafe"):
            messages.decode_line(json.dumps(payload).encode() + b"\n")


if __name__ == "__main__":
    unittest.main()
