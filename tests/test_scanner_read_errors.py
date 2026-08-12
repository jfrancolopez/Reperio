from __future__ import annotations

import unittest

from scanner import messages, read_errors


class FaultReader:
    def __init__(self, outcomes: list[bytes | OSError]) -> None:
        self.outcomes = outcomes
        self.calls = 0

    def read_at(self, offset_bytes: int, length_bytes: int) -> bytes:
        self.calls += 1
        outcome = self.outcomes.pop(0)
        if isinstance(outcome, OSError):
            raise outcome
        return outcome


class ScannerReadErrorTests(unittest.TestCase):
    def test_eio_is_retried_then_recorded_as_gap(self) -> None:
        sleeps: list[float] = []
        reader = read_errors.ResilientReader(
            FaultReader([OSError("EIO"), OSError("EIO")]),
            policy=read_errors.ReadPolicy(max_attempts=2, base_backoff_ms=25),
            sleep=sleeps.append,
        )

        outcome = reader.read_or_gap(1024, 512)

        self.assertEqual(bytes(512), outcome.data)
        gap = outcome.gap
        assert gap is not None
        self.assertEqual("eio", gap.code)
        self.assertEqual((0.025,), tuple(sleeps))
        self.assertEqual(2, outcome.counters.attempted_reads)
        self.assertEqual(1, outcome.counters.retry_reads)
        self.assertEqual(512, outcome.counters.skipped_bytes)

    def test_timeout_is_normalized_and_warned(self) -> None:
        reader = read_errors.ResilientReader(
            FaultReader([read_errors.ReadTimeoutError("timeout")]),
            policy=read_errors.ReadPolicy(max_attempts=1),
        )

        outcome = reader.read_or_gap(0, 4)

        gap = outcome.gap
        assert gap is not None
        self.assertEqual("timeout", gap.code)
        self.assertEqual(1, outcome.counters.timeouts)
        self.assertEqual("read_gap", outcome.warnings[0]["code"])

    def test_short_read_is_normalized_as_gap(self) -> None:
        reader = read_errors.ResilientReader(
            FaultReader([b"abc"]), policy=read_errors.ReadPolicy(max_attempts=1)
        )

        outcome = reader.read_or_gap(0, 4)

        gap = outcome.gap
        assert gap is not None
        self.assertEqual("short_read", gap.code)
        self.assertEqual(1, outcome.counters.short_reads)

    def test_recovery_after_retry_returns_data_and_counter(self) -> None:
        reader = read_errors.ResilientReader(
            FaultReader([OSError("EIO"), b"abcd"]),
            policy=read_errors.ReadPolicy(max_attempts=2),
        )

        outcome = reader.read_or_gap(0, 4)

        self.assertIsNone(outcome.gap)
        self.assertEqual(b"abcd", outcome.data)
        self.assertEqual(1, outcome.counters.recovered_after_retry)
        self.assertEqual(0, outcome.counters.skipped_bytes)

    def test_escalating_errors_recommend_pause(self) -> None:
        reader = read_errors.ResilientReader(
            FaultReader([OSError("EIO"), OSError("EIO")]),
            policy=read_errors.ReadPolicy(max_attempts=1, pause_after_errors=2),
        )

        first = reader.read_or_gap(0, 1)
        second = reader.read_or_gap(1, 1)

        self.assertIsNone(first.pause_reason)
        self.assertEqual("read error threshold reached", second.pause_reason)
        self.assertEqual("read_pause_recommended", second.warnings[-1]["code"])

    def test_warning_messages_use_scanner_protocol(self) -> None:
        reader = read_errors.ResilientReader(
            FaultReader([OSError("EIO")]), policy=read_errors.ReadPolicy(max_attempts=1)
        )
        reader.read_or_gap(0, 1)

        decoded = messages.decode_line(
            reader.warning_messages(stage="extract", sequence_start=7)[0]
        )

        self.assertEqual("warning", decoded.message_type)
        self.assertEqual(7, decoded.sequence)
        self.assertEqual("read_gap", decoded.payload["code"])

    def test_temperature_threshold_recommends_pause_without_repair(self) -> None:
        reader = read_errors.ResilientReader(
            FaultReader([b"abcd"]),
            policy=read_errors.ReadPolicy(max_attempts=1, pause_temperature_celsius=50),
            temperature=lambda: 55,
        )

        outcome = reader.read_or_gap(0, 4)

        self.assertEqual("source temperature threshold reached", outcome.pause_reason)


if __name__ == "__main__":
    unittest.main()
