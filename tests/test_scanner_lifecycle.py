from __future__ import annotations

import unittest

from scanner import lifecycle, messages, scheduler
from shared import checkpoints


class FakeProcess:
    def __init__(self, waits: list[bool]) -> None:
        self.waits = waits
        self.signals: list[str] = []

    def send_signal(self, signal_name: str) -> None:
        self.signals.append(signal_name)

    def wait(self, timeout_seconds: int) -> bool:
        return self.waits.pop(0) if self.waits else True


class ScannerLifecycleTests(unittest.TestCase):
    def test_pause_during_enumeration_returns_checkpoint_and_ack(self) -> None:
        decision = lifecycle.cooperative_pause(
            stage=scheduler.STAGE_ENUMERATION,
            cursor={"volume_id": "vol1", "object_id": "42"},
            counters={"entries": 10},
            pause=lifecycle.PauseRequest(True, "operator requested pause"),
        )

        decoded = messages.decode_line(decision.ack_message(stage=scheduler.STAGE_ENUMERATION))

        self.assertTrue(decision.should_pause)
        checkpoint_payload = decision.checkpoint_payload
        assert checkpoint_payload is not None
        self.assertEqual("operator requested pause", checkpoint_payload["reason"])
        self.assertEqual("pause_ack", decoded.message_type)

    def test_pause_during_extraction_preserves_extent_cursor(self) -> None:
        decision = lifecycle.cooperative_pause(
            stage=scheduler.STAGE_ARTIFACTS,
            cursor={"entry_id": "entry1", "extent_index": 3},
            counters={"bytes": 4096},
            pause=lifecycle.PauseRequest(True, "read error threshold reached"),
        )

        checkpoint_payload = decision.checkpoint_payload
        assert checkpoint_payload is not None
        self.assertEqual({"entry_id": "entry1", "extent_index": 3}, checkpoint_payload["cursor"])
        self.assertEqual({"bytes": 4096}, checkpoint_payload["counters"])

    def test_force_kill_occurs_only_after_timeout_and_preserves_checkpoint(self) -> None:
        process = FakeProcess([False, True])

        result = lifecycle.safe_stop_process(
            process, policy=lifecycle.StopPolicy(timeout_seconds=5)
        )

        self.assertEqual(["TERM", "KILL"], process.signals)
        self.assertEqual("force_stopped", result.status)
        self.assertTrue(result.checkpoint_preserved)

    def test_graceful_stop_does_not_force_kill(self) -> None:
        process = FakeProcess([True])

        result = lifecycle.safe_stop_process(process)

        self.assertEqual(["TERM"], process.signals)
        self.assertEqual("stopped", result.status)
        self.assertIsNone(result.force_signal_sent)

    def test_host_restart_resumes_from_valid_checkpoint(self) -> None:
        record = checkpoint_record(stage=scheduler.STAGE_ENUMERATION, cursor={"object_id": "42"})

        decision = lifecycle.restart_from_checkpoint(
            load_checkpoint=lambda: record,
            completed_stages={scheduler.STAGE_VALIDATION, scheduler.STAGE_VOLUMES},
            expected_source_fingerprint="a" * 64,
            current_source_fingerprint="a" * 64,
        )

        self.assertEqual("resume", decision.status)
        self.assertEqual({"object_id": "42"}, decision.cursor)
        self.assertIn(scheduler.STAGE_ARTIFACTS, decision.runnable)

    def test_corrupt_checkpoint_restarts_stage_not_completed_batches(self) -> None:
        def load_corrupt() -> checkpoints.CheckpointRecord:
            raise checkpoints.CheckpointError("checkpoint integrity hash mismatch; restart stage")

        decision = lifecycle.restart_from_checkpoint(
            load_checkpoint=load_corrupt,
            completed_stages={scheduler.STAGE_VALIDATION, scheduler.STAGE_VOLUMES},
            expected_source_fingerprint="a" * 64,
            current_source_fingerprint="a" * 64,
        )

        self.assertEqual("restart_stage", decision.status)
        self.assertEqual((scheduler.STAGE_ENUMERATION,), decision.runnable)

    def test_source_reconnect_mismatch_blocks_restart(self) -> None:
        decision = lifecycle.restart_from_checkpoint(
            load_checkpoint=lambda: checkpoint_record(stage=scheduler.STAGE_ENUMERATION),
            completed_stages={scheduler.STAGE_VALIDATION},
            expected_source_fingerprint="a" * 64,
            current_source_fingerprint="b" * 64,
        )

        self.assertEqual("blocked", decision.status)
        self.assertEqual((), decision.runnable)


def checkpoint_record(
    *, stage: str, cursor: dict[str, object] | None = None
) -> checkpoints.CheckpointRecord:
    return checkpoints.CheckpointRecord(
        checkpoint_id="checkpoint1",
        job_id="job1",
        source_fingerprint="a" * 64,
        stage=stage,
        checkpoint_version=1,
        tool_name="scanner",
        tool_version="1",
        cursor=cursor or {},
        counters={},
        blob=b"",
        integrity_sha256="0" * 64,
        supersedes_checkpoint_id=None,
    )


if __name__ == "__main__":
    unittest.main()
