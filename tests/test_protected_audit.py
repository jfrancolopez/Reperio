#!/usr/bin/env python3

from __future__ import annotations

import unittest
from typing import Any

from worker import protected_audit

VAULT_REF = "vault:" + "a" * 32


def target_record(**overrides: Any) -> dict[str, Any]:
    record: dict[str, Any] = {
        "target_id": "target_1",
        "artifact_id": "artifact_1",
        "finding_id": "finding_1",
        "format": "kdbx",
        "kdf": "argon2",
        "protection_kind": "password-vault",
        "secret_set_ref": VAULT_REF,
        "engine_strategy": "stdin",
    }
    record.update(overrides)
    return record


class NormalizeTargetTests(unittest.TestCase):
    def test_normalize_target_is_opt_in_and_separate_from_detection(self) -> None:
        target = protected_audit.normalize_target(target_record())
        self.assertEqual("pending", target.state)
        self.assertEqual("kdbx", target.format)
        self.assertEqual(VAULT_REF, target.secret_set_ref)
        self.assertEqual("password-vault", target.protection_kind)

    def test_unsupported_format_is_rejected(self) -> None:
        with self.assertRaisesRegex(
            protected_audit.ProtectedAuditError, "not an audit target format"
        ):
            protected_audit.normalize_target(target_record(format="elf"))

    def test_unsupported_kdf_is_rejected(self) -> None:
        with self.assertRaisesRegex(protected_audit.ProtectedAuditError, "is not recognized"):
            protected_audit.normalize_target(target_record(kdf="quantum"))

    def test_plaintext_secret_is_rejected(self) -> None:
        with self.assertRaisesRegex(protected_audit.ProtectedAuditError, "opaque vault reference"):
            protected_audit.normalize_target(
                target_record(secret_set_ref="correct horse battery staple")
            )

    def test_result_secret_reference_is_opaque(self) -> None:
        target = protected_audit.normalize_target(target_record(result_secret_ref=VAULT_REF))
        self.assertEqual(VAULT_REF, target.result_secret_ref)
        with self.assertRaisesRegex(protected_audit.ProtectedAuditError, "opaque vault reference"):
            protected_audit.normalize_target(target_record(result_secret_ref="plain"))

    def test_invalid_engine_strategy_is_rejected(self) -> None:
        with self.assertRaisesRegex(protected_audit.ProtectedAuditError, "is not supported"):
            protected_audit.normalize_target(target_record(engine_strategy="argv"))

    def test_cost_estimate_and_tiers_are_deterministic(self) -> None:
        low = protected_audit.estimate_target_cost("zip", "pbkdf2")
        self.assertEqual("low", low.tier)
        high = protected_audit.estimate_target_cost("volume", "argon2")
        self.assertEqual("high", high.tier)
        same = protected_audit.estimate_target_cost("zip", "pbkdf2")
        self.assertEqual(low, same)


class StateTransitionTests(unittest.TestCase):
    def setUp(self) -> None:
        self.target = protected_audit.normalize_target(target_record())

    def test_full_happy_path_transitions(self) -> None:
        queued = protected_audit.transition_audit(self.target, "queued")
        running = protected_audit.transition_audit(queued, "running")
        verifying = protected_audit.transition_audit(running, "verifying")
        completed = protected_audit.transition_audit(verifying, "completed")
        self.assertEqual("completed", completed.state)

    def test_invalid_transition_is_rejected(self) -> None:
        with self.assertRaisesRegex(
            protected_audit.ProtectedAuditError, "invalid audit transition"
        ):
            protected_audit.transition_audit(self.target, "completed")

    def test_terminal_states_are_final(self) -> None:
        done = protected_audit.transition_audit(
            protected_audit.transition_audit(
                protected_audit.transition_audit(
                    protected_audit.transition_audit(self.target, "queued"), "running"
                ),
                "verifying",
            ),
            "completed",
        )
        with self.assertRaisesRegex(
            protected_audit.ProtectedAuditError, "invalid audit transition"
        ):
            protected_audit.transition_audit(done, "queued")

    def test_fail_and_restart_preserves_target_and_budget(self) -> None:
        failed = protected_audit.fail_audit(self.target, "wrong_password")
        self.assertEqual("failed", failed.state)
        self.assertEqual("wrong_password", failed.error_code)
        restarted = protected_audit.restart_audit(failed)
        self.assertEqual("queued", restarted.state)
        self.assertEqual(1, restarted.attempts)
        self.assertIsNone(restarted.error_code)
        self.assertEqual(self.target.artifact_id, restarted.artifact_id)
        self.assertEqual(self.target.budget, restarted.budget)

    def test_restart_blocks_after_attempt_limit(self) -> None:
        limited = protected_audit.normalize_target(
            target_record(budget={"max_attempts": 1, "max_cpu_seconds": 10, "max_memory_bytes": 10})
        )
        failed = protected_audit.fail_audit(limited, "timeout")
        restarted = protected_audit.restart_audit(failed)
        self.assertEqual(1, restarted.attempts)
        failed_again = protected_audit.fail_audit(restarted, "timeout")
        with self.assertRaisesRegex(protected_audit.ProtectedAuditError, "attempt budget"):
            protected_audit.restart_audit(failed_again)

    def test_checkpoint_updates_and_budget_enforcement(self) -> None:
        running = protected_audit.transition_audit(
            protected_audit.transition_audit(self.target, "queued"), "running"
        )
        advanced = protected_audit.update_checkpoint(
            running, "kdf-verify", "cursor-1", {"cpu_seconds": 10, "memory_bytes": 1024}
        )
        self.assertEqual("kdf-verify", advanced.checkpoint.stage)  # type: ignore[union-attr]
        with self.assertRaisesRegex(protected_audit.ProtectedAuditError, "resource budget"):
            protected_audit.update_checkpoint(
                advanced, "kdf-verify", "cursor-2", {"cpu_seconds": 10**9}
            )

    def test_block_on_missing_secret(self) -> None:
        class MissingStore:
            def metadata(self, ref: str) -> None:
                raise KeyError(ref)

        blocked = protected_audit.verify_secret_reference(self.target, MissingStore())
        self.assertEqual("blocked", blocked.state)
        self.assertEqual("secret_set_missing", blocked.error_code)

    def test_secret_present_keeps_target(self) -> None:
        class PresentStore:
            def metadata(self, ref: str) -> dict[str, object]:
                return {"ref": ref}

        same = protected_audit.verify_secret_reference(self.target, PresentStore())
        self.assertEqual(self.target, same)


if __name__ == "__main__":
    unittest.main()
