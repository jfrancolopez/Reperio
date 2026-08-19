#!/usr/bin/env python3

from __future__ import annotations

import unittest
from typing import Any

from shared.secret_store import MASKED_VALUE
from worker.secret_sets import (
    SECRET_SETS_VERSION,
    SecretSetsError,
    audit_event,
    build_verification_plan,
    define_secret_set,
    fd_payload,
    lookup_secret_set,
    redact_values,
    redacted_snapshot,
    try_secret_sets,
    verify_password,
)


def matched_runner(plan: Any) -> dict[str, Any]:
    return {"success": True}


def rejected_runner(plan: Any) -> dict[str, Any]:
    return {"success": False}


def crashed_runner(plan: Any) -> dict[str, Any]:
    raise ChildProcessError("segfault")


class DefineSetTests(unittest.TestCase):
    def test_named_set(self) -> None:
        secret_set = define_secret_set("backup", ["p@ss1", "p@ss2"])
        self.assertEqual(("p@ss1", "p@ss2"), secret_set.values)

    def test_unicode_values(self) -> None:
        secret_set = define_secret_set("unicode", ["contraseña🔑"])
        self.assertEqual("contraseña🔑", secret_set.values[0])

    def test_unsafe_name_rejected(self) -> None:
        with self.assertRaisesRegex(SecretSetsError, "not safe"):
            define_secret_set("Bad Name!", ["x"])

    def test_empty_set_rejected(self) -> None:
        with self.assertRaisesRegex(SecretSetsError, "at least one value"):
            define_secret_set("empty", [])

    def test_blank_values_dropped(self) -> None:
        secret_set = define_secret_set("blanks", ["", "real"])
        self.assertEqual(("real",), secret_set.values)

    def test_lookup(self) -> None:
        secret_set = define_secret_set("backup", ["x"])
        self.assertEqual("backup", lookup_secret_set({"backup": secret_set}, "backup").name)
        with self.assertRaisesRegex(SecretSetsError, "not defined"):
            lookup_secret_set({}, "missing")


class FdPlanTests(unittest.TestCase):
    def test_payload_length_prefixed(self) -> None:
        payload = fd_payload(["ab", "cd"])
        self.assertEqual(8 + 4, len(payload))

    def test_values_never_in_argv(self) -> None:
        plan = build_verification_plan(
            secret_set=define_secret_set("backup", ["secret-value"]),
            format="zip",
            target_path="backup.zip",
        )
        joined = " ".join(plan["arg_template"])
        self.assertNotIn("secret-value", joined)
        self.assertNotIn("--password=", joined)
        self.assertIn("--password-fd=3", joined)
        self.assertIn(b"secret-value", plan["fd_payload"])
        self.assertTrue(plan["values_never_in_argv"])

    def test_unsupported_format_rejected(self) -> None:
        with self.assertRaisesRegex(SecretSetsError, "not supported"):
            build_verification_plan(
                secret_set=define_secret_set("backup", ["x"]),
                format="unusual",
                target_path="f",
            )


class VerifyTests(unittest.TestCase):
    def test_correct_password(self) -> None:
        plan = build_verification_plan(
            secret_set=define_secret_set("backup", ["right"]), format="zip", target_path="z"
        )
        self.assertEqual("matched", verify_password(plan, matched_runner)["status"])

    def test_wrong_password(self) -> None:
        plan = build_verification_plan(
            secret_set=define_secret_set("backup", ["wrong"]), format="zip", target_path="z"
        )
        self.assertEqual("rejected", verify_password(plan, rejected_runner)["status"])

    def test_process_crash(self) -> None:
        plan = build_verification_plan(
            secret_set=define_secret_set("backup", ["x"]), format="zip", target_path="z"
        )
        outcome = verify_password(plan, crashed_runner)
        self.assertEqual("crashed", outcome["status"])
        self.assertTrue(outcome["redacted"])


class TrySetsTests(unittest.TestCase):
    def test_multiple_sets_first_match_wins(self) -> None:
        result = try_secret_sets(
            [define_secret_set("a", ["x"]), define_secret_set("b", ["y"])],
            format="zip",
            target_path="z",
            runner=matched_runner,
            scratch_destination="scratch://out",
        )
        self.assertEqual("a", result["matched_set"])
        self.assertEqual("scratch://out", result["destination"])

    def test_no_match(self) -> None:
        result = try_secret_sets(
            [define_secret_set("a", ["x"])],
            format="zip",
            target_path="z",
            runner=rejected_runner,
            scratch_destination="scratch://out",
        )
        self.assertEqual("no_match", result["status"])

    def test_crash_stops_with_outcome(self) -> None:
        result = try_secret_sets(
            [define_secret_set("a", ["x"])],
            format="zip",
            target_path="z",
            runner=crashed_runner,
            scratch_destination="scratch://out",
        )
        self.assertEqual("crashed", result["status"])

    def test_non_scratch_destination_rejected(self) -> None:
        with self.assertRaisesRegex(SecretSetsError, "scratch"):
            try_secret_sets(
                [define_secret_set("a", ["x"])],
                format="zip",
                target_path="z",
                runner=matched_runner,
                scratch_destination="/etc/output",
            )


class RedactionTests(unittest.TestCase):
    def test_attempted_values_redacted(self) -> None:
        text = redact_values(["supersecret", "another"], "tried supersecret and another")
        self.assertNotIn("supersecret", text)
        self.assertNotIn("another", text)
        self.assertEqual(2, text.count(MASKED_VALUE))

    def test_snapshot_has_no_values(self) -> None:
        snapshot = redacted_snapshot([define_secret_set("a", ["hidden-value"])])
        self.assertNotIn("hidden-value", str(snapshot))
        self.assertEqual("1", snapshot[0]["value_count"])

    def test_audit_event_masks_values(self) -> None:
        event = audit_event("backup", "matched")
        self.assertEqual(MASKED_VALUE, event["values"])

    def test_version_constant(self) -> None:
        self.assertEqual("secret-sets-v1", SECRET_SETS_VERSION)


if __name__ == "__main__":
    unittest.main()
