#!/usr/bin/env python3

from __future__ import annotations

import sqlite3
import tempfile
import unittest
from contextlib import closing
from pathlib import Path
from typing import Any

from migrations import runner
from shared import catalog_schema, event_outbox, job_state, notification_rules

NOW = "2026-08-19T10:00:00Z"
QUIET_NOW = "2026-08-19T02:00:00Z"


def default_rules(
    overrides: dict[str, dict[str, Any]] | None = None,
) -> notification_rules.NotificationRules:
    rules = notification_rules.default_notification_rules("reperio://host")
    if not overrides:
        return rules
    adjusted = []
    for rule in rules.rules:
        fields: dict[str, Any] = dict(
            event_type=rule.event_type,
            enabled=rule.enabled,
            threshold=rule.threshold,
            threshold_once=rule.threshold_once,
            throttle_seconds=rule.throttle_seconds,
            quiet_start=rule.quiet_start,
            quiet_end=rule.quiet_end,
            severity=rule.severity,
            template=rule.template,
        )
        if rule.event_type in overrides:
            fields.update(overrides[rule.event_type])
        adjusted.append(notification_rules.NotificationRule(**fields))
    return notification_rules.NotificationRules(
        version=rules.version, rules=tuple(adjusted), local_ui_base=rules.local_ui_base
    )


def count_event(count: int, event_type: str = "job.count") -> dict[str, Any]:
    return {
        "event_type": event_type,
        "event_id": "event_1",
        "case_id": "case_1",
        "payload": {"job_id": "job_1", "count": count, "case_id": "case_1"},
    }


class RuleMatchingTests(unittest.TestCase):
    def test_rule_matching_selects_supported_event_types(self) -> None:
        rules = default_rules()
        for event_type in sorted(notification_rules.NOTIFICATION_EVENT_TYPES):
            rule = rules.rule_for(event_type)
            self.assertIsNotNone(rule, event_type)
        self.assertIsNone(rules.rule_for("job.unknown"))

    def test_disabled_rule_never_notifies(self) -> None:
        rules = default_rules({"job.failure": {"enabled": False}})
        decision = notification_rules.evaluate_notification(
            rules, event_type="job.failure", now=NOW, last_sent_at=None
        )
        self.assertFalse(decision.send)
        self.assertEqual("disabled", decision.reason)

    def test_threshold_gates_count_events(self) -> None:
        rules = default_rules()
        below = notification_rules.evaluate_notification(
            rules, event_type="job.count", now=NOW, last_sent_at=None, count=0
        )
        self.assertFalse(below.send)
        self.assertEqual("below_threshold", below.reason)
        crossed = notification_rules.evaluate_notification(
            rules, event_type="job.count", now=NOW, last_sent_at=None, count=5
        )
        self.assertTrue(crossed.send)
        self.assertEqual("matched", crossed.reason)
        self.assertTrue(crossed.crossed_once)

    def test_threshold_once_notifies_once(self) -> None:
        rules = default_rules()
        first = notification_rules.evaluate_notification(
            rules, event_type="job.count", now=NOW, last_sent_at=None, count=3
        )
        second = notification_rules.evaluate_notification(
            rules,
            event_type="job.count",
            now=NOW,
            last_sent_at="2026-08-19T10:01:00Z",
            count=10,
            crossed_once=True,
        )
        self.assertTrue(first.send)
        self.assertFalse(second.send)
        self.assertEqual("already_crossed_once", second.reason)

    def test_throttle_suppresses_duplicate_sends(self) -> None:
        rules = default_rules({"job.heartbeat": {"throttle_seconds": 300}})
        first = notification_rules.evaluate_notification(
            rules, event_type="job.heartbeat", now="2026-08-19T10:00:00Z", last_sent_at=None
        )
        throttled = notification_rules.evaluate_notification(
            rules,
            event_type="job.heartbeat",
            now="2026-08-19T10:04:00Z",
            last_sent_at="2026-08-19T10:00:00Z",
        )
        allowed = notification_rules.evaluate_notification(
            rules,
            event_type="job.heartbeat",
            now="2026-08-19T10:05:00Z",
            last_sent_at="2026-08-19T10:00:00Z",
        )
        self.assertTrue(first.send)
        self.assertFalse(throttled.send)
        self.assertEqual("throttled", throttled.reason)
        self.assertTrue(allowed.send)

    def test_quiet_hours_suppress_notifications(self) -> None:
        rules = default_rules({"job.completion": {"quiet_start": "23:00", "quiet_end": "07:00"}})
        decision = notification_rules.evaluate_notification(
            rules, event_type="job.completion", now=QUIET_NOW, last_sent_at=None
        )
        self.assertFalse(decision.send)
        self.assertEqual("quiet_hours", decision.reason)
        allowed = notification_rules.evaluate_notification(
            rules, event_type="job.completion", now="2026-08-19T12:00:00Z", last_sent_at=None
        )
        self.assertTrue(allowed.send)

    def test_quiet_hours_overnight_window(self) -> None:
        rules = default_rules({"job.completion": {"quiet_start": "22:00", "quiet_end": "06:00"}})
        quiet = notification_rules.evaluate_notification(
            rules, event_type="job.completion", now="2026-08-19T23:30:00Z", last_sent_at=None
        )
        self.assertFalse(quiet.send)
        outside = notification_rules.evaluate_notification(
            rules, event_type="job.completion", now="2026-08-19T12:00:00Z", last_sent_at=None
        )
        self.assertTrue(outside.send)

    def test_invalid_quiet_hours_are_rejected(self) -> None:
        with self.assertRaisesRegex(notification_rules.NotificationRulesError, "invalid"):
            notification_rules._parse_hhmm("25:00")


class RedactionTests(unittest.TestCase):
    def test_redaction_never_leaks_sensitive_keys(self) -> None:
        rules = default_rules()
        event = {
            "event_type": "job.count",
            "event_id": "event_1",
            "case_id": "case_1",
            "payload": {
                "job_id": "job_1",
                "count": 3,
                "case_id": "case_1",
                "display_path": "/Volumes/card/secret.docx",
                "url": "https://example.invalid/x",
                "password": "hunter2",
                "recovery_phrase": "word word word word word word word word word word word word",
            },
        }
        summary = notification_rules.build_summary(
            event,
            rules,
            decision=notification_rules.evaluate_notification(
                rules, event_type="job.count", now=NOW, last_sent_at=None, count=3
            ),
        )
        assert summary is not None
        self.assertNotIn("/Volumes/card", summary.body)
        self.assertNotIn("example.invalid", summary.body)
        self.assertNotIn("hunter2", summary.body)
        self.assertNotIn("word word word", summary.body)

    def test_high_value_sensitive_alerts_are_counts_only(self) -> None:
        rules = default_rules()
        event = {
            "event_type": "job.high-value-sensitive-count",
            "event_id": "event_2",
            "case_id": "case_1",
            "payload": {
                "job_id": "job_1",
                "high_value_count": 2,
                "sensitive_count": 4,
                "case_id": "case_1",
                "display_path": "/Volumes/card/wallet.json",
            },
        }
        decision = notification_rules.evaluate_notification(
            rules,
            event_type="job.high-value-sensitive-count",
            now=NOW,
            last_sent_at=None,
            count=4,
        )
        summary = notification_rules.build_summary(event, rules, decision=decision)
        assert summary is not None
        self.assertTrue(summary.counts_only)
        self.assertIn("job_1", summary.body)
        self.assertNotIn("wallet.json", summary.body)
        self.assertIn("/#/case/case_1", summary.local_ui_link)

    def test_redact_text_removes_forbidden_patterns(self) -> None:
        redacted, names = notification_rules.redact_text(
            "wallet_id=abc123def456 and password=topsecret99"
        )
        self.assertNotIn("abc123def456", redacted)
        self.assertNotIn("topsecret99", redacted)
        self.assertTrue(names)

    def test_summary_has_no_raw_sensitive_field_duplication(self) -> None:
        rules = default_rules()
        event = count_event(1)
        event["payload"]["case_id"] = "case_1"
        summary = notification_rules.build_summary(
            event,
            rules,
            decision=notification_rules.evaluate_notification(
                rules, event_type="job.count", now=NOW, last_sent_at=None, count=1
            ),
        )
        assert summary is not None
        self.assertEqual("Scan found 1 findings so far", summary.body)


class ValidationTests(unittest.TestCase):
    def test_default_rules_validate_clean(self) -> None:
        self.assertEqual((), notification_rules.validate_notification_rules(default_rules()))

    def test_validation_flags_unsafe_template_token(self) -> None:
        rules = default_rules({"job.start": {"template": "started {display_path}"}})
        warnings = notification_rules.validate_notification_rules(rules)
        self.assertTrue(any("unsafe_template_token" in warning for warning in warnings))

    def test_validation_flags_incomplete_quiet_hours(self) -> None:
        rules = default_rules({"job.start": {"quiet_start": "23:00", "quiet_end": None}})
        warnings = notification_rules.validate_notification_rules(rules)
        self.assertTrue(any("incomplete_quiet_hours" in warning for warning in warnings))


class DeliveryFailureOutboxTests(unittest.TestCase):
    def _connection(self) -> sqlite3.Connection:
        scratch = Path(tempfile.mkdtemp(prefix="rpr111-"))
        db_path = scratch / "catalog.sqlite3"
        runner.migrate_catalog(db_path)
        return catalog_schema.connect_catalog(db_path)

    def test_delivery_failure_does_not_affect_job_state(self) -> None:
        with closing(self._connection()) as connection:
            self._insert_source_case_and_job(connection)
            event = event_outbox.transition_job_and_append_event(
                connection,
                job_id="job_1",
                to_state="running",
                event_id="event_1",
                event_type="job.start",
                now=NOW,
            )

            def failing_delivery(summary: object) -> None:
                raise RuntimeError("notification provider unreachable")

            with self.assertRaisesRegex(RuntimeError, "unreachable"):
                failing_delivery(event)
            self.assertEqual("running", job_state.get_job(connection, "job_1")["state"])
            self.assertIsNone(event_outbox.get_event(connection, "event_1")["published_at"])

            event_outbox.mark_published(connection, event_ids=["event_1"], published_at=NOW)
            self.assertIsNotNone(event_outbox.get_event(connection, "event_1")["published_at"])
            self.assertEqual("running", job_state.get_job(connection, "job_1")["state"])

    def _insert_source_case_and_job(self, connection: sqlite3.Connection) -> None:
        connection.execute(
            """
            INSERT INTO sources
            (source_id, stable_identity, media_kind, size_bytes, sector_size,
             fingerprint_sha256, status, created_at, updated_at)
            VALUES ('source_1', 'stable-source-1', 'block', 1024, 512, ?, 'candidate', ?, ?)
            """,
            ("b" * 64, NOW, NOW),
        )
        connection.execute(
            """
            INSERT INTO scan_cases
            (case_id, source_id, state, policy_json, created_at, updated_at)
            VALUES ('case_1', 'source_1', 'created', '{}', ?, ?)
            """,
            (NOW, NOW),
        )
        job_state.create_job(
            connection,
            job_id="job_1",
            job_type="scan",
            input_payload={"stage": "scan"},
            idempotency_key="key_1",
            now=NOW,
            case_id="case_1",
        )
        job_state.transition_job(connection, job_id="job_1", to_state="leased", now=NOW)
        connection.commit()


if __name__ == "__main__":
    unittest.main()
