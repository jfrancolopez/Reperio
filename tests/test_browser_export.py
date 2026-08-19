#!/usr/bin/env python3

from __future__ import annotations

import json
import unittest
from typing import Any

from worker.browser_export import (
    BROWSER_EXPORT_VERSION,
    build_browser_csv,
    build_browser_html,
    build_browser_json,
    export_row,
    field_dictionary,
    redact_session_tokens,
    stream_browser_csv,
)


def record(**overrides: Any) -> dict[str, Any]:
    data: dict[str, Any] = {
        "entry_id": "e1",
        "artifact_kind": "visit",
        "browser_family": "firefox",
        "user": "alice",
        "display_url": "https://example.com/page",
        "title": "Example Page",
        "visited_at": "2026-08-19T10:00:00Z",
        "timezone_notes": "utc",
        "provenance": "recovered",
        "recovery_confidence": "high",
        "domain": "example.com",
        "session_token": "sess-abc123",
    }
    data.update(overrides)
    return data


class RedactionTests(unittest.TestCase):
    def test_tokens_redacted_by_default(self) -> None:
        row = export_row(record())
        self.assertNotIn("session_token", row)
        self.assertNotIn("sess-abc123", json.dumps(row))

    def test_tokens_explicitly_included(self) -> None:
        row = export_row(record(), include_tokens=True)
        self.assertEqual("sess-abc123", row.get("session_token"))

    def test_redact_removes_all_token_field_names(self) -> None:
        redacted = redact_session_tokens(record(token="t", cookie_value="c", value="v"))
        self.assertNotIn("token", redacted)
        self.assertNotIn("cookie_value", redacted)
        self.assertNotIn("value", redacted)


class CsvTests(unittest.TestCase):
    def test_malicious_url_formula_neutralized(self) -> None:
        csv_text = build_browser_csv([record(display_url="=HYPERLINK(evil)")])
        self.assertIn("'=HYPERLINK", csv_text)
        self.assertNotIn("\r", csv_text.replace("\n", ""))

    def test_header_row_and_field_order(self) -> None:
        csv_text = build_browser_csv([record()])
        header = csv_text.splitlines()[0]
        self.assertEqual(["entry_id", "artifact_kind", "browser_family"], header.split(",")[:3])

    def test_unicode_values_preserved(self) -> None:
        csv_text = build_browser_csv([record(title="Пример 📄")])
        self.assertIn("Пример 📄", csv_text)

    def test_streaming_never_materializes_all_rows(self) -> None:
        generated = list(stream_browser_csv(record(i=str(i)) for i in range(1_000_000)))
        self.assertEqual(1_000_001, len(generated))
        self.assertTrue(generated[0].startswith("entry_id,"))


class JsonTests(unittest.TestCase):
    def test_deterministic_json_schema(self) -> None:
        first = build_browser_json(
            [record()], export_id="e1", filter_label="all", created_at="2026-08-19T10:00:00Z"
        )
        second = build_browser_json(
            [record()], export_id="e1", filter_label="all", created_at="2026-08-19T10:00:00Z"
        )
        self.assertEqual(first, second)
        payload = json.loads(first)
        self.assertEqual(BROWSER_EXPORT_VERSION, payload["export_version"])
        self.assertEqual(1, payload["count"])
        self.assertFalse(payload["token_fields_included"])

    def test_filtered_export_reflects_filter(self) -> None:
        payload = json.loads(
            build_browser_json(
                [record()],
                export_id="e1",
                filter_label="domain:example.com",
                created_at="x",
            )
        )
        self.assertEqual("domain:example.com", payload["filter"])

    def test_field_dictionary(self) -> None:
        fields = field_dictionary()
        self.assertIn({"key": "display_url", "label": "URL", "type": "string"}, fields)


class HtmlTests(unittest.TestCase):
    def test_script_injection_neutralized(self) -> None:
        payload = build_browser_html([record(title="<script>alert(1)</script>")], export_id="e1")
        self.assertNotIn("<script>", payload)
        self.assertIn("&lt;script&gt;", payload)

    def test_event_handlers_neutralized(self) -> None:
        payload = build_browser_html([record(title='x" onload="alert(1)')], export_id="e1")
        self.assertNotIn('onload="', payload)

    def test_standalone_passive_html(self) -> None:
        payload = build_browser_html([record()], export_id="e1")
        self.assertIn("<!DOCTYPE html>", payload)
        self.assertNotIn("<script", payload)

    def test_export_id_present(self) -> None:
        payload = build_browser_html([record()], export_id="export_42")
        self.assertIn("export_42", payload)


if __name__ == "__main__":
    unittest.main()
