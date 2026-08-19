"""Browser CSV/JSON/HTML export (RPR-068).

Exports browser artifacts for the complete set or the current filter, with a
field dictionary, timezone/provenance notes, counts, and escaping. Spreadsheet
formula injection and HTML/script injection are neutralized, and reusable auth
token fields are redacted by default. The HTML export is standalone and passive:
no scripts, no event handlers, all values HTML-escaped. Deterministic and
dependency-free; the CSV writer streams row-by-row for large exports.
"""

from __future__ import annotations

import csv
import html
import io
import json
from collections.abc import Iterable, Mapping, Sequence
from typing import Any

from shared.browser_artifact_schemas import SESSION_TOKEN_FIELD_NAMES
from worker.export_manifest import formula_safe

BROWSER_EXPORT_VERSION = "browser-export-v1"

BROWSER_EXPORT_FIELDS: tuple[tuple[str, str], ...] = (
    ("entry_id", "Entry ID"),
    ("artifact_kind", "Artifact kind"),
    ("browser_family", "Browser family"),
    ("user", "User"),
    ("display_url", "URL"),
    ("title", "Title"),
    ("visited_at", "Visited at"),
    ("timezone_notes", "Timezone notes"),
    ("provenance", "Provenance"),
    ("recovery_confidence", "Recovery confidence"),
    ("domain", "Domain"),
)

CSV_FORMULA_LEADERS = ("=", "+", "-", "@", "\t", "\r")


class BrowserExportError(ValueError):
    """Raised when a browser export input is invalid."""


def field_dictionary() -> list[dict[str, str]]:
    """Ordered field dictionary with labels and value types."""
    return [{"key": key, "label": label, "type": "string"} for key, label in BROWSER_EXPORT_FIELDS]


def redact_session_tokens(record: Mapping[str, Any]) -> dict[str, Any]:
    """Drop reusable auth token fields from the exported record by default."""
    return {
        key: value
        for key, value in dict(record).items()
        if not any(token_field in str(key).lower() for token_field in SESSION_TOKEN_FIELD_NAMES)
    }


def export_row(
    record: Mapping[str, Any],
    *,
    include_tokens: bool = False,
    timezone_notes: str | None = None,
) -> dict[str, Any]:
    """Deterministic export row; tokens redacted unless explicitly included."""
    base = dict(record) if include_tokens else redact_session_tokens(record)
    row: dict[str, Any] = {}
    for key, _label in BROWSER_EXPORT_FIELDS:
        row[key] = base.get(key, "")
    if include_tokens:
        for key, value in base.items():
            if key not in row and any(
                token_field in str(key).lower() for token_field in SESSION_TOKEN_FIELD_NAMES
            ):
                row[key] = value
    if timezone_notes:
        row["timezone_notes"] = timezone_notes
    return row


def build_browser_csv(
    records: Sequence[Mapping[str, Any]],
    *,
    include_tokens: bool = False,
    timezone_notes: str | None = None,
) -> str:
    """Deterministic CSV with formula-safe cells and a header row."""
    output = io.StringIO()
    writer = csv.writer(output, lineterminator="\n")
    writer.writerow([key for key, _label in BROWSER_EXPORT_FIELDS])
    for record in records:
        row = export_row(record, include_tokens=include_tokens, timezone_notes=timezone_notes)
        writer.writerow([formula_safe(row.get(key)) for key, _label in BROWSER_EXPORT_FIELDS])
    return output.getvalue()


def stream_browser_csv(
    records: Iterable[Mapping[str, Any]],
    *,
    include_tokens: bool = False,
    timezone_notes: str | None = None,
) -> Iterable[str]:
    """Streaming CSV that never materializes all rows (million-row safe)."""
    yield ",".join(formula_safe(key) for key, _label in BROWSER_EXPORT_FIELDS) + "\n"
    for record in records:
        row = export_row(record, include_tokens=include_tokens, timezone_notes=timezone_notes)
        yield (
            ",".join(formula_safe(str(row.get(key))) for key, _label in BROWSER_EXPORT_FIELDS)
            + "\n"
        )


def build_browser_json(
    records: Sequence[Mapping[str, Any]],
    *,
    include_tokens: bool = False,
    timezone_notes: str | None = None,
    export_id: str,
    filter_label: str = "all",
    created_at: str,
) -> str:
    """Deterministic JSON schema with field dictionary and notes."""
    payload = {
        "export_version": BROWSER_EXPORT_VERSION,
        "export_id": export_id,
        "filter": filter_label,
        "fields": field_dictionary(),
        "timezone_notes": timezone_notes,
        "provenance_notes": "Raw and derived browser provenance is preserved from recovery metadata.",
        "token_fields_included": include_tokens,
        "count": len(records),
        "records": [
            export_row(record, include_tokens=include_tokens, timezone_notes=timezone_notes)
            for record in records
        ],
    }
    return json.dumps(payload, sort_keys=False, ensure_ascii=True, separators=(",", ":"))


def build_browser_html(
    records: Sequence[Mapping[str, Any]],
    *,
    include_tokens: bool = False,
    timezone_notes: str | None = None,
    export_id: str,
    title: str = "Browser export",
) -> str:
    """Standalone passive HTML export: no scripts, no event handlers, escaped."""
    header = "".join(f"<th>{_escape(label)}</th>" for _key, label in BROWSER_EXPORT_FIELDS)
    rows_html: list[str] = []
    for record in records:
        row = export_row(record, include_tokens=include_tokens, timezone_notes=timezone_notes)
        cells = "".join(
            f"<td>{_escape(str(row.get(key)))}</td>" for key, _label in BROWSER_EXPORT_FIELDS
        )
        rows_html.append(f"<tr>{cells}</tr>")
    body = "\n".join(
        [
            "<!DOCTYPE html>",
            '<html lang="en">',
            "<head>",
            '<meta charset="utf-8">',
            f"<title>{_escape(title)}</title>",
            "</head>",
            "<body>",
            f"<h1>{_escape(title)}</h1>",
            f"<p>Export id: {_escape(export_id)}</p>",
            "<table>",
            f"<thead><tr>{header}</tr></thead>",
            f"<tbody>{''.join(rows_html)}</tbody>",
            "</table>",
            "</body>",
            "</html>",
        ]
    )
    lower = body.lower()
    if "<script" in lower or 'onload="' in lower or 'onclick="' in lower:
        raise BrowserExportError("unsafe_html", "export HTML must remain passive")
    return body


def _escape(value: str) -> str:
    return html.escape(value, quote=True)
