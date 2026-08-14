"""Deterministic browser parser cross-validation helpers."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Any

SUPPORTED_BROWSER_PARSER_MATRIX: tuple[dict[str, str], ...] = (
    {
        "browser_family": "chromium",
        "parser": "chromium-artifacts-v1",
        "validated_reference": "synthetic-golden-browser-fixtures-v1",
        "supported_artifacts": "bookmark,cache_entry,download,extension,search,session_tab,visit",
    },
    {
        "browser_family": "firefox",
        "parser": "firefox-artifacts-v1",
        "validated_reference": "synthetic-golden-browser-fixtures-v1",
        "supported_artifacts": "bookmark,cache_entry,download,extension,search,session_tab,visit",
    },
    {
        "browser_family": "legacy_ie_edge",
        "parser": "legacy-webcache-adapter-v1",
        "validated_reference": "synthetic-golden-browser-fixtures-v1",
        "supported_artifacts": "bookmark,cache_entry,download,visit",
    },
)


@dataclass(frozen=True)
class BrowserGoldenRecord:
    artifact_kind: str
    source_artifact: str
    row_reference: str
    fields: Mapping[str, Any]


@dataclass(frozen=True)
class BrowserParserValidationResult:
    browser_family: str
    parser: str
    reference: str
    status: str
    matched_count: int
    missing: tuple[str, ...]
    unexpected: tuple[str, ...]
    mismatches: tuple[str, ...]

    def as_report(self) -> dict[str, Any]:
        return {
            "browser_family": self.browser_family,
            "parser": self.parser,
            "reference": self.reference,
            "status": self.status,
            "matched_count": self.matched_count,
            "missing": list(self.missing),
            "unexpected": list(self.unexpected),
            "mismatches": list(self.mismatches),
            "supported_versions": list(SUPPORTED_BROWSER_PARSER_MATRIX),
        }


def validate_browser_parser_output(
    *,
    browser_family: str,
    parser: str,
    records: Sequence[Mapping[str, Any]],
    expected: Sequence[BrowserGoldenRecord],
    reference: str = "synthetic-golden-browser-fixtures-v1",
) -> BrowserParserValidationResult:
    """Compare parser output with approved golden records and keep all mismatches visible."""

    _require_supported(browser_family, parser, reference)
    actual_by_key = {_record_key(record): record for record in records}
    expected_by_key = {_golden_key(record): record for record in expected}
    actual_keys = set(actual_by_key)
    expected_keys = set(expected_by_key)
    missing = tuple(sorted(expected_keys - actual_keys))
    unexpected = tuple(sorted(actual_keys - expected_keys))
    mismatches: list[str] = []
    matched = 0
    for key in sorted(actual_keys & expected_keys):
        expected_record = expected_by_key[key]
        actual_record = actual_by_key[key]
        record_mismatches = _field_mismatches(key, actual_record, expected_record.fields)
        if record_mismatches:
            mismatches.extend(record_mismatches)
        else:
            matched += 1
    status = "pass" if not missing and not unexpected and not mismatches else "fail"
    return BrowserParserValidationResult(
        browser_family=browser_family,
        parser=parser,
        reference=reference,
        status=status,
        matched_count=matched,
        missing=missing,
        unexpected=unexpected,
        mismatches=tuple(mismatches),
    )


def _require_supported(browser_family: str, parser: str, reference: str) -> None:
    for item in SUPPORTED_BROWSER_PARSER_MATRIX:
        if (
            item["browser_family"] == browser_family
            and item["parser"] == parser
            and item["validated_reference"] == reference
        ):
            return
    raise ValueError("browser parser/reference combination is not in the supported matrix")


def _field_mismatches(
    key: str, actual: Mapping[str, Any], expected_fields: Mapping[str, Any]
) -> tuple[str, ...]:
    mismatches: list[str] = []
    for field, expected in sorted(expected_fields.items()):
        actual_value = _nested_value(actual, field)
        if actual_value != expected:
            mismatches.append(f"{key}:{field}:expected={expected!r}:actual={actual_value!r}")
    return tuple(mismatches)


def _record_key(record: Mapping[str, Any]) -> str:
    provenance = record.get("raw_provenance")
    if not isinstance(provenance, Mapping):
        return f"{record.get('artifact_kind', 'unknown')}:missing-provenance"
    return ":".join(
        (
            str(record.get("artifact_kind", "unknown")),
            str(provenance.get("source_artifact", "unknown")),
            str(provenance.get("row_reference", "unknown")),
        )
    )


def _golden_key(record: BrowserGoldenRecord) -> str:
    return ":".join((record.artifact_kind, record.source_artifact, record.row_reference))


def _nested_value(record: Mapping[str, Any], dotted_field: str) -> Any:
    value: Any = record
    for part in dotted_field.split("."):
        if not isinstance(value, Mapping):
            return None
        value = value.get(part)
    return value
