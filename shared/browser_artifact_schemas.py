"""Versioned browser artifact schemas and lightweight validation."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

SCHEMA_VERSION = 1
ARTIFACT_KINDS = frozenset(
    {
        "profile",
        "visit",
        "download",
        "bookmark",
        "search",
        "session_tab",
        "cookie_metadata",
        "cache_entry",
        "extension",
    }
)
SESSION_TOKEN_FIELD_NAMES = frozenset(
    {"token", "session_token", "auth_token", "cookie_value", "value", "secret"}
)


@dataclass(frozen=True)
class BrowserSchemaValidationResult:
    valid: bool
    warnings: tuple[str, ...] = ()


def schema_for(kind: str) -> dict[str, Any]:
    if kind not in ARTIFACT_KINDS:
        raise ValueError("unknown browser artifact kind")
    return {
        "schema_version": SCHEMA_VERSION,
        "artifact_kind": kind,
        "required": tuple(_required_fields(kind)),
        "optional": tuple(_optional_fields(kind)),
        "forbidden": tuple(sorted(SESSION_TOKEN_FIELD_NAMES))
        if kind in {"session_tab", "cookie_metadata"}
        else (),
    }


def browser_artifact_schemas() -> dict[str, dict[str, Any]]:
    return {kind: schema_for(kind) for kind in sorted(ARTIFACT_KINDS)}


def validate_browser_artifact(record: Mapping[str, Any]) -> BrowserSchemaValidationResult:
    """Validate the common browser schema contract without third-party tools."""

    warnings: list[str] = []
    kind = record.get("artifact_kind")
    if not isinstance(kind, str) or kind not in ARTIFACT_KINDS:
        return BrowserSchemaValidationResult(False, ("unknown_artifact_kind",))
    required = _required_fields(kind)
    missing = [field for field in required if field not in record]
    if missing:
        warnings.extend(f"missing:{field}" for field in missing)
    forbidden = sorted(SESSION_TOKEN_FIELD_NAMES.intersection(record))
    if forbidden:
        warnings.extend(f"forbidden_token_field:{field}" for field in forbidden)
    warnings.extend(_timestamp_warnings(record))
    warnings.extend(_provenance_warnings(record))
    confidence = record.get("recovery_confidence")
    if not isinstance(confidence, int | float) or confidence < 0 or confidence > 1:
        warnings.append("invalid_recovery_confidence")
    return BrowserSchemaValidationResult(not warnings, tuple(warnings))


def _required_fields(kind: str) -> tuple[str, ...]:
    common = (
        "artifact_id",
        "artifact_kind",
        "browser_family",
        "profile_id",
        "raw_provenance",
        "recovery_confidence",
    )
    specific = {
        "profile": ("display_name", "profile_path"),
        "visit": ("url", "title", "visit_time"),
        "download": ("source_url", "target_path", "start_time"),
        "bookmark": ("url", "title", "created_time"),
        "search": ("query", "search_time"),
        "session_tab": ("url", "title", "last_active_time"),
        "cookie_metadata": ("host", "name", "created_time"),
        "cache_entry": ("url", "cache_key", "stored_time"),
        "extension": ("extension_id", "name", "install_path"),
    }[kind]
    return (*common, *specific)


def _optional_fields(kind: str) -> tuple[str, ...]:
    timestamp_notes = (
        "display_timezone",
        "parser_version",
        "warnings",
        "url_normalization",
        "source_url_normalization",
        "visit_collapse_key",
    )
    if kind == "profile":
        return (*timestamp_notes, "browser_version", "os_user_id")
    if kind == "download":
        return (*timestamp_notes, "end_time", "received_bytes", "total_bytes")
    if kind == "extension":
        return (*timestamp_notes, "version", "enabled", "source_store")
    return timestamp_notes


def _timestamp_warnings(record: Mapping[str, Any]) -> tuple[str, ...]:
    warnings: list[str] = []
    for key, value in record.items():
        if not key.endswith("_time"):
            continue
        if not isinstance(value, Mapping):
            warnings.append(f"invalid_timestamp:{key}")
            continue
        has_raw = "raw_value" in value or "raw_epoch" in value
        if not has_raw:
            warnings.append(f"missing_raw_timestamp:{key}")
        if "normalized_utc" not in value:
            warnings.append(f"missing_normalized_timestamp:{key}")
        if "display_timezone" not in value:
            warnings.append(f"missing_display_timezone:{key}")
    return tuple(warnings)


def _provenance_warnings(record: Mapping[str, Any]) -> tuple[str, ...]:
    provenance = record.get("raw_provenance")
    if not isinstance(provenance, Mapping):
        return ("invalid_raw_provenance",)
    required = ("entry_id", "source_artifact", "parser", "row_reference")
    return tuple(f"missing_provenance:{field}" for field in required if field not in provenance)
