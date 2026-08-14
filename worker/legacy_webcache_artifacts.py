"""Isolated legacy IE/Edge WebCache parser adapter."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from hashlib import sha256
from pathlib import Path
from typing import Any

from shared.browser_artifact_schemas import validate_browser_artifact
from worker import parser_sandbox
from worker.browser_profiles import BrowserProfile

PARSER_VERSION = "legacy-webcache-adapter-v1"


@dataclass(frozen=True)
class LegacyWebCacheResult:
    records: tuple[dict[str, Any], ...]
    warnings: tuple[str, ...] = ()


class LegacyWebCacheError(ValueError):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


def parse_legacy_webcache(
    profile: BrowserProfile,
    *,
    copied_webcache_path: Path,
    job_scratch: Path,
    resource_profile: Mapping[str, int],
    runtime: parser_sandbox.ParserRuntime,
    entry_id: str = "unknown",
) -> LegacyWebCacheResult:
    """Run the fixed WebCache/ESE sandbox parser and normalize browser records."""

    if profile.browser_family != "legacy_ie_edge":
        raise LegacyWebCacheError("unsupported_browser_family", "profile must be legacy IE/Edge")
    copied_webcache_path = copied_webcache_path.resolve()
    job_scratch = job_scratch.resolve()
    if not _under(copied_webcache_path, job_scratch):
        raise LegacyWebCacheError("input_not_copied", "WebCache input must be a scratch copy")
    if not copied_webcache_path.exists():
        return LegacyWebCacheResult(
            (_status_record(profile, entry_id, "missing", ("missing_artifact:WebCacheV01.dat",)),),
            ("missing_artifact:WebCacheV01.dat",),
        )
    spec = parser_sandbox.build_parser_sandbox(
        profile_name="legacy-webcache",
        copied_input=copied_webcache_path,
        job_scratch=job_scratch,
        resource_profile=resource_profile,
    )
    parsed = parser_sandbox.run_parser_sandbox(spec, runtime)
    if parsed.status != "complete":
        failure_warnings = tuple(f"webcache_{warning}" for warning in parsed.warnings) or (
            "webcache_failed",
        )
        return LegacyWebCacheResult(
            (_status_record(profile, entry_id, parsed.status, failure_warnings),),
            failure_warnings,
        )
    records: list[dict[str, Any]] = []
    warnings: list[str] = []
    for index, raw in enumerate(parsed.records, start=1):
        record = _normalize_record(profile, entry_id, raw, index)
        if record is None:
            warnings.append(f"unsupported_record:{raw.get('artifact_kind', 'unknown')}")
            continue
        validation = validate_browser_artifact(record)
        if validation.valid:
            records.append(record)
        else:
            warnings.extend(
                f"invalid_record:{record.get('artifact_kind')}:{item}"
                for item in validation.warnings
            )
    if not records and not warnings:
        warnings.append("no_artifacts")
    return LegacyWebCacheResult(tuple(records), tuple(warnings))


def _normalize_record(
    profile: BrowserProfile, entry_id: str, raw: Mapping[str, Any], index: int
) -> dict[str, Any] | None:
    kind = raw.get("artifact_kind")
    if kind == "favorite":
        kind = "bookmark"
    if kind not in {"visit", "download", "bookmark", "cache_entry"}:
        return None
    row_reference = str(raw.get("row_reference") or f"record:{index}")
    common = _base_record(profile, entry_id, kind, row_reference)
    if kind == "visit":
        common.update(
            {
                "url": str(raw.get("url") or ""),
                "title": str(raw.get("title") or ""),
                "visit_time": _timestamp(raw.get("timestamp")),
                "container": str(raw.get("container") or "WebCache"),
            }
        )
    elif kind == "download":
        common.update(
            {
                "source_url": str(raw.get("source_url") or raw.get("url") or ""),
                "target_path": str(raw.get("target_path") or raw.get("path") or ""),
                "start_time": _timestamp(raw.get("start_time") or raw.get("timestamp")),
                "end_time": _timestamp(raw.get("end_time") or raw.get("timestamp")),
                "received_bytes": _int_or_zero(raw.get("received_bytes")),
                "total_bytes": _int_or_zero(raw.get("total_bytes")),
            }
        )
    elif kind == "bookmark":
        common.update(
            {
                "url": str(raw.get("url") or ""),
                "title": str(raw.get("title") or raw.get("name") or ""),
                "created_time": _timestamp(raw.get("created_time") or raw.get("timestamp")),
            }
        )
    elif kind == "cache_entry":
        common.update(
            {
                "url": str(raw.get("url") or ""),
                "cache_key": str(raw.get("cache_key") or raw.get("url") or ""),
                "stored_time": _timestamp(raw.get("stored_time") or raw.get("timestamp")),
            }
        )
    return common


def _base_record(
    profile: BrowserProfile, entry_id: str, kind: str, row_reference: str
) -> dict[str, Any]:
    return {
        "artifact_id": _artifact_id(profile.browser_profile_id, kind, row_reference),
        "artifact_kind": kind,
        "browser_family": "legacy_ie_edge",
        "profile_id": profile.browser_profile_id,
        "raw_provenance": {
            "entry_id": entry_id,
            "source_artifact": "WebCacheV01.dat",
            "parser": PARSER_VERSION,
            "row_reference": row_reference,
        },
        "recovery_confidence": 0.9,
        "parser_version": PARSER_VERSION,
    }


def _status_record(
    profile: BrowserProfile, entry_id: str, status: str, warnings: tuple[str, ...]
) -> dict[str, Any]:
    record = _base_record(profile, entry_id, "profile", f"webcache-status:{status}")
    record.update(
        {
            "display_name": f"{profile.browser_name} {profile.profile_name} WebCache",
            "profile_path": profile.profile_path,
            "browser_version": "unknown",
            "os_user_id": profile.owner_profile_id,
            "warnings": warnings,
        }
    )
    return record


def _timestamp(value: object) -> dict[str, object]:
    raw_value = str(value or "1970-01-01T00:00:00Z")
    return {"raw_value": raw_value, "normalized_utc": raw_value, "display_timezone": "UTC"}


def _int_or_zero(value: object) -> int:
    if isinstance(value, int):
        return value
    if isinstance(value, str) and value.isdecimal():
        return int(value)
    return 0


def _under(path: Path, root: Path) -> bool:
    try:
        path.relative_to(root)
    except ValueError:
        return False
    return True


def _artifact_id(*values: str) -> str:
    digest = sha256("\0".join(values).encode("utf-8")).hexdigest()
    return f"browser-artifact-{digest[:32]}"
