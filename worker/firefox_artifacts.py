"""Read-only Firefox-family browser artifact parser for copied profiles."""

from __future__ import annotations

import hashlib
import json
import sqlite3
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from shared.browser_artifact_schemas import validate_browser_artifact
from shared.browser_normalization import normalize_browser_record
from worker.browser_profiles import BrowserProfile
from worker.sqlite_artifacts import copied_sqlite_bundle, open_copied_sqlite_bundle

PARSER_VERSION = "firefox-artifacts-v1"
UNIX_EPOCH = datetime(1970, 1, 1, tzinfo=UTC)


@dataclass(frozen=True)
class FirefoxParseResult:
    records: tuple[dict[str, Any], ...]
    warnings: tuple[str, ...] = ()


class FirefoxArtifactError(ValueError):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


def parse_firefox_profile(
    profile: BrowserProfile,
    *,
    copied_profile_path: Path,
    job_scratch: Path,
    entry_ids: Mapping[str, str] | None = None,
) -> FirefoxParseResult:
    """Parse Firefox artifacts from an already-copied profile directory."""

    if profile.browser_family != "firefox":
        raise FirefoxArtifactError("unsupported_browser_family", "profile must be Firefox-family")
    root = copied_profile_path.resolve()
    scratch = job_scratch.resolve()
    if not _under(root, scratch):
        raise FirefoxArtifactError("input_not_copied", "Firefox profile must be a scratch copy")
    if not root.is_dir():
        raise FirefoxArtifactError(
            "missing_profile_copy", "copied profile path must be a directory"
        )
    entries = entry_ids or {}
    records: list[dict[str, Any]] = []
    warnings: list[str] = []
    _extend(records, warnings, _parse_places(profile, root, entries))
    _extend(records, warnings, _parse_sessionstore(profile, root, entries))
    _extend(records, warnings, _parse_cache(profile, root, entries))
    _extend(records, warnings, _parse_extensions(profile, root, entries))
    valid_records = tuple(record for record in records if _valid(record, warnings))
    return FirefoxParseResult(valid_records, tuple(warnings))


def _parse_places(
    profile: BrowserProfile, root: Path, entry_ids: Mapping[str, str]
) -> FirefoxParseResult:
    places = root / "places.sqlite"
    if not places.exists():
        return FirefoxParseResult((), ("missing_artifact:places.sqlite",))
    connection, sqlite_warnings = _open_sqlite(places, root, "places.sqlite")
    if connection is None:
        return FirefoxParseResult((), (*sqlite_warnings, "malformed_artifact:places.sqlite"))
    try:
        warnings = [
            *sqlite_warnings,
            *_missing_tables(connection, ("moz_places", "moz_historyvisits")),
        ]
        records: list[dict[str, Any]] = []
        if (
            "missing_table:moz_places" not in warnings
            and "missing_table:moz_historyvisits" not in warnings
        ):
            records.extend(_visit_records(profile, connection, entry_ids))
            records.extend(_search_records(profile, connection, entry_ids))
        if "missing_table:moz_places" not in warnings and _has_table(connection, "moz_bookmarks"):
            records.extend(_bookmark_records(profile, connection, entry_ids))
        elif "missing_table:moz_places" not in warnings:
            warnings.append("missing_table:moz_bookmarks")
        if _has_table(connection, "moz_downloads"):
            records.extend(_download_records(profile, connection, entry_ids))
        return FirefoxParseResult(tuple(records), tuple(warnings))
    except sqlite3.DatabaseError:
        return FirefoxParseResult((), ("malformed_artifact:places.sqlite",))
    finally:
        connection.close()


def _visit_records(
    profile: BrowserProfile, connection: sqlite3.Connection, entry_ids: Mapping[str, str]
) -> tuple[dict[str, Any], ...]:
    rows = connection.execute(
        """
        SELECT moz_historyvisits.id, moz_historyvisits.visit_date,
               moz_historyvisits.from_visit, moz_historyvisits.visit_type,
               moz_places.id AS place_id, moz_places.url, moz_places.title, moz_places.visit_count
        FROM moz_historyvisits
        JOIN moz_places ON moz_places.id = moz_historyvisits.place_id
        ORDER BY moz_historyvisits.id
        """
    ).fetchall()
    return tuple(
        _record(
            profile,
            "visit",
            "places.sqlite",
            f"moz_historyvisits:{row['id']}",
            entry_ids,
            {
                "url": row["url"] or "",
                "title": row["title"] or "",
                "visit_time": _firefox_time(row["visit_date"]),
                "visit_count": row["visit_count"] or 0,
                "transition": row["visit_type"],
                "from_visit": row["from_visit"],
                "container_id": "default",
                "private_context": False,
                "source_place_id": row["place_id"],
            },
        )
        for row in rows
    )


def _bookmark_records(
    profile: BrowserProfile, connection: sqlite3.Connection, entry_ids: Mapping[str, str]
) -> tuple[dict[str, Any], ...]:
    rows = connection.execute(
        """
        SELECT moz_bookmarks.id, moz_bookmarks.title AS bookmark_title,
               moz_bookmarks.dateAdded, moz_places.url, moz_places.title AS page_title
        FROM moz_bookmarks
        JOIN moz_places ON moz_places.id = moz_bookmarks.fk
        WHERE moz_bookmarks.type = 1
        ORDER BY moz_bookmarks.id
        """
    ).fetchall()
    return tuple(
        _record(
            profile,
            "bookmark",
            "places.sqlite",
            f"moz_bookmarks:{row['id']}",
            entry_ids,
            {
                "url": row["url"] or "",
                "title": row["bookmark_title"] or row["page_title"] or "",
                "created_time": _firefox_time(row["dateAdded"]),
            },
        )
        for row in rows
    )


def _search_records(
    profile: BrowserProfile, connection: sqlite3.Connection, entry_ids: Mapping[str, str]
) -> tuple[dict[str, Any], ...]:
    if not _has_table(connection, "moz_inputhistory"):
        return ()
    rows = connection.execute(
        """
        SELECT moz_inputhistory.place_id, moz_inputhistory.input, moz_places.last_visit_date
        FROM moz_inputhistory
        LEFT JOIN moz_places ON moz_places.id = moz_inputhistory.place_id
        ORDER BY moz_inputhistory.place_id, moz_inputhistory.input
        """
    ).fetchall()
    return tuple(
        _record(
            profile,
            "search",
            "places.sqlite",
            f"moz_inputhistory:{row['place_id']}:{row['input']}",
            entry_ids,
            {
                "query": row["input"] or "",
                "search_time": _firefox_time(row["last_visit_date"] or 0),
            },
        )
        for row in rows
    )


def _download_records(
    profile: BrowserProfile, connection: sqlite3.Connection, entry_ids: Mapping[str, str]
) -> tuple[dict[str, Any], ...]:
    rows = connection.execute(
        """
        SELECT id, source, target, startTime, endTime, currBytes, maxBytes
        FROM moz_downloads
        ORDER BY id
        """
    ).fetchall()
    return tuple(
        _record(
            profile,
            "download",
            "places.sqlite",
            f"moz_downloads:{row['id']}",
            entry_ids,
            {
                "source_url": row["source"] or "",
                "target_path": row["target"] or "",
                "start_time": _firefox_time(row["startTime"]),
                "end_time": _firefox_time(row["endTime"]),
                "received_bytes": row["currBytes"] or 0,
                "total_bytes": row["maxBytes"] or 0,
            },
        )
        for row in rows
    )


def _parse_sessionstore(
    profile: BrowserProfile, root: Path, entry_ids: Mapping[str, str]
) -> FirefoxParseResult:
    session = root / "sessionstore.json"
    if not session.exists():
        return FirefoxParseResult((), ("missing_artifact:sessionstore.json",))
    data = _load_json(session, root)
    if data is None:
        return FirefoxParseResult((), ("malformed_artifact:sessionstore.json",))
    windows = data.get("windows", []) if isinstance(data, Mapping) else []
    if not isinstance(windows, list):
        return FirefoxParseResult((), ("malformed_artifact:sessionstore.windows",))
    records: list[dict[str, Any]] = []
    for window_index, window in enumerate(windows):
        if not isinstance(window, Mapping):
            continue
        tabs = window.get("tabs", [])
        if not isinstance(tabs, list):
            continue
        for tab_index, tab in enumerate(tabs):
            if not isinstance(tab, Mapping):
                continue
            entry = _selected_session_entry(tab)
            if entry is None:
                continue
            records.append(
                _record(
                    profile,
                    "session_tab",
                    "sessionstore.json",
                    f"windows:{window_index}:tabs:{tab_index}",
                    entry_ids,
                    {
                        "url": str(entry.get("url") or ""),
                        "title": str(entry.get("title") or ""),
                        "last_active_time": _unix_millis_time(tab.get("lastAccessed")),
                        "private_context": bool(tab.get("private", False)),
                    },
                )
            )
    return FirefoxParseResult(tuple(records))


def _parse_cache(
    profile: BrowserProfile, root: Path, entry_ids: Mapping[str, str]
) -> FirefoxParseResult:
    metadata = root / "cache2" / "index.json"
    if not metadata.exists():
        return FirefoxParseResult((), ("missing_artifact:cache2/index.json",))
    data = _load_json(metadata, root)
    if data is None:
        return FirefoxParseResult((), ("malformed_artifact:cache2/index.json",))
    entries = data.get("entries", []) if isinstance(data, Mapping) else []
    if not isinstance(entries, list):
        return FirefoxParseResult((), ("malformed_artifact:cache2.entries",))
    records = [
        _record(
            profile,
            "cache_entry",
            "cache2/index.json",
            f"entries:{index}",
            entry_ids,
            {
                "url": str(item.get("url") or ""),
                "cache_key": str(item.get("cache_key") or item.get("key") or ""),
                "stored_time": _firefox_time(item.get("stored_time")),
            },
        )
        for index, item in enumerate(entries, start=1)
        if isinstance(item, Mapping)
    ]
    return FirefoxParseResult(tuple(records))


def _parse_extensions(
    profile: BrowserProfile, root: Path, entry_ids: Mapping[str, str]
) -> FirefoxParseResult:
    extensions = root / "extensions.json"
    if not extensions.exists():
        return FirefoxParseResult((), ("missing_artifact:extensions.json",))
    data = _load_json(extensions, root)
    if data is None:
        return FirefoxParseResult((), ("malformed_artifact:extensions.json",))
    addons = data.get("addons", []) if isinstance(data, Mapping) else []
    if not isinstance(addons, list):
        return FirefoxParseResult((), ("malformed_artifact:extensions.addons",))
    records = [
        _record(
            profile,
            "extension",
            "extensions.json",
            f"addons:{index}:{addon.get('id', '')}",
            entry_ids,
            {
                "extension_id": str(addon.get("id") or ""),
                "name": str(addon.get("defaultLocale", {}).get("name") or addon.get("id") or ""),
                "install_path": str(addon.get("path") or ""),
                "version": str(addon.get("version") or ""),
                "enabled": bool(addon.get("active", False)),
                "source_store": str(addon.get("sourceURI") or "unknown"),
            },
        )
        for index, addon in enumerate(addons, start=1)
        if isinstance(addon, Mapping)
    ]
    return FirefoxParseResult(tuple(records))


def _selected_session_entry(tab: Mapping[str, Any]) -> Mapping[str, Any] | None:
    entries = tab.get("entries", [])
    if not isinstance(entries, list) or not entries:
        return None
    selected = tab.get("index", 1)
    index = max(_int_or_zero(selected) - 1, 0)
    entry = entries[index] if index < len(entries) else entries[-1]
    return entry if isinstance(entry, Mapping) else None


def _open_sqlite(
    path: Path, root: Path, label: str
) -> tuple[sqlite3.Connection | None, tuple[str, ...]]:
    try:
        bundle = copied_sqlite_bundle(path, root, label)
    except ValueError as error:
        raise FirefoxArtifactError("artifact_escape", str(error)) from error
    return open_copied_sqlite_bundle(bundle)


def _load_json(path: Path, root: Path) -> Any | None:
    resolved = path.resolve()
    if not _under(resolved, root):
        raise FirefoxArtifactError(
            "artifact_escape", "artifact must be under copied profile directory"
        )
    try:
        with resolved.open("r", encoding="utf-8") as handle:
            return json.load(handle)
    except (OSError, json.JSONDecodeError, UnicodeDecodeError):
        return None


def _record(
    profile: BrowserProfile,
    kind: str,
    source_artifact: str,
    row_reference: str,
    entry_ids: Mapping[str, str],
    fields: Mapping[str, Any],
) -> dict[str, Any]:
    record = {
        "artifact_id": _artifact_id(
            profile.browser_profile_id, kind, source_artifact, row_reference
        ),
        "artifact_kind": kind,
        "browser_family": "firefox",
        "profile_id": profile.browser_profile_id,
        "raw_provenance": {
            "entry_id": entry_ids.get(source_artifact, "unknown"),
            "source_artifact": source_artifact,
            "parser": PARSER_VERSION,
            "row_reference": row_reference,
        },
        "recovery_confidence": 1.0,
        "parser_version": PARSER_VERSION,
    }
    record.update(fields)
    return normalize_browser_record(record)


def _firefox_time(value: object) -> dict[str, object]:
    raw_epoch = _int_or_zero(value)
    normalized = UNIX_EPOCH + timedelta(microseconds=raw_epoch)
    return {
        "raw_epoch": raw_epoch,
        "normalized_utc": normalized.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "display_timezone": "UTC",
    }


def _unix_millis_time(value: object) -> dict[str, object]:
    raw_epoch = _int_or_zero(value)
    normalized = UNIX_EPOCH + timedelta(milliseconds=raw_epoch)
    return {
        "raw_epoch": raw_epoch,
        "normalized_utc": normalized.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "display_timezone": "UTC",
    }


def _missing_tables(connection: sqlite3.Connection, tables: tuple[str, ...]) -> tuple[str, ...]:
    return tuple(f"missing_table:{table}" for table in tables if not _has_table(connection, table))


def _has_table(connection: sqlite3.Connection, table: str) -> bool:
    row = connection.execute(
        "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ?",
        (table,),
    ).fetchone()
    return row is not None


def _valid(record: dict[str, Any], warnings: list[str]) -> bool:
    result = validate_browser_artifact(record)
    if result.valid:
        return True
    warnings.extend(
        f"invalid_record:{record.get('artifact_kind')}:{warning}" for warning in result.warnings
    )
    return False


def _extend(records: list[dict[str, Any]], warnings: list[str], result: FirefoxParseResult) -> None:
    records.extend(result.records)
    warnings.extend(result.warnings)


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
    digest = hashlib.sha256("\0".join(values).encode("utf-8")).hexdigest()
    return f"browser-artifact-{digest[:32]}"
