"""Read-only Chromium-family browser artifact parser for copied profiles."""

from __future__ import annotations

import json
import sqlite3
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from hashlib import sha256
from pathlib import Path
from typing import Any
from urllib.parse import quote

from shared.browser_artifact_schemas import validate_browser_artifact
from shared.browser_normalization import normalize_browser_record
from worker.browser_profiles import BrowserProfile

PARSER_VERSION = "chromium-artifacts-v1"
CHROMIUM_EPOCH = datetime(1601, 1, 1, tzinfo=UTC)


@dataclass(frozen=True)
class ChromiumParseResult:
    records: tuple[dict[str, Any], ...]
    warnings: tuple[str, ...] = ()


class ChromiumArtifactError(ValueError):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


def parse_chromium_profile(
    profile: BrowserProfile,
    *,
    copied_profile_path: Path,
    job_scratch: Path,
    entry_ids: Mapping[str, str] | None = None,
) -> ChromiumParseResult:
    """Parse Chromium artifacts from an already-copied profile directory."""

    if profile.browser_family != "chromium":
        raise ChromiumArtifactError("unsupported_browser_family", "profile must be chromium-family")
    root = copied_profile_path.resolve()
    scratch = job_scratch.resolve()
    if not _under(root, scratch):
        raise ChromiumArtifactError("input_not_copied", "Chromium profile must be a scratch copy")
    if not root.is_dir():
        raise ChromiumArtifactError(
            "missing_profile_copy", "copied profile path must be a directory"
        )
    entries = entry_ids or {}
    records: list[dict[str, Any]] = []
    warnings: list[str] = []
    _extend(records, warnings, _parse_history(profile, root, entries))
    _extend(records, warnings, _parse_bookmarks(profile, root, entries))
    _extend(records, warnings, _parse_preferences(profile, root, entries))
    _extend(records, warnings, _parse_session_json(profile, root, entries))
    _extend(records, warnings, _parse_cache_metadata(profile, root, entries))
    valid_records = tuple(record for record in records if _valid(record, warnings))
    return ChromiumParseResult(valid_records, tuple(warnings))


def _parse_history(
    profile: BrowserProfile, root: Path, entry_ids: Mapping[str, str]
) -> ChromiumParseResult:
    history = root / "History"
    if not history.exists():
        return ChromiumParseResult((), ("missing_artifact:History",))
    connection = _open_sqlite(history, root, "History")
    if connection is None:
        return ChromiumParseResult((), ("malformed_artifact:History",))
    try:
        warnings = list(_missing_tables(connection, ("urls", "visits", "downloads")))
        records: list[dict[str, Any]] = []
        if "missing_table:urls" not in warnings and "missing_table:visits" not in warnings:
            records.extend(_visit_records(profile, connection, entry_ids))
            records.extend(_search_records(profile, connection, entry_ids))
        if "missing_table:downloads" not in warnings:
            records.extend(_download_records(profile, connection, entry_ids))
        return ChromiumParseResult(tuple(records), tuple(warnings))
    except sqlite3.DatabaseError:
        return ChromiumParseResult((), ("malformed_artifact:History",))
    finally:
        connection.close()


def _visit_records(
    profile: BrowserProfile, connection: sqlite3.Connection, entry_ids: Mapping[str, str]
) -> tuple[dict[str, Any], ...]:
    rows = connection.execute(
        """
        SELECT visits.id, urls.url, urls.title, urls.visit_count, urls.typed_count,
               visits.visit_time, visits.transition, visits.from_visit
        FROM visits JOIN urls ON visits.url = urls.id
        ORDER BY visits.id
        """
    ).fetchall()
    return tuple(
        _record(
            profile,
            "visit",
            "History",
            f"visits:{row['id']}",
            entry_ids,
            {
                "url": row["url"] or "",
                "title": row["title"] or "",
                "visit_time": _chromium_time(row["visit_time"]),
                "visit_count": row["visit_count"],
                "typed_count": row["typed_count"],
                "transition": row["transition"],
                "from_visit": row["from_visit"],
            },
        )
        for row in rows
    )


def _download_records(
    profile: BrowserProfile, connection: sqlite3.Connection, entry_ids: Mapping[str, str]
) -> tuple[dict[str, Any], ...]:
    if not _has_table(connection, "downloads"):
        return ()
    url_lookup = _download_url_lookup(connection)
    rows = connection.execute(
        """
        SELECT id, target_path, current_path, start_time, end_time,
               received_bytes, total_bytes
        FROM downloads
        ORDER BY id
        """
    ).fetchall()
    return tuple(
        _record(
            profile,
            "download",
            "History",
            f"downloads:{row['id']}",
            entry_ids,
            {
                "source_url": url_lookup.get(row["id"], ""),
                "target_path": row["target_path"] or row["current_path"] or "",
                "start_time": _chromium_time(row["start_time"]),
                "end_time": _chromium_time(row["end_time"]),
                "received_bytes": row["received_bytes"] or 0,
                "total_bytes": row["total_bytes"] or 0,
            },
        )
        for row in rows
    )


def _download_url_lookup(connection: sqlite3.Connection) -> dict[int, str]:
    if not _has_table(connection, "downloads_url_chains"):
        return {}
    rows = connection.execute(
        """
        SELECT id, url
        FROM downloads_url_chains
        WHERE chain_index = 0
        ORDER BY id
        """
    ).fetchall()
    return {int(row["id"]): str(row["url"] or "") for row in rows}


def _search_records(
    profile: BrowserProfile, connection: sqlite3.Connection, entry_ids: Mapping[str, str]
) -> tuple[dict[str, Any], ...]:
    if not _has_table(connection, "keyword_search_terms"):
        return ()
    rows = connection.execute(
        """
        SELECT keyword_search_terms.rowid AS row_id, keyword_search_terms.term,
               urls.last_visit_time
        FROM keyword_search_terms LEFT JOIN urls ON keyword_search_terms.url_id = urls.id
        ORDER BY keyword_search_terms.rowid
        """
    ).fetchall()
    return tuple(
        _record(
            profile,
            "search",
            "History",
            f"keyword_search_terms:{row['row_id']}",
            entry_ids,
            {"query": row["term"] or "", "search_time": _chromium_time(row["last_visit_time"])},
        )
        for row in rows
    )


def _parse_bookmarks(
    profile: BrowserProfile, root: Path, entry_ids: Mapping[str, str]
) -> ChromiumParseResult:
    bookmarks = root / "Bookmarks"
    if not bookmarks.exists():
        return ChromiumParseResult((), ("missing_artifact:Bookmarks",))
    data = _load_json(bookmarks, root)
    if data is None:
        return ChromiumParseResult((), ("malformed_artifact:Bookmarks",))
    records = [
        _record(
            profile,
            "bookmark",
            "Bookmarks",
            f"bookmark:{index}",
            entry_ids,
            {
                "url": item.get("url", ""),
                "title": item.get("name", ""),
                "created_time": _chromium_time(item.get("date_added")),
            },
        )
        for index, item in enumerate(_bookmark_items(data), start=1)
    ]
    return ChromiumParseResult(tuple(records), ())


def _parse_preferences(
    profile: BrowserProfile, root: Path, entry_ids: Mapping[str, str]
) -> ChromiumParseResult:
    preferences = root / "Preferences"
    if not preferences.exists():
        return ChromiumParseResult((), ("missing_artifact:Preferences",))
    data = _load_json(preferences, root)
    if data is None:
        return ChromiumParseResult((), ("malformed_artifact:Preferences",))
    settings = data.get("extensions", {}).get("settings", {})
    if not isinstance(settings, Mapping):
        return ChromiumParseResult((), ("malformed_artifact:Preferences.extensions",))
    records = [
        _record(
            profile,
            "extension",
            "Preferences",
            f"extensions.settings:{extension_id}",
            entry_ids,
            {
                "extension_id": extension_id,
                "name": str(details.get("manifest", {}).get("name") or details.get("name") or ""),
                "install_path": str(details.get("path") or ""),
                "version": str(details.get("manifest", {}).get("version") or ""),
                "enabled": bool(details.get("state", 1)),
                "source_store": str(details.get("location", "unknown")),
            },
        )
        for extension_id, details in sorted(settings.items())
        if isinstance(extension_id, str) and isinstance(details, Mapping)
    ]
    return ChromiumParseResult(tuple(records), ())


def _parse_session_json(
    profile: BrowserProfile, root: Path, entry_ids: Mapping[str, str]
) -> ChromiumParseResult:
    session = root / "Sessions.json"
    if not session.exists():
        return ChromiumParseResult((), ("missing_artifact:Sessions.json",))
    data = _load_json(session, root)
    if data is None:
        return ChromiumParseResult((), ("malformed_artifact:Sessions.json",))
    tabs = data.get("tabs", ()) if isinstance(data, Mapping) else ()
    if not isinstance(tabs, Iterable):
        return ChromiumParseResult((), ("malformed_artifact:Sessions.tabs",))
    records = [
        _record(
            profile,
            "session_tab",
            "Sessions.json",
            f"tabs:{index}",
            entry_ids,
            {
                "url": str(tab.get("url") or ""),
                "title": str(tab.get("title") or ""),
                "last_active_time": _chromium_time(tab.get("last_active_time")),
            },
        )
        for index, tab in enumerate(tabs, start=1)
        if isinstance(tab, Mapping)
    ]
    return ChromiumParseResult(tuple(records), ())


def _parse_cache_metadata(
    profile: BrowserProfile, root: Path, entry_ids: Mapping[str, str]
) -> ChromiumParseResult:
    metadata = root / "Cache" / "index.json"
    if not metadata.exists():
        return ChromiumParseResult((), ("missing_artifact:Cache/index.json",))
    data = _load_json(metadata, root)
    if data is None:
        return ChromiumParseResult((), ("malformed_artifact:Cache/index.json",))
    entries = data.get("entries", ()) if isinstance(data, Mapping) else ()
    if not isinstance(entries, Iterable):
        return ChromiumParseResult((), ("malformed_artifact:Cache.entries",))
    records = [
        _record(
            profile,
            "cache_entry",
            "Cache/index.json",
            f"entries:{index}",
            entry_ids,
            {
                "url": str(item.get("url") or ""),
                "cache_key": str(item.get("cache_key") or item.get("key") or ""),
                "stored_time": _chromium_time(item.get("stored_time")),
            },
        )
        for index, item in enumerate(entries, start=1)
        if isinstance(item, Mapping)
    ]
    return ChromiumParseResult(tuple(records), ())


def _profile_record(profile: BrowserProfile, entry_ids: Mapping[str, str]) -> dict[str, Any]:
    return _record(
        profile,
        "profile",
        "profile-locator",
        profile.browser_profile_id,
        entry_ids,
        {
            "display_name": f"{profile.browser_name} {profile.profile_name}",
            "profile_path": profile.profile_path,
            "browser_version": "unknown",
            "os_user_id": profile.owner_profile_id,
        },
    )


def _record(
    profile: BrowserProfile,
    kind: str,
    source_artifact: str,
    row_reference: str,
    entry_ids: Mapping[str, str],
    fields: Mapping[str, Any],
) -> dict[str, Any]:
    artifact_id = _stable_id(profile.browser_profile_id, kind, source_artifact, row_reference)
    record = {
        "artifact_id": artifact_id,
        "artifact_kind": kind,
        "browser_family": "chromium",
        "profile_id": profile.browser_profile_id,
        "raw_provenance": {
            "entry_id": entry_ids.get(source_artifact, "unknown"),
            "source_artifact": source_artifact,
            "parser": PARSER_VERSION,
            "row_reference": row_reference,
        },
        "recovery_confidence": 1.0,
        "parser_version": PARSER_VERSION,
        **fields,
    }
    return normalize_browser_record(record)


def _open_sqlite(path: Path, root: Path, label: str) -> sqlite3.Connection | None:
    resolved = path.resolve()
    if not _under(resolved, root):
        raise ValueError(f"{label} must be under copied profile directory")
    connection: sqlite3.Connection | None = None
    try:
        connection = sqlite3.connect(
            f"file:{quote(resolved.as_posix())}?mode=ro&immutable=1",
            uri=True,
        )
        connection.row_factory = sqlite3.Row
        connection.execute("SELECT 1").fetchone()
    except sqlite3.DatabaseError:
        if connection is not None:
            connection.close()
        return None
    return connection


def _load_json(path: Path, root: Path) -> Any | None:
    resolved = path.resolve()
    if not _under(resolved, root):
        raise ValueError("artifact must be under copied profile directory")
    try:
        with resolved.open("r", encoding="utf-8") as handle:
            return json.load(handle)
    except (OSError, json.JSONDecodeError, UnicodeDecodeError):
        return None


def _bookmark_items(data: Any) -> tuple[Mapping[str, Any], ...]:
    result: list[Mapping[str, Any]] = []

    def walk(node: Any) -> None:
        if not isinstance(node, Mapping):
            return
        if node.get("type") == "url" and isinstance(node.get("url"), str):
            result.append(node)
        children = node.get("children", ())
        if isinstance(children, Iterable) and not isinstance(children, str | bytes):
            for child in children:
                walk(child)

    roots = data.get("roots", {}) if isinstance(data, Mapping) else {}
    for node in roots.values() if isinstance(roots, Mapping) else ():
        walk(node)
    return tuple(result)


def _chromium_time(value: object) -> dict[str, object]:
    raw_epoch = _int_or_zero(value)
    normalized = CHROMIUM_EPOCH + timedelta(microseconds=raw_epoch)
    return {
        "raw_epoch": raw_epoch,
        "normalized_utc": normalized.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "display_timezone": "UTC",
    }


def _int_or_zero(value: object) -> int:
    if isinstance(value, int):
        return value
    if isinstance(value, str) and value.isdecimal():
        return int(value)
    return 0


def _missing_tables(connection: sqlite3.Connection, tables: tuple[str, ...]) -> tuple[str, ...]:
    return tuple(f"missing_table:{table}" for table in tables if not _has_table(connection, table))


def _has_table(connection: sqlite3.Connection, table: str) -> bool:
    row = connection.execute(
        "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ?",
        (table,),
    ).fetchone()
    return row is not None


def _extend(
    records: list[dict[str, Any]], warnings: list[str], result: ChromiumParseResult
) -> None:
    records.extend(result.records)
    warnings.extend(result.warnings)


def _valid(record: dict[str, Any], warnings: list[str]) -> bool:
    result = validate_browser_artifact(record)
    if result.valid:
        return True
    warnings.extend(
        f"invalid_record:{record.get('artifact_kind')}:{warning}" for warning in result.warnings
    )
    return False


def _under(path: Path, root: Path) -> bool:
    try:
        path.relative_to(root)
    except ValueError:
        return False
    return True


def _stable_id(*values: str) -> str:
    digest = sha256("\0".join(values).encode("utf-8")).hexdigest()
    return f"browser-artifact-{digest[:32]}"
