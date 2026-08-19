"""Virtualized findings table state (RPR-120).

Cursor-paginated, stably sorted findings table that never loads the full catalog.
Pages are sliced from a sorted row provider so only the visible window is held in
memory; cursors are opaque and derived from the last visible row's sort key, so
concurrent ingest cannot skip or duplicate rows. Row selection is keyed by
entry_id, never by row index, so it survives concurrent ingest. Pure and
dependency-free; the row provider performs the actual I/O.
"""

from __future__ import annotations

import base64
import json
from collections.abc import Callable, Iterable, Mapping, Sequence
from dataclasses import dataclass
from typing import Any

FINDINGS_TABLE_VERSION = "findings-table-v1"

DEFAULT_PAGE_SIZE = 100
MAX_PAGE_SIZE = 500

COLUMNS = (
    "path",
    "type",
    "size_bytes",
    "modified_at",
    "state",
    "interest_score",
    "confidence",
    "category",
    "export",
)

SORTABLE_FIELDS = frozenset({"path", "type", "size_bytes", "modified_at", "confidence"})

TERMINAL_STATES = frozenset({"dismissed", "completed"})


class FindingsTableError(ValueError):
    """Raised when a table input or cursor is invalid."""


@dataclass(frozen=True)
class Page:
    items: tuple[Mapping[str, Any], ...]
    next_cursor: str | None
    has_more: bool
    total: int | None = None


RowProvider = Callable[[int, int], Iterable[Mapping[str, Any]]]


def validate_sort(sort: str) -> str:
    if sort not in SORTABLE_FIELDS:
        raise FindingsTableError("invalid_sort", f"sort field {sort!r} is not supported")
    return sort


def stable_sort_key(row: Mapping[str, Any], sort: str) -> tuple[Any, ...]:
    """Deterministic sort key with entry_id tiebreaker for stability."""
    validate_sort(sort)
    entry_id = row.get("entry_id")
    return (row.get(sort), entry_id)


def encode_cursor(sort: str, last_row: Mapping[str, Any]) -> str:
    """Opaque cursor encoding the last visible row's sort key."""
    data = {
        "sort": sort,
        "key": last_row.get("entry_id"),
        "value": _jsonable(last_row.get(sort)),
    }
    encoded = base64.urlsafe_b64encode(
        json.dumps(data, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).decode("ascii")
    return encoded


def decode_cursor(cursor: str) -> dict[str, Any]:
    try:
        raw = base64.urlsafe_b64decode(cursor.encode("ascii")).decode("utf-8")
        data = json.loads(raw)
    except (ValueError, UnicodeDecodeError) as error:
        raise FindingsTableError("invalid_cursor", "cursor is not valid") from error
    if not isinstance(data, Mapping) or "key" not in data or "sort" not in data:
        raise FindingsTableError("invalid_cursor", "cursor is malformed")
    validate_sort(str(data["sort"]))
    return dict(data)


def after_cursor(row: Mapping[str, Any], cursor: dict[str, Any]) -> bool:
    """True when the row sorts strictly after the cursor's last row."""
    sort = str(cursor["sort"])
    row_key = row.get("entry_id")
    row_value = row.get(sort)
    cursor_value = cursor.get("value")
    cursor_key = cursor.get("key")
    if row_value != cursor_value:
        return _compare(row_value, cursor_value) > 0
    if row_key is None or cursor_key is None:
        return False
    return bool(row_key > cursor_key)


def fetch_page(
    rows: Sequence[Mapping[str, Any]],
    *,
    sort: str = "path",
    limit: int = DEFAULT_PAGE_SIZE,
    cursor: str | None = None,
    total: int | None = None,
) -> Page:
    """Slice a sorted row window by cursor without loading all rows.

    ``rows`` must already be sorted by ``stable_sort_key``; only the window
    after the cursor is returned, so callers pass a provider that yields a
    bounded slice. Returns an opaque next cursor plus the bounded item tuple.
    """
    validate_sort(sort)
    if limit < 1 or limit > MAX_PAGE_SIZE:
        raise FindingsTableError("invalid_limit", "page limit is out of range")
    start = 0
    if cursor is not None:
        decoded = decode_cursor(cursor)
        if decoded["sort"] != sort:
            raise FindingsTableError("invalid_cursor", "cursor sort does not match request")
        start = _first_index_after(rows, decoded)
    window = rows[start : start + limit]
    items = tuple(dict(row) for row in window)
    next_cursor = None
    has_more = False
    if items:
        known_total = total if total is not None else len(rows)
        if start + limit < known_total:
            has_more = True
            next_cursor = encode_cursor(sort, rows[start + limit - 1])
    return Page(items=items, next_cursor=next_cursor, has_more=has_more, total=total)


def select_rows(
    selection: Mapping[str, bool],
    rows: Sequence[Mapping[str, Any]],
    *,
    toggle: str | None = None,
    replace_all: bool = False,
    selected_all: bool = False,
) -> dict[str, bool]:
    """Keyed row selection that survives concurrent ingest.

    Selection is keyed by entry_id and is unchanged by rows appearing or
    disappearing elsewhere in the catalog.
    """
    current = dict(selection)
    if replace_all:
        current = {}
        if selected_all:
            for row in rows:
                current[str(row.get("entry_id"))] = True
        return current
    if toggle is not None:
        current[str(toggle)] = not current.get(str(toggle), False)
    return current


def make_columns(
    row: Mapping[str, Any],
    *,
    ui_base: str = "",
    selected: bool = False,
) -> dict[str, Any]:
    """Render the table columns for one finding row."""
    entry_id = row.get("entry_id")
    detail_link = f"{ui_base}/case/{row.get('case_id', '')}/finding/{entry_id}" if ui_base else ""
    return {
        "path": row.get("path"),
        "type": row.get("entry_type"),
        "size_bytes": row.get("size_bytes"),
        "modified_at": row.get("modified_at"),
        "state": row.get("state"),
        "interest_score": row.get("interest_score"),
        "confidence": row.get("confidence"),
        "category": row.get("category"),
        "export": row.get("export_state"),
        "detail_link": detail_link,
        "selected": selected,
    }


def table_state(
    *,
    rows: Sequence[Mapping[str, Any]],
    sort: str = "path",
    limit: int = DEFAULT_PAGE_SIZE,
    cursor: str | None = None,
    selection: Mapping[str, bool] | None = None,
    ui_base: str = "",
    loading: bool = False,
    error: str | None = None,
    total: int | None = None,
) -> dict[str, Any]:
    """Deterministic table state including loading/error/empty states."""
    page = fetch_page(rows, sort=sort, limit=limit, cursor=cursor, total=total)
    selection = selection or {}
    items = [
        make_columns(row, ui_base=ui_base, selected=bool(selection.get(str(row.get("entry_id")))))
        for row in page.items
    ]
    return {
        "table_version": FINDINGS_TABLE_VERSION,
        "sort": sort,
        "cursor": cursor,
        "next_cursor": page.next_cursor,
        "has_more": page.has_more,
        "total": page.total,
        "columns": list(COLUMNS),
        "items": items,
        "loading": loading,
        "error": error,
        "empty": not items and not loading and error is None,
        "selected_count": sum(1 for value in selection.values() if value),
    }


def _first_index_after(rows: Sequence[Mapping[str, Any]], cursor: dict[str, Any]) -> int:
    for index, row in enumerate(rows):
        if after_cursor(row, cursor):
            return index
    return len(rows)


def _compare(left: Any, right: Any) -> int:
    if left is None and right is None:
        return 0
    if left is None:
        return -1
    if right is None:
        return 1
    try:
        return int(left > right) - int(left < right)
    except TypeError:
        left_s = str(left)
        right_s = str(right)
        return int(left_s > right_s) - int(left_s < right_s)


def _jsonable(value: Any) -> Any:
    if isinstance(value, str | int | float | bool) or value is None:
        return value
    return str(value)
