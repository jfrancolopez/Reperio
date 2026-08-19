"""Filters, facets, FTS, and saved views (RPR-121).

Normalizes filter state with an explicit ``include_noise`` flag, matches rows
deterministically against it, derives facet counts, encodes/decodes share-local
URL state (invalid state is rejected, never partially applied), and snapshots
the filter state immutably for saved views and export. Pure and
dependency-free; performs no I/O.
"""

from __future__ import annotations

import base64
import json
import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Any

FILTER_STATE_VERSION = "filter-state-v1"

FACET_KEYS = (
    "users",
    "volumes",
    "categories",
    "allocations",
    "encrypted",
    "corrupt",
    "duplicates",
)

FACET_ROW_FIELDS = {
    "users": "owner_id",
    "volumes": "volume_id",
    "categories": "category",
    "allocations": "allocation",
    "encrypted": "encrypted",
    "corrupt": "corrupt",
    "duplicates": "duplicate",
}

SEARCHABLE_FIELDS = ("display_path", "display_name")


class FilterStateError(ValueError):
    """Raised when a filter state or URL token is invalid."""


@dataclass(frozen=True)
class FilterState:
    text: str = ""
    users: tuple[str, ...] = ()
    volumes: tuple[str, ...] = ()
    categories: tuple[str, ...] = ()
    date_from: str | None = None
    date_to: str | None = None
    min_size: int | None = None
    max_size: int | None = None
    allocations: tuple[str, ...] = ()
    encrypted: bool | None = None
    corrupt: bool | None = None
    duplicates: bool | None = None
    min_interest: float | None = None
    include_noise: bool = False
    include_exported: bool = False
    include_dismissed: bool = False

    @property
    def explicit_include_noise(self) -> bool:
        return self.include_noise


def normalize_filter_state(raw: Mapping[str, Any]) -> FilterState:
    """Validate a raw filter mapping into a canonical FilterState.

    ``include_noise`` defaults to False and is always surfaced explicitly in
    the canonical state; system/noise rows are excluded unless the operator
    opts in.
    """
    return FilterState(
        text=_optional_text(raw.get("text")),
        users=_string_tuple(raw.get("users")),
        volumes=_string_tuple(raw.get("volumes")),
        categories=_string_tuple(raw.get("categories")),
        date_from=_optional_text(raw.get("date_from")),
        date_to=_optional_text(raw.get("date_to")),
        min_size=_optional_int(raw.get("min_size")),
        max_size=_optional_int(raw.get("max_size")),
        allocations=_string_tuple(raw.get("allocations")),
        encrypted=_optional_bool(raw.get("encrypted")),
        corrupt=_optional_bool(raw.get("corrupt")),
        duplicates=_optional_bool(raw.get("duplicates")),
        min_interest=_optional_float(raw.get("min_interest")),
        include_noise=bool(raw.get("include_noise")),
        include_exported=bool(raw.get("include_exported")),
        include_dismissed=bool(raw.get("include_dismissed")),
    )


def filter_matches(row: Mapping[str, Any], state: FilterState) -> bool:
    """Deterministic row predicate; all present filters must match."""
    if state.text:
        haystack = " ".join(str(row.get(field) or "") for field in SEARCHABLE_FIELDS).lower()
        if _normalize_search(state.text) not in haystack:
            return False
    if state.users and _row_value(row, "owner_id") not in state.users:
        return False
    if state.volumes and str(row.get("volume_id") or "") not in state.volumes:
        return False
    if state.categories and _row_value(row, "category") not in state.categories:
        return False
    if state.date_from and str(row.get("modified_at") or "") < state.date_from:
        return False
    if state.date_to and str(row.get("modified_at") or "") > state.date_to:
        return False
    size = _optional_int(row.get("size_bytes"))
    if size is not None:
        if state.min_size is not None and size < state.min_size:
            return False
        if state.max_size is not None and size > state.max_size:
            return False
    if state.allocations and _row_value(row, "allocation") not in state.allocations:
        return False
    if state.encrypted is not None and bool(row.get("encrypted")) != state.encrypted:
        return False
    if state.corrupt is not None and bool(row.get("corrupt")) != state.corrupt:
        return False
    if state.duplicates is not None and bool(row.get("duplicate")) != state.duplicates:
        return False
    interest = _optional_float(row.get("interest_score"))
    if state.min_interest is not None:
        if interest is None or interest < state.min_interest:
            return False
    if not state.include_noise and _row_value(row, "system_noise") in {"noise", "system"}:
        return False
    if not state.include_exported and _row_value(row, "export_state") == "exported":
        return False
    if not state.include_dismissed and row.get("dismissed") is True:
        return False
    return True


def apply_filters(rows: Sequence[Mapping[str, Any]], state: FilterState) -> list[dict[str, Any]]:
    """Filtered rows; filter state is reflected in the resulting counts."""
    return [dict(row) for row in rows if filter_matches(row, state)]


def facet_counts(
    rows: Sequence[Mapping[str, Any]], state: FilterState, *, key: str
) -> dict[str, int]:
    """Count rows per option for one facet key within the filtered set."""
    if key not in FACET_KEYS:
        raise FilterStateError("unknown_facet", f"facet {key!r} is not supported")
    row_field = FACET_ROW_FIELDS[key]
    counts: dict[str, int] = {}
    for row in rows:
        if not filter_matches(row, state):
            continue
        value = _facet_value(row, key, row_field)
        counts[value] = counts.get(value, 0) + 1
    return dict(sorted(counts.items()))


def encode_url_state(state: FilterState) -> str:
    """Opaque share-local URL state derived from the canonical filter state."""
    payload = {
        "version": FILTER_STATE_VERSION,
        "state": _to_dict(state),
    }
    return base64.urlsafe_b64encode(
        json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).decode("ascii")


def decode_url_state(token: str) -> FilterState:
    """Decode and validate a share-local URL token; reject invalid state."""
    try:
        raw = base64.urlsafe_b64decode(token.encode("ascii")).decode("utf-8")
        payload = json.loads(raw)
    except (ValueError, UnicodeDecodeError) as error:
        raise FilterStateError("invalid_url_state", "URL filter state is not valid") from error
    if not isinstance(payload, Mapping) or payload.get("version") != FILTER_STATE_VERSION:
        raise FilterStateError("invalid_url_state", "URL filter state version is unsupported")
    state = payload.get("state")
    if not isinstance(state, Mapping):
        raise FilterStateError("invalid_url_state", "URL filter state is malformed")
    return normalize_filter_state(state)


def saved_view(
    *,
    view_id: str,
    name: str,
    state: FilterState,
    created_at: str,
) -> dict[str, Any]:
    """Immutable saved-view record capturing the filter snapshot."""
    return {
        "view_version": FILTER_STATE_VERSION,
        "view_id": view_id,
        "name": name,
        "filter_state": _to_dict(state),
        "created_at": created_at,
    }


def export_filter_snapshot(state: FilterState) -> dict[str, Any]:
    """Immutable filter snapshot recorded with an export attempt."""
    return {
        "snapshot_version": FILTER_STATE_VERSION,
        "filter_state": _to_dict(state),
        "explicit_include_noise": state.include_noise,
    }


def _to_dict(state: FilterState) -> dict[str, Any]:
    return {
        "text": state.text,
        "users": list(state.users),
        "volumes": list(state.volumes),
        "categories": list(state.categories),
        "date_from": state.date_from,
        "date_to": state.date_to,
        "min_size": state.min_size,
        "max_size": state.max_size,
        "allocations": list(state.allocations),
        "encrypted": state.encrypted,
        "corrupt": state.corrupt,
        "duplicates": state.duplicates,
        "min_interest": state.min_interest,
        "include_noise": state.include_noise,
        "include_exported": state.include_exported,
        "include_dismissed": state.include_dismissed,
    }


def _facet_value(row: Mapping[str, Any], key: str, row_field: str) -> str:
    if key in {"encrypted", "corrupt", "duplicates"}:
        return "true" if bool(row.get(row_field)) else "false"
    return str(row.get(row_field) or "unknown")


def _row_value(row: Mapping[str, Any], key: str) -> str:
    return str(row.get(key) or "")


def _normalize_search(text: str) -> str:
    return re.sub(r"\s+", " ", text.strip().lower())


def _optional_text(value: Any) -> str:
    return str(value).strip() if isinstance(value, str) else ""


def _string_tuple(value: Any) -> tuple[str, ...]:
    if isinstance(value, list | tuple):
        return tuple(str(item) for item in value if isinstance(item, str) and item)
    return ()


def _optional_int(value: Any) -> int | None:
    if isinstance(value, int) and not isinstance(value, bool):
        return value
    return None


def _optional_float(value: Any) -> float | None:
    if isinstance(value, int | float) and not isinstance(value, bool):
        return float(value)
    return None


def _optional_bool(value: Any) -> bool | None:
    if isinstance(value, bool):
        return value
    return None
