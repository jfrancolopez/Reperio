"""Media masonry gallery state (RPR-122).

Virtualized responsive masonry with aspect-ratio placeholders, infinite cursor
loading, selection without opening, keyboard/range selection, date/device/
location grouping, and duplicate indicators. Missing thumbnails keep a stable
placeholder ratio so layout never thrashes. Only safe derivative thumbnail
references are exposed; original/source active content is never rendered by the
gallery. Pure and dependency-free; performs no I/O.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Any

from worker.findings_table import fetch_page

MEDIA_GALLERY_VERSION = "media-gallery-v1"

DEFAULT_GALLERY_PAGE = 60
MAX_GALLERY_PAGE = 200

GROUP_KEYS = frozenset({"date", "device", "location"})

PLACEHOLDER_RATIO = 4 / 3


class MediaGalleryError(ValueError):
    """Raised when a gallery input is invalid."""


@dataclass(frozen=True)
class GalleryItem:
    entry_id: str
    thumbnail_ref: str | None
    aspect_ratio: float
    missing_thumbnail: bool
    duplicate: bool = False
    group_key: str | None = None


@dataclass(frozen=True)
class GalleryPage:
    items: tuple[GalleryItem, ...]
    next_cursor: str | None
    has_more: bool
    total: int | None = None


def aspect_ratio_for(item: Mapping[str, Any]) -> float:
    """Stable aspect ratio from width/height; falls back to a placeholder ratio."""
    width = item.get("thumb_width")
    height = item.get("thumb_height")
    if isinstance(width, int) and isinstance(height, int) and width > 0 and height > 0:
        return width / height
    return PLACEHOLDER_RATIO


def gallery_item(item: Mapping[str, Any], *, duplicate: bool = False) -> GalleryItem:
    """One gallery item exposing only the derivative thumbnail reference."""
    thumb = item.get("thumbnail_ref")
    thumbnail_ref = str(thumb) if isinstance(thumb, str) and thumb else None
    missing = thumbnail_ref is None
    return GalleryItem(
        entry_id=str(item.get("entry_id") or ""),
        thumbnail_ref=thumbnail_ref,
        aspect_ratio=aspect_ratio_for(item),
        missing_thumbnail=missing,
        duplicate=duplicate,
        group_key=_optional_text(item.get("group_key")),
    )


def gallery_page(
    rows: Sequence[Mapping[str, Any]],
    *,
    limit: int = DEFAULT_GALLERY_PAGE,
    cursor: str | None = None,
    total: int | None = None,
    duplicates: Mapping[str, bool] | None = None,
) -> GalleryPage:
    """Bounded infinite-cursor page; never loads all rows."""
    duplicates = duplicates or {}
    page = fetch_page(rows, sort="path", limit=limit, cursor=cursor, total=total)
    items = tuple(
        gallery_item(row, duplicate=bool(duplicates.get(str(row.get("entry_id")))))
        for row in page.items
    )
    return GalleryPage(
        items=items,
        next_cursor=page.next_cursor,
        has_more=page.has_more,
        total=page.total,
    )


def select_without_opening(
    selection: Mapping[str, bool],
    items: Sequence[Mapping[str, Any]],
    *,
    anchor: str | None = None,
    toggle: str | None = None,
    activate: str | None = None,
) -> tuple[dict[str, bool], str | None]:
    """Selection that never opens the finding; supports anchor/range toggles."""
    current = dict(selection)
    if activate is not None:
        current[str(activate)] = True
        return current, str(activate)
    if toggle is not None:
        if anchor is not None and str(toggle) in {str(item.get("entry_id")) for item in items}:
            ids = [str(item.get("entry_id")) for item in items]
            if str(toggle) in ids:
                anchor_index = ids.index(str(anchor)) if str(anchor) in ids else 0
                toggle_index = ids.index(str(toggle))
                start, end = sorted((anchor_index, toggle_index))
                for entry_id in ids[start : end + 1]:
                    current[entry_id] = not current.get(entry_id, False)
        else:
            current[str(toggle)] = not current.get(str(toggle), False)
        return current, str(anchor or toggle)
    return current, None


def group_items(items: Sequence[Mapping[str, Any]], *, group_by: str) -> list[dict[str, Any]]:
    """Group gallery items deterministically by date/device/location key."""
    if group_by not in GROUP_KEYS:
        raise MediaGalleryError("unknown_group", f"group key {group_by!r} is not supported")
    groups: dict[str, list[str]] = {}
    for item in items:
        key = _optional_text(item.get(group_by)) or "ungrouped"
        groups.setdefault(key, []).append(str(item.get("entry_id") or ""))
    return [
        {"group_by": group_by, "key": key, "entry_ids": entry_ids}
        for key, entry_ids in sorted(groups.items())
    ]


def gallery_state(
    *,
    rows: Sequence[Mapping[str, Any]],
    cursor: str | None = None,
    limit: int = DEFAULT_GALLERY_PAGE,
    selection: Mapping[str, bool] | None = None,
    group_by: str | None = None,
    duplicates: Mapping[str, bool] | None = None,
    narrow_viewport: bool = False,
    error: str | None = None,
) -> dict[str, Any]:
    """Deterministic gallery state with placeholders and accessibility labels."""
    page = gallery_page(rows, limit=limit, cursor=cursor, duplicates=duplicates)
    selection = selection or {}
    items: list[dict[str, Any]] = []
    for item in page.items:
        ratio = item.aspect_ratio
        if item.missing_thumbnail:
            width, height = 300, int(round(300 / PLACEHOLDER_RATIO))
        else:
            width, height = 300, max(1, int(round(300 / ratio)))
        items.append(
            {
                "entry_id": item.entry_id,
                "thumbnail_ref": item.thumbnail_ref,
                "placeholder_width": width,
                "placeholder_height": height,
                "missing_thumbnail": item.missing_thumbnail,
                "duplicate": item.duplicate,
                "selected": bool(selection.get(item.entry_id)),
                "aria_label": f"media finding {item.entry_id}",
                "role": "img",
            }
        )
    result: dict[str, Any] = {
        "gallery_version": MEDIA_GALLERY_VERSION,
        "items": items,
        "next_cursor": page.next_cursor,
        "has_more": page.has_more,
        "total": page.total,
        "selection_count": sum(1 for value in selection.values() if value),
        "narrow_viewport": narrow_viewport,
        "renders_original_content": False,
        "error": error,
        "groups": group_items(rows, group_by=group_by) if group_by is not None else [],
    }
    return result


def _optional_text(value: Any) -> str:
    return str(value) if isinstance(value, str) and value else ""
