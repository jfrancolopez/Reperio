#!/usr/bin/env python3

from __future__ import annotations

import unittest
from typing import Any

from worker.media_gallery import (
    MEDIA_GALLERY_VERSION,
    MediaGalleryError,
    aspect_ratio_for,
    gallery_item,
    gallery_page,
    gallery_state,
    group_items,
    select_without_opening,
)


def item(entry_id: str, **overrides: Any) -> dict[str, Any]:
    data: dict[str, Any] = {
        "entry_id": entry_id,
        "thumbnail_ref": f"thumb/{entry_id}.jpg",
        "thumb_width": 400,
        "thumb_height": 300,
        "date": "2026-08-19",
        "device": "dcim",
        "location": "vacation",
    }
    data.update(overrides)
    return data


class AspectRatioTests(unittest.TestCase):
    def test_derived_ratio(self) -> None:
        self.assertEqual(4 / 3, aspect_ratio_for(item("e1")))

    def test_missing_dimensions_use_placeholder_ratio(self) -> None:
        self.assertEqual(4 / 3, aspect_ratio_for(item("e1", thumb_width=None, thumb_height=None)))

    def test_variable_ratios(self) -> None:
        tall = aspect_ratio_for(item("e1", thumb_width=200, thumb_height=600))
        self.assertLess(tall, 1.0)
        wide = aspect_ratio_for(item("e1", thumb_width=1200, thumb_height=300))
        self.assertGreater(wide, 1.0)


class GalleryItemTests(unittest.TestCase):
    def test_missing_thumbnail_flagged(self) -> None:
        rendered = gallery_item(item("e1", thumbnail_ref=None))
        self.assertTrue(rendered.missing_thumbnail)
        self.assertIsNone(rendered.thumbnail_ref)

    def test_duplicate_indicator(self) -> None:
        rendered = gallery_item(item("e1"), duplicate=True)
        self.assertTrue(rendered.duplicate)

    def test_only_derivative_reference_exposed(self) -> None:
        rendered = gallery_item(item("e1"))
        self.assertEqual("thumb/e1.jpg", rendered.thumbnail_ref)


class GalleryPageTests(unittest.TestCase):
    def test_bounded_infinite_cursor(self) -> None:
        rows = [item(f"e{i:05d}") for i in range(100_000)]
        page = gallery_page(rows[:60], limit=60, total=len(rows))
        self.assertEqual(60, len(page.items))
        self.assertTrue(page.has_more)
        self.assertIsNotNone(page.next_cursor)

    def test_failed_thumbnail_keeps_placeholder_ratio(self) -> None:
        rows = [item("e1", thumbnail_ref=None), item("e2")]
        state = gallery_state(rows=rows)
        first = state["items"][0]
        self.assertTrue(first["missing_thumbnail"])
        self.assertGreater(first["placeholder_height"], 0)
        self.assertEqual(300, first["placeholder_width"])


class SelectionTests(unittest.TestCase):
    def test_select_without_opening(self) -> None:
        selection, opened = select_without_opening({}, [item("e1")], activate="e1")
        self.assertTrue(selection["e1"])
        self.assertEqual("e1", opened)

    def test_toggle(self) -> None:
        selection, _ = select_without_opening({"e1": False}, [item("e1")], toggle="e1")
        self.assertTrue(selection["e1"])

    def test_range_selection_with_anchor(self) -> None:
        items = [item("e1"), item("e2"), item("e3"), item("e4")]
        selection, _ = select_without_opening({}, items, anchor="e1", toggle="e3")
        self.assertTrue(selection["e1"])
        self.assertTrue(selection["e2"])
        self.assertTrue(selection["e3"])
        self.assertFalse(selection.get("e4"))


class GroupTests(unittest.TestCase):
    def test_group_by_date(self) -> None:
        groups = group_items([item("e1"), item("e2", date="2026-08-20")], group_by="date")
        self.assertEqual(2, len(groups))
        self.assertEqual("2026-08-19", groups[0]["key"])

    def test_unknown_group_rejected(self) -> None:
        with self.assertRaisesRegex(MediaGalleryError, "unknown_group"):
            group_items([], group_by="color")


class GalleryStateTests(unittest.TestCase):
    def test_safe_rendering_never_original(self) -> None:
        state = gallery_state(rows=[item("e1")])
        self.assertFalse(state["renders_original_content"])
        self.assertIn("thumb/e1.jpg", state["items"][0]["thumbnail_ref"])

    def test_accessibility_labels(self) -> None:
        state = gallery_state(rows=[item("e1")])
        first = state["items"][0]
        self.assertEqual("img", first["role"])
        self.assertEqual("media finding e1", first["aria_label"])

    def test_narrow_viewport_flag(self) -> None:
        state = gallery_state(rows=[item("e1")], narrow_viewport=True)
        self.assertTrue(state["narrow_viewport"])

    def test_error_state(self) -> None:
        state = gallery_state(rows=[], error="thumbnail store unavailable")
        self.assertEqual("thumbnail store unavailable", state["error"])

    def test_version_constant(self) -> None:
        self.assertEqual("media-gallery-v1", MEDIA_GALLERY_VERSION)


if __name__ == "__main__":
    unittest.main()
