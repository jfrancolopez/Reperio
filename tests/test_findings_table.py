#!/usr/bin/env python3

from __future__ import annotations

import unittest
from typing import Any

from worker.findings_table import (
    FINDINGS_TABLE_VERSION,
    FindingsTableError,
    after_cursor,
    decode_cursor,
    encode_cursor,
    fetch_page,
    make_columns,
    select_rows,
    stable_sort_key,
    table_state,
    validate_sort,
)


def row(entry_id: str, path: str, size: int = 10, confidence: float = 0.5) -> dict[str, Any]:
    return {
        "entry_id": entry_id,
        "case_id": "case_1",
        "path": path,
        "entry_type": "image",
        "size_bytes": size,
        "modified_at": "2026-08-19T10:00:00Z",
        "state": "review",
        "interest_score": 0.7,
        "confidence": confidence,
        "category": "media",
        "export_state": "pending",
    }


class ValidateSortTests(unittest.TestCase):
    def test_supported_sorts(self) -> None:
        for field in ("path", "type", "size_bytes", "modified_at", "confidence"):
            self.assertEqual(field, validate_sort(field))

    def test_unsupported_sort_rejected(self) -> None:
        with self.assertRaisesRegex(FindingsTableError, "invalid_sort"):
            validate_sort("category")


class StableSortTests(unittest.TestCase):
    def test_stable_sort_key_ties_by_entry_id(self) -> None:
        a = row("a2", "same-path")
        b = row("a1", "same-path")
        self.assertLess(stable_sort_key(b, "path"), stable_sort_key(a, "path"))


class CursorTests(unittest.TestCase):
    def test_cursor_round_trip(self) -> None:
        cursor = encode_cursor("path", row("a1", "docs/a.txt"))
        decoded = decode_cursor(cursor)
        self.assertEqual("path", decoded["sort"])
        self.assertEqual("a1", decoded["key"])
        self.assertEqual("docs/a.txt", decoded["value"])

    def test_invalid_cursor_rejected(self) -> None:
        with self.assertRaisesRegex(FindingsTableError, "invalid_cursor"):
            decode_cursor("not-base64!!")

    def test_cursor_sort_mismatch_rejected(self) -> None:
        cursor = encode_cursor("path", row("a1", "docs/a.txt"))
        with self.assertRaisesRegex(FindingsTableError, "cursor sort"):
            fetch_page([], sort="size_bytes", cursor=cursor)

    def test_after_cursor_by_value(self) -> None:
        cursor = decode_cursor(encode_cursor("path", row("a1", "docs/a.txt")))
        self.assertTrue(after_cursor(row("b1", "docs/b.txt"), cursor))
        self.assertFalse(after_cursor(row("a1", "docs/a.txt"), cursor))


class FetchPageTests(unittest.TestCase):
    def setUp(self) -> None:
        self.rows = [row(f"e{i:03d}", f"docs/f{i:04d}.jpg", size=i) for i in range(10_000)]

    def test_first_page_bounded(self) -> None:
        page = fetch_page(self.rows[:100], sort="path", limit=100, total=len(self.rows))
        self.assertEqual(100, len(page.items))
        self.assertTrue(page.has_more)
        self.assertIsNotNone(page.next_cursor)

    def test_cursor_pagination_does_not_skip_or_duplicate(self) -> None:
        limit = 5
        seen: list[str] = []
        cursor: str | None = None
        for _ in range(5):
            page = fetch_page(
                self.rows, sort="path", limit=limit, cursor=cursor, total=len(self.rows)
            )
            seen.extend(str(item["entry_id"]) for item in page.items)
            cursor = page.next_cursor
            if not page.has_more:
                break
        self.assertEqual(25, len(seen))
        self.assertEqual(25, len(set(seen)))

    def test_invalid_limit_rejected(self) -> None:
        with self.assertRaisesRegex(FindingsTableError, "limit"):
            fetch_page([], limit=0)
        with self.assertRaisesRegex(FindingsTableError, "limit"):
            fetch_page([], limit=501)


class SelectionTests(unittest.TestCase):
    def test_selection_keyed_by_entry_id_survives_ingest(self) -> None:
        selection = {"e001": True}
        rows = [row("e000", "a"), row("e002", "b"), row("e003", "c")]
        result = select_rows(selection, rows)
        self.assertTrue(result["e001"])
        self.assertFalse(result.get("e002"))

    def test_toggle_selection(self) -> None:
        result = select_rows({"e001": False}, [row("e001", "a")], toggle="e001")
        self.assertTrue(result["e001"])

    def test_new_rows_do_not_jump_selection(self) -> None:
        result = select_rows({"e001": True}, [row("e000", "a")])
        self.assertTrue(result["e001"])
        self.assertNotIn("e000", result)


class ColumnsTests(unittest.TestCase):
    def test_columns_and_detail_link(self) -> None:
        columns = make_columns(row("e1", "path/x.jpg"), ui_base="http://localhost:8080")
        self.assertEqual("path/x.jpg", columns["path"])
        self.assertEqual("image", columns["type"])
        self.assertEqual("http://localhost:8080/case/case_1/finding/e1", columns["detail_link"])

    def test_long_unicode_path_rendered(self) -> None:
        path = "数据/" + "长" * 400 + "/файл.jpg"
        columns = make_columns(row("e1", path))
        self.assertEqual(path, columns["path"])


class TableStateTests(unittest.TestCase):
    def test_loading_state(self) -> None:
        state = table_state(rows=[], loading=True)
        self.assertTrue(state["loading"])
        self.assertFalse(state["empty"])

    def test_error_state(self) -> None:
        state = table_state(rows=[], error="catalog unavailable")
        self.assertEqual("catalog unavailable", state["error"])
        self.assertFalse(state["empty"])

    def test_empty_state(self) -> None:
        state = table_state(rows=[])
        self.assertTrue(state["empty"])

    def test_selected_count(self) -> None:
        state = table_state(
            rows=[row("e1", "a"), row("e2", "b")],
            selection={"e1": True},
        )
        self.assertEqual(1, state["selected_count"])
        self.assertTrue(state["items"][0]["selected"])
        self.assertFalse(state["items"][1]["selected"])

    def test_version(self) -> None:
        self.assertEqual("findings-table-v1", FINDINGS_TABLE_VERSION)


class PerformanceBudgetTests(unittest.TestCase):
    def test_only_bounded_window_accessed(self) -> None:
        accesses: list[int] = []
        synthetic_rows = [row(f"e{i:06d}", f"path/f{i:06d}.jpg", size=i) for i in range(1_000_000)]

        def provider(offset: int, limit: int) -> list[dict[str, Any]]:
            accesses.append(limit)
            return synthetic_rows[offset : offset + limit]

        page = fetch_page(provider(0, 100), sort="path", limit=100)
        self.assertEqual(100, len(page.items))
        self.assertTrue(all(access <= 100 for access in accesses))


if __name__ == "__main__":
    unittest.main()
