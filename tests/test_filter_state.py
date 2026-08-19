#!/usr/bin/env python3

from __future__ import annotations

import unittest
from typing import Any

from worker.filter_state import (
    FILTER_STATE_VERSION,
    FilterStateError,
    apply_filters,
    decode_url_state,
    encode_url_state,
    export_filter_snapshot,
    facet_counts,
    filter_matches,
    normalize_filter_state,
    saved_view,
)


def row(**overrides: Any) -> dict[str, Any]:
    data: dict[str, Any] = {
        "entry_id": "e1",
        "volume_id": "vol_1",
        "display_path": "photos/IMG_001.jpg",
        "display_name": "IMG_001.jpg",
        "category": "media",
        "owner_id": "alice",
        "size_bytes": 2048,
        "modified_at": "2026-08-19T10:00:00Z",
        "allocation": "allocated",
        "encrypted": False,
        "corrupt": False,
        "duplicate": False,
        "interest_score": 0.8,
        "system_noise": "none",
        "export_state": "pending",
        "dismissed": False,
    }
    data.update(overrides)
    return data


class NormalizeTests(unittest.TestCase):
    def test_noise_inclusion_is_explicit_and_defaults_false(self) -> None:
        state = normalize_filter_state({})
        self.assertFalse(state.include_noise)
        self.assertFalse(state.explicit_include_noise)
        self.assertTrue("include_noise" in export_filter_snapshot(state)["filter_state"])

    def test_opt_in_noise_is_surface(self) -> None:
        state = normalize_filter_state({"include_noise": True})
        self.assertTrue(state.explicit_include_noise)

    def test_invalid_types_ignored_safely(self) -> None:
        state = normalize_filter_state({"users": "alice", "min_size": "abc"})
        self.assertEqual((), state.users)
        self.assertIsNone(state.min_size)


class FilterMatchTests(unittest.TestCase):
    def test_no_filters_match_everything_except_noise(self) -> None:
        self.assertTrue(filter_matches(row(), normalize_filter_state({})))
        self.assertFalse(filter_matches(row(system_noise="noise"), normalize_filter_state({})))

    def test_noise_included_when_explicit(self) -> None:
        state = normalize_filter_state({"include_noise": True})
        self.assertTrue(filter_matches(row(system_noise="noise"), state))

    def test_text_search(self) -> None:
        state = normalize_filter_state({"text": "IMG_001"})
        self.assertTrue(filter_matches(row(), state))
        self.assertFalse(
            filter_matches(row(display_path="other/other.jpg", display_name="other.jpg"), state)
        )

    def test_facet_combinations(self) -> None:
        state = normalize_filter_state(
            {"categories": ["media"], "users": ["alice"], "min_size": 1000}
        )
        self.assertTrue(filter_matches(row(), state))
        self.assertFalse(filter_matches(row(owner_id="bob"), state))
        self.assertFalse(filter_matches(row(size_bytes=500), state))

    def test_boolean_facets(self) -> None:
        self.assertFalse(
            filter_matches(row(encrypted=True), normalize_filter_state({"encrypted": False}))
        )
        self.assertTrue(
            filter_matches(row(encrypted=True), normalize_filter_state({"encrypted": True}))
        )
        self.assertTrue(
            filter_matches(row(duplicate=True), normalize_filter_state({"duplicates": True}))
        )

    def test_date_and_allocation_range(self) -> None:
        state = normalize_filter_state(
            {"date_from": "2026-08-01", "date_to": "2026-08-31", "allocations": ["allocated"]}
        )
        self.assertTrue(filter_matches(row(), state))
        self.assertFalse(filter_matches(row(modified_at="2026-07-01T00:00:00Z"), state))

    def test_interest_threshold(self) -> None:
        state = normalize_filter_state({"min_interest": 0.9})
        self.assertFalse(filter_matches(row(interest_score=0.8), state))

    def test_exported_and_dismissed_excluded_unless_requested(self) -> None:
        self.assertFalse(filter_matches(row(export_state="exported"), normalize_filter_state({})))
        self.assertTrue(
            filter_matches(
                row(export_state="exported"), normalize_filter_state({"include_exported": True})
            )
        )
        self.assertFalse(filter_matches(row(dismissed=True), normalize_filter_state({})))
        self.assertTrue(
            filter_matches(row(dismissed=True), normalize_filter_state({"include_dismissed": True}))
        )


class ApplyFiltersTests(unittest.TestCase):
    def test_zero_results(self) -> None:
        rows = [row(), row(category="docs")]
        filtered = apply_filters(rows, normalize_filter_state({"categories": ["wallets"]}))
        self.assertEqual(0, len(filtered))

    def test_counts_reflect_filter_state(self) -> None:
        rows = [row(), row(), row(category="docs")]
        filtered = apply_filters(rows, normalize_filter_state({"categories": ["media"]}))
        self.assertEqual(2, len(filtered))


class FacetTests(unittest.TestCase):
    def test_facet_counts_within_filtered_set(self) -> None:
        rows = [row(category="media"), row(category="media"), row(category="docs")]
        counts = facet_counts(rows, normalize_filter_state({}), key="categories")
        self.assertEqual({"docs": 1, "media": 2}, counts)

    def test_unknown_facet_rejected(self) -> None:
        with self.assertRaisesRegex(FilterStateError, "unknown_facet"):
            facet_counts([], normalize_filter_state({}), key="nonsense")


class UrlStateTests(unittest.TestCase):
    def test_round_trip(self) -> None:
        state = normalize_filter_state({"categories": ["media"], "include_noise": True})
        decoded = decode_url_state(encode_url_state(state))
        self.assertEqual(state, decoded)

    def test_invalid_token_rejected(self) -> None:
        with self.assertRaisesRegex(FilterStateError, "invalid_url_state"):
            decode_url_state("###")

    def test_wrong_version_rejected(self) -> None:
        import base64
        import json

        token = base64.urlsafe_b64encode(
            json.dumps({"version": "old", "state": {}}).encode("utf-8")
        ).decode("ascii")
        with self.assertRaisesRegex(FilterStateError, "invalid_url_state"):
            decode_url_state(token)


class SavedViewTests(unittest.TestCase):
    def test_saved_view_is_immutable_snapshot(self) -> None:
        state = normalize_filter_state({"text": "wallet", "include_noise": False})
        view = saved_view(
            view_id="v1", name="Wallets", state=state, created_at="2026-08-19T10:00:00Z"
        )
        self.assertEqual(FILTER_STATE_VERSION, view["view_version"])
        self.assertEqual("wallet", view["filter_state"]["text"])
        self.assertFalse(view["filter_state"]["include_noise"])

    def test_export_snapshot_has_explicit_noise_flag(self) -> None:
        state = normalize_filter_state({})
        snapshot = export_filter_snapshot(state)
        self.assertIn("explicit_include_noise", snapshot)
        self.assertIn("snapshot_version", snapshot)


if __name__ == "__main__":
    unittest.main()
