#!/usr/bin/env python3

from __future__ import annotations

import unittest
from typing import cast

from worker.export_manifest import (
    EXPORT_MANIFEST_VERSION,
    PlannedPath,
    build_csv_manifest,
    build_json_manifest,
    canonical_manifest_json,
    carved_destination_name,
    formula_safe,
    manifest_sha256,
    plan_export_paths,
    safe_relative_path,
    sanitize_component,
    sanitize_component_bytes,
)
from worker.local_export import ExportItem


def item(item_id: str, path: str, size: int = 100, sha: str = "d" * 64) -> ExportItem:
    return ExportItem(
        export_item_id=item_id,
        source_path=path,
        expected_size=size,
        expected_sha256=sha,
    )


class SanitizeComponentTests(unittest.TestCase):
    def test_plain_component_unchanged(self) -> None:
        component = sanitize_component("report.pdf")
        self.assertEqual("report.pdf", component.name)
        self.assertEqual((), component.warnings)

    def test_reserved_name_recorded(self) -> None:
        component = sanitize_component("CON")
        self.assertEqual("_CON", component.name)
        self.assertIn("reserved_name", component.warnings)

    def test_reserved_with_extension(self) -> None:
        component = sanitize_component("lpt1.txt")
        self.assertEqual("_lpt1.txt", component.name)
        self.assertIn("reserved_name", component.warnings)

    def test_trailing_dot_stripped(self) -> None:
        self.assertEqual("name", sanitize_component("name..").name)

    def test_empty_name_becomes_unnamed(self) -> None:
        component = sanitize_component(" ")
        self.assertEqual("unnamed", component.name)
        self.assertIn("empty_name", component.warnings)

    def test_control_character_recorded(self) -> None:
        component = sanitize_component("a\x00b")
        self.assertIn("control_character", component.warnings)
        self.assertNotIn("\x00", component.name)

    def test_invalid_unicode_bytes(self) -> None:
        component = sanitize_component_bytes(b"bad\xffname")
        self.assertIn("invalid_unicode", component.warnings)


class SafeRelativePathTests(unittest.TestCase):
    def test_hierarchy_preserved(self) -> None:
        relative, warnings = safe_relative_path("photos/2024/IMG_001.jpg")
        self.assertEqual("photos/2024/IMG_001.jpg", relative)
        self.assertEqual((), warnings)

    def test_traversal_recorded_not_passed(self) -> None:
        relative, warnings = safe_relative_path("../secret/../../etc/passwd")
        self.assertIn("path_traversal", warnings)
        self.assertNotIn("..", relative)

    def test_reserved_name_recorded(self) -> None:
        relative, warnings = safe_relative_path("docs/CON.txt")
        self.assertEqual("docs/_CON.txt", relative)
        self.assertIn("reserved_name", warnings)

    def test_duplicate_component_recorded(self) -> None:
        relative, warnings = safe_relative_path("a/a", case_insensitive=True)
        self.assertIn("duplicate_component", warnings)

    def test_long_path_truncated_and_recorded(self) -> None:
        long_path = "x" * 5000
        relative, warnings = safe_relative_path(long_path)
        self.assertIn("long_path_truncated", warnings)
        self.assertLess(len(relative), 4096)

    def test_remote_kind_shorter_limit(self) -> None:
        long_path = "x" * 3000
        relative, warnings = safe_relative_path(long_path, destination_kind="rclone")
        self.assertIn("long_path_truncated", warnings)
        self.assertLess(len(relative), 1024)


class CarvedNamingTests(unittest.TestCase):
    def test_carved_name_from_item(self) -> None:
        name = carved_destination_name(
            item("i1", "volume1/dcim/IMG.001", size=2048), extension="jpg"
        )
        self.assertTrue(name.startswith("carved/"))
        self.assertIn("IMG.001", name)
        self.assertIn("2048", name)
        self.assertTrue(name.endswith(".jpg"))

    def test_carved_without_extension(self) -> None:
        name = carved_destination_name(item("i1", "lost/block", size=0))
        self.assertNotIn("..", name)


class PlanExportPathsTests(unittest.TestCase):
    def test_duplicate_names_get_collision_suffix(self) -> None:
        items = [item("a", "docs/report.pdf"), item("b", "docs/report.pdf")]
        plans, warnings = plan_export_paths(items)
        self.assertEqual("docs/report.pdf", plans[0].destination_path)
        self.assertEqual("docs/report.pdf__1", plans[1].destination_path)
        self.assertTrue(any(w.startswith("collision:") for w in warnings))

    def test_case_insensitive_collision(self) -> None:
        items = [item("a", "docs/Report.pdf"), item("b", "docs/report.pdf")]
        plans, _ = plan_export_paths(items, case_insensitive=True)
        self.assertEqual("docs/report.pdf__1", plans[1].destination_path)

    def test_carved_provenance_uses_carved_path(self) -> None:
        carved = item("c1", "vol/raw/segment", size=4096)
        plans, _ = plan_export_paths(
            [item("a", "docs/x.txt"), carved],
            provenance_of={"c1": "carved"},
        )
        self.assertTrue(plans[1].destination_path.startswith("carved/"))
        self.assertEqual("carved", plans[1].provenance)

    def test_malicious_names_recorded(self) -> None:
        items = [item("a", "../../evil/..\\..\\root.txt"), item("b", "CON")]
        plans, warnings = plan_export_paths(items)
        self.assertIn("path_traversal", warnings)
        self.assertIn("reserved_name", warnings)
        self.assertEqual("evil/root.txt", plans[0].destination_path)
        self.assertEqual("_CON", plans[1].destination_path)


class FormulaSafeTests(unittest.TestCase):
    def test_formula_leaders_neutralized(self) -> None:
        for leader in ("=", "+", "-", "@", "\t", "\r"):
            self.assertTrue(formula_safe(f"{leader}cmd").startswith("'"))

    def test_plain_values_unchanged(self) -> None:
        self.assertEqual("report.pdf", formula_safe("report.pdf"))
        self.assertEqual("", formula_safe(""))
        self.assertEqual("", formula_safe(None))


class ManifestTests(unittest.TestCase):
    def setUp(self) -> None:
        self.items = [item("i1", "photos/a.jpg", size=10), item("i2", "docs/b.pdf", size=20)]
        self.plans, _ = plan_export_paths(self.items)
        self.manifest = build_json_manifest(
            export_id="export_1",
            case_id="case_1",
            plans=self.plans,
            item_hashes={"i1": "a" * 64, "i2": "b" * 64},
            item_sizes={"i1": 10, "i2": 20},
            item_statuses={"i1": "complete", "i2": "complete"},
            app_version="1.0.0",
            tool_versions={"photorec": "7.2"},
            created_at="2026-08-19T10:00:00Z",
        )

    def test_deterministic_json_manifest(self) -> None:
        first = canonical_manifest_json(self.manifest)
        second = build_json_manifest(
            export_id="export_1",
            case_id="case_1",
            plans=self.plans,
            item_hashes={"i1": "a" * 64, "i2": "b" * 64},
            item_sizes={"i1": 10, "i2": 20},
            item_statuses={"i1": "complete", "i2": "complete"},
            app_version="1.0.0",
            tool_versions={"photorec": "7.2"},
            created_at="2026-08-19T10:00:00Z",
        )
        self.assertEqual(first, canonical_manifest_json(second))
        self.assertEqual(64, len(manifest_sha256(self.manifest)))

    def test_manifest_records_hashes_provenance_status(self) -> None:
        items = cast(list[dict[str, object]], self.manifest["items"])
        self.assertEqual(2, len(items))
        self.assertEqual("a" * 64, items[0]["sha256"])
        self.assertEqual("complete", items[0]["status"])
        self.assertEqual("allocated", items[0]["provenance"])

    def test_csv_manifest_formula_safe(self) -> None:
        csv_text = build_csv_manifest(self.manifest)
        self.assertIn("export_item_id,source_display_path", csv_text.splitlines()[0])
        self.assertNotIn("\r", csv_text.replace("\n", ""))

    def test_csv_neutralizes_hostile_cells(self) -> None:
        hostile = build_json_manifest(
            export_id="e",
            case_id="c",
            plans=[PlannedPath("i1", "=HYPERLINK(x)", "docs/=x.csv", "allocated")],
            item_hashes={"i1": "0" * 64},
            item_sizes={"i1": 1},
            item_statuses={"i1": "complete"},
            app_version="1.0.0",
            created_at="2026-08-19T10:00:00Z",
        )
        csv_text = build_csv_manifest(hostile)
        self.assertIn("'=HYPERLINK", csv_text)

    def test_version_constant(self) -> None:
        self.assertEqual("export-manifest-v1", EXPORT_MANIFEST_VERSION)


if __name__ == "__main__":
    unittest.main()
