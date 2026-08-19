#!/usr/bin/env python3

from __future__ import annotations

import importlib.util
import re
import sys
import unittest
from pathlib import Path

REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPOSITORY_ROOT))
sys.path.insert(0, str(REPOSITORY_ROOT / "scripts"))

import design_system_check  # noqa: E402

FRONTEND_TEST_PATH = REPOSITORY_ROOT / "scripts" / "frontend-test.py"
_FRONTEND_SPEC = importlib.util.spec_from_file_location("frontend_test", FRONTEND_TEST_PATH)
assert _FRONTEND_SPEC is not None and _FRONTEND_SPEC.loader is not None
frontend_test = importlib.util.module_from_spec(_FRONTEND_SPEC)
_FRONTEND_SPEC.loader.exec_module(frontend_test)

ROOT = Path(__file__).resolve().parents[1]
CATALOG_TEXT = design_system_check.CATALOG_PATH.read_text(encoding="utf-8")


class DesignSystemGateTests(unittest.TestCase):
    def test_full_gate_passes(self) -> None:
        self.assertEqual([], design_system_check.check_design_system())

    def test_frontend_test_gate_passes(self) -> None:
        self.assertEqual([], frontend_test.check_frontend())

    def test_tokens_schema_version_is_1(self) -> None:
        tokens = design_system_check.load_document(design_system_check.TOKENS_PATH)
        self.assertEqual(1, tokens["schema_version"])

    def test_contrast_ratio_helper(self) -> None:
        self.assertAlmostEqual(21.0, design_system_check.contrast_ratio("#000000", "#ffffff"))
        self.assertAlmostEqual(1.0, design_system_check.contrast_ratio("#111111", "#111111"))

    def test_declared_contrast_pairs_meet_wcag_aa(self) -> None:
        tokens = design_system_check.load_document(design_system_check.TOKENS_PATH)
        self.assertEqual([], design_system_check.check_contrast(tokens))


class CatalogKeyboardAndAccessibilityTests(unittest.TestCase):
    def test_every_input_has_an_associated_label(self) -> None:
        input_ids = set(re.findall(r'<input[^>]*\bid="([^"]+)"', CATALOG_TEXT))
        labels_for = set(re.findall(r'<label[^>]*\bfor="([^"]+)"', CATALOG_TEXT))
        self.assertEqual(set(), input_ids - labels_for)

    def test_interactive_elements_are_keyboard_reachable(self) -> None:
        focusable_controls = re.findall(r"<(button|input|select)\b", CATALOG_TEXT)
        self.assertGreater(len(focusable_controls), 5)
        self.assertNotIn('tabindex="-1"', CATALOG_TEXT)

    def test_visible_focus_ring_is_defined(self) -> None:
        self.assertIn(":focus-visible", CATALOG_TEXT)
        self.assertIn("var(--rpr-focus-ring)", CATALOG_TEXT)

    def test_dialog_is_modal_accessible(self) -> None:
        self.assertIn('role="dialog"', CATALOG_TEXT)
        self.assertIn('aria-modal="true"', CATALOG_TEXT)
        self.assertIn('aria-label="Dismiss confirmation"', CATALOG_TEXT)

    def test_status_regions_are_present(self) -> None:
        self.assertEqual(2, CATALOG_TEXT.count('role="status"'))

    def test_no_third_party_branding_or_remote_assets(self) -> None:
        self.assertEqual(
            [],
            design_system_check.check_catalog(
                design_system_check.load_document(design_system_check.TOKENS_PATH),
                design_system_check.parse_css_properties(
                    design_system_check.TOKENS_CSS_PATH.read_text(encoding="utf-8")
                ),
                CATALOG_TEXT,
            ),
        )

    def test_all_var_references_resolve_to_tokens(self) -> None:
        css_properties = design_system_check.parse_css_properties(
            design_system_check.TOKENS_CSS_PATH.read_text(encoding="utf-8")
        )
        used = set(re.findall(r"var\((--rpr-[a-z0-9-]+)\)", CATALOG_TEXT))
        self.assertEqual(set(), used - set(css_properties))


if __name__ == "__main__":
    unittest.main()
