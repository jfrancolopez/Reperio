#!/usr/bin/env python3

from __future__ import annotations

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "scripts"))

import app_shell_check  # noqa: E402
from design_system_check import parse_css_properties  # noqa: E402


def css_properties() -> dict[str, str]:
    return parse_css_properties(
        (ROOT / "web" / "design-system" / "tokens.css").read_text(encoding="utf-8")
    )


class AppShellGateTests(unittest.TestCase):
    def test_real_app_shell_passes(self) -> None:
        self.assertEqual([], app_shell_check.check_app_shell())

    def test_all_planned_tabs_present(self) -> None:
        html = (ROOT / "web" / "app-shell" / "index.html").read_text(encoding="utf-8")
        for tab in app_shell_check.TABS:
            self.assertIn(f'href="#{tab}"', html)

    def test_connection_state_and_case_context_regions_present(self) -> None:
        html = (ROOT / "web" / "app-shell" / "index.html").read_text(encoding="utf-8")
        self.assertIn('id="connection-state"', html)
        self.assertIn('role="status"', html)
        self.assertIn('id="case-context"', html)

    def test_lan_warning_is_critical_and_persistent(self) -> None:
        html = (ROOT / "web" / "app-shell" / "index.html").read_text(encoding="utf-8")
        self.assertIn('data-critical="true"', html)
        self.assertIn('role="alert"', html)
        self.assertNotIn("dismiss", html.lower())

    def test_route_boundaries_exist(self) -> None:
        html = (ROOT / "web" / "app-shell" / "index.html").read_text(encoding="utf-8")
        self.assertIn('aria-busy="true"', html)
        self.assertIn('id="route-error"', html)
        self.assertIn('role="alert"', html)
        self.assertIn('id="route-loading"', html)


class AppShellFailurePathTests(unittest.TestCase):
    def test_inline_script_is_rejected(self) -> None:
        html = "<script>alert(1)</script>"
        failures = app_shell_check.check_index(html, css_properties())
        self.assertTrue(any("inline scripts" in failure for failure in failures))

    def test_remote_asset_is_rejected(self) -> None:
        html = '<script src="https://evil.example/x.js"></script>'
        failures = app_shell_check.check_index(html, css_properties())
        self.assertTrue(any("remote assets" in failure for failure in failures))

    def test_missing_lan_warning_is_rejected(self) -> None:
        html = '<div id="lan-warning">warning</div>'
        failures = app_shell_check.check_index(html, css_properties())
        self.assertTrue(any("LAN warning" in failure for failure in failures))

    def test_innerhtml_is_rejected(self) -> None:
        js = "node.innerHTML = value;"
        failures = app_shell_check.check_js(js)
        self.assertTrue(any("innerHTML" in failure for failure in failures))

    def test_eval_is_rejected(self) -> None:
        js = "eval(payload);"
        failures = app_shell_check.check_js(js)
        self.assertTrue(any("eval" in failure for failure in failures))

    def test_unbounded_reconnect_is_rejected(self) -> None:
        js = "function reconnect() { setTimeout(reconnect, 1000); }"
        failures = app_shell_check.check_js(js)
        self.assertTrue(any("bounded reconnect" in failure for failure in failures))

    def test_js_uses_textcontent_not_innerhtml(self) -> None:
        js = (ROOT / "web" / "app-shell" / "app-shell.js").read_text(encoding="utf-8")
        self.assertIn("textContent", js)
        self.assertNotIn("innerHTML", js)


if __name__ == "__main__":
    unittest.main()
