#!/usr/bin/env python3
"""App-shell gate for RPR-117.

Deterministically verifies the application shell and navigation without a
browser or third-party dependency:

- ``web/app-shell/index.html`` defines the responsive sidebar/top status, all
  planned tabs, case/source context, connection-state indicator, a persistent
  unauthenticated-LAN critical warning, route-level loading/error boundaries,
  a strict single-origin CSP, and no remote assets or inline scripts.
- ``web/app-shell/app-shell.css`` uses only ``--rpr-*`` tokens (verified against
  the derived tokens.css) and keeps keyboard/reduced-motion requirements.
- ``web/app-shell/app-shell.js`` is dependency-free: EventSource with bounded
  SSE reconnect (backoff and attempt cap), route boundary helpers that write
  dynamic text with ``textContent`` only, no ``innerHTML``, ``eval``, or
  ``document.write``, and no inline event handlers.

The shell never renders source HTML, SVG, scripts, or active document content.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "scripts"))

from design_system_check import VAR_RE, parse_css_properties  # noqa: E402

SHELL_DIR = ROOT / "web" / "app-shell"
INDEX_PATH = SHELL_DIR / "index.html"
CSS_PATH = SHELL_DIR / "app-shell.css"
JS_PATH = SHELL_DIR / "app-shell.js"
TOKENS_CSS_PATH = ROOT / "web" / "design-system" / "tokens.css"

TABS = (
    "dashboard",
    "scan",
    "findings",
    "media",
    "browser",
    "export",
    "settings",
    "notifications",
)

REMOTE_URL_RE = re.compile(r"(?:src|href)=[\"']https?://", re.IGNORECASE)
CSP_MARKERS = (
    "default-src 'self'",
    "script-src 'self'",
    "object-src 'none'",
    "base-uri 'none'",
)


def check_index(html_text: str, css_properties: dict[str, str]) -> list[str]:
    failures: list[str] = []
    label = INDEX_PATH.relative_to(ROOT)
    for required in (
        "<!doctype html>",
        'lang="en"',
        '<meta charset="utf-8">',
        'name="viewport"',
        "tokens.css",
        "app-shell.css",
        "app-shell.js",
        'id="route-view"',
        'id="route-error"',
        'id="route-loading"',
        'id="connection-state"',
        'id="case-context"',
        'id="lan-warning"',
    ):
        if required not in html_text:
            failures.append(f"{label}: missing {required!r}")

    for marker in CSP_MARKERS:
        if marker not in html_text:
            failures.append(f"{label}: CSP must include {marker!r}")

    remote = REMOTE_URL_RE.findall(html_text)
    if remote:
        failures.append(f"{label}: remote assets are forbidden: {', '.join(remote)}")

    if re.search(r"<script(?![^>]*\bsrc=)[^>]*>", html_text):
        failures.append(f"{label}: inline scripts are forbidden")

    for tab in TABS:
        if f'href="#{tab}"' not in html_text:
            failures.append(f"{label}: missing tab #{tab}")

    if 'role="alert"' not in html_text or 'data-critical="true"' not in html_text:
        failures.append(f"{label}: LAN warning must be an alert and critical")

    used = sorted(set(VAR_RE.findall(html_text)))
    undefined = [name for name in used if name not in css_properties]
    if undefined:
        failures.append(
            f"{label}: undefined token references in inline style: {', '.join(undefined)}"
        )

    return failures


def check_css(css_text: str, css_properties: dict[str, str]) -> list[str]:
    failures: list[str] = []
    label = CSS_PATH.relative_to(ROOT)
    used = sorted(set(VAR_RE.findall(css_text)))
    undefined = [name for name in used if name not in css_properties]
    if undefined:
        failures.append(f"{label}: undefined token references: {', '.join(undefined)}")
    if ":focus-visible" not in css_text:
        failures.append(f"{label}: missing :focus-visible focus ring rule")
    if "@media (prefers-reduced-motion" not in css_text:
        failures.append(f"{label}: missing prefers-reduced-motion rule")
    if "@media (max-width: 720px)" not in css_text:
        failures.append(f"{label}: missing responsive sidebar rule")
    return failures


def check_js(js_text: str) -> list[str]:
    failures: list[str] = []
    label = JS_PATH.relative_to(ROOT)
    if '"use strict";' not in js_text:
        failures.append(f"{label}: missing 'use strict'")
    if "new EventSource(" not in js_text:
        failures.append(f"{label}: missing EventSource connection")
    if "MAX_RECONNECT_ATTEMPTS" not in js_text or "setTimeout" not in js_text:
        failures.append(f"{label}: missing bounded reconnect schedule")
    for forbidden, pattern in (
        ("innerHTML assignment", re.compile(r"innerHTML\s*=")),
        ("outerHTML assignment", re.compile(r"outerHTML\s*=")),
        ("eval", re.compile(r"\beval\s*\(")),
        ("document.write", re.compile(r"document\.write\s*\(")),
        ("insertAdjacentHTML", re.compile(r"insertAdjacentHTML\s*\(")),
    ):
        if pattern.search(js_text):
            failures.append(f"{label}: forbidden API {forbidden}")
    if "textContent" not in js_text:
        failures.append(f"{label}: dynamic text must use textContent")
    if re.search(r"\bon\w+=", js_text):
        failures.append(f"{label}: inline event handlers are forbidden")
    return failures


def check_app_shell() -> list[str]:
    failures: list[str] = []
    if not INDEX_PATH.exists() or not CSS_PATH.exists() or not JS_PATH.exists():
        return [f"{SHELL_DIR.relative_to(ROOT)}: app shell files are missing"]
    try:
        css_properties = parse_css_properties(TOKENS_CSS_PATH.read_text(encoding="utf-8"))
    except OSError as error:
        return [f"{TOKENS_CSS_PATH.relative_to(ROOT)}: cannot read tokens.css: {error}"]

    try:
        failures.extend(check_index(INDEX_PATH.read_text(encoding="utf-8"), css_properties))
        failures.extend(check_css(CSS_PATH.read_text(encoding="utf-8"), css_properties))
        failures.extend(check_js(JS_PATH.read_text(encoding="utf-8")))
    except OSError as error:
        failures.append(f"{SHELL_DIR.relative_to(ROOT)}: cannot read shell files: {error}")
    return failures


def main() -> int:
    failures = check_app_shell()
    if failures:
        print("FAIL: app shell")
        for failure in failures:
            print(f"  - {failure}")
        return 1
    print("PASS: app shell")
    return 0


if __name__ == "__main__":
    sys.exit(main())
