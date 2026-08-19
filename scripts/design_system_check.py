#!/usr/bin/env python3
"""Design-system gate for RPR-116.

Validates the versioned design-token source, the derived tokens.css, and the
static accessible component catalog without any third-party dependency:

- ``web/design-system/tokens.json`` conforms to its JSON Schema.
- ``web/design-system/tokens.css`` defines exactly the custom properties that
  derive from tokens.json, with matching values (no ad-hoc values).
- Every ``var(--rpr-*)`` referenced by ``web/design-system/catalog.html``
  resolves to a token custom property.
- Declared foreground/background pairs meet WCAG 2.1 AA contrast ratios in both
  light and dark themes.
- The catalog contains no remote assets or third-party branding and satisfies
  keyboard/focus/contrast structure basics: visible focus ring, reduced-motion
  handling, labelled inputs, and correctly exposed dialogs/status regions.

Screenshots remain a manual release check (recorded in RPR-116 acceptance);
the automated contract above runs in CI.
"""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "scripts"))

from check_schema_compat import load_document, validate_schema  # noqa: E402

TOKENS_PATH = ROOT / "web" / "design-system" / "tokens.json"
SCHEMA_PATH = ROOT / "scripts" / "schemas" / "design-tokens.schema.json"
TOKENS_CSS_PATH = ROOT / "web" / "design-system" / "tokens.css"
CATALOG_PATH = ROOT / "web" / "design-system" / "catalog.html"

CSS_PROPERTY_RE = re.compile(r"(--rpr-[a-z0-9-]+)\s*:\s*([^;]+);")
VAR_RE = re.compile(r"var\((--rpr-[a-z0-9-]+)\)")
HEX_RE = re.compile(r"^#[0-9a-fA-F]{6}$")
REMOTE_URL_RE = re.compile(r"(?:src|href)=[\"']https?://", re.IGNORECASE)
MEDIA_DARK_MARKER = "@media (prefers-color-scheme: dark)"


def expected_custom_properties(tokens: dict) -> dict[str, str]:
    """Derive the exact set of custom properties tokens.css must define."""
    expected: dict[str, str] = {}

    for name, value in tokens["colors"].items():
        expected[f"--rpr-{name}"] = value["light"]
        expected[f"--rpr-{name}-dark"] = value["dark"]
    for name, value in tokens["status"].items():
        expected[f"--rpr-status-{name}"] = value["light"]
        expected[f"--rpr-status-{name}-dark"] = value["dark"]
    for name, value in tokens["spacing"].items():
        expected[f"--rpr-space-{name}"] = value
    for name, value in tokens["radii"].items():
        expected[f"--rpr-radius-{name}"] = value
    expected["--rpr-font-family"] = tokens["typography"]["font-family"]["value"]
    for name, value in tokens["typography"]["scale"].items():
        expected[f"--rpr-font-{name}"] = value
    for name, value in tokens["typography"]["weights"].items():
        expected[f"--rpr-weight-{name}"] = value
    return expected


def parse_css_properties(text: str) -> dict[str, str]:
    return {match.group(1): match.group(2).strip() for match in CSS_PROPERTY_RE.finditer(text)}


def _split_theme_blocks(css_text: str) -> tuple[dict[str, str], dict[str, str]]:
    """Split tokens.css into base (:root) and dark-theme override properties."""
    marker = MEDIA_DARK_MARKER
    if marker in css_text:
        base_text, media_text = css_text.split(marker, 1)
    else:
        base_text, media_text = css_text, ""
    base = parse_css_properties(base_text)
    media = parse_css_properties(media_text)
    return base, media


def check_tokens_schema(tokens: dict, schema: dict) -> list[str]:
    return [
        f"{TOKENS_PATH.relative_to(ROOT)}: {failure}"
        for failure in validate_schema(schema, schema, tokens, "tokens.json")
    ]


def check_css_derivation(tokens: dict, css_text: str) -> list[str]:
    expected = expected_custom_properties(tokens)
    base, media = _split_theme_blocks(css_text)
    failures: list[str] = []

    extra = sorted(set(base) - set(expected))
    if extra:
        failures.append(
            f"{TOKENS_CSS_PATH.relative_to(ROOT)}: undeclared ad-hoc properties: {', '.join(extra)}"
        )
    missing = sorted(set(expected) - set(base))
    if missing:
        failures.append(
            f"{TOKENS_CSS_PATH.relative_to(ROOT)}: missing derived properties: {', '.join(missing)}"
        )
    for name in sorted(set(expected) & set(base)):
        if base[name] != expected[name]:
            failures.append(
                f"{TOKENS_CSS_PATH.relative_to(ROOT)}: {name} value {base[name]!r} "
                f"does not match token {expected[name]!r}"
            )

    override_names = {name.removeprefix("--rpr-") for name in media if not name.endswith("-dark")}
    expected_overrides = {
        name.removeprefix("--rpr-")
        for name in expected
        if not name.endswith("-dark")
        and f"{name}-dark" in expected
        and expected[name] != expected[f"{name}-dark"]
    }
    unexpected_overrides = sorted(override_names - expected_overrides)
    if unexpected_overrides:
        failures.append(
            f"{TOKENS_CSS_PATH.relative_to(ROOT)}: unexpected dark-theme overrides: "
            f"{', '.join(unexpected_overrides)}"
        )
    missing_overrides = sorted(expected_overrides - override_names)
    if missing_overrides:
        failures.append(
            f"{TOKENS_CSS_PATH.relative_to(ROOT)}: missing dark-theme overrides: "
            f"{', '.join(missing_overrides)}"
        )
    for name in sorted(expected_overrides & override_names):
        property_name = f"--rpr-{name}"
        if media.get(property_name) != expected.get(f"{property_name}-dark"):
            failures.append(
                f"{TOKENS_CSS_PATH.relative_to(ROOT)}: dark override for {property_name} "
                f"must equal token dark value {expected.get(property_name + '-dark')!r}"
            )
    return failures


def _channel(channel: int) -> float:
    scaled = channel / 255.0
    if scaled <= 0.03928:
        return scaled / 12.92
    return float(((scaled + 0.055) / 1.055) ** 2.4)


def _luminance(hex_color: str) -> float:
    red = int(hex_color[1:3], 16)
    green = int(hex_color[3:5], 16)
    blue = int(hex_color[5:7], 16)
    return 0.2126 * _channel(red) + 0.7152 * _channel(green) + 0.0722 * _channel(blue)


def contrast_ratio(fg: str, bg: str) -> float:
    lighter = max(_luminance(fg), _luminance(bg))
    darker = min(_luminance(fg), _luminance(bg))
    return (lighter + 0.05) / (darker + 0.05)


def check_contrast(tokens: dict) -> list[str]:
    colors = tokens["colors"]
    failures: list[str] = []
    for pair in tokens.get("contrastPairs", []):
        fg_name = pair.get("fg")
        bg_name = pair.get("bg")
        minimum = pair.get("minRatio")
        for theme in ("light", "dark"):
            fg = (colors.get(fg_name) or {}).get(theme)
            bg = (colors.get(bg_name) or {}).get(theme)
            if not isinstance(fg, str) or not HEX_RE.match(fg):
                failures.append(
                    f"contrast pair {fg_name}/{bg_name}: unknown color in {theme} theme"
                )
                continue
            if not isinstance(bg, str) or not HEX_RE.match(bg):
                failures.append(
                    f"contrast pair {fg_name}/{bg_name}: unknown color in {theme} theme"
                )
                continue
            ratio = contrast_ratio(fg, bg)
            if ratio < minimum:
                failures.append(
                    f"contrast pair {fg_name}/{bg_name} ({theme}): ratio {ratio:.2f} "
                    f"below minimum {minimum}"
                )
    return failures


def check_catalog(tokens: dict, css_properties: dict[str, str], catalog_text: str) -> list[str]:
    failures: list[str] = []
    label = CATALOG_PATH.relative_to(ROOT)

    remote = REMOTE_URL_RE.findall(catalog_text)
    if remote:
        failures.append(f"{label}: remote assets are forbidden: {', '.join(remote)}")

    used = sorted(set(VAR_RE.findall(catalog_text)))
    undefined = [name for name in used if name not in css_properties]
    if undefined:
        failures.append(f"{label}: undefined token references: {', '.join(undefined)}")

    if ":focus-visible" not in catalog_text:
        failures.append(f"{label}: missing :focus-visible focus ring rule")
    if "@media (prefers-reduced-motion" not in catalog_text:
        failures.append(f"{label}: missing prefers-reduced-motion rule")

    input_ids = set(re.findall(r'<input[^>]*\bid="([^"]+)"', catalog_text))
    labels_for = set(re.findall(r'<label[^>]*\bfor="([^"]+)"', catalog_text))
    unlabelled = input_ids - labels_for
    if unlabelled:
        failures.append(
            f"{label}: inputs without label association: {', '.join(sorted(unlabelled))}"
        )

    dialogs = catalog_text.count('role="dialog"')
    aria_modal = catalog_text.count('aria-modal="true"')
    if dialogs and dialogs != aria_modal:
        failures.append(f'{label}: every dialog must set aria-modal="true"')
    for required in ('role="dialog"', "aria-label", 'role="status"'):
        if required not in catalog_text:
            failures.append(f"{label}: missing required a11y attribute {required!r}")

    return failures


def check_design_system() -> list[str]:
    failures: list[str] = []
    if not TOKENS_PATH.exists():
        return [f"{TOKENS_PATH.relative_to(ROOT)}: design tokens are missing"]
    try:
        tokens = load_document(TOKENS_PATH)
    except (OSError, json.JSONDecodeError) as error:
        return [f"{TOKENS_PATH.relative_to(ROOT)}: cannot read tokens: {error}"]

    try:
        schema = load_document(SCHEMA_PATH)
    except (OSError, json.JSONDecodeError) as error:
        return [f"{SCHEMA_PATH.relative_to(ROOT)}: cannot read schema: {error}"]

    failures.extend(check_tokens_schema(tokens, schema))
    failures.extend(check_contrast(tokens))

    try:
        css_text = TOKENS_CSS_PATH.read_text(encoding="utf-8")
    except OSError as error:
        return [*failures, f"{TOKENS_CSS_PATH.relative_to(ROOT)}: cannot read tokens.css: {error}"]
    failures.extend(check_css_derivation(tokens, css_text))
    css_properties = parse_css_properties(css_text)

    try:
        catalog_text = CATALOG_PATH.read_text(encoding="utf-8")
    except OSError as error:
        return [*failures, f"{CATALOG_PATH.relative_to(ROOT)}: cannot read catalog: {error}"]
    failures.extend(check_catalog(tokens, css_properties, catalog_text))

    return failures


def main() -> int:
    failures = check_design_system()
    if failures:
        print("FAIL: design system")
        for failure in failures:
            print(f"  - {failure}")
        return 1
    print("PASS: design system")
    return 0


if __name__ == "__main__":
    sys.exit(main())
