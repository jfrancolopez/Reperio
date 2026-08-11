#!/usr/bin/env python3
"""Schema compatibility gate (RPR-006).

Every versioned JSON document in the repository must be matched by a JSON
Schema held under ``scripts/schemas/<stem>.schema.json``. The schema declares
its version inside its ``$id`` URI (``.../v<N>``); the data document must carry
a matching ``schema_version`` (backwards-compatible reject: a newer document is
refused until the schema is migrated). Structural compliance is checked with a
small dependency-free draft-07 subset (type/required/properties/items/$ref/
enum/const) deliberately large enough for registry, license-policy, and the
fixtures that exercise them.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCHEMAS_DIR = ROOT / "scripts" / "schemas"
VERSIONED_DOCUMENTS = (
    ROOT / "docs" / "dependency-registry.json",
    ROOT / "scripts" / "dependency-license-policy.json",
)

CANONICAL_STEMS = ("dependency-registry", "dependency-license-policy")

VERSION_RE = re.compile(r"/v(\d+)$")


def load_document(path: Path) -> dict:
    with path.open(encoding="utf-8") as handle:
        data = json.load(handle)
    if not isinstance(data, dict):
        raise SystemExit(f"{path.relative_to(ROOT)}: expected a JSON object")
    return data


def canonical_stem_for(data_path: Path) -> str | None:
    for stem in CANONICAL_STEMS:
        if data_path.name == f"{stem}.json" or data_path.name.startswith(f"{stem}_"):
            return stem
    return None


def schema_path_for(data_path: Path) -> Path:
    stem = canonical_stem_for(data_path)
    if stem is None:
        return SCHEMAS_DIR / "unknown.schema.json"
    return SCHEMAS_DIR / f"{stem}.schema.json"


def schema_version_from_id(document_id: object) -> int | None:
    if not isinstance(document_id, str):
        return None
    match = VERSION_RE.search(document_id)
    if not match:
        return None
    return int(match.group(1))


def _json_type(value: object) -> str:
    if value is None:
        return "null"
    if isinstance(value, bool):
        return "boolean"
    if isinstance(value, int):
        return "integer"
    if isinstance(value, float):
        return "number"
    if isinstance(value, str):
        return "string"
    if isinstance(value, list):
        return "array"
    return "object"


def _dereference(document: dict, reference: str, path: str) -> tuple[dict, list[str]]:
    if not reference.startswith("#/"):
        return {}, [f"{path}: unsupported $ref {reference!r}"]
    node: dict = document
    for part in reference[2:].split("/"):
        part = part.replace("~1", "/").replace("~0", "~")
        if isinstance(node, dict) and part in node and isinstance(node[part], dict):
            node = node[part]
        else:
            return {}, [f"{path}: unresolvable $ref {reference!r}"]
    return node, []


def validate_schema(document: dict, schema: dict, value: object, path: str) -> list[str]:
    failures: list[str] = []

    reference = schema.get("$ref")
    if isinstance(reference, str):
        ref_schema, ref_errors = _dereference(document, reference, path)
        failures.extend(ref_errors)
        if ref_schema:
            failures.extend(validate_schema(document, ref_schema, value, path))
        return failures

    if "const" in schema:
        if value != schema["const"]:
            failures.append(f"{path}: expected const {schema['const']!r}, got {value!r}")
        return failures

    expected = schema.get("type")
    observation = _json_type(value)
    if isinstance(expected, str) and observation != expected:
        failures.append(f"{path}: expected type {expected!r}, got {observation!r}")
        return failures

    if observation == "object":
        required = schema.get("required")
        if isinstance(required, list):
            for key in required:
                if not isinstance(value, dict) or key not in value:
                    failures.append(f"{path}: missing required property {key!r}")
        properties = schema.get("properties")
        if isinstance(properties, dict) and isinstance(value, dict):
            for key, sub_schema in properties.items():
                if key in value:
                    failures.extend(
                        validate_schema(document, sub_schema, value[key], f"{path}.{key}")
                    )

    if observation == "array":
        items = schema.get("items")
        if isinstance(items, dict) and isinstance(value, list):
            for index, item in enumerate(value):
                failures.extend(validate_schema(document, items, item, f"{path}[{index}]"))

    enumeration = schema.get("enum")
    if isinstance(enumeration, list) and value not in enumeration:
        failures.append(f"{path}: {value!r} is not one of {enumeration}")

    return failures


def check_schema_compatibility(data_path: Path) -> list[str]:
    failures: list[str] = []
    data_path = data_path.resolve()
    label = data_path.relative_to(ROOT)

    try:
        document = load_document(data_path)
    except (OSError, json.JSONDecodeError) as error:
        return [f"{label}: cannot read document for schema check: {error}"]

    schema_path = schema_path_for(data_path)
    if canonical_stem_for(data_path) is None or not schema_path.exists():
        return [f"{label}: no schema found for this document kind"]

    try:
        schema = load_document(schema_path)
    except (OSError, json.JSONDecodeError) as error:
        return [f"{schema_path.relative_to(ROOT)}: cannot read schema: {error}"]

    schema_version = schema_version_from_id(schema.get("$id"))
    if schema_version is None:
        failures.append(f"{schema_path.relative_to(ROOT)}: $id must end in /v<N>")

    data_version = document.get("schema_version")
    if data_version != schema_version:
        failures.append(
            f"{label}: schema_version {data_version!r} does not match "
            f"schema {schema_path.relative_to(ROOT)} version {schema_version!r}"
        )

    failures.extend(validate_schema(schema, schema, document, str(label)))

    return failures


def check_schema_compat_all() -> list[str]:
    failures: list[str] = []
    for data_path in VERSIONED_DOCUMENTS:
        failures.extend(check_schema_compatibility(data_path))
    return failures


def main() -> int:
    parser = argparse.ArgumentParser(description="Versioned-document schema compatibility gate")
    parser.add_argument(
        "--registry", type=Path, dest="extra", help="additional data document to check"
    )
    args = parser.parse_args()

    data_paths = list(VERSIONED_DOCUMENTS)
    if args.extra is not None:
        data_paths.append(args.extra)

    failures: list[str] = []
    for data_path in data_paths:
        failures.extend(check_schema_compatibility(data_path))

    if failures:
        print("FAIL: schema compatibility")
        for failure in failures:
            print(f"  - {failure}")
        return 1
    print("PASS: schema compatibility")
    return 0


if __name__ == "__main__":
    sys.exit(main())
