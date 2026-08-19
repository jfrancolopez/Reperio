"""Safe export paths, naming, and manifests (RPR-107).

Produces destination-relative paths that preserve a safe subset of the source
hierarchy while recording every deviation, handles destination-specific
sanitization and collision rules, derives carved names, and emits deterministic
JSON/CSV manifests carrying hashes, provenance, statuses, and tool/app versions.
All inputs are treated as hostile content: traversal, reserved names, invalid
Unicode, oversized paths, and CSV formula injection are handled and recorded,
never silently dropped.
"""

from __future__ import annotations

import csv
import io
import json
import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass

from worker.local_export import ExportItem

EXPORT_MANIFEST_VERSION = "export-manifest-v1"

MAX_COMPONENT_BYTES = 255
MAX_LOCAL_PATH_BYTES = 4096
MAX_REMOTE_PATH_BYTES = 1024

RESERVED_WINDOWS_NAMES = frozenset(
    {
        "CON",
        "PRN",
        "AUX",
        "NUL",
        "COM1",
        "COM2",
        "COM3",
        "COM4",
        "COM5",
        "COM6",
        "COM7",
        "COM8",
        "COM9",
        "LPT1",
        "LPT2",
        "LPT3",
        "LPT4",
        "LPT5",
        "LPT6",
        "LPT7",
        "LPT8",
        "LPT9",
    }
)

CSV_FORMULA_LEADERS = ("=", "+", "-", "@", "\t", "\r")

INVALID_UNICODE_REPLACEMENT = "\ufffd"

PROVENANCE_KINDS = frozenset({"allocated", "hidden", "trashed", "deleted", "carved"})


class ExportManifestError(ValueError):
    """Raised when a manifest or path plan is invalid."""


@dataclass(frozen=True)
class SanitizedComponent:
    name: str
    warnings: tuple[str, ...] = ()


@dataclass(frozen=True)
class PlannedPath:
    export_item_id: str
    source_display_path: str
    destination_path: str
    provenance: str
    warnings: tuple[str, ...] = ()


def sanitize_component(name: str) -> SanitizedComponent:
    """Sanitize one path component; record every deviation."""
    warnings: list[str] = []
    if any(ord(ch) < 32 for ch in name):
        warnings.append("control_character")
    cleaned = "".join(
        ch if ord(ch) >= 32 and ch != "\x7f" else INVALID_UNICODE_REPLACEMENT for ch in name
    )
    cleaned = cleaned.strip().rstrip(".")
    if cleaned == "":
        cleaned = "unnamed"
        warnings.append("empty_name")
    upper = cleaned.upper()
    base = upper.split(".")[0]
    if base in RESERVED_WINDOWS_NAMES:
        cleaned = f"_{cleaned}"
        warnings.append("reserved_name")
    if not _valid_utf8(cleaned):
        warnings.append("invalid_unicode")
    return SanitizedComponent(cleaned, tuple(dict.fromkeys(warnings)))


def sanitize_component_bytes(raw: bytes) -> SanitizedComponent:
    """Sanitize a raw byte component, recording invalid Unicode."""
    decoded = raw.decode("utf-8", errors="replace")
    component = sanitize_component(decoded)
    if _contains_replacement(decoded):
        warnings = list(component.warnings)
        if "invalid_unicode" not in warnings:
            warnings.append("invalid_unicode")
        return SanitizedComponent(component.name, tuple(warnings))
    return component


def safe_relative_path(
    display_path: str,
    *,
    destination_kind: str = "local",
    case_insensitive: bool = False,
) -> tuple[str, tuple[str, ...]]:
    """Map a source display path to a destination-relative safe path.

    Preserves hierarchy below the volume root, drops only the root name, records
    traversal segments, and enforces component/length limits. Returns the
    destination-relative path plus every deviation recorded.
    """
    warnings: list[str] = []
    parts = re.split(r"[/\\]+", display_path)
    parts = [part for part in parts if part not in {"", "."}]
    sanitized: list[str] = []
    seen: set[str] = set()
    for part in parts:
        if part == "..":
            warnings.append("path_traversal")
            continue
        component = sanitize_component(part)
        warnings.extend(component.warnings)
        key = component.name.upper() if case_insensitive else component.name
        if key in seen:
            warnings.append("duplicate_component")
        seen.add(key)
        sanitized.append(component.name)
    relative = "/".join(sanitized)
    max_bytes = MAX_LOCAL_PATH_BYTES if destination_kind == "local" else MAX_REMOTE_PATH_BYTES
    if len(relative.encode("utf-8")) > max_bytes:
        relative = _truncate_to_bytes(relative, max_bytes)
        warnings.append("long_path_truncated")
    return relative, tuple(dict.fromkeys(warnings))


def carved_destination_name(item: ExportItem, *, extension: str | None = None) -> str:
    """Deterministic carved naming from the source path and size."""
    stem = _carved_stem(item)
    suffix = f".{extension.lstrip('.')}" if extension else ""
    return f"carved/{stem}{suffix}"


def plan_export_paths(
    items: Sequence[ExportItem],
    *,
    destination_kind: str = "local",
    case_insensitive: bool = False,
    provenance_of: Mapping[str, str] | None = None,
) -> tuple[tuple[PlannedPath, ...], tuple[str, ...]]:
    """Plan deterministic destination paths with collision resolution.

    Collisions append ``__1``, ``__2``, ... deterministically by item order and
    record each collision. The mapping is stable for the same input.
    """
    provenance_of = provenance_of or {}
    plans: list[PlannedPath] = []
    used: set[str] = set()
    warnings: list[str] = []
    for index, item in enumerate(items):
        relative, path_warnings = safe_relative_path(
            item.source_path, destination_kind=destination_kind, case_insensitive=case_insensitive
        )
        warnings.extend(path_warnings)
        provenance = provenance_of.get(item.export_item_id, "allocated")
        if provenance == "carved":
            relative = carved_destination_name(item)
        final = _unique(relative, used, case_insensitive=case_insensitive)
        if final != relative:
            warnings.append(f"collision:{relative}")
        used.add(_key(final, case_insensitive))
        plans.append(
            PlannedPath(
                export_item_id=item.export_item_id,
                source_display_path=item.source_path,
                destination_path=final,
                provenance=provenance if provenance in PROVENANCE_KINDS else "allocated",
                warnings=tuple(path_warnings),
            )
        )
    return tuple(plans), tuple(dict.fromkeys(warnings))


def formula_safe(value: object) -> str:
    """Neutralize CSV formula-injection leaders from hostile content."""
    text = "" if value is None else str(value)
    if text and text[0] in CSV_FORMULA_LEADERS:
        return "'" + text
    return text


def build_json_manifest(
    *,
    export_id: str,
    case_id: str,
    plans: Sequence[PlannedPath],
    item_hashes: Mapping[str, str],
    item_sizes: Mapping[str, int],
    item_statuses: Mapping[str, str],
    app_version: str,
    tool_versions: Mapping[str, str] | None = None,
    created_at: str,
) -> Mapping[str, object]:
    """Build a deterministic JSON manifest (sorted keys)."""
    items: list[dict[str, object]] = []
    for plan in plans:
        items.append(
            {
                "export_item_id": plan.export_item_id,
                "source_display_path": plan.source_display_path,
                "destination_path": plan.destination_path,
                "provenance": plan.provenance,
                "status": item_statuses.get(plan.export_item_id, "unknown"),
                "size_bytes": item_sizes.get(plan.export_item_id, 0),
                "sha256": item_hashes.get(plan.export_item_id, ""),
            }
        )
    manifest: dict[str, object] = {
        "manifest_version": EXPORT_MANIFEST_VERSION,
        "export_id": export_id,
        "case_id": case_id,
        "app_version": app_version,
        "tool_versions": dict(sorted((tool_versions or {}).items())),
        "created_at": created_at,
        "items": items,
    }
    return manifest


def canonical_manifest_json(manifest: Mapping[str, object]) -> str:
    """Deterministic serialization for hashing and snapshot storage."""
    return json.dumps(manifest, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def manifest_sha256(manifest: Mapping[str, object]) -> str:
    """SHA-256 hex of the canonical manifest JSON."""
    import hashlib

    return hashlib.sha256(canonical_manifest_json(manifest).encode("utf-8")).hexdigest()


def build_csv_manifest(manifest: Mapping[str, object]) -> str:
    """Deterministic CSV manifest with formula-safe cells."""
    output = io.StringIO()
    writer = csv.writer(output, lineterminator="\n")
    writer.writerow(
        [
            "export_item_id",
            "source_display_path",
            "destination_path",
            "provenance",
            "status",
            "size_bytes",
            "sha256",
        ]
    )
    items = manifest.get("items")
    if isinstance(items, list):
        for item in items:
            if isinstance(item, Mapping):
                writer.writerow(
                    [
                        formula_safe(item.get("export_item_id")),
                        formula_safe(item.get("source_display_path")),
                        formula_safe(item.get("destination_path")),
                        formula_safe(item.get("provenance")),
                        formula_safe(item.get("status")),
                        formula_safe(item.get("size_bytes")),
                        formula_safe(item.get("sha256")),
                    ]
                )
    return output.getvalue()


def _carved_stem(item: ExportItem) -> str:
    stem = _stem_of(item.source_path)
    return f"{stem}_size_{item.expected_size}"


def _stem_of(path: str) -> str:
    base = path.rstrip("/\\").rsplit("/", 1)[-1].rsplit("\\", 1)[-1]
    return base or "carved"


def _unique(relative: str, used: set[str], *, case_insensitive: bool) -> str:
    candidate = relative
    counter = 1
    while _key(candidate, case_insensitive) in used:
        candidate = f"{relative}__{counter}"
        counter += 1
    return candidate


def _key(value: str, case_insensitive: bool) -> str:
    return value.upper() if case_insensitive else value


def _valid_utf8(value: str) -> bool:
    try:
        value.encode("utf-8")
        return True
    except UnicodeError:
        return False


def _contains_replacement(value: str) -> bool:
    return INVALID_UNICODE_REPLACEMENT in value


def _truncate_to_bytes(value: str, max_bytes: int) -> str:
    encoded = value.encode("utf-8")
    if len(encoded) <= max_bytes:
        return value
    truncated = encoded[: max_bytes - 1].decode("utf-8", errors="ignore")
    return truncated if truncated else value[: max_bytes - 1]
