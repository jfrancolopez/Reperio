"""Versioned destination and export contracts for RPR-105.

Defines destination profiles (local/network/object/rclone), capability and
verification flags, opaque secret references, immutable export snapshots, and
export item/status records. Destinations must be validated at submission and
again at execution time; the source-separation recheck is provided as a wrapper
over the RPR-015 host-side separation evaluator so the API never repeats that
logic. Secrets are always opaque ``vault:`` references, never inline values.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from typing import Any

DESTINATION_CONTRACT_VERSION = 1

DESTINATION_KINDS = frozenset({"local", "nas", "sftp", "webdav", "s3", "cloud", "rclone"})
EXPORT_STATES = frozenset(
    {"pending", "running", "completed", "completed-warning", "failed", "cancelled"}
)

CAPABILITY_NAMES = frozenset(
    {
        "checksum",
        "resume",
        "atomic_finalize",
        "streaming",
        "source_separation_provable",
    }
)

OPAQUE_ID_PATTERN = "^[a-z][a-z0-9_]*_[A-Za-z0-9_-]{16,128}$"
SECRET_REF_PREFIX = "vault:"


@dataclass(frozen=True)
class DestinationValidationResult:
    valid: bool
    warnings: tuple[str, ...] = ()


def destination_profile(
    *,
    destination_id: str,
    kind: str,
    label: str,
    capabilities: list[dict[str, Any]] | None = None,
    verification_flags: Mapping[str, bool] | None = None,
    secret_ref: str | None = None,
    created_at: str,
) -> dict[str, Any]:
    """Build a normalized destination profile.

    ``secret_ref`` is optional for local destinations and must be an opaque
    ``vault:`` reference for any remote/network destination. Local destinations
    never carry inline credentials.
    """
    selected = capabilities if capabilities is not None else _default_capabilities(kind)
    flags = dict(verification_flags or _default_verification_flags(kind))
    return {
        "schema_version": DESTINATION_CONTRACT_VERSION,
        "destination_id": destination_id,
        "kind": kind,
        "label": label,
        "capabilities": [_normalize_capability(item) for item in selected],
        "verification_flags": flags,
        "secret_ref": secret_ref,
        "created_at": created_at,
    }


def export_snapshot(
    *,
    snapshot_id: str,
    case_id: str,
    filter_snapshot: Mapping[str, Any],
    item_ids: list[str],
    manifest_sha256: str,
    created_at: str,
) -> dict[str, Any]:
    """Record an immutable selected-finding set for export.

    ``item_ids`` is captured once at snapshot time; later catalog changes never
    alter what an export attempt is allowed to copy.
    """
    return {
        "schema_version": DESTINATION_CONTRACT_VERSION,
        "snapshot_id": snapshot_id,
        "case_id": case_id,
        "filter_snapshot": dict(filter_snapshot),
        "item_ids": list(item_ids),
        "manifest_sha256": manifest_sha256,
        "created_at": created_at,
    }


def export_status(
    *,
    export_id: str,
    snapshot_id: str,
    state: str,
    counts: Mapping[str, int],
    items: list[dict[str, Any]],
    created_at: str,
    updated_at: str,
    errors: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    """Build a normalized export-status record.

    ``counts`` distinguishes ready/exported/waiting/failed so that a
    ``completed`` state cannot hide unverified or failed items.
    """
    return {
        "schema_version": DESTINATION_CONTRACT_VERSION,
        "export_id": export_id,
        "snapshot_id": snapshot_id,
        "state": state,
        "counts": {
            "ready": int(counts.get("ready", 0)),
            "exported": int(counts.get("exported", 0)),
            "waiting": int(counts.get("waiting", 0)),
            "failed": int(counts.get("failed", 0)),
        },
        "items": list(items),
        "errors": list(errors or []),
        "created_at": created_at,
        "updated_at": updated_at,
    }


def validate_destination_profile(profile: Mapping[str, Any]) -> DestinationValidationResult:
    """Validate a destination profile against the versioned contract."""
    warnings: list[str] = []
    if profile.get("schema_version") != DESTINATION_CONTRACT_VERSION:
        return DestinationValidationResult(False, ("unsupported_schema_version",))
    if not _matches(profile.get("destination_id", ""), OPAQUE_ID_PATTERN):
        warnings.append("invalid_destination_id")
    kind = profile.get("kind")
    if kind not in DESTINATION_KINDS:
        warnings.append("unknown_destination_kind")
    if not isinstance(profile.get("label"), str) or not profile["label"].strip():
        warnings.append("missing_label")

    capabilities = profile.get("capabilities")
    if not isinstance(capabilities, list) or not capabilities:
        warnings.append("missing_capabilities")
    else:
        names: set[str] = set()
        for item in capabilities:
            if not isinstance(item, Mapping):
                continue
            name = item.get("name")
            if isinstance(name, str):
                names.add(name)
        unknown = sorted(names - CAPABILITY_NAMES)
        if unknown:
            warnings.append("unknown_capability:" + ",".join(unknown))
        for item in capabilities:
            if not isinstance(item, Mapping):
                continue
            if not isinstance(item.get("supported"), bool):
                warnings.append("capability_must_be_boolean")

    flags = profile.get("verification_flags")
    if isinstance(flags, Mapping):
        for name, value in flags.items():
            if not isinstance(value, bool):
                warnings.append("verification_flag_must_be_boolean:" + str(name))

    secret_ref = profile.get("secret_ref")
    if secret_ref is not None:
        if not isinstance(secret_ref, str) or not secret_ref.startswith(SECRET_REF_PREFIX):
            warnings.append("secret_ref_must_be_opaque_vault_reference")
        elif kind == "local":
            warnings.append("local_destination_cannot_have_secret")
    elif kind in {"nas", "sftp", "webdav", "s3", "cloud", "rclone"}:
        warnings.append("missing_secret_for_remote_destination")

    return DestinationValidationResult(not warnings, tuple(warnings))


def validate_export_snapshot(snapshot: Mapping[str, Any]) -> DestinationValidationResult:
    """Validate an immutable export snapshot."""
    warnings: list[str] = []
    if snapshot.get("schema_version") != DESTINATION_CONTRACT_VERSION:
        return DestinationValidationResult(False, ("unsupported_schema_version",))
    if not _matches(snapshot.get("snapshot_id", ""), OPAQUE_ID_PATTERN):
        warnings.append("invalid_snapshot_id")
    if not isinstance(snapshot.get("item_ids"), list):
        warnings.append("missing_item_ids")
    manifest = snapshot.get("manifest_sha256")
    if (
        not isinstance(manifest, str)
        or len(manifest) != 64
        or any(char not in "0123456789abcdef" for char in manifest)
    ):
        warnings.append("invalid_manifest_sha256")
    return DestinationValidationResult(not warnings, tuple(warnings))


def validate_export_status(status: Mapping[str, Any]) -> DestinationValidationResult:
    """Validate an export-status record."""
    warnings: list[str] = []
    if status.get("schema_version") != DESTINATION_CONTRACT_VERSION:
        return DestinationValidationResult(False, ("unsupported_schema_version",))
    if not _matches(status.get("export_id", ""), OPAQUE_ID_PATTERN):
        warnings.append("invalid_export_id")
    if status.get("state") not in EXPORT_STATES:
        warnings.append("unknown_export_state")
    counts = status.get("counts")
    if not isinstance(counts, Mapping):
        warnings.append("missing_counts")
    else:
        for name in ("ready", "exported", "waiting", "failed"):
            if not isinstance(counts.get(name), int) or counts[name] < 0:
                warnings.append(f"invalid_count:{name}")
    return DestinationValidationResult(not warnings, tuple(warnings))


def recheck_source_separation(
    destination_path: str,
    source: Mapping[str, Any],
    *,
    mounts: Iterable[Mapping[str, Any]],
    holders: Mapping[str, Iterable[Mapping[str, str]]] | None = None,
    evaluate: Any = None,
) -> dict[str, Any]:
    """Re-validate physical separation at export execution time.

    The wrapper consumes the RPR-015 host-side evaluator (injected for tests or
    imported lazily for production) and never opens, writes, or mounts the
    destination itself.
    """
    if evaluate is None:
        from hostd import destination_separation as evaluate

    from pathlib import Path

    result = evaluate.evaluate_destination_separation(
        source, Path(destination_path), mounts=mounts, holders=holders
    )
    return {
        "destination_path": result["resolved_path"],
        "separate": result["separate"],
        "blockers": result["blockers"],
        "warnings": result["warnings"],
        "destination_ancestry": result["destination_ancestry"],
    }


def _default_capabilities(kind: str) -> list[dict[str, Any]]:
    local = {
        "checksum": True,
        "resume": True,
        "atomic_finalize": True,
        "streaming": True,
        "source_separation_provable": True,
    }
    remote = {
        "checksum": True,
        "resume": True,
        "atomic_finalize": False,
        "streaming": True,
        "source_separation_provable": True,
    }
    selected = local if kind == "local" else remote
    return [
        {"name": name, "supported": supported, "detail": "default"}
        for name, supported in selected.items()
    ]


def _default_verification_flags(kind: str) -> dict[str, bool]:
    if kind == "local":
        return {"can_verify_checksum": True, "can_atomic_rename": True}
    return {"can_verify_checksum": True, "can_atomic_rename": False}


def _normalize_capability(item: Any) -> dict[str, Any]:
    if isinstance(item, Mapping) and item.get("name") in CAPABILITY_NAMES:
        return {
            "name": item["name"],
            "supported": bool(item.get("supported", False)),
            "detail": str(item.get("detail", "")),
        }
    if isinstance(item, str):
        return {"name": item, "supported": True, "detail": ""}
    return {"name": "", "supported": False, "detail": ""}


def _matches(value: str, pattern: str) -> bool:
    import re

    return re.fullmatch(pattern, value) is not None
