"""Bounded sampled-source fingerprinting for RPR-012.

Fingerprints combine immutable device facts with hashes of a small deterministic
sector sample. Sampled bytes are never returned or logged by this module.
"""

from __future__ import annotations

import hashlib
import os
from collections.abc import Callable, Mapping
from pathlib import Path
from typing import Any

FINGERPRINT_SCHEMA_VERSION = 1
FINGERPRINT_ALGORITHM = "reperio-sampled-sector-sha256-v1"
DEFAULT_SECTOR_SIZE = 512
MAX_SAMPLES = 3

ReadAt = Callable[[int, int], bytes]


def fingerprint_path(path: Path, identity_facts: Mapping[str, Any]) -> dict[str, Any]:
    """Open ``path`` read-only and compute a sampled fingerprint.

    This wrapper exists for hostd. Tests primarily use ``fingerprint_from_reader``
    so failure cases do not need privileged block devices.
    """
    size_bytes = _positive_int(identity_facts.get("size_bytes"), "size_bytes")
    sector_size = _positive_int(
        identity_facts.get("logical_block_size", DEFAULT_SECTOR_SIZE), "logical_block_size"
    )
    fd = os.open(path, os.O_RDONLY | getattr(os, "O_CLOEXEC", 0))
    try:
        return fingerprint_from_reader(
            lambda offset, length: os.pread(fd, length, offset),
            size_bytes=size_bytes,
            sector_size=sector_size,
            identity_facts=identity_facts,
        )
    finally:
        os.close(fd)


def fingerprint_from_reader(
    read_at: ReadAt,
    *,
    size_bytes: int,
    sector_size: int,
    identity_facts: Mapping[str, Any],
) -> dict[str, Any]:
    """Compute a deterministic bounded fingerprint from ``read_at``.

    ``read_at`` receives byte offsets and lengths. The function reads at most one
    sector from each planned sample location and returns only SHA-256 digests or
    explicit failure statuses.
    """
    if size_bytes < 0:
        raise ValueError("size_bytes must be non-negative")
    if sector_size <= 0:
        raise ValueError("sector_size must be positive")

    plan = sample_plan(size_bytes=size_bytes, sector_size=sector_size)
    samples = [_read_sample(read_at, offset, length) for offset, length in plan]
    facts = _immutable_facts(identity_facts, size_bytes=size_bytes, sector_size=sector_size)
    fingerprint_hash = _digest(
        {
            "algorithm": FINGERPRINT_ALGORITHM,
            "facts": facts,
            "samples": samples,
        }
    )
    return {
        "schema_version": FINGERPRINT_SCHEMA_VERSION,
        "algorithm": FINGERPRINT_ALGORITHM,
        "size_bytes": size_bytes,
        "sector_size": sector_size,
        "sample_count": len(samples),
        "samples": samples,
        "immutable_facts": facts,
        "fingerprint_hash": fingerprint_hash,
    }


def sample_plan(*, size_bytes: int, sector_size: int) -> list[tuple[int, int]]:
    """Return deterministic byte ranges for first, middle, and last sectors."""
    if size_bytes <= 0:
        return []
    if sector_size <= 0:
        raise ValueError("sector_size must be positive")
    sector_count = (size_bytes + sector_size - 1) // sector_size
    sector_indexes = sorted({0, sector_count // 2, sector_count - 1})[:MAX_SAMPLES]
    plan: list[tuple[int, int]] = []
    for sector_index in sector_indexes:
        offset = sector_index * sector_size
        length = min(sector_size, max(0, size_bytes - offset))
        if length > 0:
            plan.append((offset, length))
    return plan


def _read_sample(read_at: ReadAt, offset: int, length: int) -> dict[str, Any]:
    try:
        data = read_at(offset, length)
    except OSError as error:
        return {
            "offset": offset,
            "length": length,
            "status": "unreadable",
            "error": error.__class__.__name__,
        }
    if len(data) != length:
        return {
            "offset": offset,
            "length": length,
            "status": "truncated",
            "read_length": len(data),
            "sha256": hashlib.sha256(data).hexdigest(),
        }
    return {
        "offset": offset,
        "length": length,
        "status": "ok",
        "sha256": hashlib.sha256(data).hexdigest(),
    }


def _immutable_facts(
    identity_facts: Mapping[str, Any], *, size_bytes: int, sector_size: int
) -> dict[str, Any]:
    keys = (
        "source_id",
        "identity_strength",
        "by_id_name",
        "vendor",
        "model",
        "serial",
        "transport",
        "device_type",
        "physical_block_size",
        "removable",
    )
    facts = {key: identity_facts.get(key) for key in keys if key in identity_facts}
    facts["size_bytes"] = size_bytes
    facts["logical_block_size"] = sector_size
    normalized = _normalize(facts)
    if not isinstance(normalized, dict):
        raise TypeError("immutable facts must normalize to an object")
    return normalized


def _positive_int(value: object, label: str) -> int:
    if not isinstance(value, int) or value <= 0:
        raise ValueError(f"{label} must be a positive integer")
    return value


def _digest(value: object) -> str:
    return hashlib.sha256(repr(_normalize(value)).encode()).hexdigest()


def _normalize(value: object) -> object:
    if isinstance(value, dict):
        return {key: _normalize(value[key]) for key in sorted(value)}
    if isinstance(value, list):
        return [_normalize(item) for item in value]
    return value
