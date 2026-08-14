"""Sandboxed tiered thumbnail derivative adapter for copied images."""

from __future__ import annotations

import hashlib
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from worker import content_signature, parser_sandbox

PARSER_VERSION = "image-thumbnail-adapter-v1"
PROFILE = "libvips-thumbnail-json"
SAFE_OUTPUT_MIME_TYPES = frozenset({"image/webp", "image/png"})
IMAGE_MIME_TYPES = frozenset(
    {"image/jpeg", "image/png", "image/heic", "image/tiff", "image/x-dcraw", "image/gif"}
)
TIERS = {
    "embedded": 256,
    "small": 512,
    "large": 1600,
}


class ThumbnailError(ValueError):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


@dataclass(frozen=True)
class ThumbnailDerivative:
    tier: str
    storage_uri: str
    mime_type: str
    width: int
    height: int
    size_bytes: int
    cache_key: str
    warnings: tuple[str, ...] = ()
    parser_version: str = PARSER_VERSION


@dataclass(frozen=True)
class ThumbnailResult:
    status: str
    source_mime_type: str
    derivatives: tuple[ThumbnailDerivative, ...]
    warnings: tuple[str, ...]
    parser_profile: str | None
    parser_version: str = PARSER_VERSION


def generate_image_thumbnails(
    *,
    copied_image_path: Path,
    job_scratch: Path,
    content_sha256: str,
    resource_profile: Mapping[str, int],
    runtime: parser_sandbox.ParserRuntime,
    original_name: str | None = None,
    requested_tiers: Iterable[str] = ("embedded", "small", "large"),
    cached_derivatives: Mapping[str, ThumbnailDerivative] | None = None,
) -> ThumbnailResult:
    copied = copied_image_path.resolve()
    scratch = job_scratch.resolve()
    if not _under(copied, scratch):
        raise ThumbnailError("input_not_copied", "thumbnail input must be a scratch copy")
    if copied.is_symlink() or not copied.is_file():
        raise ThumbnailError("invalid_image_path", "thumbnail input must be a regular file")
    if not _valid_sha256(content_sha256):
        raise ThumbnailError("invalid_content_sha256", "content hash must be a sha256 hex digest")
    tiers = tuple(dict.fromkeys(requested_tiers))
    invalid_tiers = tuple(tier for tier in tiers if tier not in TIERS)
    if invalid_tiers:
        raise ThumbnailError("invalid_tier", "thumbnail tier is not configured")

    signature = content_signature.detect_content_signature(copied, original_name=original_name)
    if signature.signature == "pe-executable" or "polyglot_signature" in signature.evidence:
        return _empty(
            "skipped",
            signature.mime_type,
            (f"parser_unsafe_signature:{signature.signature}", *signature.evidence),
            None,
        )
    if signature.mime_type not in IMAGE_MIME_TYPES:
        return _empty(
            "skipped",
            signature.mime_type,
            (f"unsupported_mime:{signature.mime_type}", *signature.evidence),
            None,
        )
    if not signature.parser_safe:
        return _empty(
            "skipped",
            signature.mime_type,
            (f"parser_unsafe_signature:{signature.signature}", *signature.evidence),
            None,
        )

    cached = cached_derivatives or {}
    cached_hits = tuple(
        cached[key] for key in (_cache_key(content_sha256, tier) for tier in tiers) if key in cached
    )
    if len(cached_hits) == len(tiers):
        return ThumbnailResult("cache-hit", signature.mime_type, cached_hits, (), None)

    spec = parser_sandbox.build_parser_sandbox(
        profile_name=PROFILE,
        copied_input=copied,
        job_scratch=scratch,
        resource_profile=resource_profile,
    )
    parsed = parser_sandbox.run_parser_sandbox(spec, runtime)
    if parsed.status != "complete":
        return _empty(
            parsed.status,
            signature.mime_type,
            tuple(f"{PROFILE}_{warning}" for warning in parsed.warnings),
            PROFILE,
        )

    derivatives, warnings = _normalize_derivatives(
        parsed.records, tiers, content_sha256, resource_profile
    )
    if not derivatives:
        return _empty(
            "failed", signature.mime_type, warnings or (f"{PROFILE}_no_derivatives",), PROFILE
        )
    return ThumbnailResult("complete", signature.mime_type, derivatives, warnings, PROFILE)


def _normalize_derivatives(
    records: tuple[dict[str, Any], ...],
    tiers: tuple[str, ...],
    content_sha256: str,
    resource_profile: Mapping[str, int],
) -> tuple[tuple[ThumbnailDerivative, ...], tuple[str, ...]]:
    warnings: list[str] = []
    by_tier: dict[str, ThumbnailDerivative] = {}
    output_limit = int(resource_profile.get("output_limit_mib", 1)) * 1024 * 1024
    for record in records[: len(TIERS) + 4]:
        tier = str(record.get("tier") or "")
        if tier not in tiers or tier in by_tier:
            continue
        derivative = _derivative(record, tier, content_sha256, output_limit, warnings)
        if derivative is not None:
            by_tier[tier] = derivative
    if len(records) > len(TIERS) + 4:
        warnings.append("thumbnail_record_limit_exceeded")
    for tier in tiers:
        if tier not in by_tier:
            warnings.append(f"missing_thumbnail_tier:{tier}")
    return tuple(by_tier[tier] for tier in tiers if tier in by_tier), tuple(dict.fromkeys(warnings))


def _derivative(
    record: Mapping[str, Any],
    tier: str,
    content_sha256: str,
    output_limit: int,
    warnings: list[str],
) -> ThumbnailDerivative | None:
    mime_type = str(record.get("mime_type") or "")
    if mime_type not in SAFE_OUTPUT_MIME_TYPES:
        warnings.append(f"unsafe_thumbnail_mime:{tier}")
        return None
    width = _positive_int(record.get("width"))
    height = _positive_int(record.get("height"))
    size_bytes = _positive_int(record.get("size_bytes"))
    if width is None or height is None or size_bytes is None:
        warnings.append(f"invalid_thumbnail_dimensions:{tier}")
        return None
    if width > TIERS[tier] or height > TIERS[tier]:
        warnings.append(f"thumbnail_dimension_limit:{tier}")
        return None
    if size_bytes > output_limit:
        warnings.append(f"thumbnail_output_limit:{tier}")
        return None
    storage_uri = str(record.get("storage_uri") or "")
    if not storage_uri.startswith("scratch://sha256/"):
        warnings.append(f"invalid_thumbnail_storage:{tier}")
        return None
    record_warnings = tuple(
        str(item)[:128] for item in record.get("warnings", ()) if isinstance(item, str)
    )
    return ThumbnailDerivative(
        tier=tier,
        storage_uri=storage_uri,
        mime_type=mime_type,
        width=width,
        height=height,
        size_bytes=size_bytes,
        cache_key=_cache_key(content_sha256, tier),
        warnings=record_warnings,
    )


def _empty(
    status: str,
    mime_type: str,
    warnings: tuple[str, ...],
    parser_profile: str | None,
) -> ThumbnailResult:
    return ThumbnailResult(status, mime_type, (), tuple(dict.fromkeys(warnings)), parser_profile)


def _cache_key(content_sha256: str, tier: str) -> str:
    raw = "\0".join((PARSER_VERSION, content_sha256, tier))
    return hashlib.sha256(raw.encode("ascii")).hexdigest()


def _positive_int(value: object) -> int | None:
    if isinstance(value, int) and value > 0:
        return value
    return None


def _valid_sha256(value: str) -> bool:
    return len(value) == 64 and all(char in "0123456789abcdef" for char in value.lower())


def _under(path: Path, root: Path) -> bool:
    try:
        path.relative_to(root)
    except ValueError:
        return False
    return True
