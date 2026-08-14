"""Sandboxed image, audio, and video metadata extraction adapter."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from worker import content_signature, parser_sandbox

PARSER_VERSION = "media-metadata-adapter-v1"
MAX_RAW_FIELDS = 256
MAX_RAW_VALUE_CHARS = 4096
IMAGE_MIME_TYPES = frozenset(
    {"image/jpeg", "image/png", "image/heic", "image/tiff", "image/x-dcraw"}
)
AUDIO_MIME_TYPES = frozenset({"audio/mpeg", "audio/wav"})
VIDEO_MIME_TYPES = frozenset({"video/mp4", "video/quicktime"})


class MediaMetadataError(ValueError):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


@dataclass(frozen=True)
class MediaMetadataResult:
    status: str
    media_kind: str
    mime_type: str
    dimensions: Mapping[str, int]
    duration_seconds: float | None
    codecs: tuple[str, ...]
    creation_time: str | None
    device: Mapping[str, str]
    location: Mapping[str, float]
    editor: str | None
    raw_metadata: Mapping[str, str]
    warnings: tuple[str, ...]
    parser_profile: str | None
    parser_version: str = PARSER_VERSION


def extract_media_metadata(
    *,
    copied_media_path: Path,
    job_scratch: Path,
    resource_profile: Mapping[str, int],
    runtime: parser_sandbox.ParserRuntime,
    original_name: str | None = None,
) -> MediaMetadataResult:
    copied = copied_media_path.resolve()
    scratch = job_scratch.resolve()
    if not _under(copied, scratch):
        raise MediaMetadataError("input_not_copied", "media input must be a scratch copy")
    if copied.is_symlink() or not copied.is_file():
        raise MediaMetadataError("invalid_media_path", "media input must be a regular file")
    signature = content_signature.detect_content_signature(copied, original_name=original_name)
    if signature.signature == "pe-executable" or "polyglot_signature" in signature.evidence:
        return _empty(
            "skipped",
            "unknown",
            signature.mime_type,
            (f"parser_unsafe_signature:{signature.signature}", *signature.evidence),
            None,
        )
    media_kind = _media_kind(signature.mime_type)
    if media_kind is None:
        return _empty(
            "skipped",
            "unknown",
            signature.mime_type,
            (f"unsupported_mime:{signature.mime_type}", *signature.evidence),
            None,
        )
    if not signature.parser_safe:
        return _empty(
            "skipped",
            media_kind,
            signature.mime_type,
            (f"parser_unsafe_signature:{signature.signature}", *signature.evidence),
            None,
        )
    profile = "exiftool-json" if media_kind == "image" else "ffprobe-json"
    spec = parser_sandbox.build_parser_sandbox(
        profile_name=profile,
        copied_input=copied,
        job_scratch=scratch,
        resource_profile=resource_profile,
    )
    parsed = parser_sandbox.run_parser_sandbox(spec, runtime)
    if parsed.status != "complete":
        return _empty(
            parsed.status,
            media_kind,
            signature.mime_type,
            tuple(f"{profile}_{warning}" for warning in parsed.warnings),
            profile,
        )
    if not parsed.records:
        return _empty("failed", media_kind, signature.mime_type, (f"{profile}_no_output",), profile)
    return _normalize_record(parsed.records[0], media_kind, signature.mime_type, profile)


def _normalize_record(
    record: Mapping[str, Any], media_kind: str, mime_type: str, profile: str
) -> MediaMetadataResult:
    status = str(record.get("status") or "complete")
    warnings = list(_strings(record.get("warnings")))
    if bool(record.get("malformed")):
        warnings.append("malformed_media")
    return MediaMetadataResult(
        status=status,
        media_kind=media_kind,
        mime_type=mime_type,
        dimensions=_dimensions(record.get("dimensions")),
        duration_seconds=_duration(record.get("duration_seconds")),
        codecs=_strings(record.get("codecs")),
        creation_time=_optional_string(record.get("creation_time")),
        device=_string_map(record.get("device")),
        location=_location(record.get("location")),
        editor=_optional_string(record.get("editor")),
        raw_metadata=_bounded_raw(record.get("raw_metadata")),
        warnings=tuple(dict.fromkeys(warnings)),
        parser_profile=profile,
    )


def _empty(
    status: str,
    media_kind: str,
    mime_type: str,
    warnings: tuple[str, ...],
    parser_profile: str | None,
) -> MediaMetadataResult:
    return MediaMetadataResult(
        status=status,
        media_kind=media_kind,
        mime_type=mime_type,
        dimensions={},
        duration_seconds=None,
        codecs=(),
        creation_time=None,
        device={},
        location={},
        editor=None,
        raw_metadata={},
        warnings=tuple(dict.fromkeys(warnings)),
        parser_profile=parser_profile,
    )


def _media_kind(mime_type: str) -> str | None:
    if mime_type in IMAGE_MIME_TYPES:
        return "image"
    if mime_type in AUDIO_MIME_TYPES:
        return "audio"
    if mime_type in VIDEO_MIME_TYPES:
        return "video"
    return None


def _dimensions(value: object) -> dict[str, int]:
    if not isinstance(value, Mapping):
        return {}
    result: dict[str, int] = {}
    for key in ("width", "height"):
        item = value.get(key)
        if isinstance(item, int) and item > 0:
            result[key] = item
    return result


def _duration(value: object) -> float | None:
    if isinstance(value, int | float) and value >= 0:
        return float(value)
    return None


def _strings(value: object) -> tuple[str, ...]:
    if isinstance(value, list | tuple):
        return tuple(str(item)[:256] for item in value)
    return ()


def _optional_string(value: object) -> str | None:
    if isinstance(value, str) and value:
        return value[:256]
    return None


def _string_map(value: object) -> dict[str, str]:
    if not isinstance(value, Mapping):
        return {}
    return {str(key)[:128]: str(item)[:256] for key, item in sorted(value.items())}


def _location(value: object) -> dict[str, float]:
    if not isinstance(value, Mapping):
        return {}
    lat = value.get("latitude")
    lon = value.get("longitude")
    if (
        isinstance(lat, int | float)
        and isinstance(lon, int | float)
        and -90 <= lat <= 90
        and -180 <= lon <= 180
    ):
        return {"latitude": float(lat), "longitude": float(lon)}
    return {}


def _bounded_raw(value: object) -> dict[str, str]:
    if not isinstance(value, Mapping):
        return {}
    result: dict[str, str] = {}
    for key, item in sorted(value.items()):
        if len(result) >= MAX_RAW_FIELDS:
            break
        result[str(key)[:256]] = str(item)[:MAX_RAW_VALUE_CHARS]
    return result


def _under(path: Path, root: Path) -> bool:
    try:
        path.relative_to(root)
    except ValueError:
        return False
    return True
