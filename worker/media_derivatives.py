"""Sandboxed safe media derivative adapter for full-screen inspection."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from worker import content_signature, parser_sandbox

PARSER_VERSION = "media-derivative-adapter-v1"
PROFILE = "media-derivative-json"
IMAGE_MIME_TYPES = frozenset(
    {"image/jpeg", "image/png", "image/heic", "image/tiff", "image/x-dcraw", "image/gif"}
)
AUDIO_MIME_TYPES = frozenset({"audio/mpeg", "audio/wav"})
VIDEO_MIME_TYPES = frozenset({"video/mp4", "video/quicktime"})
SAFE_OUTPUTS = {
    "image-preview": frozenset({"image/webp", "image/png"}),
    "video-preview": frozenset({"video/mp4"}),
    "video-keyframe": frozenset({"image/webp", "image/png"}),
    "audio-waveform": frozenset({"image/webp", "image/png"}),
    "audio-preview": frozenset({"audio/mpeg", "audio/wav"}),
}
KIND_BY_MEDIA = {
    "image": frozenset({"image-preview"}),
    "video": frozenset({"video-preview", "video-keyframe"}),
    "audio": frozenset({"audio-waveform", "audio-preview"}),
}


class MediaDerivativeError(ValueError):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


@dataclass(frozen=True)
class MediaDerivative:
    derivative_kind: str
    storage_uri: str
    mime_type: str
    size_bytes: int
    width: int | None = None
    height: int | None = None
    duration_seconds: float | None = None
    range_supported: bool = False
    warnings: tuple[str, ...] = ()
    parser_version: str = PARSER_VERSION


@dataclass(frozen=True)
class MediaDerivativeResult:
    status: str
    media_kind: str
    source_mime_type: str
    derivatives: tuple[MediaDerivative, ...]
    warnings: tuple[str, ...]
    parser_profile: str | None
    parser_version: str = PARSER_VERSION


def generate_media_derivatives(
    *,
    copied_media_path: Path,
    job_scratch: Path,
    resource_profile: Mapping[str, int],
    runtime: parser_sandbox.ParserRuntime,
    original_name: str | None = None,
    max_duration_seconds: float = 300.0,
) -> MediaDerivativeResult:
    copied = copied_media_path.resolve()
    scratch = job_scratch.resolve()
    if not _under(copied, scratch):
        raise MediaDerivativeError("input_not_copied", "media input must be a scratch copy")
    if copied.is_symlink() or not copied.is_file():
        raise MediaDerivativeError("invalid_media_path", "media input must be a regular file")
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
            media_kind,
            signature.mime_type,
            tuple(f"{PROFILE}_{warning}" for warning in parsed.warnings),
            PROFILE,
        )
    derivatives, warnings = _normalize(
        parsed.records, media_kind, resource_profile, max_duration_seconds
    )
    if not derivatives:
        return _empty(
            "failed",
            media_kind,
            signature.mime_type,
            warnings or (f"{PROFILE}_no_derivatives",),
            PROFILE,
        )
    return MediaDerivativeResult(
        "complete", media_kind, signature.mime_type, derivatives, warnings, PROFILE
    )


def _normalize(
    records: tuple[dict[str, Any], ...],
    media_kind: str,
    resource_profile: Mapping[str, int],
    max_duration_seconds: float,
) -> tuple[tuple[MediaDerivative, ...], tuple[str, ...]]:
    output_limit = int(resource_profile.get("output_limit_mib", 1)) * 1024 * 1024
    allowed = KIND_BY_MEDIA[media_kind]
    warnings: list[str] = []
    derivatives: list[MediaDerivative] = []
    for record in records[:8]:
        kind = str(record.get("derivative_kind") or "")
        if kind not in allowed:
            warnings.append(f"unsupported_derivative_kind:{kind or 'missing'}")
            continue
        derivative = _derivative(record, kind, output_limit, max_duration_seconds, warnings)
        if derivative is not None:
            derivatives.append(derivative)
    if len(records) > 8:
        warnings.append("media_derivative_record_limit_exceeded")
    return tuple(derivatives), tuple(dict.fromkeys(warnings))


def _derivative(
    record: Mapping[str, Any],
    kind: str,
    output_limit: int,
    max_duration_seconds: float,
    warnings: list[str],
) -> MediaDerivative | None:
    mime_type = str(record.get("mime_type") or "")
    if mime_type not in SAFE_OUTPUTS[kind]:
        warnings.append(f"unsafe_derivative_mime:{kind}")
        return None
    storage_uri = str(record.get("storage_uri") or "")
    if not storage_uri.startswith("scratch://sha256/"):
        warnings.append(f"invalid_derivative_storage:{kind}")
        return None
    size_bytes = _positive_int(record.get("size_bytes"))
    if size_bytes is None or size_bytes > output_limit:
        warnings.append(f"derivative_output_limit:{kind}")
        return None
    duration_seconds = _duration(record.get("duration_seconds"))
    if duration_seconds is not None and duration_seconds > max_duration_seconds:
        warnings.append(f"derivative_duration_limit:{kind}")
        return None
    range_supported = bool(record.get("range_supported")) and kind in {
        "video-preview",
        "audio-preview",
    }
    return MediaDerivative(
        derivative_kind=kind,
        storage_uri=storage_uri,
        mime_type=mime_type,
        size_bytes=size_bytes,
        width=_positive_int(record.get("width")),
        height=_positive_int(record.get("height")),
        duration_seconds=duration_seconds,
        range_supported=range_supported,
        warnings=tuple(
            str(item)[:128] for item in record.get("warnings", ()) if isinstance(item, str)
        ),
    )


def _empty(
    status: str,
    media_kind: str,
    mime_type: str,
    warnings: tuple[str, ...],
    parser_profile: str | None,
) -> MediaDerivativeResult:
    return MediaDerivativeResult(
        status, media_kind, mime_type, (), tuple(dict.fromkeys(warnings)), parser_profile
    )


def _media_kind(mime_type: str) -> str | None:
    if mime_type in IMAGE_MIME_TYPES:
        return "image"
    if mime_type in AUDIO_MIME_TYPES:
        return "audio"
    if mime_type in VIDEO_MIME_TYPES:
        return "video"
    return None


def _positive_int(value: object) -> int | None:
    if isinstance(value, int) and value > 0:
        return value
    return None


def _duration(value: object) -> float | None:
    if isinstance(value, int | float) and value >= 0:
        return float(value)
    return None


def _under(path: Path, root: Path) -> bool:
    try:
        path.relative_to(root)
    except ValueError:
        return False
    return True
