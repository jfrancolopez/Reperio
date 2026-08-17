"""Local sandboxed audio/video transcription adapter."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from worker import content_signature, parser_sandbox

PARSER_VERSION = "local-transcription-adapter-v1"
PROFILE = "local-transcription-json"
AUDIO_MIME_TYPES = frozenset({"audio/mpeg", "audio/wav"})
VIDEO_MIME_TYPES = frozenset({"video/mp4", "video/quicktime"})
SUPPORTED_LANGUAGES = frozenset({"en", "es", "unknown"})
DEFAULT_MAX_TEXT_CHARS = 100_000
MAX_SEGMENTS = 1024


class TranscriptionError(ValueError):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


@dataclass(frozen=True)
class TranscriptionSegment:
    start_seconds: float
    end_seconds: float
    text: str
    confidence: float | None
    language: str


@dataclass(frozen=True)
class TranscriptionResult:
    status: str
    media_kind: str
    mime_type: str
    text: str
    language: str
    confidence: float | None
    segments: tuple[TranscriptionSegment, ...]
    extracted_audio_uri: str | None
    checkpoint: Mapping[str, object]
    warnings: tuple[str, ...]
    truncated: bool
    parser_profile: str | None
    parser_version: str = PARSER_VERSION


def transcribe_media(
    *,
    copied_media_path: Path,
    job_scratch: Path,
    resource_profile: Mapping[str, int],
    runtime: parser_sandbox.ParserRuntime,
    original_name: str | None = None,
    capability: Mapping[str, object] | None = None,
    checkpoint: Mapping[str, object] | None = None,
    max_text_chars: int = DEFAULT_MAX_TEXT_CHARS,
) -> TranscriptionResult:
    if max_text_chars <= 0:
        raise TranscriptionError("invalid_text_limit", "transcription text limit must be positive")
    capability = capability or {"enabled": True, "mode": "cpu"}
    if capability.get("enabled") is False:
        return _empty(
            "disabled",
            "unknown",
            "application/octet-stream",
            ("transcription_capability_disabled",),
            None,
        )
    if capability.get("mode") not in {"cpu", "gpu"}:
        raise TranscriptionError("invalid_capability", "transcription capability mode is invalid")
    copied = copied_media_path.resolve()
    scratch = job_scratch.resolve()
    if not _under(copied, scratch):
        raise TranscriptionError("input_not_copied", "transcription input must be a scratch copy")
    if copied.is_symlink() or not copied.is_file():
        raise TranscriptionError("invalid_media_path", "transcription input must be a regular file")
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
    if not parsed.records:
        return _empty("failed", media_kind, signature.mime_type, (f"{PROFILE}_no_output",), PROFILE)
    return _normalize_record(
        parsed.records[0],
        media_kind,
        signature.mime_type,
        checkpoint or {},
        max_text_chars=max_text_chars,
        cpu_only=capability.get("mode") == "cpu",
    )


def _normalize_record(
    record: Mapping[str, Any],
    media_kind: str,
    mime_type: str,
    previous_checkpoint: Mapping[str, object],
    *,
    max_text_chars: int,
    cpu_only: bool,
) -> TranscriptionResult:
    status = str(record.get("status") or "complete")
    warnings = list(_strings(record.get("warnings")))
    if cpu_only:
        warnings.append("cpu_only_transcription")
    if status != "complete":
        return _empty(status, media_kind, mime_type, tuple(warnings), PROFILE)
    text = str(record.get("text") or "")
    truncated = len(text) > max_text_chars
    if truncated:
        warnings.append("transcript_truncated")
        text = text[:max_text_chars]
    language = str(record.get("language") or "unknown")
    if language not in SUPPORTED_LANGUAGES:
        warnings.append(f"unsupported_detected_language:{language}")
        language = "unknown"
    confidence = _confidence(record.get("confidence"))
    if not text.strip():
        warnings.append("silence_or_no_speech")
    segments = _segments(record.get("segments"))
    if isinstance(record.get("segments"), list) and len(record["segments"]) > MAX_SEGMENTS:
        warnings.append("transcript_segment_limit_applied")
    audio_uri = record.get("extracted_audio_uri")
    if audio_uri is not None:
        audio_uri = str(audio_uri)
        if not audio_uri.startswith("scratch://sha256/"):
            warnings.append("invalid_extracted_audio_storage")
            audio_uri = None
    checkpoint = _checkpoint(record.get("checkpoint"), previous_checkpoint)
    return TranscriptionResult(
        "complete",
        media_kind,
        mime_type,
        text,
        language,
        confidence,
        segments,
        audio_uri,
        checkpoint,
        tuple(dict.fromkeys(warnings)),
        truncated,
        PROFILE,
    )


def _segments(value: object) -> tuple[TranscriptionSegment, ...]:
    if not isinstance(value, list):
        return ()
    segments: list[TranscriptionSegment] = []
    for item in value[:MAX_SEGMENTS]:
        if not isinstance(item, Mapping):
            continue
        start = _seconds(item.get("start_seconds"))
        end = _seconds(item.get("end_seconds"))
        language = str(item.get("language") or "unknown")
        text = str(item.get("text") or "")[:2048]
        if start is not None and end is not None and end >= start and text:
            segments.append(
                TranscriptionSegment(
                    start,
                    end,
                    text,
                    _confidence(item.get("confidence")),
                    language if language in SUPPORTED_LANGUAGES else "unknown",
                )
            )
    return tuple(segments)


def _checkpoint(value: object, previous: Mapping[str, object]) -> dict[str, object]:
    result = dict(previous)
    if isinstance(value, Mapping):
        for key in ("next_offset_seconds", "chunk_index", "complete"):
            if key in value:
                result[key] = value[key]
    return result


def _empty(
    status: str,
    media_kind: str,
    mime_type: str,
    warnings: tuple[str, ...],
    parser_profile: str | None,
) -> TranscriptionResult:
    return TranscriptionResult(
        status,
        media_kind,
        mime_type,
        "",
        "unknown",
        None,
        (),
        None,
        {},
        tuple(dict.fromkeys(warnings)),
        False,
        parser_profile,
    )


def _media_kind(mime_type: str) -> str | None:
    if mime_type in AUDIO_MIME_TYPES:
        return "audio"
    if mime_type in VIDEO_MIME_TYPES:
        return "video"
    return None


def _seconds(value: object) -> float | None:
    if isinstance(value, int | float) and value >= 0:
        return float(value)
    return None


def _confidence(value: object) -> float | None:
    if isinstance(value, int | float) and 0 <= value <= 1:
        return float(value)
    return None


def _strings(value: object) -> tuple[str, ...]:
    if isinstance(value, list | tuple):
        return tuple(str(item)[:256] for item in value)
    return ()


def _under(path: Path, root: Path) -> bool:
    try:
        path.relative_to(root)
    except ValueError:
        return False
    return True
