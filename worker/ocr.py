"""Sandboxed OCR adapter for copied images and scanned PDFs."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from worker import content_signature, parser_sandbox

PARSER_VERSION = "ocr-adapter-v1"
PROFILE = "ocr-json"
SUPPORTED_MIME_TYPES = frozenset(
    {
        "application/pdf",
        "image/jpeg",
        "image/png",
        "image/heic",
        "image/tiff",
        "image/x-dcraw",
        "image/gif",
    }
)
LANGUAGE_PACKS = frozenset({"eng", "spa"})
DEFAULT_MAX_TEXT_CHARS = 100_000
MAX_REGIONS = 512
LOW_CONFIDENCE_THRESHOLD = 0.55


class OcrError(ValueError):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


@dataclass(frozen=True)
class OcrRegion:
    page_number: int
    text: str
    confidence: float
    bbox: Mapping[str, int]


@dataclass(frozen=True)
class OcrResult:
    status: str
    mime_type: str
    needs_ocr: bool
    existing_text: str
    ocr_text: str
    language_packs: tuple[str, ...]
    mean_confidence: float | None
    regions: tuple[OcrRegion, ...]
    derivative_uri: str | None
    warnings: tuple[str, ...]
    truncated: bool
    parser_profile: str | None
    parser_version: str = PARSER_VERSION


def extract_ocr_text(
    *,
    copied_input_path: Path,
    job_scratch: Path,
    resource_profile: Mapping[str, int],
    runtime: parser_sandbox.ParserRuntime,
    original_name: str | None = None,
    existing_text: str = "",
    language_packs: tuple[str, ...] = ("eng", "spa"),
    max_text_chars: int = DEFAULT_MAX_TEXT_CHARS,
) -> OcrResult:
    if max_text_chars <= 0:
        raise OcrError("invalid_text_limit", "OCR text limit must be positive")
    invalid_languages = tuple(
        language for language in language_packs if language not in LANGUAGE_PACKS
    )
    if invalid_languages:
        raise OcrError("unsupported_language_pack", "OCR language pack is not configured")
    copied = copied_input_path.resolve()
    scratch = job_scratch.resolve()
    if not _under(copied, scratch):
        raise OcrError("input_not_copied", "OCR input must be a scratch copy")
    if copied.is_symlink() or not copied.is_file():
        raise OcrError("invalid_input_path", "OCR input must be a regular file")
    signature = content_signature.detect_content_signature(copied, original_name=original_name)
    if signature.signature == "pe-executable" or "polyglot_signature" in signature.evidence:
        return _empty(
            "skipped",
            signature.mime_type,
            False,
            existing_text,
            language_packs,
            (f"parser_unsafe_signature:{signature.signature}", *signature.evidence),
            None,
        )
    if signature.mime_type not in SUPPORTED_MIME_TYPES:
        return _empty(
            "skipped",
            signature.mime_type,
            False,
            existing_text,
            language_packs,
            (f"unsupported_mime:{signature.mime_type}", *signature.evidence),
            None,
        )
    if not signature.parser_safe:
        return _empty(
            "skipped",
            signature.mime_type,
            False,
            existing_text,
            language_packs,
            (f"parser_unsafe_signature:{signature.signature}", *signature.evidence),
            None,
        )
    if existing_text.strip():
        return _empty(
            "skipped-existing-text",
            signature.mime_type,
            False,
            existing_text,
            language_packs,
            ("existing_text_preserved",),
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
            signature.mime_type,
            True,
            existing_text,
            language_packs,
            tuple(f"{PROFILE}_{warning}" for warning in parsed.warnings),
            PROFILE,
        )
    if not parsed.records:
        return _empty(
            "failed",
            signature.mime_type,
            True,
            existing_text,
            language_packs,
            (f"{PROFILE}_no_output",),
            PROFILE,
        )
    return _normalize_record(
        parsed.records[0],
        signature.mime_type,
        existing_text,
        language_packs,
        max_text_chars=max_text_chars,
    )


def _normalize_record(
    record: Mapping[str, Any],
    mime_type: str,
    existing_text: str,
    language_packs: tuple[str, ...],
    *,
    max_text_chars: int,
) -> OcrResult:
    status = str(record.get("status") or "complete")
    warnings = list(_strings(record.get("warnings")))
    if status != "complete":
        return _empty(
            status, mime_type, True, existing_text, language_packs, tuple(warnings), PROFILE
        )
    text = str(record.get("text") or "")
    truncated = len(text) > max_text_chars
    if truncated:
        warnings.append("ocr_text_truncated")
        text = text[:max_text_chars]
    confidence = _confidence(record.get("mean_confidence"))
    if confidence is not None and confidence < LOW_CONFIDENCE_THRESHOLD:
        warnings.append("low_confidence_ocr")
    regions = _regions(record.get("regions"))
    if isinstance(record.get("regions"), list) and len(record["regions"]) > MAX_REGIONS:
        warnings.append("ocr_region_limit_applied")
    derivative_uri = record.get("derivative_uri")
    if derivative_uri is not None:
        derivative_uri = str(derivative_uri)
        if not derivative_uri.startswith("scratch://sha256/"):
            warnings.append("invalid_ocr_derivative_storage")
            derivative_uri = None
    return OcrResult(
        status="complete",
        mime_type=mime_type,
        needs_ocr=True,
        existing_text=existing_text,
        ocr_text=text,
        language_packs=language_packs,
        mean_confidence=confidence,
        regions=regions,
        derivative_uri=derivative_uri,
        warnings=tuple(dict.fromkeys(warnings)),
        truncated=truncated,
        parser_profile=PROFILE,
    )


def _regions(value: object) -> tuple[OcrRegion, ...]:
    if not isinstance(value, list):
        return ()
    regions: list[OcrRegion] = []
    for item in value[:MAX_REGIONS]:
        if not isinstance(item, Mapping):
            continue
        text = str(item.get("text") or "")[:1024]
        confidence = _confidence(item.get("confidence"))
        page_number = _positive_int(item.get("page_number"))
        bbox = _bbox(item.get("bbox"))
        if text and confidence is not None and page_number is not None and bbox:
            regions.append(OcrRegion(page_number, text, confidence, bbox))
    return tuple(regions)


def _bbox(value: object) -> dict[str, int]:
    if not isinstance(value, Mapping):
        return {}
    result: dict[str, int] = {}
    for key in ("x", "y", "width", "height"):
        number = _positive_int(value.get(key))
        if number is None:
            return {}
        result[key] = number
    return result


def _empty(
    status: str,
    mime_type: str,
    needs_ocr: bool,
    existing_text: str,
    language_packs: tuple[str, ...],
    warnings: tuple[str, ...],
    parser_profile: str | None,
) -> OcrResult:
    return OcrResult(
        status,
        mime_type,
        needs_ocr,
        existing_text,
        "",
        language_packs,
        None,
        (),
        None,
        tuple(dict.fromkeys(warnings)),
        False,
        parser_profile,
    )


def _confidence(value: object) -> float | None:
    if isinstance(value, int | float) and 0 <= value <= 1:
        return float(value)
    return None


def _positive_int(value: object) -> int | None:
    if isinstance(value, int) and value > 0:
        return value
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
