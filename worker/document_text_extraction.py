"""Sandboxed document metadata and text extraction adapter."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from worker import content_signature, parser_sandbox

PARSER_VERSION = "tika-json-adapter-v1"
TIKA_PROFILE = "tika-json"
DEFAULT_MAX_TEXT_CHARS = 100_000
MAX_METADATA_FIELDS = 128
MAX_METADATA_VALUE_CHARS = 4096
SUPPORTED_MIME_TYPES = frozenset(
    {
        "application/pdf",
        "application/rtf",
        "application/vnd.openxmlformats-officedocument.presentationml.presentation",
        "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
        "message/rfc822",
        "text/plain",
    }
)


class DocumentExtractionError(ValueError):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


@dataclass(frozen=True)
class DocumentExtractionResult:
    status: str
    mime_type: str
    text: str
    metadata: Mapping[str, Any]
    parser_chain: tuple[str, ...]
    warnings: tuple[str, ...]
    truncated: bool
    parser_version: str = PARSER_VERSION


def extract_document_text(
    *,
    copied_document_path: Path,
    job_scratch: Path,
    resource_profile: Mapping[str, int],
    runtime: parser_sandbox.ParserRuntime,
    original_name: str | None = None,
    max_text_chars: int = DEFAULT_MAX_TEXT_CHARS,
) -> DocumentExtractionResult:
    """Extract passive document text from a scratch copy through the parser sandbox."""

    if max_text_chars <= 0:
        raise DocumentExtractionError("invalid_text_limit", "text limit must be positive")
    copied = copied_document_path.resolve()
    scratch = job_scratch.resolve()
    if not _under(copied, scratch):
        raise DocumentExtractionError("input_not_copied", "document input must be a scratch copy")
    signature = content_signature.detect_content_signature(
        copied,
        original_name=original_name,
    )
    warnings = list(signature.evidence)
    if not signature.parser_safe:
        warnings.append("parser_unsafe_content")
        return _empty("skipped", signature.mime_type, warnings)
    if signature.mime_type not in SUPPORTED_MIME_TYPES:
        warnings.append(f"unsupported_mime:{signature.mime_type}")
        return _empty("skipped", signature.mime_type, warnings)

    spec = parser_sandbox.build_parser_sandbox(
        profile_name=TIKA_PROFILE,
        copied_input=copied,
        job_scratch=scratch,
        resource_profile=resource_profile,
    )
    parsed = parser_sandbox.run_parser_sandbox(spec, runtime)
    if parsed.status != "complete":
        return _empty(parsed.status, signature.mime_type, (*warnings, *parsed.warnings))
    if not parsed.records:
        return _empty("failed", signature.mime_type, (*warnings, "tika_no_output"))
    record = parsed.records[0]
    status = str(record.get("status") or "complete")
    record_warnings = _strings(record.get("warnings"))
    if status != "complete":
        return _empty(status, signature.mime_type, (*warnings, *record_warnings))
    metadata = _metadata(record.get("metadata"))
    parser_chain = _strings(record.get("parser_chain")) or ("apache-tika",)
    text = str(record.get("text") or "")
    truncated = len(text) > max_text_chars
    if truncated:
        warnings.append("text_truncated")
        text = text[:max_text_chars]
    return DocumentExtractionResult(
        status="complete",
        mime_type=signature.mime_type,
        text=text,
        metadata=metadata,
        parser_chain=parser_chain,
        warnings=tuple(dict.fromkeys((*warnings, *record_warnings))),
        truncated=truncated,
    )


def _empty(
    status: str, mime_type: str, warnings: tuple[str, ...] | list[str]
) -> DocumentExtractionResult:
    return DocumentExtractionResult(
        status=status,
        mime_type=mime_type,
        text="",
        metadata={},
        parser_chain=(),
        warnings=tuple(dict.fromkeys(warnings)),
        truncated=False,
    )


def _strings(value: object) -> tuple[str, ...]:
    if isinstance(value, list | tuple):
        return tuple(str(item) for item in value)
    return ()


def _metadata(value: object) -> dict[str, str]:
    if not isinstance(value, Mapping):
        return {}
    result: dict[str, str] = {}
    for key, item in sorted(value.items()):
        if len(result) >= MAX_METADATA_FIELDS:
            break
        result[str(key)[:256]] = str(item)[:MAX_METADATA_VALUE_CHARS]
    return result


def _under(path: Path, root: Path) -> bool:
    try:
        path.relative_to(root)
    except ValueError:
        return False
    return True
