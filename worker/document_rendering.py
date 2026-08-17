"""Sandboxed safe PDF and document page rendering adapter."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from worker import content_signature, parser_sandbox

PARSER_VERSION = "document-render-adapter-v1"
PROFILE = "document-render-json"
SUPPORTED_MIME_TYPES = frozenset(
    {
        "application/pdf",
        "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
        "application/vnd.openxmlformats-officedocument.presentationml.presentation",
        "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        "application/rtf",
        "text/plain",
        "message/rfc822",
    }
)
SAFE_PAGE_MIME_TYPES = frozenset({"image/webp", "image/png"})
DEFAULT_MAX_PAGES = 3
DEFAULT_MAX_DIMENSION = 4096


class DocumentRenderError(ValueError):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


@dataclass(frozen=True)
class RenderedPage:
    page_number: int
    storage_uri: str
    mime_type: str
    width: int
    height: int
    size_bytes: int
    text_alignment_uri: str | None = None
    warnings: tuple[str, ...] = ()


@dataclass(frozen=True)
class DocumentRenderResult:
    status: str
    mime_type: str
    pages: tuple[RenderedPage, ...]
    first_page_thumbnail_uri: str | None
    total_pages: int | None
    warnings: tuple[str, ...]
    parser_profile: str | None
    parser_version: str = PARSER_VERSION


def render_document_pages(
    *,
    copied_document_path: Path,
    job_scratch: Path,
    resource_profile: Mapping[str, int],
    runtime: parser_sandbox.ParserRuntime,
    original_name: str | None = None,
    max_pages: int = DEFAULT_MAX_PAGES,
    max_dimension: int = DEFAULT_MAX_DIMENSION,
) -> DocumentRenderResult:
    if max_pages <= 0:
        raise DocumentRenderError("invalid_page_limit", "page limit must be positive")
    if max_dimension <= 0:
        raise DocumentRenderError("invalid_dimension_limit", "dimension limit must be positive")
    copied = copied_document_path.resolve()
    scratch = job_scratch.resolve()
    if not _under(copied, scratch):
        raise DocumentRenderError("input_not_copied", "document input must be a scratch copy")
    if copied.is_symlink() or not copied.is_file():
        raise DocumentRenderError("invalid_document_path", "document input must be a regular file")
    signature = content_signature.detect_content_signature(copied, original_name=original_name)
    if signature.signature == "pe-executable" or "polyglot_signature" in signature.evidence:
        return _empty(
            "skipped",
            signature.mime_type,
            (f"parser_unsafe_signature:{signature.signature}", *signature.evidence),
            None,
        )
    if signature.mime_type not in SUPPORTED_MIME_TYPES:
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
    if not parsed.records:
        return _empty("failed", signature.mime_type, (f"{PROFILE}_no_output",), PROFILE)
    return _normalize_record(
        parsed.records[0],
        signature.mime_type,
        resource_profile,
        max_pages=max_pages,
        max_dimension=max_dimension,
    )


def _normalize_record(
    record: Mapping[str, Any],
    mime_type: str,
    resource_profile: Mapping[str, int],
    *,
    max_pages: int,
    max_dimension: int,
) -> DocumentRenderResult:
    status = str(record.get("status") or "complete")
    warnings = list(_strings(record.get("warnings")))
    if status != "complete":
        return DocumentRenderResult(
            status,
            mime_type,
            (),
            None,
            _total_pages(record),
            tuple(dict.fromkeys(warnings)),
            PROFILE,
        )
    output_limit = int(resource_profile.get("output_limit_mib", 1)) * 1024 * 1024
    pages: list[RenderedPage] = []
    raw_pages = record.get("pages")
    if not isinstance(raw_pages, list):
        warnings.append("missing_rendered_pages")
        raw_pages = []
    if len(raw_pages) > max_pages:
        warnings.append("page_limit_applied")
    for page in raw_pages[:max_pages]:
        rendered = _page(page, output_limit, max_dimension, warnings)
        if rendered is not None:
            pages.append(rendered)
    if not pages:
        return DocumentRenderResult(
            "failed",
            mime_type,
            (),
            None,
            _total_pages(record),
            tuple(dict.fromkeys(warnings)),
            PROFILE,
        )
    pages.sort(key=lambda page: page.page_number)
    return DocumentRenderResult(
        "complete",
        mime_type,
        tuple(pages),
        pages[0].storage_uri,
        _total_pages(record),
        tuple(dict.fromkeys(warnings)),
        PROFILE,
    )


def _page(
    page: object, output_limit: int, max_dimension: int, warnings: list[str]
) -> RenderedPage | None:
    if not isinstance(page, Mapping):
        warnings.append("invalid_page_record")
        return None
    page_number = _positive_int(page.get("page_number"))
    if page_number is None:
        warnings.append("invalid_page_number")
        return None
    mime_type = str(page.get("mime_type") or "")
    if mime_type not in SAFE_PAGE_MIME_TYPES:
        warnings.append(f"unsafe_page_mime:{page_number}")
        return None
    storage_uri = str(page.get("storage_uri") or "")
    if not storage_uri.startswith("scratch://sha256/"):
        warnings.append(f"invalid_page_storage:{page_number}")
        return None
    width = _positive_int(page.get("width"))
    height = _positive_int(page.get("height"))
    size_bytes = _positive_int(page.get("size_bytes"))
    if width is None or height is None or size_bytes is None:
        warnings.append(f"invalid_page_dimensions:{page_number}")
        return None
    if width > max_dimension or height > max_dimension:
        warnings.append(f"page_dimension_limit:{page_number}")
        return None
    if size_bytes > output_limit:
        warnings.append(f"page_output_limit:{page_number}")
        return None
    text_alignment_uri = page.get("text_alignment_uri")
    if text_alignment_uri is not None:
        text_alignment_uri = str(text_alignment_uri)
        if not text_alignment_uri.startswith("scratch://sha256/"):
            warnings.append(f"invalid_text_alignment_storage:{page_number}")
            text_alignment_uri = None
    return RenderedPage(
        page_number=page_number,
        storage_uri=storage_uri,
        mime_type=mime_type,
        width=width,
        height=height,
        size_bytes=size_bytes,
        text_alignment_uri=text_alignment_uri,
        warnings=_strings(page.get("warnings")),
    )


def _empty(
    status: str,
    mime_type: str,
    warnings: tuple[str, ...],
    parser_profile: str | None,
) -> DocumentRenderResult:
    return DocumentRenderResult(
        status, mime_type, (), None, None, tuple(dict.fromkeys(warnings)), parser_profile
    )


def _total_pages(record: Mapping[str, Any]) -> int | None:
    return _positive_int(record.get("total_pages"))


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
