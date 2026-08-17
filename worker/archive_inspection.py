"""Sandboxed archive listing and bounded extraction planning."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any

from worker import content_signature, parser_sandbox

PARSER_VERSION = "archive-inspection-adapter-v1"
PROFILE = "archive-inspect-json"
SUPPORTED_MIME_TYPES = frozenset(
    {
        "application/zip",
        "application/x-7z-compressed",
        "application/vnd.rar",
        "application/x-tar",
        "application/gzip",
    }
)
MAX_MEMBERS = 10_000
MAX_NESTED_DEPTH = 3
MAX_COMPRESSION_RATIO = 100.0


class ArchiveInspectionError(ValueError):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


@dataclass(frozen=True)
class ArchiveMember:
    path: str
    kind: str
    size_bytes: int
    compressed_size_bytes: int | None
    encrypted: bool
    extraction_allowed: bool
    warnings: tuple[str, ...] = ()


@dataclass(frozen=True)
class ArchiveInspectionResult:
    status: str
    mime_type: str
    archive_format: str
    encrypted: bool
    password_required: bool
    members: tuple[ArchiveMember, ...]
    nested_depth: int
    extraction_plan: Mapping[str, object]
    warnings: tuple[str, ...]
    parser_profile: str | None
    parser_version: str = PARSER_VERSION


def inspect_archive(
    *,
    copied_archive_path: Path,
    job_scratch: Path,
    resource_profile: Mapping[str, int],
    runtime: parser_sandbox.ParserRuntime,
    original_name: str | None = None,
    allow_extraction: bool = False,
    max_members: int = MAX_MEMBERS,
    max_nested_depth: int = MAX_NESTED_DEPTH,
) -> ArchiveInspectionResult:
    if max_members <= 0 or max_nested_depth < 0:
        raise ArchiveInspectionError("invalid_limits", "archive limits must be positive")
    copied = copied_archive_path.resolve()
    scratch = job_scratch.resolve()
    if not _under(copied, scratch):
        raise ArchiveInspectionError("input_not_copied", "archive input must be a scratch copy")
    if copied.is_symlink() or not copied.is_file():
        raise ArchiveInspectionError("invalid_archive_path", "archive input must be a regular file")
    signature = content_signature.detect_content_signature(copied, original_name=original_name)
    if signature.signature == "pe-executable" or "polyglot_signature" in signature.evidence:
        return _empty(
            "skipped",
            signature.mime_type,
            "unknown",
            (f"parser_unsafe_signature:{signature.signature}", *signature.evidence),
            None,
        )
    if signature.mime_type not in SUPPORTED_MIME_TYPES:
        return _empty(
            "skipped",
            signature.mime_type,
            "unknown",
            (f"unsupported_mime:{signature.mime_type}", *signature.evidence),
            None,
        )
    if not signature.parser_safe:
        return _empty(
            "skipped",
            signature.mime_type,
            "unknown",
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
            _format_from_mime(signature.mime_type),
            tuple(f"{PROFILE}_{warning}" for warning in parsed.warnings),
            PROFILE,
        )
    if not parsed.records:
        return _empty(
            "failed",
            signature.mime_type,
            _format_from_mime(signature.mime_type),
            (f"{PROFILE}_no_output",),
            PROFILE,
        )
    return _normalize_record(
        parsed.records[0],
        signature.mime_type,
        allow_extraction=allow_extraction,
        max_members=max_members,
        max_nested_depth=max_nested_depth,
    )


def _normalize_record(
    record: Mapping[str, Any],
    mime_type: str,
    *,
    allow_extraction: bool,
    max_members: int,
    max_nested_depth: int,
) -> ArchiveInspectionResult:
    status = str(record.get("status") or "complete")
    archive_format = str(record.get("archive_format") or _format_from_mime(mime_type))
    encrypted = bool(record.get("encrypted"))
    password_required = bool(record.get("password_required")) or encrypted
    warnings = list(_strings(record.get("warnings")))
    if status != "complete":
        return ArchiveInspectionResult(
            status,
            mime_type,
            archive_format,
            encrypted,
            password_required,
            (),
            0,
            {},
            tuple(dict.fromkeys(warnings)),
            PROFILE,
        )
    raw_members = record.get("members")
    if not isinstance(raw_members, list):
        warnings.append("missing_archive_members")
        raw_members = []
    if len(raw_members) > max_members:
        warnings.append("archive_member_limit_applied")
    members: list[ArchiveMember] = []
    for item in raw_members[:max_members]:
        member = _member(item, warnings)
        if member is not None:
            members.append(member)
    nested_depth = _positive_int(record.get("nested_depth")) or 0
    if nested_depth > max_nested_depth:
        warnings.append("nested_depth_limit_exceeded")
    plan = _extraction_plan(
        allow_extraction, members, password_required, nested_depth, max_nested_depth
    )
    if not plan["allowed"]:
        warnings.append(str(plan["reason"]))
    return ArchiveInspectionResult(
        "complete",
        mime_type,
        archive_format,
        encrypted,
        password_required,
        tuple(members),
        nested_depth,
        plan,
        tuple(dict.fromkeys(warnings)),
        PROFILE,
    )


def _member(value: object, warnings: list[str]) -> ArchiveMember | None:
    if not isinstance(value, Mapping):
        warnings.append("invalid_archive_member")
        return None
    path = str(value.get("path") or "")
    kind = str(value.get("kind") or "file")
    size_bytes = _nonnegative_int(value.get("size_bytes"))
    compressed_size = _nonnegative_int(value.get("compressed_size_bytes"))
    if not path or kind not in {"file", "directory", "symlink", "device"} or size_bytes is None:
        warnings.append("invalid_archive_member")
        return None
    member_warnings = list(_strings(value.get("warnings")))
    if _unsafe_path(path):
        member_warnings.append("unsafe_member_path")
    if kind in {"symlink", "device"}:
        member_warnings.append(f"unsafe_member_kind:{kind}")
    if (
        compressed_size is not None
        and compressed_size > 0
        and size_bytes / compressed_size > MAX_COMPRESSION_RATIO
    ):
        member_warnings.append("compression_ratio_limit")
    encrypted = bool(value.get("encrypted"))
    extraction_allowed = not member_warnings and not encrypted
    return ArchiveMember(
        path,
        kind,
        size_bytes,
        compressed_size,
        encrypted,
        extraction_allowed,
        tuple(dict.fromkeys(member_warnings)),
    )


def _extraction_plan(
    allow_extraction: bool,
    members: list[ArchiveMember],
    password_required: bool,
    nested_depth: int,
    max_nested_depth: int,
) -> dict[str, object]:
    if not allow_extraction:
        return {
            "allowed": False,
            "reason": "extraction_not_requested",
            "member_count": len(members),
        }
    if password_required:
        return {"allowed": False, "reason": "password_required", "member_count": len(members)}
    if nested_depth > max_nested_depth:
        return {"allowed": False, "reason": "nested_depth_blocked", "member_count": len(members)}
    if any(not member.extraction_allowed for member in members):
        return {"allowed": False, "reason": "unsafe_members_blocked", "member_count": len(members)}
    return {"allowed": True, "reason": "bounded_scratch_extraction", "member_count": len(members)}


def _unsafe_path(path: str) -> bool:
    pure = PurePosixPath(path.replace("\\", "/"))
    return (
        path.startswith(("/", "\\")) or ".." in pure.parts or any(part == "" for part in pure.parts)
    )


def _empty(
    status: str,
    mime_type: str,
    archive_format: str,
    warnings: tuple[str, ...],
    parser_profile: str | None,
) -> ArchiveInspectionResult:
    return ArchiveInspectionResult(
        status,
        mime_type,
        archive_format,
        False,
        False,
        (),
        0,
        {},
        tuple(dict.fromkeys(warnings)),
        parser_profile,
    )


def _format_from_mime(mime_type: str) -> str:
    return {
        "application/zip": "zip",
        "application/x-7z-compressed": "7z",
        "application/vnd.rar": "rar",
        "application/x-tar": "tar",
        "application/gzip": "gzip",
    }.get(mime_type, "unknown")


def _nonnegative_int(value: object) -> int | None:
    if isinstance(value, int) and value >= 0:
        return value
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
