"""Bounded copy-repair and regeneration adapter operating only on scratch copies."""

from __future__ import annotations

import hashlib
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from worker import content_signature, parser_sandbox

PARSER_VERSION = "copy-repair-adapter-v1"
PROFILE = "copy-repair-json"
MEDIA_REMUX_MIME_TYPES = frozenset({"video/mp4", "video/quicktime", "audio/mpeg", "audio/wav"})
ARCHIVE_RECOVERY_MIME_TYPES = frozenset(
    {
        "application/zip",
        "application/x-7z-compressed",
        "application/vnd.rar",
        "application/x-tar",
        "application/gzip",
    }
)
PDF_REBUILD_MIME_TYPES = frozenset({"application/pdf"})
IMAGE_REENCODE_MIME_TYPES = frozenset(
    {"image/jpeg", "image/png", "image/gif", "image/tiff", "image/heic", "image/x-dcraw"}
)
QUALITY_STATUSES = frozenset({"recovered", "partial", "possibly_lossy"})
SAFE_OUTPUTS = {
    "media-remux": frozenset({"video/mp4", "video/quicktime", "audio/mpeg", "audio/wav"}),
    "archive-recovery": frozenset(
        {
            "application/zip",
            "application/x-7z-compressed",
            "application/vnd.rar",
            "application/x-tar",
            "application/gzip",
        }
    ),
    "pdf-rebuild": frozenset({"application/pdf"}),
    "image-reencode": frozenset({"image/jpeg", "image/png", "image/webp"}),
}
MAX_REPAIRS = 4


class CopyRepairError(ValueError):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


@dataclass(frozen=True)
class RepairedArtifact:
    repair_kind: str
    storage_uri: str
    mime_type: str
    size_bytes: int
    quality_status: str
    original_linkage: str
    derived: bool = True
    warnings: tuple[str, ...] = ()
    parser_version: str = PARSER_VERSION


@dataclass(frozen=True)
class CopyRepairResult:
    status: str
    source_mime_type: str
    source_signature: str
    repair_kind: str | None
    original_content_sha256: str | None
    repaired: RepairedArtifact | None
    warnings: tuple[str, ...]
    parser_profile: str | None
    parser_version: str = PARSER_VERSION


def attempt_bounded_repair(
    *,
    copied_artifact_path: Path,
    job_scratch: Path,
    resource_profile: Mapping[str, int],
    runtime: parser_sandbox.ParserRuntime,
    original_name: str | None = None,
) -> CopyRepairResult:
    """Attempt bounded repair/regeneration of a scratch copy only.

    The input must already be a scratch copy; the repair tool never receives a
    source path or device. Repaired output is always a new derived artifact in
    scratch storage linked to the original content hash, never a replacement.
    """
    copied = copied_artifact_path.resolve()
    scratch = job_scratch.resolve()
    if not _under(copied, scratch):
        raise CopyRepairError("input_not_copied", "repair input must be a scratch copy")
    if copied.is_symlink() or not copied.is_file():
        raise CopyRepairError("invalid_repair_path", "repair input must be a regular file")
    signature = content_signature.detect_content_signature(copied, original_name=original_name)
    if signature.signature == "pe-executable" or "polyglot_signature" in signature.evidence:
        return _empty(
            "skipped",
            signature.mime_type,
            signature.signature,
            (f"parser_unsafe_signature:{signature.signature}", *signature.evidence),
            None,
        )
    repair_kind = _repair_kind(signature.mime_type)
    if repair_kind is None:
        return _empty(
            "skipped",
            signature.mime_type,
            signature.signature,
            (f"unsupported_mime:{signature.mime_type}", *signature.evidence),
            None,
        )
    if not signature.parser_safe:
        return _empty(
            "skipped",
            signature.mime_type,
            signature.signature,
            (f"parser_unsafe_signature:{signature.signature}", *signature.evidence),
            None,
        )

    original_content_sha256 = _file_sha256(copied)
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
            signature.signature,
            tuple(f"{PROFILE}_{warning}" for warning in parsed.warnings),
            PROFILE,
            original_content_sha256=original_content_sha256,
        )
    repaired, warnings = _normalize(
        parsed.records, repair_kind, resource_profile, original_content_sha256
    )
    if repaired is None:
        return _empty(
            "failed",
            signature.mime_type,
            signature.signature,
            warnings or (f"{PROFILE}_no_repaired_output",),
            PROFILE,
            original_content_sha256=original_content_sha256,
        )
    return CopyRepairResult(
        "complete",
        signature.mime_type,
        signature.signature,
        repair_kind,
        original_content_sha256,
        repaired,
        warnings,
        PROFILE,
    )


def _normalize(
    records: tuple[dict[str, Any], ...],
    repair_kind: str,
    resource_profile: Mapping[str, int],
    original_content_sha256: str,
) -> tuple[RepairedArtifact | None, tuple[str, ...]]:
    output_limit = int(resource_profile.get("output_limit_mib", 1)) * 1024 * 1024
    warnings: list[str] = []
    if len(records) > MAX_REPAIRS:
        warnings.append("copy_repair_record_limit_exceeded")
    for record in records[:MAX_REPAIRS]:
        kind = str(record.get("repair_kind") or "")
        if kind != repair_kind:
            warnings.append(f"unsupported_repair_kind:{kind or 'missing'}")
            continue
        record_warnings = _strings(record.get("warnings"))
        warnings.extend(record_warnings)
        if str(record.get("status") or "complete") != "complete":
            return None, tuple(dict.fromkeys(warnings))
        repaired = _artifact(record, repair_kind, output_limit, original_content_sha256, warnings)
        if repaired is not None:
            return repaired, tuple(dict.fromkeys(warnings))
    return None, tuple(dict.fromkeys(warnings))


def _artifact(
    record: Mapping[str, Any],
    kind: str,
    output_limit: int,
    original_content_sha256: str,
    warnings: list[str],
) -> RepairedArtifact | None:
    mime_type = str(record.get("mime_type") or "")
    if mime_type not in SAFE_OUTPUTS[kind]:
        warnings.append(f"unsafe_repaired_mime:{kind}")
        return None
    storage_uri = str(record.get("storage_uri") or "")
    if not storage_uri.startswith("scratch://sha256/"):
        warnings.append("invalid_repaired_storage")
        return None
    size_bytes = _positive_int(record.get("size_bytes"))
    if size_bytes is None or size_bytes > output_limit:
        warnings.append("repair_output_limit")
        return None
    quality_status = str(record.get("quality_status") or "possibly_lossy")
    if quality_status not in QUALITY_STATUSES:
        warnings.append("invalid_quality_status")
        return None
    if not bool(record.get("derived")):
        warnings.append("repair_derived_required")
        return None
    if str(record.get("original_sha256") or "") != original_content_sha256:
        warnings.append("original_linkage_mismatch")
        return None
    return RepairedArtifact(
        repair_kind=kind,
        storage_uri=storage_uri,
        mime_type=mime_type,
        size_bytes=size_bytes,
        quality_status=quality_status,
        original_linkage=f"sha256:{original_content_sha256}",
        derived=True,
        warnings=tuple(
            str(item)[:128] for item in record.get("warnings", ()) if isinstance(item, str)
        ),
    )


def _empty(
    status: str,
    source_mime_type: str,
    source_signature: str,
    warnings: tuple[str, ...],
    parser_profile: str | None,
    *,
    original_content_sha256: str | None = None,
) -> CopyRepairResult:
    return CopyRepairResult(
        status,
        source_mime_type,
        source_signature,
        None,
        original_content_sha256,
        None,
        tuple(dict.fromkeys(warnings)),
        parser_profile,
    )


def _repair_kind(mime_type: str) -> str | None:
    if mime_type in MEDIA_REMUX_MIME_TYPES:
        return "media-remux"
    if mime_type in ARCHIVE_RECOVERY_MIME_TYPES:
        return "archive-recovery"
    if mime_type in PDF_REBUILD_MIME_TYPES:
        return "pdf-rebuild"
    if mime_type in IMAGE_REENCODE_MIME_TYPES:
        return "image-reencode"
    return None


def _file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _strings(value: object) -> tuple[str, ...]:
    if isinstance(value, list | tuple):
        return tuple(str(item)[:256] for item in value)
    return ()


def _positive_int(value: object) -> int | None:
    if isinstance(value, int) and value > 0:
        return value
    return None


def _under(path: Path, root: Path) -> bool:
    try:
        path.relative_to(root)
    except ValueError:
        return False
    return True
