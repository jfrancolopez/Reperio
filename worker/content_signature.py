"""Deterministic content-signature and MIME detection."""

from __future__ import annotations

import hashlib
import os
from dataclasses import dataclass
from pathlib import Path

SAMPLE_BYTES = 8192
EXTENSION_MIME = {
    ".exe": "application/x-msdownload",
    ".jpg": "image/jpeg",
    ".jpeg": "image/jpeg",
    ".pdf": "application/pdf",
    ".png": "image/png",
    ".zip": "application/zip",
    ".docx": "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
}


class ContentSignatureError(ValueError):
    """Raised when content signature input is invalid."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


@dataclass(frozen=True)
class SignatureResult:
    mime_type: str
    signature: str
    confidence: float
    extension_mime: str | None
    parser_safe: bool
    evidence: tuple[str, ...]
    sample_sha256: str
    sample_size: int


def detect_content_signature(
    path: Path,
    *,
    original_name: str | None = None,
    sample_limit: int = SAMPLE_BYTES,
) -> SignatureResult:
    """Detect content type from bounded bytes; extension is evidence only."""

    if sample_limit <= 0:
        raise ContentSignatureError("invalid_sample_limit", "sample limit must be positive")
    if path.is_symlink() or not path.is_file():
        raise ContentSignatureError("invalid_content_path", "content path must be a regular file")
    with path.open("rb") as handle:
        sample = handle.read(sample_limit)
    extension_mime = EXTENSION_MIME.get(Path(original_name or path.name).suffix.lower())
    return detect_content_signature_bytes(sample, extension_mime=extension_mime)


def detect_content_signature_bytes(
    sample: bytes, *, extension_mime: str | None = None
) -> SignatureResult:
    evidence: list[str] = []
    signature, mime_type, base_confidence = _magic(sample)
    if not sample:
        evidence.append("empty_content")
    if extension_mime is not None:
        evidence.append(f"extension:{extension_mime}")
        if extension_mime != mime_type:
            evidence.append("extension_mismatch")
    if _is_polyglot(sample):
        evidence.append("polyglot_signature")
        base_confidence = min(base_confidence, 0.65)
    if signature == "unknown" and sample:
        evidence.append("unknown_magic")
    parser_safe = (
        signature not in {"pe-executable", "unknown", "empty"}
        and "polyglot_signature" not in evidence
    )
    if extension_mime is not None and extension_mime != mime_type:
        parser_safe = False
    return SignatureResult(
        mime_type=mime_type,
        signature=signature,
        confidence=round(base_confidence, 2),
        extension_mime=extension_mime,
        parser_safe=parser_safe,
        evidence=tuple(dict.fromkeys(evidence)),
        sample_sha256=hashlib.sha256(sample).hexdigest(),
        sample_size=len(sample),
    )


def _magic(sample: bytes) -> tuple[str, str, float]:
    if not sample:
        return "empty", "application/x-empty", 1.0
    if sample.startswith(b"MZ"):
        return "pe-executable", "application/x-msdownload", 0.98
    if sample.startswith(b"\xff\xd8\xff"):
        return "jpeg", "image/jpeg", 0.98
    if sample.startswith(b"%PDF-"):
        return "pdf", "application/pdf", 0.98
    if sample.startswith(b"\x89PNG\r\n\x1a\n"):
        return "png", "image/png", 0.98
    if sample.startswith(b"PK\x03\x04"):
        if b"word/" in sample[:SAMPLE_BYTES]:
            return (
                "docx",
                "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
                0.92,
            )
        return "zip", "application/zip", 0.9
    if _looks_random(sample):
        return "random", "application/octet-stream", 0.4
    return "unknown", "application/octet-stream", 0.2


def _is_polyglot(sample: bytes) -> bool:
    hits = 0
    for marker in (b"MZ", b"%PDF-", b"PK\x03\x04", b"\xff\xd8\xff", b"\x89PNG\r\n\x1a\n"):
        if marker in sample:
            hits += 1
    return hits > 1


def _looks_random(sample: bytes) -> bool:
    if len(sample) < 512:
        return False
    unique = len(set(sample))
    zeros = sample.count(0)
    return unique > 200 and zeros < len(sample) // 100


def sparse_sample(path: Path, *, sample_limit: int = SAMPLE_BYTES) -> bytes:
    """Read a bounded sample from a possibly sparse file without expanding it."""

    if sample_limit <= 0:
        raise ContentSignatureError("invalid_sample_limit", "sample limit must be positive")
    fd = os.open(path, os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0))
    try:
        return os.pread(fd, sample_limit, 0)
    finally:
        os.close(fd)
