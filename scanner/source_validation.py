"""Scanner-side source validation before any parser can run."""

from __future__ import annotations

import os
import stat
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Protocol

from hostd import fingerprint
from scanner import messages


class SourceValidationError(ValueError):
    """Raised when the selected source cannot be trusted by the scanner."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


@dataclass(frozen=True)
class SourceStat:
    is_block: bool
    is_symlink: bool
    device_id: int


@dataclass(frozen=True)
class ExpectedSource:
    path: Path
    source_id: str
    size_bytes: int
    sector_size: int
    fingerprint_hash: str
    identity_facts: Mapping[str, Any]


@dataclass(frozen=True)
class SourceValidationResult:
    source_id: str
    size_bytes: int
    sector_size: int
    fingerprint_hash: str
    capabilities: tuple[str, ...]

    def capabilities_message(self, sequence: int = 0) -> bytes:
        return messages.encode_message(
            "capabilities",
            sequence,
            {"capabilities": list(self.capabilities)},
        )


class SourceOps(Protocol):
    def lstat(self, path: Path) -> SourceStat: ...

    def open_readonly(self, path: Path) -> int: ...

    def fstat(self, fd: int) -> SourceStat: ...

    def pread(self, fd: int, length: int, offset: int) -> bytes: ...

    def verify_read_only(self, fd: int) -> bool: ...

    def close(self, fd: int) -> None: ...


class LinuxSourceOps:
    """Linux implementation used by scanner workers inside the fixed sandbox."""

    def lstat(self, path: Path) -> SourceStat:
        return _stat_to_source_stat(os.lstat(path))

    def open_readonly(self, path: Path) -> int:
        flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
        return os.open(path, flags)

    def fstat(self, fd: int) -> SourceStat:
        return _stat_to_source_stat(os.fstat(fd))

    def pread(self, fd: int, length: int, offset: int) -> bytes:
        return os.pread(fd, length, offset)

    def verify_read_only(self, fd: int) -> bool:
        return not os.access(f"/proc/self/fd/{fd}", os.W_OK)

    def close(self, fd: int) -> None:
        os.close(fd)


def validate_source(
    expected: ExpectedSource, *, ops: SourceOps | None = None
) -> SourceValidationResult:
    """Validate source identity, read-only state, geometry, and fingerprint."""

    selected_ops = ops or LinuxSourceOps()
    before = selected_ops.lstat(expected.path)
    if before.is_symlink:
        raise SourceValidationError("source_symlink", "source path must not be a symlink")
    if not before.is_block:
        raise SourceValidationError("source_not_block", "source path must be block-special")

    try:
        fd = selected_ops.open_readonly(expected.path)
    except OSError as error:
        raise SourceValidationError(
            "source_open_failed", "source could not be opened read-only"
        ) from error
    try:
        after = selected_ops.fstat(fd)
        if not after.is_block or after.device_id != before.device_id:
            raise SourceValidationError("source_replaced", "source changed during validation")
        if not selected_ops.verify_read_only(fd):
            raise SourceValidationError("source_writable", "source is not verified read-only")
        actual = fingerprint.fingerprint_from_reader(
            lambda offset, length: selected_ops.pread(fd, length, offset),
            size_bytes=expected.size_bytes,
            sector_size=expected.sector_size,
            identity_facts=expected.identity_facts,
        )
    finally:
        selected_ops.close(fd)

    if actual["size_bytes"] != expected.size_bytes:
        raise SourceValidationError("source_size_mismatch", "source size does not match expected")
    if actual["sector_size"] != expected.sector_size:
        raise SourceValidationError(
            "source_sector_size_mismatch", "source sector size does not match expected"
        )
    if actual["fingerprint_hash"] != expected.fingerprint_hash:
        raise SourceValidationError(
            "source_fingerprint_mismatch", "source fingerprint does not match expected"
        )

    return SourceValidationResult(
        source_id=expected.source_id,
        size_bytes=expected.size_bytes,
        sector_size=expected.sector_size,
        fingerprint_hash=str(actual["fingerprint_hash"]),
        capabilities=("source-validation", "read-only-source", "sampled-fingerprint"),
    )


def _stat_to_source_stat(value: os.stat_result) -> SourceStat:
    mode = value.st_mode
    return SourceStat(
        is_block=stat.S_ISBLK(mode),
        is_symlink=stat.S_ISLNK(mode),
        device_id=int(value.st_rdev),
    )
