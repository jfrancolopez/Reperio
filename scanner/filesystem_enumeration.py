"""Read-only filesystem identification and entry enumeration through TSK."""

from __future__ import annotations

import re
import subprocess
from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol

from scanner.partition_discovery import PartitionEntry

SUPPORTED_FILESYSTEMS = frozenset({"ntfs", "fat12", "fat16", "fat32", "exfat"})
DENIED_ARGUMENT_FRAGMENTS = frozenset(
    {
        "repair",
        "write",
        "wipe",
        "format",
        "init",
        "mkfs",
        "mount",
        "fsck",
        "chkdsk",
        "testdisk",
    }
)
FLS_LINE = re.compile(
    r"^(?P<kind>[drlv-])/(?P<alloc>[*\-])\s+"
    r"(?P<object_id>\d+(?:-\d+)?)\s*:\s*"
    r"(?P<name>.*)$"
)


class FilesystemEnumerationError(ValueError):
    """Raised when filesystem enumeration cannot run safely."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


@dataclass(frozen=True)
class FilesystemVolume:
    volume_id: str
    source_id: str
    offset_bytes: int
    filesystem: str | None
    supported: bool
    warnings: tuple[str, ...] = ()


@dataclass(frozen=True)
class FilesystemEntry:
    volume_id: str
    object_id: str
    parent_object_id: str | None
    entry_id: str
    name: str
    entry_type: str
    allocated: bool
    path: str


@dataclass(frozen=True)
class FilesystemEnumerationResult:
    volume: FilesystemVolume
    entries: tuple[FilesystemEntry, ...]
    warnings: tuple[str, ...] = ()


@dataclass(frozen=True)
class TskCommandResult:
    returncode: int
    stdout: str
    stderr: str


class FilesystemRunner(Protocol):
    def run_fsstat(self, args: tuple[str, ...], timeout_seconds: int) -> TskCommandResult: ...

    def run_fls(self, args: tuple[str, ...], timeout_seconds: int) -> TskCommandResult: ...


class SubprocessFilesystemRunner:
    """Bounded command runner for TSK filesystem tools inside the scanner sandbox."""

    def run_fsstat(self, args: tuple[str, ...], timeout_seconds: int) -> TskCommandResult:
        return _run_tsk(args, timeout_seconds, timeout_code="fsstat_timeout")

    def run_fls(self, args: tuple[str, ...], timeout_seconds: int) -> TskCommandResult:
        return _run_tsk(args, timeout_seconds, timeout_code="fls_timeout")


def enumerate_filesystem(
    source_path: Path,
    partition: PartitionEntry,
    *,
    source_id: str,
    runner: FilesystemRunner | None = None,
    timeout_seconds: int = 30,
    batch_size: int = 256,
    fsstat_binary: str = "fsstat",
    fls_binary: str = "fls",
) -> FilesystemEnumerationResult:
    """Identify a volume and enumerate entries by direct byte offset only."""

    if batch_size <= 0:
        raise FilesystemEnumerationError("invalid_batch_size", "batch size must be positive")
    offset_arg = str(partition.offset_bytes)
    fsstat_args = (fsstat_binary, "-o", offset_arg, str(source_path))
    fls_args = (fls_binary, "-r", "-p", "-o", offset_arg, str(source_path))
    _validate_safe_command(fsstat_args, expected_binary="fsstat")
    _validate_safe_command(fls_args, expected_binary="fls")

    selected_runner = runner or SubprocessFilesystemRunner()
    fsstat = selected_runner.run_fsstat(fsstat_args, timeout_seconds)
    volume = identify_volume(
        fsstat.stdout,
        fsstat.stderr,
        fsstat.returncode,
        source_id=source_id,
        partition=partition,
    )
    if not volume.supported:
        return FilesystemEnumerationResult(volume=volume, entries=(), warnings=volume.warnings)

    fls = selected_runner.run_fls(fls_args, timeout_seconds)
    entries, warnings = parse_fls_output(
        fls.stdout,
        fls.stderr,
        fls.returncode,
        volume_id=volume.volume_id,
        batch_size=batch_size,
    )
    all_warnings = tuple(dict.fromkeys((*volume.warnings, *warnings)))
    return FilesystemEnumerationResult(
        volume=volume,
        entries=entries,
        warnings=all_warnings,
    )


def identify_volume(
    stdout: str,
    stderr: str,
    returncode: int,
    *,
    source_id: str,
    partition: PartitionEntry,
) -> FilesystemVolume:
    """Normalize fsstat output into a supported/unsupported filesystem volume."""

    filesystem = _detect_filesystem(stdout)
    warnings: list[str] = []
    if returncode != 0:
        warnings.append(f"fsstat_exit:{returncode}")
    stderr_text = _sanitize_text(stderr)
    if stderr_text:
        warnings.append(f"fsstat_stderr:{stderr_text}")
    if filesystem is None:
        warnings.append("filesystem_unknown")
    elif filesystem not in SUPPORTED_FILESYSTEMS:
        warnings.append(f"filesystem_unsupported:{filesystem}")
    volume_id = f"vol-{source_id}-{partition.start_sector}-{partition.sector_count}"
    return FilesystemVolume(
        volume_id=volume_id,
        source_id=source_id,
        offset_bytes=partition.offset_bytes,
        filesystem=filesystem,
        supported=filesystem in SUPPORTED_FILESYSTEMS and returncode == 0,
        warnings=tuple(dict.fromkeys(warnings)),
    )


def parse_fls_output(
    stdout: str,
    stderr: str,
    returncode: int,
    *,
    volume_id: str,
    batch_size: int,
) -> tuple[tuple[FilesystemEntry, ...], tuple[str, ...]]:
    """Parse bounded fls output while preserving stable object and parent IDs."""

    if batch_size <= 0:
        raise FilesystemEnumerationError("invalid_batch_size", "batch size must be positive")
    warnings: list[str] = []
    entries: list[FilesystemEntry] = []
    for raw_line in _bounded_lines(stdout, limit=batch_size):
        match = FLS_LINE.match(raw_line.strip())
        if match is None:
            warnings.append("fls_unparsed_line")
            continue
        path = _normalize_path(match.group("name"))
        object_id = match.group("object_id")
        entries.append(
            FilesystemEntry(
                volume_id=volume_id,
                object_id=object_id,
                parent_object_id=_parent_id(path, entries),
                entry_id=f"entry-{volume_id}-{object_id}",
                name=path.rsplit("/", 1)[-1],
                entry_type=_entry_type(match.group("kind")),
                allocated=match.group("alloc") == "-",
                path=path,
            )
        )
    if len(stdout.splitlines()) > batch_size:
        warnings.append("fls_batch_truncated")
    if returncode != 0:
        warnings.append(f"fls_exit:{returncode}")
    stderr_text = _sanitize_text(stderr)
    if stderr_text:
        warnings.append(f"fls_stderr:{stderr_text}")
    return tuple(entries), tuple(dict.fromkeys(warnings))


def _run_tsk(args: tuple[str, ...], timeout_seconds: int, *, timeout_code: str) -> TskCommandResult:
    _validate_safe_command(args, expected_binary=Path(args[0]).name)
    try:
        completed = subprocess.run(
            args,
            check=False,
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
            timeout=timeout_seconds,
        )
    except subprocess.TimeoutExpired as error:
        raise FilesystemEnumerationError(
            timeout_code, "filesystem enumeration timed out"
        ) from error
    return TskCommandResult(completed.returncode, completed.stdout, completed.stderr)


def _detect_filesystem(stdout: str) -> str | None:
    text = stdout.lower()
    if "file system type:" in text:
        tail = text.split("file system type:", 1)[1].splitlines()[0].strip()
        return _normalize_filesystem(tail)
    return _normalize_filesystem(text)


def _normalize_filesystem(value: str) -> str | None:
    lowered = value.lower()
    if "exfat" in lowered or "ex-fat" in lowered:
        return "exfat"
    if "fat32" in lowered or "fat 32" in lowered:
        return "fat32"
    if "fat16" in lowered or "fat 16" in lowered:
        return "fat16"
    if "fat12" in lowered or "fat 12" in lowered:
        return "fat12"
    if "ntfs" in lowered:
        return "ntfs"
    if "ext4" in lowered:
        return "ext4"
    if "hfs" in lowered:
        return "hfs"
    return None


def _normalize_path(value: str) -> str:
    path = value.replace("\\", "/").strip().strip("/")
    return path or "."


def _parent_id(path: str, entries: Iterable[FilesystemEntry]) -> str | None:
    if "/" not in path:
        return None
    parent_path = path.rsplit("/", 1)[0]
    for entry in reversed(tuple(entries)):
        if entry.path == parent_path:
            return entry.object_id
    return None


def _entry_type(kind: str) -> str:
    return {
        "d": "directory",
        "r": "file",
        "l": "symlink",
        "v": "virtual",
        "-": "unknown",
    }.get(kind, "unknown")


def _bounded_lines(value: str, *, limit: int) -> tuple[str, ...]:
    return tuple(line for line in value.splitlines() if line.strip())[:limit]


def _sanitize_text(value: str) -> str:
    return " ".join(value.replace("\x00", " ").split())[:240]


def _validate_safe_command(args: tuple[str, ...], *, expected_binary: str) -> None:
    if not args:
        raise FilesystemEnumerationError("empty_command", "filesystem command is empty")
    binary = Path(args[0]).name
    if binary != expected_binary:
        raise FilesystemEnumerationError(
            "unsafe_filesystem_command", "unexpected filesystem tool requested"
        )
    joined = " ".join(args).lower()
    if any(fragment in joined for fragment in DENIED_ARGUMENT_FRAGMENTS):
        raise FilesystemEnumerationError(
            "unsafe_filesystem_command", "repair, mount, or write command surface is prohibited"
        )
