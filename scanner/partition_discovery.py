"""Read-only partition discovery through The Sleuth Kit mmls output."""

from __future__ import annotations

import re
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol

SUPPORTED_TABLES = frozenset({"DOS Partition Table", "GUID Partition Table"})
DENIED_ARGUMENT_FRAGMENTS = frozenset(
    {
        "repair",
        "write",
        "wipe",
        "format",
        "init",
        "mkfs",
        "parted",
        "fdisk",
        "sgdisk",
        "testdisk",
    }
)
MMLS_LINE = re.compile(
    r"^\s*(?P<slot>\d{3}:)\s+"
    r"(?P<meta>Meta|-----)\s+"
    r"(?P<start>\d+)\s+"
    r"(?P<end>\d+)\s+"
    r"(?P<length>\d+)\s+"
    r"(?P<description>.+?)\s*$"
)


class PartitionDiscoveryError(ValueError):
    """Raised when partition discovery cannot run safely."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


@dataclass(frozen=True)
class PartitionEntry:
    slot: str
    offset_bytes: int
    length_bytes: int
    start_sector: int
    end_sector: int
    sector_count: int
    description: str
    partition_type: str | None
    label: str | None
    allocated: bool
    warnings: tuple[str, ...] = ()


@dataclass(frozen=True)
class PartitionDiscoveryResult:
    source_id: str
    table_type: str | None
    sector_size: int
    partitions: tuple[PartitionEntry, ...]
    warnings: tuple[str, ...] = ()


@dataclass(frozen=True)
class TskCommandResult:
    returncode: int
    stdout: str
    stderr: str


class TskRunner(Protocol):
    def run_mmls(self, args: tuple[str, ...], timeout_seconds: int) -> TskCommandResult: ...


class SubprocessTskRunner:
    """Bounded command runner for TSK tools inside the scanner sandbox."""

    def run_mmls(self, args: tuple[str, ...], timeout_seconds: int) -> TskCommandResult:
        _validate_safe_command(args)
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
            raise PartitionDiscoveryError(
                "partition_timeout", "partition discovery timed out"
            ) from error
        return TskCommandResult(completed.returncode, completed.stdout, completed.stderr)


def discover_partitions(
    source_path: Path,
    *,
    source_id: str,
    sector_size: int,
    runner: TskRunner | None = None,
    timeout_seconds: int = 30,
    mmls_binary: str = "mmls",
) -> PartitionDiscoveryResult:
    """Discover partition extents without mounting or exposing repair commands."""

    if sector_size <= 0:
        raise PartitionDiscoveryError("invalid_sector_size", "sector size must be positive")
    args = (mmls_binary, "-B", "-S", str(sector_size), str(source_path))
    _validate_safe_command(args)
    selected_runner = runner or SubprocessTskRunner()
    result = selected_runner.run_mmls(args, timeout_seconds)
    return parse_mmls_output(
        result.stdout,
        result.stderr,
        result.returncode,
        source_id=source_id,
        sector_size=sector_size,
    )


def parse_mmls_output(
    stdout: str,
    stderr: str,
    returncode: int,
    *,
    source_id: str,
    sector_size: int,
) -> PartitionDiscoveryResult:
    """Parse bounded mmls text into normalized partition entries and warnings."""

    if sector_size <= 0:
        raise PartitionDiscoveryError("invalid_sector_size", "sector size must be positive")
    warnings: list[str] = []
    table_type: str | None = None
    partitions: list[PartitionEntry] = []
    for raw_line in stdout.splitlines():
        line = raw_line.strip()
        if not line:
            continue
        if line.startswith("Partition Table:"):
            table_type = line.split(":", 1)[1].strip() or None
            if table_type is not None and table_type not in SUPPORTED_TABLES:
                warnings.append(f"unsupported_table:{table_type}")
            continue
        match = MMLS_LINE.match(raw_line)
        if match is None:
            continue
        entry = _entry_from_match(match, sector_size)
        partitions.append(entry)
        warnings.extend(entry.warnings)

    stderr_text = _sanitize_text(stderr)
    if returncode != 0:
        warnings.append(f"mmls_exit:{returncode}")
    if stderr_text:
        warnings.append(f"mmls_stderr:{stderr_text}")
    if table_type is None:
        warnings.append("partition_table_missing")
    if not partitions:
        warnings.append("no_partitions")
    if _has_overlap(partitions):
        warnings.append("overlapping_partitions")
    return PartitionDiscoveryResult(
        source_id=source_id,
        table_type=table_type,
        sector_size=sector_size,
        partitions=tuple(partitions),
        warnings=tuple(dict.fromkeys(warnings)),
    )


def _entry_from_match(match: re.Match[str], sector_size: int) -> PartitionEntry:
    start_sector = int(match.group("start"))
    end_sector = int(match.group("end"))
    sector_count = int(match.group("length"))
    description = match.group("description").strip()
    allocated = match.group("meta") == "Meta"
    expected_count = max(0, end_sector - start_sector + 1)
    warnings: list[str] = []
    if sector_count != expected_count:
        warnings.append(f"length_mismatch:{match.group('slot')}")
    if "Primary Table" in description or "Unallocated" in description:
        allocated = False
    return PartitionEntry(
        slot=match.group("slot"),
        offset_bytes=start_sector * sector_size,
        length_bytes=sector_count * sector_size,
        start_sector=start_sector,
        end_sector=end_sector,
        sector_count=sector_count,
        description=description,
        partition_type=_partition_type(description),
        label=_partition_label(description),
        allocated=allocated,
        warnings=tuple(warnings),
    )


def _partition_type(description: str) -> str | None:
    for separator in (",", "("):
        if separator in description:
            return description.split(separator, 1)[0].strip() or None
    return description or None


def _partition_label(description: str) -> str | None:
    if "(" not in description or ")" not in description:
        return None
    return description.split("(", 1)[1].split(")", 1)[0].strip() or None


def _has_overlap(partitions: list[PartitionEntry]) -> bool:
    allocated = sorted(
        (entry.start_sector, entry.end_sector) for entry in partitions if entry.allocated
    )
    previous_end: int | None = None
    for start, end in allocated:
        if previous_end is not None and start <= previous_end:
            return True
        previous_end = end
    return False


def _sanitize_text(value: str) -> str:
    return " ".join(value.replace("\x00", " ").split())[:240]


def _validate_safe_command(args: tuple[str, ...]) -> None:
    if not args:
        raise PartitionDiscoveryError("empty_command", "partition command is empty")
    binary = Path(args[0]).name
    if binary != "mmls":
        raise PartitionDiscoveryError("unsafe_partition_command", "only mmls is allowed")
    joined = " ".join(args).lower()
    if any(fragment in joined for fragment in DENIED_ARGUMENT_FRAGMENTS):
        raise PartitionDiscoveryError(
            "unsafe_partition_command", "repair or write command surface is prohibited"
        )
