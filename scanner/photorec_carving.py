"""Scripted PhotoRec carving adapter with strict safety boundaries."""

from __future__ import annotations

import re
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol

PHOTOREC_VERSION = "7.2"
ALLOWED_SIGNATURES = frozenset({"jpg", "pdf", "zip"})
DENIED_COMMAND_FRAGMENTS = frozenset(
    {"testdisk", "repair", "write", "wipe", "format", "init", "mkfs", "mount", "fsck", "chkdsk"}
)
RECOVERED_LINE = re.compile(r"(?P<count>\d+)\s+files?\s+saved", re.IGNORECASE)


class PhotoRecCarvingError(ValueError):
    """Raised when a PhotoRec carve cannot be started safely."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


@dataclass(frozen=True)
class CarveRange:
    offset_bytes: int
    length_bytes: int


@dataclass(frozen=True)
class PhotoRecCommand:
    args: tuple[str, ...]
    destination: Path
    signatures: tuple[str, ...]


@dataclass(frozen=True)
class PhotoRecRunResult:
    returncode: int
    stdout: str
    stderr: str
    timed_out: bool = False


@dataclass(frozen=True)
class PhotoRecSummary:
    status: str
    recovered_count: int
    destination: Path
    warnings: tuple[str, ...]
    command: PhotoRecCommand


class PhotoRecRunner(Protocol):
    def run(self, args: tuple[str, ...], timeout_seconds: int) -> PhotoRecRunResult: ...


class SubprocessPhotoRecRunner:
    """Bounded non-interactive runner for the scanner sandbox."""

    def run(self, args: tuple[str, ...], timeout_seconds: int) -> PhotoRecRunResult:
        _validate_command(args)
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
            return PhotoRecRunResult(
                124,
                _decode_timeout_output(error.stdout),
                _decode_timeout_output(error.stderr),
                timed_out=True,
            )
        return PhotoRecRunResult(completed.returncode, completed.stdout, completed.stderr)


def build_photorec_command(
    *,
    source_path: Path,
    scratch_root: Path,
    signatures: tuple[str, ...],
    ranges: tuple[CarveRange, ...],
    photorec_binary: str = "photorec",
) -> PhotoRecCommand:
    """Build a scripted PhotoRec command that writes only under scratch."""

    if not signatures:
        raise PhotoRecCarvingError("empty_signature_set", "at least one signature is required")
    normalized_signatures = tuple(sorted(set(signatures)))
    disallowed = sorted(set(normalized_signatures) - ALLOWED_SIGNATURES)
    if disallowed:
        raise PhotoRecCarvingError("signature_not_allowed", "PhotoRec signature is not allowlisted")
    _validate_ranges(ranges)
    destination = (scratch_root / "photorec-quarantine").resolve(strict=False)
    if scratch_root.resolve(strict=False) not in (destination, *destination.parents):
        raise PhotoRecCarvingError("destination_escape", "PhotoRec output must stay under scratch")
    options = ["/log", "/d", str(destination), "/cmd", str(source_path)]
    for signature in normalized_signatures:
        options.extend(("fileopt", f"{signature},enable"))
    for carve_range in ranges:
        options.extend(("range", f"{carve_range.offset_bytes}:{carve_range.length_bytes}"))
    options.append("search")
    command = PhotoRecCommand((photorec_binary, *options), destination, normalized_signatures)
    _validate_command(command.args)
    return command


def run_photorec_carve(
    *,
    source_path: Path,
    scratch_root: Path,
    signatures: tuple[str, ...],
    ranges: tuple[CarveRange, ...],
    runner: PhotoRecRunner | None = None,
    timeout_seconds: int = 300,
    photorec_binary: str = "photorec",
) -> PhotoRecSummary:
    command = build_photorec_command(
        source_path=source_path,
        scratch_root=scratch_root,
        signatures=signatures,
        ranges=ranges,
        photorec_binary=photorec_binary,
    )
    command.destination.mkdir(mode=0o700, parents=True, exist_ok=True)
    selected_runner = runner or SubprocessPhotoRecRunner()
    result = selected_runner.run(command.args, timeout_seconds)
    recovered_count, warnings = parse_photorec_log(
        result.stdout, result.stderr, result.returncode, timed_out=result.timed_out
    )
    status = "partial" if result.timed_out or result.returncode not in {0, 1} else "complete"
    if result.returncode == 1:
        status = "completed-warning"
    return PhotoRecSummary(status, recovered_count, command.destination, warnings, command)


def parse_photorec_log(
    stdout: str, stderr: str, returncode: int, *, timed_out: bool = False
) -> tuple[int, tuple[str, ...]]:
    recovered = 0
    warnings: list[str] = []
    for line in stdout.splitlines():
        match = RECOVERED_LINE.search(line)
        if match is not None:
            recovered = max(recovered, int(match.group("count")))
    stderr_text = _sanitize(stderr)
    if timed_out:
        warnings.append("photorec_timeout")
    if returncode not in {0, 1, 124}:
        warnings.append(f"photorec_exit:{returncode}")
    if stderr_text:
        warnings.append(f"photorec_stderr:{stderr_text}")
    if "not a disk image" in stdout.lower() or "unknown filesystem" in stdout.lower():
        warnings.append("photorec_input_unknown")
    if "no space" in stderr.lower() or "no space" in stdout.lower():
        warnings.append("photorec_no_space")
    return recovered, tuple(dict.fromkeys(warnings))


def _validate_ranges(ranges: tuple[CarveRange, ...]) -> None:
    if not ranges:
        raise PhotoRecCarvingError("empty_range_set", "at least one carve range is required")
    for carve_range in ranges:
        if carve_range.offset_bytes < 0 or carve_range.length_bytes <= 0:
            raise PhotoRecCarvingError("invalid_range", "carve ranges must be positive")


def _validate_command(args: tuple[str, ...]) -> None:
    if not args or Path(args[0]).name != "photorec":
        raise PhotoRecCarvingError("unsafe_photorec_command", "only photorec is allowed")
    joined = " ".join(args).lower()
    if any(fragment in joined for fragment in DENIED_COMMAND_FRAGMENTS):
        raise PhotoRecCarvingError(
            "unsafe_photorec_command", "repair, mount, or write command surface is prohibited"
        )
    if "/cmd" not in args or "/d" not in args or "search" not in args:
        raise PhotoRecCarvingError("unsafe_photorec_command", "PhotoRec must run scripted search")


def _sanitize(value: str) -> str:
    return " ".join(value.replace("\x00", " ").split())[:240]


def _decode_timeout_output(value: bytes | str | None) -> str:
    if value is None:
        return ""
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace")
    return value
