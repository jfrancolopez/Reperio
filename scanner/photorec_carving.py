"""Scripted PhotoRec carving adapter with strict safety boundaries."""

from __future__ import annotations

import re
import stat
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol

PHOTOREC_BINARY = "photorec"
PHOTOREC_VERSION = "7.2"
ALLOWED_SIGNATURES = frozenset({"jpg", "pdf", "zip"})
MAX_TIMEOUT_SECONDS = 24 * 60 * 60
MAX_TOOL_OUTPUT_CHARS = 1_048_576
MAX_RECOVERED_COUNT = (1 << 63) - 1
MAX_RANGES = 4_096
MAX_RANGE_VALUE = (1 << 63) - 1
MAX_PATH_CHARS = 4_096
FORBIDDEN_PATH_PARTS = frozenset({".", ".."})
SAFE_SUBPROCESS_ENV = {
    "LANG": "C",
    "LC_ALL": "C",
    "PATH": "/usr/sbin:/usr/bin:/sbin:/bin",
}
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

    def __post_init__(self) -> None:
        _validate_range_values(self.offset_bytes, self.length_bytes)


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
        _validate_timeout(timeout_seconds)
        _validate_command(args)
        try:
            completed = subprocess.run(
                args,
                check=False,
                stdin=subprocess.DEVNULL,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                cwd="/",
                env=SAFE_SUBPROCESS_ENV,
                start_new_session=True,
                timeout=timeout_seconds,
            )
        except subprocess.TimeoutExpired as error:
            return PhotoRecRunResult(
                124,
                _decode_timeout_output(error.stdout),
                _decode_timeout_output(error.stderr),
                timed_out=True,
            )
        except (OSError, ValueError) as error:
            raise PhotoRecCarvingError(
                "runner_failed", "PhotoRec could not be started safely"
            ) from error
        result = PhotoRecRunResult(completed.returncode, completed.stdout, completed.stderr)
        _validate_run_result(result)
        return result


def build_photorec_command(
    *,
    source_path: Path,
    scratch_root: Path,
    signatures: tuple[str, ...],
    ranges: tuple[CarveRange, ...],
    photorec_binary: str = PHOTOREC_BINARY,
) -> PhotoRecCommand:
    """Build a scripted PhotoRec command that writes only under scratch."""

    _validate_source_path(source_path)
    _validate_binary(photorec_binary)
    scratch_root_resolved, destination = _validate_scratch_root(scratch_root)
    normalized_signatures = _normalize_signatures(signatures)
    _validate_ranges(ranges)
    if destination.parent != scratch_root_resolved:
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
    photorec_binary: str = PHOTOREC_BINARY,
) -> PhotoRecSummary:
    _validate_timeout(timeout_seconds)
    command = build_photorec_command(
        source_path=source_path,
        scratch_root=scratch_root,
        signatures=signatures,
        ranges=ranges,
        photorec_binary=photorec_binary,
    )
    scratch_root_path = command.destination.parent
    try:
        scratch_root_path.mkdir(mode=0o700, parents=True, exist_ok=True)
        scratch_root_path.chmod(0o700)
        command.destination.mkdir(mode=0o700, exist_ok=True)
        command.destination.chmod(0o700)
    except OSError as error:
        raise PhotoRecCarvingError(
            "destination_unavailable", "PhotoRec quarantine cannot be created"
        ) from error
    _validate_private_directory(command.destination.parent, "scratch root")
    _validate_private_directory(command.destination, "PhotoRec quarantine")
    selected_runner = runner or SubprocessPhotoRecRunner()
    result = selected_runner.run(command.args, timeout_seconds)
    _validate_run_result(result)
    recovered_count, warnings = parse_photorec_log(
        result.stdout, result.stderr, result.returncode, timed_out=result.timed_out
    )
    if result.timed_out or result.returncode not in {0, 1}:
        status = "partial"
    elif result.returncode == 1:
        status = "completed-warning"
    else:
        status = "complete"
    return PhotoRecSummary(status, recovered_count, command.destination, warnings, command)


def parse_photorec_log(
    stdout: str, stderr: str, returncode: int, *, timed_out: bool = False
) -> tuple[int, tuple[str, ...]]:
    _validate_log_text(stdout, "stdout")
    _validate_log_text(stderr, "stderr")
    if type(returncode) is not int or type(timed_out) is not bool:
        raise PhotoRecCarvingError(
            "invalid_tool_result", "PhotoRec returned invalid result metadata"
        )
    recovered = 0
    warnings: list[str] = []
    for line in stdout.splitlines():
        match = RECOVERED_LINE.search(line)
        if match is not None:
            try:
                count = int(match.group("count"))
            except ValueError:
                warnings.append("photorec_count_invalid")
                continue
            if count > MAX_RECOVERED_COUNT:
                recovered = MAX_RECOVERED_COUNT
                warnings.append("photorec_count_capped")
            else:
                recovered = max(recovered, count)
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
    if not isinstance(ranges, tuple) or not ranges:
        raise PhotoRecCarvingError("empty_range_set", "at least one carve range is required")
    if len(ranges) > MAX_RANGES:
        raise PhotoRecCarvingError(
            "too_many_ranges", "PhotoRec range count exceeds the bounded limit"
        )
    for carve_range in ranges:
        if not isinstance(carve_range, CarveRange):
            raise PhotoRecCarvingError("invalid_range", "carve range is malformed")
        _validate_range_values(carve_range.offset_bytes, carve_range.length_bytes)


def _validate_command(args: tuple[str, ...]) -> None:
    if (
        not isinstance(args, tuple)
        or len(args) < 9
        or any(not isinstance(argument, str) for argument in args)
        or args[0] != PHOTOREC_BINARY
        or args[1] != "/log"
        or args[2] != "/d"
        or args[4] != "/cmd"
        or args[-1] not in {"search", "resume"}
    ):
        raise PhotoRecCarvingError(
            "unsafe_photorec_command", "only the fixed PhotoRec command is allowed"
        )
    _validate_source_path(Path(args[5]))
    destination = Path(args[3])
    if (
        not destination.is_absolute()
        or len(str(destination)) > MAX_PATH_CHARS
        or any(char in str(destination) for char in "\x00\n\r")
        or destination.name != "photorec-quarantine"
        or any(part in FORBIDDEN_PATH_PARTS for part in destination.parts)
    ):
        raise PhotoRecCarvingError("destination_escape", "PhotoRec output path is invalid")

    signatures: list[str] = []
    ranges: list[CarveRange] = []
    index = 6
    while index < len(args) - 1:
        option = args[index]
        if option == "fileopt" and index + 1 < len(args) - 1:
            value = args[index + 1]
            signature, separator, enabled = value.partition(",")
            if separator != "," or enabled != "enable":
                raise PhotoRecCarvingError(
                    "unsafe_photorec_command", "PhotoRec file options are invalid"
                )
            signatures.extend(_normalize_signatures((signature,)))
            index += 2
            continue
        if option == "range" and index + 1 < len(args) - 1:
            offset_text, separator, length_text = args[index + 1].partition(":")
            if separator != ":" or not offset_text.isdigit() or not length_text.isdigit():
                raise PhotoRecCarvingError(
                    "unsafe_photorec_command", "PhotoRec range option is invalid"
                )
            try:
                ranges.append(CarveRange(int(offset_text), int(length_text)))
            except (PhotoRecCarvingError, ValueError) as error:
                raise PhotoRecCarvingError(
                    "unsafe_photorec_command", "PhotoRec range option is invalid"
                ) from error
            index += 2
            continue
        raise PhotoRecCarvingError(
            "unsafe_photorec_command", "PhotoRec command option is not allowlisted"
        )
    if not signatures or not ranges:
        raise PhotoRecCarvingError(
            "unsafe_photorec_command", "PhotoRec requires signatures and ranges"
        )
    _validate_ranges(tuple(ranges))


def _validate_source_path(source_path: Path) -> None:
    if (
        not isinstance(source_path, Path)
        or not source_path.is_absolute()
        or len(str(source_path)) > MAX_PATH_CHARS
        or any(char in str(source_path) for char in "\x00\n\r")
        or any(part in FORBIDDEN_PATH_PARTS for part in source_path.parts)
        or Path("/dev") not in source_path.parents
        or source_path == Path("/dev")
    ):
        raise PhotoRecCarvingError(
            "unsafe_source_path", "PhotoRec source must be an absolute device path"
        )
    if source_path.is_symlink():
        raise PhotoRecCarvingError("unsafe_source_path", "PhotoRec source must not be a symlink")
    if source_path.exists():
        try:
            is_block = stat.S_ISBLK(source_path.stat().st_mode)
        except OSError as error:
            raise PhotoRecCarvingError(
                "unsafe_source_path", "PhotoRec source device cannot be inspected"
            ) from error
        if not is_block:
            raise PhotoRecCarvingError(
                "unsafe_source_path", "PhotoRec source must be block-special"
            )


def _validate_binary(binary: str) -> None:
    if binary != PHOTOREC_BINARY:
        raise PhotoRecCarvingError(
            "unsafe_photorec_command", "only the pinned PhotoRec binary is allowed"
        )


def _normalize_signatures(signatures: tuple[str, ...]) -> tuple[str, ...]:
    if not isinstance(signatures, tuple) or not signatures:
        raise PhotoRecCarvingError("empty_signature_set", "at least one signature is required")
    normalized: list[str] = []
    for signature in signatures:
        if (
            not isinstance(signature, str)
            or not signature
            or len(signature) > 32
            or any(char in signature for char in "\x00\n\r, ")
        ):
            raise PhotoRecCarvingError(
                "signature_not_allowed", "PhotoRec signature is not allowlisted"
            )
        lowered = signature.lower()
        if lowered not in ALLOWED_SIGNATURES:
            raise PhotoRecCarvingError(
                "signature_not_allowed", "PhotoRec signature is not allowlisted"
            )
        normalized.append(lowered)
    return tuple(sorted(set(normalized)))


def _validate_range_values(offset_bytes: int, length_bytes: int) -> None:
    if (
        type(offset_bytes) is not int
        or type(length_bytes) is not int
        or offset_bytes < 0
        or length_bytes <= 0
        or offset_bytes > MAX_RANGE_VALUE
        or length_bytes > MAX_RANGE_VALUE
        or offset_bytes + length_bytes > MAX_RANGE_VALUE
    ):
        raise PhotoRecCarvingError(
            "invalid_range", "carve ranges must be bounded positive integers"
        )


def _validate_timeout(timeout_seconds: int) -> None:
    if type(timeout_seconds) is not int or not 0 < timeout_seconds <= MAX_TIMEOUT_SECONDS:
        raise PhotoRecCarvingError("invalid_timeout", "PhotoRec timeout is out of bounds")


def _validate_scratch_root(scratch_root: Path) -> tuple[Path, Path]:
    if (
        not isinstance(scratch_root, Path)
        or not scratch_root.is_absolute()
        or len(str(scratch_root)) > MAX_PATH_CHARS
        or any(char in str(scratch_root) for char in "\x00\n\r")
        or any(part in FORBIDDEN_PATH_PARTS for part in scratch_root.parts)
        or scratch_root == Path("/")
        or scratch_root.is_symlink()
    ):
        raise PhotoRecCarvingError("invalid_scratch_root", "PhotoRec scratch root is invalid")
    try:
        resolved = scratch_root.resolve(strict=False)
    except (OSError, RuntimeError) as error:
        raise PhotoRecCarvingError(
            "invalid_scratch_root", "PhotoRec scratch root cannot be resolved"
        ) from error
    if resolved == Path("/") or resolved == Path("/dev") or Path("/dev") in resolved.parents:
        raise PhotoRecCarvingError(
            "invalid_scratch_root", "PhotoRec scratch root cannot be under /dev"
        )
    candidate = scratch_root / "photorec-quarantine"
    if candidate.is_symlink():
        raise PhotoRecCarvingError(
            "destination_escape", "PhotoRec output directory must not be a symlink"
        )
    destination = resolved / "photorec-quarantine"
    if destination.is_symlink():
        raise PhotoRecCarvingError(
            "destination_escape", "PhotoRec output directory must not be a symlink"
        )
    return resolved, destination


def _validate_private_directory(path: Path, label: str) -> None:
    if path.is_symlink() or not path.is_dir():
        raise PhotoRecCarvingError("invalid_scratch_root", f"{label} must be a directory")
    try:
        mode = stat.S_IMODE(path.stat().st_mode)
    except OSError as error:
        raise PhotoRecCarvingError(
            "invalid_scratch_root", f"{label} cannot be inspected"
        ) from error
    if mode & 0o077:
        raise PhotoRecCarvingError("invalid_scratch_root", f"{label} permissions are too broad")


def _validate_run_result(result: PhotoRecRunResult) -> None:
    if not isinstance(result, PhotoRecRunResult):
        raise PhotoRecCarvingError("invalid_tool_result", "PhotoRec returned an invalid result")
    if type(result.returncode) is not int or type(result.timed_out) is not bool:
        raise PhotoRecCarvingError(
            "invalid_tool_result", "PhotoRec returned invalid result metadata"
        )
    _validate_log_text(result.stdout, "stdout")
    _validate_log_text(result.stderr, "stderr")


def _validate_log_text(value: str, label: str) -> None:
    if not isinstance(value, str):
        raise PhotoRecCarvingError("invalid_tool_output", f"PhotoRec {label} is not text")
    if len(value) > MAX_TOOL_OUTPUT_CHARS:
        raise PhotoRecCarvingError(
            "photorec_output_too_large", "PhotoRec output exceeds the bounded limit"
        )


def _sanitize(value: str) -> str:
    return " ".join(value.replace("\x00", " ").split())[:240]


def _decode_timeout_output(value: bytes | str | None) -> str:
    if value is None:
        return ""
    if isinstance(value, bytes):
        decoded = value.decode("utf-8", errors="replace")
    else:
        decoded = value
    if len(decoded) > MAX_TOOL_OUTPUT_CHARS:
        raise PhotoRecCarvingError(
            "photorec_output_too_large", "PhotoRec output exceeds the bounded limit"
        )
    return decoded
