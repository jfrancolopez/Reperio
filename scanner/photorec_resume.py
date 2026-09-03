"""Durable PhotoRec session binding and resume helpers."""

from __future__ import annotations

import hashlib
import json
import os
import re
import stat
import subprocess
import uuid
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Protocol

from scanner import photorec_carving

SESSION_NAME = "photorec.ses"
SESSION_MAX_BYTES = 40_960
MAX_MANIFEST_BYTES = 1_048_576
MAX_PROGRESS_BYTES = 16_384
MAX_PROGRESS_VALUE = photorec_carving.MAX_RANGE_VALUE
MAX_BINDING_TEXT = 128
SESSION_BACKUP_RE = re.compile(r"^photorec-(?P<digest>[0-9a-f]{64})\.ses$")
SESSION_TIMESTAMP_RE = re.compile(r"^#[0-9]{1,20}$")
SESSION_RANGE_RE = re.compile(r"^(?P<start>[0-9]+)-(?P<end>[0-9]+)$")
SECTOR_PROGRESS_RE = re.compile(
    r"\bsector\s*[:=]?\s*(?P<current>[0-9]+)(?:\s*/\s*[0-9]+)?", re.IGNORECASE
)
SESSION_MANIFEST_KEYS = frozenset({"session_sha256", "binding", "progress", "completed"})
PROGRESS_KEYS = frozenset({"recovered_count", "last_sector"})
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")


class PhotoRecResumeError(ValueError):
    """Raised when PhotoRec session state cannot be trusted."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


@dataclass(frozen=True)
class SessionBinding:
    source_fingerprint: str
    tool_version: str
    signatures: tuple[str, ...]
    ranges: tuple[photorec_carving.CarveRange, ...]
    command_hash: str

    def __post_init__(self) -> None:
        _validate_binding_shape(self)


@dataclass(frozen=True)
class SessionBackup:
    session_sha256: str
    backup_path: Path
    binding: SessionBinding
    progress: Mapping[str, Any]
    completed: bool = False

    def __post_init__(self) -> None:
        if (
            not isinstance(self.session_sha256, str)
            or SHA256_RE.fullmatch(self.session_sha256) is None
        ):
            raise PhotoRecResumeError(
                "invalid_session_backup", "PhotoRec session digest is invalid"
            )
        _validate_backup_path(self.backup_path)
        _validate_binding_shape(self.binding)
        _normalize_progress(self.progress)
        if type(self.completed) is not bool:
            raise PhotoRecResumeError(
                "invalid_session_backup", "PhotoRec session completion state is invalid"
            )


@dataclass(frozen=True)
class PhotoRecResumeResult:
    status: str
    recovered_count: int
    destination: Path
    warnings: tuple[str, ...]
    command: photorec_carving.PhotoRecCommand
    backup: SessionBackup


class PhotoRecResumeRunner(Protocol):
    def run(
        self, args: tuple[str, ...], timeout_seconds: int, working_directory: Path
    ) -> photorec_carving.PhotoRecRunResult: ...


class SubprocessPhotoRecResumeRunner:
    """Run the real PhotoRec resume form in a private scratch directory."""

    def run(
        self, args: tuple[str, ...], timeout_seconds: int, working_directory: Path
    ) -> photorec_carving.PhotoRecRunResult:
        _validate_timeout(timeout_seconds)
        _validate_resume_command(args)
        _validate_private_directory(working_directory, "PhotoRec resume working directory")
        try:
            completed = subprocess.run(
                args,
                check=False,
                stdin=subprocess.DEVNULL,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                cwd=str(working_directory),
                env=photorec_carving.SAFE_SUBPROCESS_ENV,
                start_new_session=True,
                timeout=timeout_seconds,
            )
        except subprocess.TimeoutExpired as error:
            return photorec_carving.PhotoRecRunResult(
                124,
                _decode_timeout_output(error.stdout),
                _decode_timeout_output(error.stderr),
                timed_out=True,
            )
        except (OSError, ValueError) as error:
            raise PhotoRecResumeError(
                "runner_failed", "PhotoRec resume could not be started safely"
            ) from error
        result = photorec_carving.PhotoRecRunResult(
            completed.returncode, completed.stdout, completed.stderr
        )
        _validate_run_result(result)
        return result


def backup_session(
    session_path: Path,
    backup_dir: Path,
    *,
    binding: SessionBinding,
    progress: Mapping[str, Any],
    completed: bool = False,
) -> SessionBackup:
    """Copy a validated PhotoRec session into durable scanner-owned storage."""

    _validate_session_path(session_path)
    _validate_binding_shape(binding)
    normalized_progress = _normalize_progress(progress)
    _validate_completion(completed)
    _prepare_private_directory(backup_dir, "PhotoRec session backup directory")
    data = _read_bounded_file(session_path, SESSION_MAX_BYTES, "invalid_session_file")
    _validate_session_data(data)
    digest = hashlib.sha256(data).hexdigest()
    backup_path = backup_dir / f"photorec-{digest}.ses"
    _atomic_write(backup_path, data, "session_backup_failed")
    _write_manifest(
        backup_path,
        binding=binding,
        progress=normalized_progress,
        completed=completed,
    )
    return SessionBackup(digest, backup_path, binding, normalized_progress, completed)


def load_session_backup(backup_path: Path, *, expected_binding: SessionBinding) -> SessionBackup:
    """Validate session bytes and binding before allowing resume."""

    _validate_backup_path(backup_path)
    _validate_binding_shape(expected_binding)
    if not backup_path.exists() or backup_path.is_symlink():
        raise PhotoRecResumeError("missing_session_backup", "PhotoRec session backup is missing")
    _validate_private_directory(backup_path.parent, "PhotoRec session backup directory")
    data = _read_bounded_file(backup_path, SESSION_MAX_BYTES, "corrupt_session", private=True)
    _validate_session_data(data)
    digest = hashlib.sha256(data).hexdigest()
    path_match = SESSION_BACKUP_RE.fullmatch(backup_path.name)
    if path_match is None or path_match.group("digest") != digest:
        raise PhotoRecResumeError("corrupt_session", "PhotoRec session backup name is invalid")

    manifest_path = backup_path.with_suffix(".json")
    if not manifest_path.exists() or manifest_path.is_symlink():
        raise PhotoRecResumeError(
            "missing_session_manifest", "PhotoRec session manifest is missing"
        )
    manifest_data = _read_bounded_file(
        manifest_path, MAX_MANIFEST_BYTES, "corrupt_session", private=True
    )
    try:
        manifest = json.loads(manifest_data.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError, ValueError) as error:
        raise PhotoRecResumeError(
            "corrupt_session", "PhotoRec session manifest is invalid"
        ) from error
    if not isinstance(manifest, dict) or frozenset(manifest) != SESSION_MANIFEST_KEYS:
        raise PhotoRecResumeError("corrupt_session", "PhotoRec session manifest is malformed")
    if manifest.get("session_sha256") != digest:
        raise PhotoRecResumeError("corrupt_session", "PhotoRec session digest mismatch")
    try:
        actual_binding = _binding_from_payload(manifest["binding"])
        progress = _normalize_progress(manifest["progress"])
        completed = manifest["completed"]
        _validate_completion(completed)
    except PhotoRecResumeError as error:
        raise PhotoRecResumeError(
            "corrupt_session", "PhotoRec session manifest is malformed"
        ) from error
    except (TypeError, ValueError, KeyError, IndexError, OverflowError, RecursionError) as error:
        raise PhotoRecResumeError(
            "corrupt_session", "PhotoRec session manifest is malformed"
        ) from error
    _validate_binding(actual_binding, expected_binding)
    return SessionBackup(digest, backup_path, actual_binding, progress, completed)


def build_resume_command(
    *,
    backup: SessionBackup,
    source_path: Path,
    scratch_root: Path,
    photorec_binary: str = photorec_carving.PHOTOREC_BINARY,
) -> photorec_carving.PhotoRecCommand:
    """Build PhotoRec's actual resume invocation for an incomplete session."""

    _validate_session_backup(backup)
    if backup.completed:
        raise PhotoRecResumeError("session_completed", "completed PhotoRec session must not resume")
    if backup.binding.tool_version != photorec_carving.PHOTOREC_VERSION:
        raise PhotoRecResumeError("wrong_tool_version", "PhotoRec session tool version differs")
    _validate_session_source(backup.backup_path, source_path)
    try:
        command = photorec_carving.build_photorec_command(
            source_path=source_path,
            scratch_root=scratch_root,
            signatures=backup.binding.signatures,
            ranges=backup.binding.ranges,
            photorec_binary=photorec_binary,
        )
        command_hash = _command_hash(command, backup.binding.ranges, backup.binding.tool_version)
    except (photorec_carving.PhotoRecCarvingError, TypeError, ValueError) as error:
        raise PhotoRecResumeError(
            "invalid_resume_command", "PhotoRec resume command is invalid"
        ) from error
    if command_hash != backup.binding.command_hash:
        raise PhotoRecResumeError("wrong_config", "PhotoRec resume command binding differs")

    args = (
        photorec_carving.PHOTOREC_BINARY,
        "/log",
        "/d",
        str(command.destination),
        "/cmd",
        "resume",
        str(source_path),
    )
    _validate_resume_command(args)
    return photorec_carving.PhotoRecCommand(args, command.destination, command.signatures)


def run_photorec_resume(
    *,
    backup: SessionBackup,
    source_path: Path,
    scratch_root: Path,
    runner: PhotoRecResumeRunner | None = None,
    timeout_seconds: int = 300,
) -> PhotoRecResumeResult:
    """Stage a validated session, invoke PhotoRec, and preserve updated state."""

    _validate_timeout(timeout_seconds)
    command = build_resume_command(
        backup=backup,
        source_path=source_path,
        scratch_root=scratch_root,
    )
    working_directory = command.destination.parent
    _prepare_private_directory(working_directory, "PhotoRec resume working directory")
    _prepare_private_directory(command.destination, "PhotoRec quarantine")
    staged_session = working_directory / SESSION_NAME
    if staged_session.is_symlink():
        raise PhotoRecResumeError(
            "unsafe_session_path", "PhotoRec session path must not be a symlink"
        )
    session_data = _read_bounded_file(
        backup.backup_path, SESSION_MAX_BYTES, "corrupt_session", private=True
    )
    _validate_session_data(session_data)
    _atomic_write(staged_session, session_data, "session_stage_failed")

    selected_runner = runner or SubprocessPhotoRecResumeRunner()
    try:
        result = selected_runner.run(command.args, timeout_seconds, working_directory)
    except PhotoRecResumeError:
        raise
    except (OSError, subprocess.SubprocessError, TimeoutError) as error:
        raise PhotoRecResumeError("runner_failed", "PhotoRec resume failed safely") from error
    _validate_run_result(result)
    recovered_count, parsed_warnings = photorec_carving.parse_photorec_log(
        result.stdout, result.stderr, result.returncode, timed_out=result.timed_out
    )
    warnings = list(parsed_warnings)
    completed = not result.timed_out and result.returncode in {0, 1}
    progress = normalize_progress(result.stdout)
    durable_backup = backup
    if staged_session.is_symlink():
        warnings.append("photorec_session_not_saved")
        if completed:
            try:
                durable_backup = _mark_backup_completed(backup, progress)
            except PhotoRecResumeError as error:
                warnings.append(f"photorec_session_backup:{error.code}")
    elif staged_session.exists():
        try:
            durable_backup = backup_session(
                staged_session,
                backup.backup_path.parent,
                binding=backup.binding,
                progress=progress,
                completed=completed,
            )
        except PhotoRecResumeError as error:
            warnings.append(f"photorec_session_backup:{error.code}")
            if completed:
                try:
                    durable_backup = _mark_backup_completed(backup, progress)
                except PhotoRecResumeError as fallback_error:
                    warnings.append(f"photorec_session_backup:{fallback_error.code}")
    elif completed:
        try:
            durable_backup = _mark_backup_completed(backup, progress)
        except PhotoRecResumeError as error:
            warnings.append(f"photorec_session_backup:{error.code}")
    elif not staged_session.exists():
        warnings.append("photorec_session_not_saved")
    status = "partial" if result.timed_out or result.returncode not in {0, 1} else "complete"
    if result.returncode == 1 and not result.timed_out:
        status = "completed-warning"
    if completed and not durable_backup.completed:
        status = "completed-warning"
    return PhotoRecResumeResult(
        status,
        recovered_count,
        command.destination,
        tuple(dict.fromkeys(warnings)),
        command,
        durable_backup,
    )


def _mark_backup_completed(backup: SessionBackup, progress: Mapping[str, Any]) -> SessionBackup:
    _write_manifest(
        backup.backup_path,
        binding=backup.binding,
        progress=progress,
        completed=True,
    )
    return SessionBackup(
        backup.session_sha256,
        backup.backup_path,
        backup.binding,
        progress,
        True,
    )


def binding_for_command(
    *,
    source_fingerprint: str,
    command: photorec_carving.PhotoRecCommand,
    ranges: tuple[photorec_carving.CarveRange, ...],
    tool_version: str = photorec_carving.PHOTOREC_VERSION,
) -> SessionBinding:
    """Create a binding only when the command and explicit ranges agree."""

    if not isinstance(command, photorec_carving.PhotoRecCommand):
        raise PhotoRecResumeError("invalid_binding", "PhotoRec command binding is malformed")
    _validate_fingerprint(source_fingerprint)
    _validate_tool_version(tool_version)
    _validate_ranges(ranges)
    try:
        photorec_carving._validate_command(command.args)
    except (photorec_carving.PhotoRecCarvingError, TypeError, ValueError) as error:
        raise PhotoRecResumeError(
            "invalid_binding", "PhotoRec command binding is unsafe"
        ) from error
    normalized_signatures = _normalize_signatures(command.signatures)
    command_ranges = _command_ranges(command.args)
    if normalized_signatures != command.signatures or command_ranges != ranges:
        raise PhotoRecResumeError("invalid_binding", "PhotoRec command binding is inconsistent")
    return SessionBinding(
        source_fingerprint=source_fingerprint,
        tool_version=tool_version,
        signatures=normalized_signatures,
        ranges=ranges,
        command_hash=_command_hash(command, ranges, tool_version),
    )


def normalize_progress(stdout: str) -> dict[str, int]:
    """Normalize bounded PhotoRec output into durable progress counters."""

    if not isinstance(stdout, str):
        raise PhotoRecResumeError("invalid_progress", "PhotoRec progress output is not text")
    try:
        recovered, _warnings = photorec_carving.parse_photorec_log(stdout, "", 0)
    except photorec_carving.PhotoRecCarvingError as error:
        raise PhotoRecResumeError(
            "invalid_progress", "PhotoRec progress output is invalid"
        ) from error
    sector = 0
    for match in SECTOR_PROGRESS_RE.finditer(stdout):
        current = _bounded_decimal(match.group("current"))
        sector = max(sector, current)
    return {"recovered_count": recovered, "last_sector": sector}


def _validate_binding(actual: SessionBinding, expected: SessionBinding) -> None:
    _validate_binding_shape(actual)
    _validate_binding_shape(expected)
    if actual.source_fingerprint != expected.source_fingerprint:
        raise PhotoRecResumeError("wrong_source", "PhotoRec session belongs to another source")
    if actual.tool_version != expected.tool_version:
        raise PhotoRecResumeError("wrong_tool_version", "PhotoRec session tool version differs")
    if actual.signatures != expected.signatures or actual.ranges != expected.ranges:
        raise PhotoRecResumeError("wrong_config", "PhotoRec session config differs")
    if actual.command_hash != expected.command_hash:
        raise PhotoRecResumeError("wrong_config", "PhotoRec command binding differs")


def _binding_payload(binding: SessionBinding) -> dict[str, object]:
    _validate_binding_shape(binding)
    return {
        "source_fingerprint": binding.source_fingerprint,
        "tool_version": binding.tool_version,
        "signatures": list(binding.signatures),
        "ranges": [(item.offset_bytes, item.length_bytes) for item in binding.ranges],
        "command_hash": binding.command_hash,
    }


def _binding_from_payload(payload: object) -> SessionBinding:
    if not isinstance(payload, Mapping) or frozenset(payload) != {
        "source_fingerprint",
        "tool_version",
        "signatures",
        "ranges",
        "command_hash",
    }:
        raise PhotoRecResumeError("corrupt_session", "PhotoRec session binding is malformed")
    source_fingerprint = payload["source_fingerprint"]
    tool_version = payload["tool_version"]
    command_hash = payload["command_hash"]
    signatures = payload["signatures"]
    ranges = payload["ranges"]
    if not isinstance(source_fingerprint, str) or not isinstance(tool_version, str):
        raise PhotoRecResumeError("corrupt_session", "PhotoRec session binding is malformed")
    if (
        not isinstance(command_hash, str)
        or not isinstance(signatures, list)
        or not isinstance(ranges, list)
    ):
        raise PhotoRecResumeError("corrupt_session", "PhotoRec session binding is malformed")
    parsed_ranges: list[photorec_carving.CarveRange] = []
    for item in ranges:
        if (
            not isinstance(item, list)
            or len(item) != 2
            or type(item[0]) is not int
            or type(item[1]) is not int
        ):
            raise PhotoRecResumeError("corrupt_session", "PhotoRec session ranges are malformed")
        parsed_ranges.append(photorec_carving.CarveRange(item[0], item[1]))
    if any(not isinstance(item, str) for item in signatures):
        raise PhotoRecResumeError("corrupt_session", "PhotoRec session signatures are malformed")
    return SessionBinding(
        source_fingerprint=source_fingerprint,
        tool_version=tool_version,
        signatures=tuple(signatures),
        ranges=tuple(parsed_ranges),
        command_hash=command_hash,
    )


def _validate_binding_shape(binding: SessionBinding) -> None:
    if not isinstance(binding, SessionBinding):
        raise PhotoRecResumeError("invalid_binding", "PhotoRec session binding is malformed")
    _validate_fingerprint(binding.source_fingerprint)
    _validate_tool_version(binding.tool_version)
    _normalize_signatures(binding.signatures)
    _validate_ranges(binding.ranges)
    if (
        not isinstance(binding.command_hash, str)
        or SHA256_RE.fullmatch(binding.command_hash) is None
    ):
        raise PhotoRecResumeError("invalid_binding", "PhotoRec command hash is invalid")


def _validate_fingerprint(value: object) -> None:
    if not isinstance(value, str) or SHA256_RE.fullmatch(value) is None:
        raise PhotoRecResumeError("invalid_binding", "PhotoRec source fingerprint is invalid")


def _validate_tool_version(value: object) -> None:
    if (
        not isinstance(value, str)
        or not value
        or len(value) > MAX_BINDING_TEXT
        or any(ord(char) < 32 or ord(char) == 127 for char in value)
    ):
        raise PhotoRecResumeError("invalid_binding", "PhotoRec tool version is invalid")


def _normalize_signatures(signatures: object) -> tuple[str, ...]:
    if not isinstance(signatures, tuple) or not signatures:
        raise PhotoRecResumeError("invalid_binding", "PhotoRec signatures are malformed")
    normalized: list[str] = []
    for signature in signatures:
        if (
            not isinstance(signature, str)
            or not signature
            or len(signature) > 32
            or any(char in signature for char in "\x00\n\r, ")
            or signature.lower() not in photorec_carving.ALLOWED_SIGNATURES
        ):
            raise PhotoRecResumeError("invalid_binding", "PhotoRec signatures are not allowlisted")
        normalized.append(signature.lower())
    result = tuple(sorted(set(normalized)))
    if result != signatures:
        raise PhotoRecResumeError("invalid_binding", "PhotoRec signatures are not canonical")
    return result


def _validate_ranges(ranges: object) -> None:
    if not isinstance(ranges, tuple) or not ranges or len(ranges) > photorec_carving.MAX_RANGES:
        raise PhotoRecResumeError("invalid_binding", "PhotoRec ranges are malformed")
    for item in ranges:
        if not isinstance(item, photorec_carving.CarveRange):
            raise PhotoRecResumeError("invalid_binding", "PhotoRec ranges are malformed")
        try:
            photorec_carving._validate_range_values(item.offset_bytes, item.length_bytes)
        except photorec_carving.PhotoRecCarvingError as error:
            raise PhotoRecResumeError("invalid_binding", "PhotoRec ranges are malformed") from error


def _command_ranges(args: tuple[str, ...]) -> tuple[photorec_carving.CarveRange, ...]:
    parsed: list[photorec_carving.CarveRange] = []
    index = 0
    while index < len(args):
        if args[index] != "range":
            index += 1
            continue
        if index + 1 >= len(args):
            raise PhotoRecResumeError("invalid_binding", "PhotoRec range option is incomplete")
        offset_text, separator, length_text = args[index + 1].partition(":")
        if separator != ":" or not offset_text.isdigit() or not length_text.isdigit():
            raise PhotoRecResumeError("invalid_binding", "PhotoRec range option is malformed")
        try:
            parsed.append(photorec_carving.CarveRange(int(offset_text), int(length_text)))
        except (ValueError, photorec_carving.PhotoRecCarvingError) as error:
            raise PhotoRecResumeError(
                "invalid_binding", "PhotoRec range option is malformed"
            ) from error
        index += 2
    return tuple(parsed)


def _command_hash(
    command: photorec_carving.PhotoRecCommand,
    ranges: tuple[photorec_carving.CarveRange, ...],
    tool_version: str,
) -> str:
    payload = json.dumps(
        {
            "args": command.args,
            "ranges": [(item.offset_bytes, item.length_bytes) for item in ranges],
            "signatures": command.signatures,
            "tool_version": tool_version,
        },
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def _validate_session_path(session_path: Path) -> None:
    if (
        not isinstance(session_path, Path)
        or not session_path.is_absolute()
        or session_path.name != SESSION_NAME
    ):
        raise PhotoRecResumeError("invalid_session_name", "PhotoRec session must be photorec.ses")
    _validate_path_text(session_path, "PhotoRec session path")
    if session_path.is_symlink():
        raise PhotoRecResumeError("invalid_session_file", "PhotoRec session must not be a symlink")


def _validate_backup_path(backup_path: Path) -> None:
    if not isinstance(backup_path, Path) or not backup_path.is_absolute():
        raise PhotoRecResumeError(
            "invalid_session_backup", "PhotoRec session backup path is invalid"
        )
    _validate_path_text(backup_path, "PhotoRec session backup path")
    if SESSION_BACKUP_RE.fullmatch(backup_path.name) is None:
        raise PhotoRecResumeError(
            "invalid_session_backup", "PhotoRec session backup name is invalid"
        )


def _validate_path_text(path: Path, label: str) -> None:
    text = str(path)
    if (
        len(text) > photorec_carving.MAX_PATH_CHARS
        or any(char in text for char in "\x00\n\r")
        or any(part in {".", ".."} for part in path.parts)
    ):
        raise PhotoRecResumeError("invalid_session_path", f"{label} is invalid")


def _prepare_private_directory(path: Path, label: str) -> Path:
    if not isinstance(path, Path) or not path.is_absolute():
        raise PhotoRecResumeError("invalid_storage_path", f"{label} must be absolute")
    _validate_path_text(path, label)
    try:
        resolved = path.resolve(strict=False)
    except (OSError, RuntimeError) as error:
        raise PhotoRecResumeError("invalid_storage_path", f"{label} cannot be resolved") from error
    if resolved == Path("/") or resolved == Path("/dev") or Path("/dev") in resolved.parents:
        raise PhotoRecResumeError("invalid_storage_path", f"{label} cannot be under /dev")
    if path.is_symlink():
        raise PhotoRecResumeError("invalid_storage_path", f"{label} must not be a symlink")
    try:
        path.mkdir(mode=0o700, parents=True, exist_ok=True)
        path.chmod(0o700)
    except OSError as error:
        raise PhotoRecResumeError("storage_unavailable", f"{label} cannot be prepared") from error
    _validate_private_directory(path, label)
    return resolved


def _validate_private_directory(path: Path, label: str) -> None:
    if path.is_symlink() or not path.is_dir():
        raise PhotoRecResumeError("invalid_storage_path", f"{label} must be a directory")
    try:
        mode = stat.S_IMODE(path.stat().st_mode)
    except OSError as error:
        raise PhotoRecResumeError("invalid_storage_path", f"{label} cannot be inspected") from error
    if mode & 0o077:
        raise PhotoRecResumeError("invalid_storage_path", f"{label} permissions are too broad")


def _read_bounded_file(
    path: Path, maximum: int, error_code: str, *, private: bool = False
) -> bytes:
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        fd = os.open(path, flags)
    except (OSError, ValueError) as error:
        raise PhotoRecResumeError(
            error_code, "PhotoRec state file cannot be read safely"
        ) from error
    try:
        opened = os.fstat(fd)
        if not stat.S_ISREG(opened.st_mode) or opened.st_nlink != 1:
            raise PhotoRecResumeError(
                error_code, "PhotoRec state file is not a private regular file"
            )
        if private and stat.S_IMODE(opened.st_mode) & 0o077:
            raise PhotoRecResumeError(error_code, "PhotoRec state file permissions are too broad")
        if opened.st_size > maximum:
            raise PhotoRecResumeError(error_code, "PhotoRec state file exceeds the bounded limit")
        chunks: list[bytes] = []
        total = 0
        while total <= maximum:
            chunk = os.read(fd, min(1024 * 1024, maximum + 1 - total))
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
            if total > maximum:
                raise PhotoRecResumeError(
                    error_code, "PhotoRec state file exceeds the bounded limit"
                )
        return b"".join(chunks)
    except PhotoRecResumeError:
        raise
    except OSError as error:
        raise PhotoRecResumeError(
            error_code, "PhotoRec state file cannot be read safely"
        ) from error
    finally:
        os.close(fd)


def _atomic_write(path: Path, data: bytes, error_code: str) -> None:
    if not isinstance(data, bytes):
        raise PhotoRecResumeError(error_code, "PhotoRec state data is invalid")
    _validate_private_directory(path.parent, "PhotoRec state directory")
    if path.is_symlink() or (path.exists() and not path.is_file()):
        raise PhotoRecResumeError(error_code, "PhotoRec state destination is unsafe")
    temp_path = path.parent / f".{path.name}.{uuid.uuid4().hex}.tmp"
    try:
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0)
        try:
            fd = os.open(temp_path, flags, 0o600)
        except (OSError, ValueError) as error:
            raise PhotoRecResumeError(
                error_code, "PhotoRec state could not be written atomically"
            ) from error
        try:
            os.fchmod(fd, 0o600)
            offset = 0
            while offset < len(data):
                written = os.write(fd, data[offset:])
                if written == 0:
                    raise PhotoRecResumeError(error_code, "PhotoRec state write made no progress")
                offset += written
            os.fsync(fd)
        finally:
            os.close(fd)
        os.replace(temp_path, path)
        _fsync_directory(path.parent)
    except PhotoRecResumeError:
        raise
    except (OSError, ValueError) as error:
        raise PhotoRecResumeError(
            error_code, "PhotoRec state could not be written atomically"
        ) from error
    finally:
        try:
            temp_path.unlink(missing_ok=True)
        except OSError:
            pass


def _fsync_directory(path: Path) -> None:
    fd = os.open(str(path), os.O_RDONLY | getattr(os, "O_CLOEXEC", 0))
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def _manifest_bytes(
    binding: SessionBinding, progress: Mapping[str, Any], completed: bool, digest: str
) -> bytes:
    if not isinstance(digest, str) or SHA256_RE.fullmatch(digest) is None:
        raise PhotoRecResumeError("invalid_session_backup", "PhotoRec session digest is invalid")
    payload = {
        "session_sha256": digest,
        "binding": _binding_payload(binding),
        "progress": _normalize_progress(progress),
        "completed": completed,
    }
    try:
        encoded = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    except (TypeError, ValueError, RecursionError) as error:
        raise PhotoRecResumeError(
            "invalid_session_manifest", "PhotoRec session manifest is invalid"
        ) from error
    if len(encoded) > MAX_MANIFEST_BYTES:
        raise PhotoRecResumeError(
            "invalid_session_manifest", "PhotoRec session manifest is too large"
        )
    return encoded


def _write_manifest(
    backup_path: Path,
    *,
    binding: SessionBinding,
    progress: Mapping[str, Any],
    completed: bool,
) -> None:
    _validate_backup_path(backup_path)
    data = _manifest_bytes(binding, progress, completed, backup_path.stem.removeprefix("photorec-"))
    _atomic_write(backup_path.with_suffix(".json"), data, "session_manifest_failed")


def _validate_session_data(data: bytes) -> None:
    if not isinstance(data, bytes) or not data or len(data) > SESSION_MAX_BYTES:
        raise PhotoRecResumeError("corrupt_session", "PhotoRec session size is invalid")
    content = data.rstrip(b"\x00")
    if not content or b"\x00" in content:
        raise PhotoRecResumeError("corrupt_session", "PhotoRec session contains invalid bytes")
    try:
        text = content.decode("utf-8")
    except UnicodeDecodeError as error:
        raise PhotoRecResumeError(
            "corrupt_session", "PhotoRec session is not valid text"
        ) from error
    lines = text.splitlines()
    if len(lines) < 3 or SESSION_TIMESTAMP_RE.fullmatch(lines[0]) is None:
        raise PhotoRecResumeError("corrupt_session", "PhotoRec session header is invalid")
    if " " not in lines[1] or not lines[1].split(" ", 1)[0]:
        raise PhotoRecResumeError("corrupt_session", "PhotoRec session source is missing")
    if not lines[2].strip():
        raise PhotoRecResumeError("corrupt_session", "PhotoRec session command is missing")
    if any(ord(char) < 32 and char not in "\r\n\t" for char in text):
        raise PhotoRecResumeError("corrupt_session", "PhotoRec session contains control characters")
    if any(len(line) > photorec_carving.MAX_PATH_CHARS for line in lines):
        raise PhotoRecResumeError("corrupt_session", "PhotoRec session line is too long")
    range_count = 0
    for line in lines[3:]:
        match = SESSION_RANGE_RE.fullmatch(line)
        if match is None:
            raise PhotoRecResumeError("corrupt_session", "PhotoRec session range is malformed")
        try:
            start = int(match.group("start"))
            end = int(match.group("end"))
            if start > end or end > photorec_carving.MAX_RANGE_VALUE:
                raise ValueError
        except ValueError as error:
            raise PhotoRecResumeError(
                "corrupt_session", "PhotoRec session range is invalid"
            ) from error
        range_count += 1
    if range_count == 0:
        raise PhotoRecResumeError("corrupt_session", "PhotoRec session has no resumable ranges")


def _session_source(data: bytes) -> str:
    _validate_session_data(data)
    content = data.rstrip(b"\x00")
    source = content.decode("utf-8").splitlines()[1].split(" ", 1)[0]
    return source


def _validate_session_source(backup_path: Path, source_path: Path) -> None:
    data = _read_bounded_file(backup_path, SESSION_MAX_BYTES, "corrupt_session", private=True)
    if _session_source(data) != str(source_path):
        raise PhotoRecResumeError("wrong_source", "PhotoRec session belongs to another device")


def _validate_resume_command(args: tuple[str, ...]) -> None:
    if (
        not isinstance(args, tuple)
        or len(args) != 7
        or args[0] != photorec_carving.PHOTOREC_BINARY
        or args[1:3] != ("/log", "/d")
        or args[4:6] != ("/cmd", "resume")
        or any(not isinstance(item, str) for item in args)
    ):
        raise PhotoRecResumeError(
            "unsafe_resume_command", "PhotoRec resume command is not allowlisted"
        )
    try:
        photorec_carving._validate_source_path(Path(args[6]))
    except (photorec_carving.PhotoRecCarvingError, TypeError, ValueError) as error:
        raise PhotoRecResumeError(
            "unsafe_resume_command", "PhotoRec resume source is invalid"
        ) from error
    destination = Path(args[3])
    if (
        not destination.is_absolute()
        or destination.name != "photorec-quarantine"
        or len(str(destination)) > photorec_carving.MAX_PATH_CHARS
        or any(char in str(destination) for char in "\x00\n\r")
        or any(part in {".", ".."} for part in destination.parts)
        or Path("/dev") in destination.parents
    ):
        raise PhotoRecResumeError("unsafe_resume_command", "PhotoRec resume destination is invalid")


def _validate_session_backup(backup: SessionBackup) -> None:
    if not isinstance(backup, SessionBackup):
        raise PhotoRecResumeError("invalid_session_backup", "PhotoRec session backup is malformed")
    _validate_binding_shape(backup.binding)
    _validate_backup_path(backup.backup_path)
    if backup.backup_path.name != f"photorec-{backup.session_sha256}.ses":
        raise PhotoRecResumeError(
            "invalid_session_backup", "PhotoRec session backup name is invalid"
        )
    _normalize_progress(backup.progress)
    _validate_completion(backup.completed)


def _validate_completion(value: object) -> None:
    if type(value) is not bool:
        raise PhotoRecResumeError(
            "invalid_session_manifest", "PhotoRec session completion state is invalid"
        )


def _normalize_progress(progress: object) -> dict[str, int]:
    if not isinstance(progress, Mapping) or any(key not in PROGRESS_KEYS for key in progress):
        raise PhotoRecResumeError("invalid_progress", "PhotoRec progress is malformed")
    normalized: dict[str, int] = {}
    for key, value in progress.items():
        if (
            not isinstance(key, str)
            or type(value) is not int
            or value < 0
            or value > MAX_PROGRESS_VALUE
        ):
            raise PhotoRecResumeError("invalid_progress", "PhotoRec progress is malformed")
        normalized[key] = value
    try:
        encoded = json.dumps(normalized, sort_keys=True, separators=(",", ":")).encode("utf-8")
    except (TypeError, ValueError, RecursionError) as error:
        raise PhotoRecResumeError("invalid_progress", "PhotoRec progress is malformed") from error
    if len(encoded) > MAX_PROGRESS_BYTES:
        raise PhotoRecResumeError("invalid_progress", "PhotoRec progress is too large")
    return normalized


def _bounded_decimal(value: str) -> int:
    if len(value) > len(str(MAX_PROGRESS_VALUE)):
        return MAX_PROGRESS_VALUE
    try:
        return min(int(value), MAX_PROGRESS_VALUE)
    except ValueError:
        return MAX_PROGRESS_VALUE


def _validate_timeout(timeout_seconds: int) -> None:
    if (
        type(timeout_seconds) is not int
        or not 0 < timeout_seconds <= photorec_carving.MAX_TIMEOUT_SECONDS
    ):
        raise PhotoRecResumeError("invalid_timeout", "PhotoRec timeout is out of bounds")


def _validate_run_result(result: photorec_carving.PhotoRecRunResult) -> None:
    if not isinstance(result, photorec_carving.PhotoRecRunResult):
        raise PhotoRecResumeError("invalid_tool_result", "PhotoRec returned an invalid result")
    if type(result.returncode) is not int or type(result.timed_out) is not bool:
        raise PhotoRecResumeError(
            "invalid_tool_result", "PhotoRec returned invalid result metadata"
        )
    for value, label in ((result.stdout, "stdout"), (result.stderr, "stderr")):
        if not isinstance(value, str) or len(value) > photorec_carving.MAX_TOOL_OUTPUT_CHARS:
            raise PhotoRecResumeError("invalid_tool_output", f"PhotoRec {label} is invalid")


def _decode_timeout_output(value: bytes | str | None) -> str:
    if value is None:
        return ""
    if isinstance(value, bytes):
        value = value.decode("utf-8", errors="replace")
    if not isinstance(value, str) or len(value) > photorec_carving.MAX_TOOL_OUTPUT_CHARS:
        raise PhotoRecResumeError("invalid_tool_output", "PhotoRec timeout output is invalid")
    return value
