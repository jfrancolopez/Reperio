"""Durable PhotoRec session binding and resume helpers."""

from __future__ import annotations

import hashlib
import json
import shutil
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from scanner import photorec_carving

SESSION_NAME = "photorec.ses"


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


@dataclass(frozen=True)
class SessionBackup:
    session_sha256: str
    backup_path: Path
    binding: SessionBinding
    progress: Mapping[str, Any]
    completed: bool = False


def backup_session(
    session_path: Path,
    backup_dir: Path,
    *,
    binding: SessionBinding,
    progress: Mapping[str, Any],
    completed: bool = False,
) -> SessionBackup:
    """Copy a PhotoRec session into durable scanner-owned storage."""

    if session_path.name != SESSION_NAME:
        raise PhotoRecResumeError("invalid_session_name", "PhotoRec session must be photorec.ses")
    if not session_path.exists() or session_path.is_symlink():
        raise PhotoRecResumeError("invalid_session_file", "PhotoRec session is missing or unsafe")
    data = session_path.read_bytes()
    if not data.startswith(b"PhotoRec"):
        raise PhotoRecResumeError("corrupt_session", "PhotoRec session header is invalid")
    digest = hashlib.sha256(data).hexdigest()
    backup_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
    backup_path = backup_dir / f"photorec-{digest}.ses"
    temp_path = backup_dir / f".photorec-{digest}.tmp"
    temp_path.write_bytes(data)
    shutil.move(str(temp_path), backup_path)
    manifest_path = backup_path.with_suffix(".json")
    manifest_path.write_text(
        json.dumps(
            {
                "session_sha256": digest,
                "binding": _binding_payload(binding),
                "progress": dict(progress),
                "completed": completed,
            },
            sort_keys=True,
            separators=(",", ":"),
        ),
        encoding="utf-8",
    )
    return SessionBackup(digest, backup_path, binding, dict(progress), completed)


def load_session_backup(backup_path: Path, *, expected_binding: SessionBinding) -> SessionBackup:
    """Validate session bytes and binding before allowing resume."""

    if not backup_path.exists() or backup_path.is_symlink():
        raise PhotoRecResumeError("missing_session_backup", "PhotoRec session backup is missing")
    manifest_path = backup_path.with_suffix(".json")
    if not manifest_path.exists() or manifest_path.is_symlink():
        raise PhotoRecResumeError(
            "missing_session_manifest", "PhotoRec session manifest is missing"
        )
    data = backup_path.read_bytes()
    if not data.startswith(b"PhotoRec"):
        raise PhotoRecResumeError("corrupt_session", "PhotoRec session backup is corrupt")
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    digest = hashlib.sha256(data).hexdigest()
    if manifest.get("session_sha256") != digest:
        raise PhotoRecResumeError("corrupt_session", "PhotoRec session digest mismatch")
    actual_binding = _binding_from_payload(dict(manifest["binding"]))
    _validate_binding(actual_binding, expected_binding)
    return SessionBackup(
        digest,
        backup_path,
        actual_binding,
        dict(manifest.get("progress", {})),
        bool(manifest.get("completed", False)),
    )


def build_resume_command(
    *,
    backup: SessionBackup,
    source_path: Path,
    scratch_root: Path,
    photorec_binary: str = "photorec",
) -> photorec_carving.PhotoRecCommand:
    """Build a resume command only for an incomplete validated session."""

    if backup.completed:
        raise PhotoRecResumeError("session_completed", "completed PhotoRec session must not resume")
    command = photorec_carving.build_photorec_command(
        source_path=source_path,
        scratch_root=scratch_root,
        signatures=backup.binding.signatures,
        ranges=backup.binding.ranges,
        photorec_binary=photorec_binary,
    )
    return photorec_carving.PhotoRecCommand(
        (*command.args[:-1], "resume"), command.destination, command.signatures
    )


def binding_for_command(
    *,
    source_fingerprint: str,
    command: photorec_carving.PhotoRecCommand,
    ranges: tuple[photorec_carving.CarveRange, ...],
    tool_version: str = photorec_carving.PHOTOREC_VERSION,
) -> SessionBinding:
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
    return SessionBinding(
        source_fingerprint=source_fingerprint,
        tool_version=tool_version,
        signatures=command.signatures,
        ranges=ranges,
        command_hash=hashlib.sha256(payload).hexdigest(),
    )


def normalize_progress(stdout: str) -> dict[str, int]:
    recovered, _warnings = photorec_carving.parse_photorec_log(stdout, "", 0)
    sector = 0
    for line in stdout.splitlines():
        if "sector" not in line.lower():
            continue
        for token in line.replace(":", " ").split():
            if token.isdigit():
                sector = max(sector, int(token))
    return {"recovered_count": recovered, "last_sector": sector}


def _validate_binding(actual: SessionBinding, expected: SessionBinding) -> None:
    if actual.source_fingerprint != expected.source_fingerprint:
        raise PhotoRecResumeError("wrong_source", "PhotoRec session belongs to another source")
    if actual.tool_version != expected.tool_version:
        raise PhotoRecResumeError("wrong_tool_version", "PhotoRec session tool version differs")
    if actual.signatures != expected.signatures or actual.ranges != expected.ranges:
        raise PhotoRecResumeError("wrong_config", "PhotoRec session config differs")
    if actual.command_hash != expected.command_hash:
        raise PhotoRecResumeError("wrong_config", "PhotoRec command binding differs")


def _binding_payload(binding: SessionBinding) -> dict[str, object]:
    return {
        "source_fingerprint": binding.source_fingerprint,
        "tool_version": binding.tool_version,
        "signatures": list(binding.signatures),
        "ranges": [(item.offset_bytes, item.length_bytes) for item in binding.ranges],
        "command_hash": binding.command_hash,
    }


def _binding_from_payload(payload: dict[str, Any]) -> SessionBinding:
    return SessionBinding(
        source_fingerprint=str(payload["source_fingerprint"]),
        tool_version=str(payload["tool_version"]),
        signatures=tuple(str(item) for item in payload["signatures"]),
        ranges=tuple(
            photorec_carving.CarveRange(int(offset), int(length))
            for offset, length in payload["ranges"]
        ),
        command_hash=str(payload["command_hash"]),
    )
