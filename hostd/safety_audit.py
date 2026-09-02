"""Append-only host safety audit for RPR-018."""

from __future__ import annotations

import fcntl
import hashlib
import json
import math
import os
import stat
from collections.abc import Iterator, Mapping, Sequence
from contextlib import contextmanager
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

AUDIT_SCHEMA_VERSION = 1
GENESIS_HASH = "0" * 64
REDACTED = "[REDACTED]"
DEVICE_PATH_REDACTED = "[DEVICE_PATH_REDACTED]"
MAX_AUDIT_RECORD_BYTES = 64 * 1024
MAX_AUDIT_FILE_BYTES = 64 * 1024 * 1024
AUDIT_EVENTS = frozenset(
    {
        "device_resolution",
        "system_disk_decision",
        "mount_holder_check",
        "destination_separation",
        "read_only_verification",
        "scanner_sandbox_profile",
        "audit_rotation_continuation",
    }
)
RECORD_KEYS = frozenset(
    {
        "schema_version",
        "sequence",
        "timestamp_utc",
        "event",
        "payload",
        "previous_hash",
        "record_hash",
    }
)
SENSITIVE_KEY_PARTS = (
    "credential",
    "password",
    "secret",
    "token",
    "sample_bytes",
    "private_key",
    "seed",
    "authorization",
    "cookie",
    "api_key",
    "mnemonic",
    "keystore",
    "wallet",
)


class AuditVerificationError(ValueError):
    """Raised when an audit log has been tampered with or truncated."""


class AuditWriteError(ValueError):
    """Raised when an audit record cannot be appended safely."""


class SafetyAuditLog:
    """Append-only JSONL safety audit with sequence numbers and hash chaining."""

    def __init__(self, path: Path) -> None:
        self.path = path
        self.lock_path = path.with_name(f".{path.name}.lock")

    def append(self, event: str, payload: Mapping[str, Any]) -> dict[str, Any]:
        """Append one redacted event and return the stored record."""
        event = _safe_event(event)
        if event not in AUDIT_EVENTS:
            raise AuditWriteError(f"audit event {event!r} is not allowlisted")
        with self._exclusive_lock():
            if self.path.is_symlink():
                raise AuditWriteError("audit log path must not be a symlink")
            state = verify_audit_log(self.path) if self.path.exists() else _empty_state()
            record = _new_record(event, payload, state["next_sequence"], state["last_hash"])
            _append_record(self.path, record)
            return record

    def rotate(self, rotated_path: Path) -> dict[str, Any]:
        """Rotate to a same-directory segment and start a chained continuation."""
        if rotated_path.parent.resolve(strict=False) != self.path.parent.resolve(strict=False):
            raise AuditWriteError("rotated audit segment must remain in the audit directory")
        if rotated_path == self.path:
            raise AuditWriteError("rotated audit segment already exists or is invalid")
        with self._exclusive_lock():
            if rotated_path.exists() or rotated_path.is_symlink():
                raise AuditWriteError("rotated audit segment already exists or is invalid")
            state = verify_audit_log(self.path)
            if not state["records"]:
                raise AuditWriteError("empty audit log cannot be rotated")
            os.replace(self.path, rotated_path)
            _fsync_directory(self.path.parent)
            continuation = _new_record(
                "audit_rotation_continuation",
                {"previous_segment": rotated_path.name},
                state["next_sequence"],
                state["last_hash"],
            )
            _append_record(self.path, continuation)
            return continuation

    @contextmanager
    def _exclusive_lock(self) -> Iterator[None]:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        flags = os.O_RDWR | os.O_CREAT | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
        try:
            fd = os.open(self.lock_path, flags, 0o600)
        except OSError as error:
            raise AuditWriteError("audit lock could not be opened safely") from error
        try:
            opened = os.fstat(fd)
            if not stat.S_ISREG(opened.st_mode) or opened.st_nlink != 1:
                raise AuditWriteError("audit lock is not a private regular file")
            os.fchmod(fd, 0o600)
            fcntl.flock(fd, fcntl.LOCK_EX)
            yield
        finally:
            fcntl.flock(fd, fcntl.LOCK_UN)
            os.close(fd)


def verify_audit_log(path: Path) -> dict[str, Any]:
    """Verify hash chain and return ordering state for an audit log."""
    try:
        raw = _read_audit_file(path)
    except FileNotFoundError:
        return _empty_state()
    raw_lines = _decode_lines(raw)
    initial_sequence = 1
    initial_hash = GENESIS_HASH
    if raw_lines:
        first = _parse_record(raw_lines[0], 1)
        if first.get("event") == "audit_rotation_continuation":
            sequence = first.get("sequence")
            previous_hash = first.get("previous_hash")
            if not isinstance(sequence, int) or not isinstance(previous_hash, str):
                raise AuditVerificationError("line 1: invalid rotation continuation")
            initial_sequence = sequence
            initial_hash = previous_hash
    return _verify_lines(raw_lines, initial_sequence, initial_hash)


def verify_audit_segments(paths: Sequence[Path]) -> dict[str, Any]:
    """Verify ordered rotated segments as one uninterrupted hash chain."""
    expected_sequence = 1
    last_hash = GENESIS_HASH
    all_records: list[dict[str, Any]] = []
    for path in paths:
        try:
            raw_lines = _decode_lines(_read_audit_file(path))
        except FileNotFoundError as error:
            raise AuditVerificationError(f"missing audit segment: {path.name}") from error
        state = _verify_lines(raw_lines, expected_sequence, last_hash)
        expected_sequence = state["next_sequence"]
        last_hash = state["last_hash"]
        all_records.extend(state["records"])
    return {"next_sequence": expected_sequence, "last_hash": last_hash, "records": all_records}


def _verify_lines(
    raw_lines: Sequence[str], initial_sequence: int, initial_hash: str
) -> dict[str, Any]:
    last_hash = initial_hash
    expected_sequence = initial_sequence
    records: list[dict[str, Any]] = []

    for line_number, line in enumerate(raw_lines, start=1):
        if not line.strip():
            raise AuditVerificationError(f"line {line_number}: blank/truncated record")
        record = _parse_record(line, line_number)
        if frozenset(record) != RECORD_KEYS:
            raise AuditVerificationError(f"line {line_number}: record keys mismatch")
        if record.get("schema_version") != AUDIT_SCHEMA_VERSION:
            raise AuditVerificationError(f"line {line_number}: incompatible schema version")
        if record.get("event") not in AUDIT_EVENTS:
            raise AuditVerificationError(f"line {line_number}: event is not allowlisted")
        if not isinstance(record.get("timestamp_utc"), str):
            raise AuditVerificationError(f"line {line_number}: timestamp is invalid")
        if not isinstance(record.get("payload"), dict):
            raise AuditVerificationError(f"line {line_number}: payload is invalid")
        if record.get("sequence") != expected_sequence:
            raise AuditVerificationError(f"line {line_number}: sequence gap or reorder")
        if record.get("previous_hash") != last_hash:
            raise AuditVerificationError(f"line {line_number}: previous hash mismatch")
        observed_hash = record.get("record_hash")
        if not isinstance(observed_hash, str) or observed_hash != _record_hash(record):
            raise AuditVerificationError(f"line {line_number}: record hash mismatch")
        last_hash = observed_hash
        expected_sequence += 1
        records.append(record)

    return {"next_sequence": expected_sequence, "last_hash": last_hash, "records": records}


def redact(value: object) -> object:
    """Recursively redact credentials, tokens, secrets, and sampled bytes."""
    if isinstance(value, Mapping):
        redacted: dict[str, object] = {}
        for key, child in value.items():
            key_text = str(key)
            if _is_sensitive_key(key_text):
                redacted[key_text] = REDACTED
            else:
                redacted[key_text] = redact(child)
        return redacted
    if isinstance(value, bytes | bytearray | memoryview):
        return REDACTED
    if isinstance(value, Sequence) and not isinstance(value, str):
        return [redact(item) for item in value]
    if isinstance(value, str):
        return _safe_string(value)
    if isinstance(value, float) and not math.isfinite(value):
        return "non_finite_number"
    if isinstance(value, int | float | bool) or value is None:
        return value
    return f"[UNSUPPORTED:{type(value).__name__}]"


def _record_hash(record: Mapping[str, Any]) -> str:
    material = dict(record)
    material.pop("record_hash", None)
    encoded = json.dumps(material, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(encoded).hexdigest()


def _empty_state() -> dict[str, Any]:
    return {"next_sequence": 1, "last_hash": GENESIS_HASH, "records": []}


def _safe_event(event: str) -> str:
    cleaned = "_".join(event.replace("\x00", "").split())
    return cleaned[:128] if cleaned else "unknown_event"


def _safe_string(value: str) -> str:
    cleaned = value.replace("\x00", "")[:512]
    return DEVICE_PATH_REDACTED if cleaned.startswith("/dev/") else cleaned


def _is_sensitive_key(key: str) -> bool:
    lowered = key.lower()
    return any(part in lowered for part in SENSITIVE_KEY_PARTS)


def _new_record(
    event: str, payload: Mapping[str, Any], sequence: int, previous_hash: str
) -> dict[str, Any]:
    record = {
        "schema_version": AUDIT_SCHEMA_VERSION,
        "sequence": sequence,
        "timestamp_utc": datetime.now(UTC).isoformat(timespec="microseconds"),
        "event": event,
        "payload": redact(payload),
        "previous_hash": previous_hash,
    }
    record["record_hash"] = _record_hash(record)
    encoded = _encoded_record(record)
    if len(encoded) > MAX_AUDIT_RECORD_BYTES:
        raise AuditWriteError("audit record exceeds the supported bound")
    return record


def _encoded_record(record: Mapping[str, Any]) -> bytes:
    return (json.dumps(record, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")


def _append_record(path: Path, record: Mapping[str, Any]) -> None:
    existed = path.exists()
    flags = (
        os.O_WRONLY
        | os.O_APPEND
        | os.O_CREAT
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    try:
        fd = os.open(path, flags, 0o600)
    except OSError as error:
        raise AuditWriteError("audit log could not be opened safely") from error
    try:
        opened = os.fstat(fd)
        if not stat.S_ISREG(opened.st_mode) or opened.st_nlink != 1:
            raise AuditWriteError("audit log is not a private regular file")
        os.fchmod(fd, 0o600)
        data = _encoded_record(record)
        if opened.st_size + len(data) > MAX_AUDIT_FILE_BYTES:
            raise AuditWriteError("audit log requires rotation before another append")
        offset = 0
        while offset < len(data):
            written = os.write(fd, data[offset:])
            if written == 0:
                raise AuditWriteError("audit log write made no progress")
            offset += written
        os.fsync(fd)
    finally:
        os.close(fd)
    if not existed:
        _fsync_directory(path.parent)


def _read_audit_file(path: Path) -> bytes:
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(path, flags)
    try:
        opened = os.fstat(fd)
        if not stat.S_ISREG(opened.st_mode) or opened.st_nlink != 1:
            raise AuditVerificationError("audit log is not a private regular file")
        if opened.st_size > MAX_AUDIT_FILE_BYTES:
            raise AuditVerificationError("audit log exceeds the supported segment bound")
        chunks = []
        remaining = opened.st_size
        while remaining:
            chunk = os.read(fd, min(remaining, 1024 * 1024))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        return b"".join(chunks)
    finally:
        os.close(fd)


def _parse_record(line: str, line_number: int) -> dict[str, Any]:
    try:
        record = json.loads(line)
    except (ValueError, RecursionError) as error:
        raise AuditVerificationError(f"line {line_number}: invalid JSON") from error
    if not isinstance(record, dict):
        raise AuditVerificationError(f"line {line_number}: record is not an object")
    return record


def _decode_lines(raw: bytes) -> list[str]:
    if raw and not raw.endswith(b"\n"):
        raise AuditVerificationError("final record is truncated")
    try:
        return raw.decode("utf-8").splitlines()
    except UnicodeDecodeError as error:
        raise AuditVerificationError("audit log is not valid UTF-8") from error


def _fsync_directory(path: Path) -> None:
    fd = os.open(path, os.O_RDONLY | getattr(os, "O_CLOEXEC", 0))
    try:
        os.fsync(fd)
    finally:
        os.close(fd)
