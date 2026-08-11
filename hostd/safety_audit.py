"""Append-only host safety audit for RPR-018."""

from __future__ import annotations

import hashlib
import json
import threading
from collections.abc import Mapping
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

AUDIT_SCHEMA_VERSION = 1
GENESIS_HASH = "0" * 64
REDACTED = "[REDACTED]"
SENSITIVE_KEY_PARTS = (
    "credential",
    "password",
    "secret",
    "token",
    "sample_bytes",
    "private_key",
    "seed",
)


class AuditVerificationError(ValueError):
    """Raised when an audit log has been tampered with or truncated."""


class SafetyAuditLog:
    """Append-only JSONL safety audit with sequence numbers and hash chaining."""

    def __init__(self, path: Path) -> None:
        self.path = path
        self._lock = threading.Lock()

    def append(self, event: str, payload: Mapping[str, Any]) -> dict[str, Any]:
        """Append one redacted event and return the stored record."""
        with self._lock:
            state = verify_audit_log(self.path) if self.path.exists() else _empty_state()
            record = {
                "schema_version": AUDIT_SCHEMA_VERSION,
                "sequence": state["next_sequence"],
                "timestamp_utc": datetime.now(UTC).isoformat(timespec="microseconds"),
                "event": _safe_event(event),
                "payload": redact(payload),
                "previous_hash": state["last_hash"],
            }
            record["record_hash"] = _record_hash(record)
            line = json.dumps(record, sort_keys=True, separators=(",", ":")) + "\n"
            self.path.parent.mkdir(parents=True, exist_ok=True)
            with self.path.open("a", encoding="utf-8") as handle:
                handle.write(line)
                handle.flush()
            return record


def verify_audit_log(path: Path) -> dict[str, Any]:
    """Verify hash chain and return ordering state for an audit log."""
    last_hash = GENESIS_HASH
    expected_sequence = 1
    records: list[dict[str, Any]] = []
    try:
        raw_lines = path.read_text(encoding="utf-8").splitlines()
    except FileNotFoundError:
        return _empty_state()

    for line_number, line in enumerate(raw_lines, start=1):
        if not line.strip():
            raise AuditVerificationError(f"line {line_number}: blank/truncated record")
        try:
            record = json.loads(line)
        except json.JSONDecodeError as error:
            raise AuditVerificationError(f"line {line_number}: invalid JSON") from error
        if not isinstance(record, dict):
            raise AuditVerificationError(f"line {line_number}: record is not an object")
        if record.get("schema_version") != AUDIT_SCHEMA_VERSION:
            raise AuditVerificationError(f"line {line_number}: incompatible schema version")
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
    if isinstance(value, list):
        return [redact(item) for item in value]
    if isinstance(value, str):
        return _safe_string(value)
    if isinstance(value, int | float | bool) or value is None:
        return value
    return str(value)


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
    return value.replace("\x00", "")[:512]


def _is_sensitive_key(key: str) -> bool:
    lowered = key.lower()
    return any(part in lowered for part in SENSITIVE_KEY_PARTS)
