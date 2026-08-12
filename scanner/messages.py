"""Versioned JSON-lines protocol between scanner and control plane."""

from __future__ import annotations

import json
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from typing import Any

PROTOCOL_VERSION = 1
MAX_LINE_BYTES = 16_384
MAX_FIELD_CHARS = 4_096
MAX_BATCH_FINDINGS = 256

MESSAGE_TYPES = frozenset(
    {
        "hello",
        "capabilities",
        "stage_start",
        "finding_batch",
        "progress",
        "checkpoint",
        "warning",
        "error",
        "pause_ack",
        "complete",
    }
)

REQUIRED_FIELDS = {
    "hello": frozenset({"worker_id", "scanner_version"}),
    "capabilities": frozenset({"capabilities"}),
    "stage_start": frozenset({"stage", "idempotency_key"}),
    "finding_batch": frozenset({"stage", "batch_id", "findings"}),
    "progress": frozenset({"stage", "completed", "total"}),
    "checkpoint": frozenset({"stage", "checkpoint_id"}),
    "warning": frozenset({"stage", "code", "message"}),
    "error": frozenset({"stage", "code", "message", "retryable"}),
    "pause_ack": frozenset({"stage", "reason"}),
    "complete": frozenset({"stage", "status"}),
}


class ScannerMessageError(ValueError):
    """Raised when worker output violates the scanner protocol."""


@dataclass(frozen=True)
class ScannerMessage:
    message_type: str
    sequence: int
    payload: dict[str, Any]

    @property
    def replay_key(self) -> tuple[str, int, str | None]:
        stage = self.payload.get("stage")
        idempotency_key = self.payload.get("idempotency_key") or self.payload.get("batch_id")
        scoped = str(idempotency_key) if idempotency_key is not None else None
        return (self.message_type, self.sequence, scoped or (str(stage) if stage else None))


def encode_message(message_type: str, sequence: int, payload: Mapping[str, Any]) -> bytes:
    """Encode one canonical JSON-lines protocol message."""

    message = {
        "protocol_version": PROTOCOL_VERSION,
        "type": message_type,
        "sequence": sequence,
        "payload": dict(payload),
    }
    _validate_decoded_object(message)
    encoded = json.dumps(message, sort_keys=True, separators=(",", ":")).encode("utf-8") + b"\n"
    if len(encoded) > MAX_LINE_BYTES:
        raise ScannerMessageError("message exceeds maximum line size")
    return encoded


def decode_line(line: bytes) -> ScannerMessage:
    """Decode one bounded JSON line without returning raw malformed output."""

    if not line.endswith(b"\n"):
        raise ScannerMessageError("truncated scanner message")
    if len(line) > MAX_LINE_BYTES:
        raise ScannerMessageError("scanner message exceeds maximum line size")
    try:
        text = line.decode("utf-8")
    except UnicodeDecodeError as error:
        raise ScannerMessageError("scanner message is not valid UTF-8") from error
    try:
        decoded = json.loads(text)
    except json.JSONDecodeError as error:
        raise ScannerMessageError("scanner message is not valid JSON") from error
    if not isinstance(decoded, dict):
        raise ScannerMessageError("scanner message must be a JSON object")
    _validate_decoded_object(decoded)
    return ScannerMessage(
        message_type=str(decoded["type"]),
        sequence=int(decoded["sequence"]),
        payload=dict(decoded["payload"]),
    )


def decode_stream(lines: Iterable[bytes]) -> list[ScannerMessage]:
    """Decode a stream while ignoring duplicate replay keys."""

    seen: set[tuple[str, int, str | None]] = set()
    messages: list[ScannerMessage] = []
    for line in lines:
        message = decode_line(line)
        if message.replay_key in seen:
            continue
        seen.add(message.replay_key)
        messages.append(message)
    return messages


def _validate_decoded_object(message: Mapping[str, Any]) -> None:
    if message.get("protocol_version") != PROTOCOL_VERSION:
        raise ScannerMessageError("unsupported scanner protocol version")
    message_type = message.get("type")
    if message_type not in MESSAGE_TYPES:
        raise ScannerMessageError("unknown scanner message type")
    sequence = message.get("sequence")
    if not isinstance(sequence, int) or sequence < 0:
        raise ScannerMessageError("scanner message sequence must be a non-negative integer")
    payload = message.get("payload")
    if not isinstance(payload, dict):
        raise ScannerMessageError("scanner message payload must be an object")
    missing = REQUIRED_FIELDS[str(message_type)] - payload.keys()
    if missing:
        raise ScannerMessageError("scanner message is missing required fields")
    _validate_value(payload)
    if message_type == "finding_batch":
        findings = payload["findings"]
        if not isinstance(findings, list) or len(findings) > MAX_BATCH_FINDINGS:
            raise ScannerMessageError("finding batch size is invalid")


def _validate_value(value: object) -> None:
    if isinstance(value, str):
        if len(value) > MAX_FIELD_CHARS:
            raise ScannerMessageError("scanner message field exceeds maximum size")
        if "\x00" in value or "\n" in value or "\r" in value:
            raise ScannerMessageError("scanner message field contains unsafe control characters")
    elif isinstance(value, dict):
        for key, child in value.items():
            if not isinstance(key, str):
                raise ScannerMessageError("scanner message object keys must be strings")
            _validate_value(key)
            _validate_value(child)
    elif isinstance(value, list):
        for child in value:
            _validate_value(child)
    elif value is None or isinstance(value, bool | int | float):
        return
    else:
        raise ScannerMessageError("scanner message field has unsupported type")
