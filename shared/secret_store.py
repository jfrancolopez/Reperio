"""Encrypted host secret store with opaque references."""

from __future__ import annotations

import base64
import json
import os
import secrets
import stat
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

KEY_BYTES = 32
NONCE_BYTES = 12
SECRET_REF_PREFIX = "vault:"
MASKED_VALUE = "********"


class SecretStoreError(ValueError):
    """Raised when secret store data cannot be decrypted or trusted."""


@dataclass(frozen=True)
class SecretMetadata:
    ref: str
    label: str
    key_version: int
    masked_value: str = MASKED_VALUE


@dataclass(frozen=True)
class PermissionAudit:
    path: Path
    mode: int
    expected_mode: int
    ok: bool


class SecretStore:
    """Store secret values encrypted at rest under restrictive file permissions."""

    def __init__(self, root: Path) -> None:
        self.root = root
        self.secret_dir = root / "secrets"
        self.key_path = root / "master.key"
        self._prepare_paths()
        self._key = self._load_or_create_key()

    def put(self, *, label: str, value: str) -> SecretMetadata:
        ref = f"{SECRET_REF_PREFIX}{secrets.token_hex(16)}"
        payload = self._encrypt_payload(label=label, value=value, key_version=1)
        path = self._path_for_ref(ref)
        _write_private_json(path, payload)
        return SecretMetadata(ref=ref, label=label, key_version=1)

    def get(self, ref: str) -> str:
        payload = self._read_payload(ref)
        try:
            plaintext = AESGCM(self._key).decrypt(
                _decode(payload["nonce"]),
                _decode(payload["ciphertext"]),
                _associated_data(payload),
            )
        except InvalidTag as error:
            raise SecretStoreError("secret cannot be decrypted with this master key") from error
        data = json.loads(plaintext.decode("utf-8"))
        return str(data["value"])

    def metadata(self, ref: str) -> SecretMetadata:
        payload = self._read_payload(ref)
        return SecretMetadata(
            ref=ref,
            label=str(payload["label"]),
            key_version=int(payload["key_version"]),
        )

    def rotate_master_key(self) -> None:
        refs = [f"{SECRET_REF_PREFIX}{path.stem}" for path in self.secret_dir.glob("*.json")]
        decrypted = [(ref, self.metadata(ref), self.get(ref)) for ref in refs]
        self._key = secrets.token_bytes(KEY_BYTES)
        _write_private_bytes(self.key_path, self._key)
        for ref, metadata, value in decrypted:
            payload = self._encrypt_payload(
                label=metadata.label,
                value=value,
                key_version=metadata.key_version + 1,
            )
            _write_private_json(self._path_for_ref(ref), payload)

    def delete(self, ref: str) -> None:
        self._path_for_ref(ref).unlink(missing_ok=True)

    def redacted_snapshot(self) -> list[dict[str, str | int]]:
        records = [
            self.metadata(f"{SECRET_REF_PREFIX}{path.stem}")
            for path in self.secret_dir.glob("*.json")
        ]
        return [
            {
                "ref": metadata.ref,
                "label": metadata.label,
                "key_version": metadata.key_version,
                "value": metadata.masked_value,
            }
            for metadata in sorted(records, key=lambda item: item.ref)
        ]

    def audit_permissions(self) -> list[PermissionAudit]:
        paths = [self.root, self.secret_dir, self.key_path, *self.secret_dir.glob("*.json")]
        audits: list[PermissionAudit] = []
        for path in paths:
            mode = stat.S_IMODE(path.stat().st_mode)
            expected = 0o700 if path.is_dir() else 0o600
            audits.append(
                PermissionAudit(path=path, mode=mode, expected_mode=expected, ok=mode == expected)
            )
        return audits

    def _prepare_paths(self) -> None:
        self.root.mkdir(parents=True, exist_ok=True)
        self.root.chmod(0o700)
        self.secret_dir.mkdir(exist_ok=True)
        self.secret_dir.chmod(0o700)

    def _load_or_create_key(self) -> bytes:
        if self.key_path.exists():
            key = self.key_path.read_bytes()
            if len(key) != KEY_BYTES:
                raise SecretStoreError("master key has invalid length")
            self.key_path.chmod(0o600)
            return key
        key = secrets.token_bytes(KEY_BYTES)
        _write_private_bytes(self.key_path, key)
        return key

    def _encrypt_payload(self, *, label: str, value: str, key_version: int) -> dict[str, Any]:
        nonce = secrets.token_bytes(NONCE_BYTES)
        plaintext = json.dumps({"value": value}, sort_keys=True, separators=(",", ":")).encode(
            "utf-8"
        )
        metadata = {"label": label, "key_version": key_version, "nonce": _encode(nonce)}
        ciphertext = AESGCM(self._key).encrypt(nonce, plaintext, _associated_data(metadata))
        metadata["ciphertext"] = _encode(ciphertext)
        return metadata

    def _read_payload(self, ref: str) -> dict[str, Any]:
        path = self._path_for_ref(ref)
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as error:
            raise SecretStoreError("secret reference cannot be read") from error
        if not isinstance(data, dict):
            raise SecretStoreError("secret record is malformed")
        return data

    def _path_for_ref(self, ref: str) -> Path:
        if not ref.startswith(SECRET_REF_PREFIX):
            raise SecretStoreError("secret reference must be opaque vault reference")
        name = ref.removeprefix(SECRET_REF_PREFIX)
        if len(name) != 32 or any(char not in "0123456789abcdef" for char in name):
            raise SecretStoreError("secret reference is malformed")
        return self.secret_dir / f"{name}.json"


def _associated_data(payload: dict[str, Any]) -> bytes:
    return json.dumps(
        {
            "key_version": payload["key_version"],
            "label": payload["label"],
            "nonce": payload["nonce"],
        },
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def _encode(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode("ascii")


def _decode(value: object) -> bytes:
    if not isinstance(value, str):
        raise SecretStoreError("secret record contains invalid encoded field")
    return base64.urlsafe_b64decode(value.encode("ascii"))


def _write_private_bytes(path: Path, data: bytes) -> None:
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "wb") as handle:
        handle.write(data)
    path.chmod(0o600)


def _write_private_json(path: Path, payload: dict[str, Any]) -> None:
    _write_private_bytes(path, json.dumps(payload, sort_keys=True).encode("utf-8"))
