"""Content-addressed scratch store for recovered derivatives."""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import threading
import uuid
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from hostd.destination_separation import evaluate_destination_separation

CHUNK_SIZE = 1024 * 1024
TEMP_PREFIX = ".reperio-incomplete-"


class ScratchStoreError(ValueError):
    """Raised when scratch storage cannot safely accept content."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


@dataclass(frozen=True)
class ScratchObject:
    content_id: str
    sha256: str
    size_bytes: int
    storage_uri: str
    path: Path
    ref_count: int
    provenance: tuple[Mapping[str, Any], ...]


class ScratchStore:
    """Atomic, SHA-256 addressed storage rooted in proven-separate scratch."""

    def __init__(
        self,
        root: Path,
        *,
        source: Mapping[str, Any],
        mounts: Iterable[Mapping[str, Any]],
        holders: Mapping[str, Iterable[Mapping[str, str]]] | None = None,
        quota_bytes: int,
        statvfs: Callable[[Path], os.statvfs_result] | None = None,
    ) -> None:
        if isinstance(quota_bytes, bool) or not isinstance(quota_bytes, int) or quota_bytes <= 0:
            raise ScratchStoreError("invalid_quota", "scratch quota must be positive")
        if root.is_symlink():
            raise ScratchStoreError("scratch_symlink", "scratch storage root must not be a symlink")
        self.root = root.resolve(strict=False)
        self.objects = self.root / "objects"
        self.tmp = self.root / "tmp"
        self.metadata = self.root / "metadata"
        self.quota_bytes = quota_bytes
        self._statvfs = statvfs or os.statvfs
        self._metadata_lock = threading.Lock()
        separation = evaluate_destination_separation(
            source, self.root, mounts=mounts, holders=holders
        )
        if not separation["separate"]:
            raise ScratchStoreError("scratch_not_separate", "scratch storage overlaps source media")

    def initialize(self) -> None:
        self.root.mkdir(mode=0o700, parents=True, exist_ok=True)
        _refuse_symlink(self.root)
        for directory in (self.objects, self.tmp, self.metadata):
            directory.mkdir(mode=0o700, exist_ok=True)
            _refuse_symlink(directory)

    def put_bytes(
        self,
        chunks: Iterable[bytes],
        *,
        provenance: Mapping[str, Any],
        expected_sha256: str | None = None,
        expected_size: int | None = None,
    ) -> ScratchObject:
        """Write content atomically; callers never choose the final path."""

        self.initialize()
        self._cleanup_incomplete()
        self._check_available_quota(0)
        temp_path = self.tmp / f"{TEMP_PREFIX}{uuid.uuid4().hex}"
        digest = hashlib.sha256()
        size = 0
        try:
            flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
            fd = os.open(temp_path, flags, 0o600)
            with os.fdopen(fd, "wb") as handle:
                for chunk in chunks:
                    if not isinstance(chunk, bytes):
                        raise ScratchStoreError("invalid_chunk", "scratch chunks must be bytes")
                    size += len(chunk)
                    if size > self.quota_bytes:
                        raise ScratchStoreError("quota_exceeded", "scratch object exceeds quota")
                    handle.write(chunk)
                    digest.update(chunk)
                handle.flush()
                os.fsync(handle.fileno())
            sha256 = digest.hexdigest()
            if expected_sha256 is not None and sha256 != expected_sha256:
                raise ScratchStoreError("hash_mismatch", "scratch object hash does not match")
            if expected_size is not None and size != expected_size:
                raise ScratchStoreError("size_mismatch", "scratch object size does not match")
            self._check_available_quota(size)
            final_path = self._object_path(sha256)
            final_path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            _refuse_symlink(final_path.parent)
            if final_path.exists() or final_path.is_symlink():
                _refuse_symlink(final_path)
            if final_path.exists():
                temp_path.unlink(missing_ok=True)
            else:
                os.replace(temp_path, final_path)
            with self._metadata_lock:
                return self._record_metadata(sha256, size, final_path, provenance)
        except Exception:
            temp_path.unlink(missing_ok=True)
            raise

    def load_metadata(self, sha256: str) -> ScratchObject:
        metadata_path = self._metadata_path(sha256)
        _refuse_symlink(metadata_path)
        try:
            data = json.loads(metadata_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as error:
            raise ScratchStoreError(
                "invalid_metadata", "scratch metadata cannot be read"
            ) from error
        if (
            not isinstance(data, dict)
            or data.get("sha256") != sha256
            or not isinstance(data.get("size_bytes"), int)
            or isinstance(data["size_bytes"], bool)
            or data["size_bytes"] < 0
            or not isinstance(data.get("ref_count"), int)
            or isinstance(data["ref_count"], bool)
            or data["ref_count"] < 1
            or not isinstance(data.get("provenance"), list)
        ):
            raise ScratchStoreError("invalid_metadata", "scratch metadata is malformed")
        path = self._object_path(sha256)
        return ScratchObject(
            content_id=str(data["content_id"]),
            sha256=str(data["sha256"]),
            size_bytes=int(data["size_bytes"]),
            storage_uri=str(data["storage_uri"]),
            path=path,
            ref_count=int(data["ref_count"]),
            provenance=tuple(data["provenance"]),
        )

    def cleanup_incomplete(self) -> int:
        self.initialize()
        return self._cleanup_incomplete()

    def _record_metadata(
        self, sha256: str, size: int, path: Path, provenance: Mapping[str, Any]
    ) -> ScratchObject:
        metadata_path = self._metadata_path(sha256)
        metadata_path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        _refuse_symlink(metadata_path.parent)
        if metadata_path.exists():
            _refuse_symlink(metadata_path)
            existing = json.loads(metadata_path.read_text(encoding="utf-8"))
            provenance_list = list(existing["provenance"])
            provenance_list.append(dict(provenance))
            data = {
                **existing,
                "ref_count": int(existing["ref_count"]) + 1,
                "provenance": provenance_list,
            }
        else:
            data = {
                "content_id": f"content-{sha256[:32]}",
                "sha256": sha256,
                "size_bytes": size,
                "storage_uri": f"scratch://sha256/{sha256}",
                "ref_count": 1,
                "provenance": [dict(provenance)],
            }
        temp_metadata = self.tmp / f"{TEMP_PREFIX}{uuid.uuid4().hex}.json"
        temp_metadata.write_text(
            json.dumps(data, sort_keys=True, separators=(",", ":")), encoding="utf-8"
        )
        os.replace(temp_metadata, metadata_path)
        return ScratchObject(
            content_id=str(data["content_id"]),
            sha256=sha256,
            size_bytes=size,
            storage_uri=f"scratch://sha256/{sha256}",
            path=path,
            ref_count=int(data["ref_count"]),
            provenance=tuple(data["provenance"]),
        )

    def _object_path(self, sha256: str) -> Path:
        _validate_sha256(sha256)
        return self.objects / sha256[:2] / sha256

    def _metadata_path(self, sha256: str) -> Path:
        _validate_sha256(sha256)
        return self.metadata / sha256[:2] / f"{sha256}.json"

    def _cleanup_incomplete(self) -> int:
        removed = 0
        for path in self.tmp.iterdir() if self.tmp.exists() else ():
            if not path.name.startswith(TEMP_PREFIX):
                continue
            _refuse_symlink(path)
            if path.is_dir():
                shutil.rmtree(path)
            else:
                path.unlink()
            removed += 1
        return removed

    def _check_available_quota(self, incoming_bytes: int) -> None:
        used = _directory_size(self.objects) + _directory_size(self.metadata) + incoming_bytes
        if used > self.quota_bytes:
            raise ScratchStoreError("quota_exceeded", "scratch quota exceeded")
        stats = self._statvfs(self.root)
        available = int(stats.f_bavail) * int(stats.f_frsize)
        if incoming_bytes > available:
            raise ScratchStoreError("disk_full", "scratch storage does not have enough space")


def _validate_sha256(value: str) -> None:
    if len(value) != 64 or any(char not in "0123456789abcdef" for char in value):
        raise ScratchStoreError("invalid_hash", "scratch object hash is invalid")


def _directory_size(path: Path) -> int:
    if not path.exists():
        return 0
    total = 0
    for child in path.rglob("*"):
        _refuse_symlink(child)
        if child.is_file():
            total += child.stat().st_size
    return total


def _refuse_symlink(path: Path) -> None:
    if path.is_symlink():
        raise ScratchStoreError("scratch_symlink", "scratch storage contains a symlink")
