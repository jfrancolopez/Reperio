"""Read-only lost-volume and corruption candidate detection."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import Protocol

from scanner import photorec_carving
from scanner.partition_discovery import PartitionEntry

SCAN_STRIDE_BYTES = 512
MAX_SCHEDULED_ATTEMPTS = 8


class LostVolumeCandidateError(ValueError):
    """Raised when candidate scanning input is invalid."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


class RangeReader(Protocol):
    def read_at(self, offset_bytes: int, length_bytes: int) -> bytes: ...


@dataclass(frozen=True)
class LostVolumeCandidate:
    candidate_id: str
    offset_bytes: int
    length_bytes: int
    signature: str
    confidence: float
    status: str
    warnings: tuple[str, ...]
    schedule: tuple[photorec_carving.CarveRange, ...]


def detect_lost_volume_candidates(
    *,
    reader: RangeReader,
    media_size_bytes: int,
    existing_partitions: tuple[PartitionEntry, ...],
    max_candidates: int = MAX_SCHEDULED_ATTEMPTS,
) -> tuple[LostVolumeCandidate, ...]:
    """Scan selected offsets for plausible lost filesystems without modifying tables."""

    if media_size_bytes <= 0 or max_candidates <= 0:
        raise LostVolumeCandidateError("invalid_scan_bounds", "scan bounds must be positive")
    candidates: list[LostVolumeCandidate] = []
    for offset in range(0, media_size_bytes, SCAN_STRIDE_BYTES):
        block = reader.read_at(offset, min(SCAN_STRIDE_BYTES, media_size_bytes - offset))
        signature = _signature(block)
        if signature is None:
            continue
        candidate = _candidate(
            offset,
            media_size_bytes,
            signature,
            block,
            existing_partitions=existing_partitions,
        )
        candidates.append(candidate)
        if len(candidates) >= max_candidates:
            break
    if not candidates and _looks_encrypted_sample(reader, media_size_bytes):
        return (
            LostVolumeCandidate(
                candidate_id="candidate-encrypted-volume",
                offset_bytes=0,
                length_bytes=media_size_bytes,
                signature="encrypted-unknown",
                confidence=0.35,
                status="encrypted",
                warnings=("encrypted_or_high_entropy_volume",),
                schedule=(photorec_carving.CarveRange(0, min(media_size_bytes, 16 * 1024 * 1024)),),
            ),
        )
    return tuple(candidates)


def _candidate(
    offset: int,
    media_size: int,
    signature: str,
    block: bytes,
    *,
    existing_partitions: tuple[PartitionEntry, ...],
) -> LostVolumeCandidate:
    warnings: list[str] = []
    overlaps = _overlapping_partitions(offset, existing_partitions)
    if overlaps:
        warnings.append("overlaps_current_partition")
    if _stale_signature(block):
        warnings.append("stale_signature")
    confidence = _confidence(signature, warnings)
    status = "overlap" if overlaps else "candidate"
    if "stale_signature" in warnings:
        status = "stale"
    length = min(media_size - offset, 128 * 1024 * 1024)
    schedule = (
        () if overlaps and confidence < 0.75 else (photorec_carving.CarveRange(offset, length),)
    )
    digest = hashlib.sha256(f"{offset}:{signature}".encode("ascii") + block[:64]).hexdigest()
    return LostVolumeCandidate(
        candidate_id=f"lost-volume-{digest[:24]}",
        offset_bytes=offset,
        length_bytes=length,
        signature=signature,
        confidence=confidence,
        status=status,
        warnings=tuple(warnings),
        schedule=schedule,
    )


def _signature(block: bytes) -> str | None:
    if len(block) >= 11 and block[3:11] == b"NTFS    ":
        return "ntfs"
    if len(block) >= 90 and block[82:90] == b"FAT32   ":
        return "fat32"
    if len(block) >= 11 and block[3:11] == b"EXFAT   ":
        return "exfat"
    if len(block) >= 2 and block[0:2] == b"\xeb\x3c" and b"FAT" in block[:90]:
        return "fat"
    return None


def _confidence(signature: str, warnings: list[str]) -> float:
    base = {"ntfs": 0.9, "fat32": 0.85, "exfat": 0.85, "fat": 0.7}.get(signature, 0.5)
    if "overlaps_current_partition" in warnings:
        base -= 0.25
    if "stale_signature" in warnings:
        base -= 0.35
    return max(0.0, min(1.0, round(base, 2)))


def _overlapping_partitions(offset: int, partitions: tuple[PartitionEntry, ...]) -> tuple[str, ...]:
    overlaps: list[str] = []
    for partition in partitions:
        start = partition.offset_bytes
        end = partition.offset_bytes + partition.length_bytes
        if start <= offset < end:
            overlaps.append(partition.slot)
    return tuple(overlaps)


def _stale_signature(block: bytes) -> bool:
    return b"STALE" in block[:128] or b"DELETED" in block[:128]


def _looks_encrypted_sample(reader: RangeReader, media_size_bytes: int) -> bool:
    sample = reader.read_at(0, min(media_size_bytes, 4096))
    if len(sample) < 512:
        return False
    if not (sample.startswith(b"LUKS") or b"VERACRYPT" in sample[:512]):
        return False
    unique = len(set(sample))
    zeros = sample.count(0)
    return unique > 200 and zeros < len(sample) // 100
