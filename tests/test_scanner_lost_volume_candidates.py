from __future__ import annotations

import unittest

from scanner import lost_volume_candidates, partition_discovery


class BytesReader:
    def __init__(self, data: bytes) -> None:
        self.data = data
        self.reads: list[tuple[int, int]] = []

    def read_at(self, offset_bytes: int, length_bytes: int) -> bytes:
        self.reads.append((offset_bytes, length_bytes))
        return self.data[offset_bytes : offset_bytes + length_bytes]


class ScannerLostVolumeCandidateTests(unittest.TestCase):
    def test_deleted_partition_signature_is_candidate_with_schedule(self) -> None:
        data = bytearray(4096)
        data[512:1024] = ntfs_block()

        candidates = lost_volume_candidates.detect_lost_volume_candidates(
            reader=BytesReader(bytes(data)), media_size_bytes=len(data), existing_partitions=()
        )

        self.assertEqual(1, len(candidates))
        self.assertEqual("ntfs", candidates[0].signature)
        self.assertGreaterEqual(candidates[0].confidence, 0.85)
        self.assertEqual(512, candidates[0].schedule[0].offset_bytes)

    def test_stale_signature_is_visible_low_confidence(self) -> None:
        data = bytearray(2048)
        block = bytearray(fat32_block())
        block[16:21] = b"STALE"
        data[0:512] = block

        candidate = lost_volume_candidates.detect_lost_volume_candidates(
            reader=BytesReader(bytes(data)), media_size_bytes=len(data), existing_partitions=()
        )[0]

        self.assertEqual("stale", candidate.status)
        self.assertIn("stale_signature", candidate.warnings)
        self.assertLess(candidate.confidence, 0.6)

    def test_overlapping_candidate_is_separate_from_current_partition(self) -> None:
        data = bytearray(4096)
        data[1024:1536] = exfat_block()

        candidate = lost_volume_candidates.detect_lost_volume_candidates(
            reader=BytesReader(bytes(data)),
            media_size_bytes=len(data),
            existing_partitions=(partition(offset=512, length=2048),),
        )[0]

        self.assertEqual("overlap", candidate.status)
        self.assertIn("overlaps_current_partition", candidate.warnings)

    def test_random_data_has_no_false_positive_candidate(self) -> None:
        data = bytes((index * 37) % 251 for index in range(4096))

        candidates = lost_volume_candidates.detect_lost_volume_candidates(
            reader=BytesReader(data), media_size_bytes=len(data), existing_partitions=()
        )

        self.assertEqual((), candidates)

    def test_encrypted_high_entropy_volume_is_visible_bounded_candidate(self) -> None:
        data = b"LUKS" + bytes(range(256)) * 32

        candidates = lost_volume_candidates.detect_lost_volume_candidates(
            reader=BytesReader(data), media_size_bytes=len(data), existing_partitions=()
        )

        self.assertEqual("encrypted", candidates[0].status)
        self.assertEqual("encrypted-unknown", candidates[0].signature)
        self.assertLessEqual(candidates[0].schedule[0].length_bytes, 16 * 1024 * 1024)


def ntfs_block() -> bytes:
    block = bytearray(512)
    block[3:11] = b"NTFS    "
    return bytes(block)


def fat32_block() -> bytes:
    block = bytearray(512)
    block[82:90] = b"FAT32   "
    return bytes(block)


def exfat_block() -> bytes:
    block = bytearray(512)
    block[3:11] = b"EXFAT   "
    return bytes(block)


def partition(*, offset: int, length: int) -> partition_discovery.PartitionEntry:
    return partition_discovery.PartitionEntry(
        slot="002:",
        offset_bytes=offset,
        length_bytes=length,
        start_sector=offset // 512,
        end_sector=(offset + length) // 512,
        sector_count=length // 512,
        description="existing",
        partition_type="ntfs",
        label=None,
        allocated=True,
    )


if __name__ == "__main__":
    unittest.main()
