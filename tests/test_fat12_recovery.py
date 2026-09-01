from __future__ import annotations

import hashlib
import struct
import unittest
from typing import TypedDict

from scanner import fat12_parser
from shared import media_checkpoints, media_identity


class MemoryReader:
    def __init__(self, image: bytes, *, failing_sectors: set[int] | None = None) -> None:
        self.image = image
        self.failing_sectors = failing_sectors or set()
        self.reads: list[tuple[int, int]] = []

    def read_at(self, offset_bytes: int, length_bytes: int) -> bytes:
        self.reads.append((offset_bytes, length_bytes))
        if offset_bytes // 512 in self.failing_sectors:
            raise OSError("synthetic unreadable sector")
        return self.image[offset_bytes : offset_bytes + length_bytes]


class EntrySpec(TypedDict):
    name: str
    first_cluster: int
    size: int
    attributes: int
    chain: tuple[int, ...] | None
    deleted: bool
    long_name: str | None
    corrupt_lfn: bool
    date_bits: int
    time_bits: int


class Fat12RecoveryTests(unittest.TestCase):
    def test_all_advertised_geometries_are_detected_exactly(self) -> None:
        for geometry in fat12_parser.SUPPORTED_GEOMETRIES:
            with self.subTest(geometry=geometry.label):
                image = build_image(geometry, [entry("FILE.TXT", first_cluster=2, size=4)])
                result = fat12_parser.scan_fat12(MemoryReader(image), source_size_bytes=len(image))
                self.assertEqual(geometry, result.geometry)
                self.assertEqual("FILE.TXT", result.entries[0].name)

    def test_geometry_mismatch_is_not_guessed(self) -> None:
        geometry = geometry_named("1.44 MiB")
        image = bytearray(build_image(geometry, []))
        struct.pack_into("<H", image, 24, 9)

        with self.assertRaises(fat12_parser.Fat12Error) as caught:
            fat12_parser.scan_fat12(MemoryReader(bytes(image)), source_size_bytes=len(image))

        self.assertEqual("ambiguous_geometry", caught.exception.code)

    def test_non_dos_signature_is_rejected(self) -> None:
        geometry = geometry_named("1.44 MiB")
        image = bytearray(build_image(geometry, []))
        image[54:62] = b"NOTFAT  "

        with self.assertRaises(fat12_parser.Fat12Error) as caught:
            fat12_parser.scan_fat12(MemoryReader(bytes(image)), source_size_bytes=len(image))

        self.assertEqual("non_dos_signature", caught.exception.code)

    def test_allocated_hidden_fragmented_and_timestamp_metadata_survive(self) -> None:
        geometry = geometry_named("1.44 MiB")
        record = entry(
            "SECRET.TXT",
            first_cluster=2,
            size=700,
            attributes=0x22,
            chain=(2, 4),
            date_bits=fat_date(2020, 5, 17),
            time_bits=fat_time(14, 30, 10),
        )
        result = scan(build_image(geometry, [record]))
        finding = result.entries[0]

        self.assertEqual("allocated_fragmented", finding.recovery_state)
        self.assertIn("hidden", finding.attributes)
        self.assertIn("fat12_fragmented_chain", finding.warnings)
        self.assertEqual((2, 4), finding.cluster_chain)
        self.assertIn(("modified", "2020-05-17T14:30:10"), finding.timestamps)

    def test_valid_long_name_is_preserved_and_invalid_lfn_falls_back(self) -> None:
        geometry = geometry_named("1.44 MiB")
        valid = entry("LONGNA~1.TXT", first_cluster=2, size=4, long_name="Long name.txt")
        invalid = entry(
            "BROKEN~1.TXT",
            first_cluster=3,
            size=4,
            long_name="Broken name.txt",
            corrupt_lfn=True,
        )
        result = scan(build_image(geometry, [valid, invalid]))

        self.assertEqual("Long name.txt", result.entries[0].name)
        self.assertEqual("BROKEN~1.TXT", result.entries[1].name)
        self.assertIn("fat12_lfn_invalid", result.entries[1].warnings)

    def test_deleted_contiguous_candidate_is_inferred_but_fragmentation_is_unknown(self) -> None:
        geometry = geometry_named("720 KiB")
        deleted = entry("DELETE.TXT", first_cluster=5, size=1300, deleted=True)
        finding = scan(build_image(geometry, [deleted])).entries[0]

        self.assertFalse(finding.allocated)
        self.assertEqual("?ELETE.TXT", finding.name)
        self.assertEqual("deleted_contiguous_candidate", finding.recovery_state)
        self.assertEqual("medium", finding.chain_confidence)
        self.assertEqual((5, 6), finding.cluster_chain)
        self.assertIn("fat12_deleted_fragmentation_unknown", finding.warnings)

    def test_deleted_reused_cluster_is_not_exposed_as_recoverable_extent(self) -> None:
        geometry = geometry_named("1.44 MiB")
        deleted = entry("DELETE.BIN", first_cluster=5, size=700, deleted=True)
        allocated = entry("OWNER.BIN", first_cluster=5, size=700, chain=(5, 6))
        finding = scan(build_image(geometry, [deleted, allocated])).entries[0]

        self.assertEqual("deleted_reused", finding.recovery_state)
        self.assertEqual((), finding.cluster_chain)
        self.assertEqual((), finding.extents)
        self.assertIn("fat12_deleted_cluster_reused", finding.warnings)

    def test_partial_chain_and_bad_sector_are_labeled(self) -> None:
        geometry = geometry_named("1.44 MiB")
        partial = entry("PARTIAL.BIN", first_cluster=2, size=1024, chain=(2,))
        image = build_image(geometry, [partial])
        data_sector = geometry.first_data_sector
        result = fat12_parser.scan_fat12(
            MemoryReader(image),
            source_size_bytes=len(image),
            known_bad_sectors={data_sector},
        )
        finding = result.entries[0]

        self.assertEqual("partial_bad_sector", finding.recovery_state)
        self.assertIn("fat12_cluster_chain_short", finding.warnings)
        self.assertIn("fat12_bad_sector_in_content", finding.warnings)
        self.assertNotIn(data_sector, sectors_from_ranges(result.carve_ranges))

    def test_corrupt_fat_copy_uses_valid_copy_and_both_corrupt_stay_explicit(self) -> None:
        geometry = geometry_named("1.44 MiB")
        image = bytearray(build_image(geometry, [entry("FILE.TXT", first_cluster=2, size=4)]))
        second_fat = (geometry.reserved_sectors + geometry.sectors_per_fat) * 512
        image[second_fat] = 0
        one_bad = scan(bytes(image))
        self.assertIn("fat_copy_corrupt", one_bad.warnings)
        self.assertEqual("allocated_intact", one_bad.entries[0].recovery_state)

        first_fat = geometry.reserved_sectors * 512
        image[first_fat] = 0
        both_bad = scan(bytes(image))
        self.assertIn("fat_copies_corrupt", both_bad.warnings)
        self.assertEqual("partial", both_bad.entries[0].recovery_state)

    def test_known_read_gaps_are_recorded_and_free_ranges_are_split(self) -> None:
        geometry = geometry_named("360 KiB")
        image = build_image(geometry, [entry("FILE.TXT", first_cluster=2, size=4)])
        bad_free_sector = geometry.first_data_sector + geometry.sectors_per_cluster
        result = fat12_parser.scan_fat12(
            MemoryReader(image),
            source_size_bytes=len(image),
            known_bad_sectors={bad_free_sector},
        )

        self.assertIn("source_read_gaps", result.warnings)
        self.assertIn(bad_free_sector, result.unreadable_sectors)
        self.assertNotIn(bad_free_sector, sectors_from_ranges(result.carve_ranges))

    def test_fat_read_error_uses_intact_copy_and_remains_visible(self) -> None:
        geometry = geometry_named("1.44 MiB")
        image = build_image(geometry, [entry("FILE.TXT", first_cluster=2, size=4)])

        result = fat12_parser.scan_fat12(
            MemoryReader(image, failing_sectors={geometry.reserved_sectors}),
            source_size_bytes=len(image),
        )

        self.assertIn(geometry.reserved_sectors, result.unreadable_sectors)
        self.assertIn("fat_copy_corrupt", result.warnings)
        self.assertIn("source_read_gaps", result.warnings)
        self.assertEqual("allocated_intact", result.entries[0].recovery_state)

    def test_scan_is_read_only_and_source_bytes_remain_identical(self) -> None:
        geometry = geometry_named("1.2 MiB")
        image = build_image(geometry, [entry("FILE.TXT", first_cluster=2, size=4)])
        before = hashlib.sha256(image).digest()
        reader = MemoryReader(image)

        fat12_parser.scan_fat12(reader, source_size_bytes=len(image))

        self.assertEqual(before, hashlib.sha256(reader.image).digest())
        self.assertTrue(reader.reads)
        self.assertFalse(hasattr(fat12_parser, "repair"))
        self.assertFalse(hasattr(fat12_parser, "write"))
        self.assertFalse(hasattr(fat12_parser, "rebuild_boot_sector"))

    def test_changed_floppy_geometry_denies_resume(self) -> None:
        before = medium_record(geometry_named("720 KiB"))
        after = medium_record(geometry_named("1.44 MiB"))

        eligibility = media_checkpoints.resume_eligibility(before, after)

        self.assertFalse(eligibility.eligible)
        self.assertEqual("capacity_changed", eligibility.reason)
        self.assertTrue(eligibility.offers_new_case)


def scan(image: bytes) -> fat12_parser.Fat12ScanResult:
    return fat12_parser.scan_fat12(MemoryReader(image), source_size_bytes=len(image))


def geometry_named(label: str) -> fat12_parser.Fat12Geometry:
    return next(
        geometry for geometry in fat12_parser.SUPPORTED_GEOMETRIES if geometry.label == label
    )


def entry(
    name: str,
    *,
    first_cluster: int,
    size: int,
    attributes: int = 0x20,
    chain: tuple[int, ...] | None = None,
    deleted: bool = False,
    long_name: str | None = None,
    corrupt_lfn: bool = False,
    date_bits: int = 0x0021,
    time_bits: int = 0,
) -> EntrySpec:
    return {
        "name": name,
        "first_cluster": first_cluster,
        "size": size,
        "attributes": attributes,
        "chain": chain,
        "deleted": deleted,
        "long_name": long_name,
        "corrupt_lfn": corrupt_lfn,
        "date_bits": date_bits,
        "time_bits": time_bits,
    }


def build_image(geometry: fat12_parser.Fat12Geometry, records: list[EntrySpec]) -> bytes:
    image = bytearray(geometry.size_bytes)
    image[:512] = boot_sector(geometry)
    fat = [0] * (geometry.cluster_count + 2)
    fat[0] = 0xF00 | geometry.media_descriptor
    fat[1] = 0xFFF
    root_entries: list[bytes] = []
    for record in records:
        chain = record["chain"] or ()
        if not record["deleted"]:
            if not chain and record["first_cluster"] >= 2:
                chain = (record["first_cluster"],)
            for index, cluster in enumerate(chain):
                fat[cluster] = chain[index + 1] if index + 1 < len(chain) else 0xFFF
        short = short_name(record["name"])
        long_name = record["long_name"]
        if isinstance(long_name, str):
            checksum = lfn_checksum(short)
            if record["corrupt_lfn"]:
                checksum = (checksum + 1) & 0xFF
            root_entries.extend(lfn_entries(long_name, checksum))
        root_entries.append(directory_entry(short, record))

    encoded_fat = encode_fat(fat).ljust(geometry.sectors_per_fat * 512, b"\x00")
    for index in range(geometry.fat_count):
        start = (geometry.reserved_sectors + index * geometry.sectors_per_fat) * 512
        image[start : start + len(encoded_fat)] = encoded_fat
    root_start = (geometry.reserved_sectors + geometry.fat_count * geometry.sectors_per_fat) * 512
    root = b"".join(root_entries) + bytes(32)
    image[root_start : root_start + len(root)] = root
    return bytes(image)


def boot_sector(geometry: fat12_parser.Fat12Geometry) -> bytes:
    boot = bytearray(512)
    boot[0:3] = b"\xeb\x3c\x90"
    boot[3:11] = b"REPERIO "
    struct.pack_into("<H", boot, 11, geometry.bytes_per_sector)
    boot[13] = geometry.sectors_per_cluster
    struct.pack_into("<H", boot, 14, geometry.reserved_sectors)
    boot[16] = geometry.fat_count
    struct.pack_into("<H", boot, 17, geometry.root_entries)
    struct.pack_into("<H", boot, 19, geometry.total_sectors)
    boot[21] = geometry.media_descriptor
    struct.pack_into("<H", boot, 22, geometry.sectors_per_fat)
    struct.pack_into("<H", boot, 24, geometry.sectors_per_track)
    struct.pack_into("<H", boot, 26, geometry.heads)
    boot[38] = 0x29
    boot[43:54] = b"REPERIO    "
    boot[54:62] = b"FAT12   "
    boot[510:512] = b"\x55\xaa"
    return bytes(boot)


def directory_entry(short: bytes, record: EntrySpec) -> bytes:
    raw = bytearray(32)
    raw[0:11] = short
    if record["deleted"]:
        raw[0] = 0xE5
    raw[11] = record["attributes"]
    struct.pack_into("<H", raw, 14, record["time_bits"])
    struct.pack_into("<H", raw, 16, record["date_bits"])
    struct.pack_into("<H", raw, 18, record["date_bits"])
    struct.pack_into("<H", raw, 22, record["time_bits"])
    struct.pack_into("<H", raw, 24, record["date_bits"])
    struct.pack_into("<H", raw, 26, record["first_cluster"])
    struct.pack_into("<I", raw, 28, record["size"])
    return bytes(raw)


def short_name(name: str) -> bytes:
    base, dot, extension = name.partition(".")
    return base[:8].upper().encode("ascii").ljust(8, b" ") + (
        extension[:3].upper().encode("ascii").ljust(3, b" ") if dot else b"   "
    )


def lfn_entries(name: str, checksum: int) -> list[bytes]:
    units = list(struct.unpack(f"<{len(name.encode('utf-16le')) // 2}H", name.encode("utf-16le")))
    chunks = [units[index : index + 13] for index in range(0, len(units), 13)]
    result: list[bytes] = []
    for sequence in range(len(chunks), 0, -1):
        chunk = chunks[sequence - 1]
        slots = [*chunk, 0, *([0xFFFF] * 13)][:13]
        raw = bytearray(32)
        raw[0] = sequence | (0x40 if sequence == len(chunks) else 0)
        raw[1:11] = b"".join(struct.pack("<H", slots[index]) for index in range(5))
        raw[11] = 0x0F
        raw[13] = checksum
        raw[14:26] = b"".join(struct.pack("<H", slots[index]) for index in range(5, 11))
        raw[28:32] = b"".join(struct.pack("<H", slots[index]) for index in range(11, 13))
        result.append(bytes(raw))
    return result


def lfn_checksum(short: bytes) -> int:
    checksum = 0
    for value in short:
        checksum = ((((checksum & 1) << 7) | (checksum >> 1)) + value) & 0xFF
    return checksum


def encode_fat(values: list[int]) -> bytes:
    output = bytearray()
    padded = values + ([0] if len(values) % 2 else [])
    for index in range(0, len(padded), 2):
        low, high = padded[index], padded[index + 1]
        output.extend((low & 0xFF, ((low >> 8) & 0x0F) | ((high & 0x0F) << 4), high >> 4))
    return bytes(output)


def fat_date(year: int, month: int, day: int) -> int:
    return ((year - 1980) << 9) | (month << 5) | day


def fat_time(hour: int, minute: int, second: int) -> int:
    return (hour << 11) | (minute << 5) | (second // 2)


def sectors_from_ranges(ranges: tuple[object, ...]) -> set[int]:
    sectors: set[int] = set()
    for carve_range in ranges:
        assert isinstance(carve_range, fat12_parser.CarveRange)
        start = carve_range.offset_bytes // 512
        count = carve_range.length_bytes // 512
        sectors.update(range(start, start + count))
    return sectors


def medium_record(geometry: fat12_parser.Fat12Geometry) -> dict[str, object]:
    signals = media_identity.normalize_medium_signals(
        {
            "size_bytes": geometry.size_bytes,
            "sampled_fingerprint_sha256": "a" * 64,
            "media_change_generation": 0,
            "geometry": {
                "cylinders": geometry.cylinders,
                "heads": geometry.heads,
                "sectors_per_track": geometry.sectors_per_track,
                "bytes_per_sector": geometry.bytes_per_sector,
            },
        }
    )
    return media_identity.medium_identity_record(
        "reader_1", signals, identity_strength="reader-plus-medium"
    )


if __name__ == "__main__":
    unittest.main()
