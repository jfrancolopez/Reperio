#!/usr/bin/env python3
"""Deterministic synthetic FAT12 fixture builder (RPR-008).

Builds a tiny, byte-exact 1.44 MB FAT12 image whose root directory contains
synthetic artifacts covering every planned recovery category: allocated,
deleted, hidden, Unicode, duplicate, malformed (truncated and broken-LFN),
encrypted-test, and browser-test. The image is generated entirely from fixed
constants; no timestamps, UUIDs, randomness, or real personal information
enters the output, so two builds are byte-identical (documented exclusion: if a
future fixture uses variable timestamps/UUIDs they are excluded from the pinned
hash contract in docs/FIXTURES.md).

Generated images are written by scripts only, never checked in.
"""

from __future__ import annotations

import hashlib
import struct

BYTES_PER_SECTOR = 512
SECTORS_PER_CLUSTER = 1
RESERVED_SECTORS = 1
NUMBER_OF_FATS = 2
ROOT_ENTRY_COUNT = 224
TOTAL_SECTORS = 2880
MEDIA_DESCRIPTOR = 0xF0
SECTORS_PER_FAT = 9
SECTORS_PER_TRACK = 18
NUMBER_OF_HEADS = 2
ROOT_DIR_SECTORS = (ROOT_ENTRY_COUNT * 32 + BYTES_PER_SECTOR - 1) // BYTES_PER_SECTOR
FIRST_DATA_SECTOR = RESERVED_SECTORS + NUMBER_OF_FATS * SECTORS_PER_FAT + ROOT_DIR_SECTORS
TOTAL_CLUSTERS = (TOTAL_SECTORS - FIRST_DATA_SECTOR) // SECTORS_PER_CLUSTER

VOLUME_LABEL = "REPERIO"
VOLUME_SERIAL = 0x12345678
GEOMETRY_LABEL = "1.44MB-FAT12-min"

FIXED_WRITE_TIME = 0x0000
FIXED_CREATE_TIME = 0x0000
FIXED_DATE = 0x0021

ATTR_READ_ONLY = 0x01
ATTR_HIDDEN = 0x02
ATTR_SYSTEM = 0x04
ATTR_VOLUME_LABEL = 0x08
ATTR_DIRECTORY = 0x10
ATTR_ARCHIVE = 0x20
ATTR_LFN = 0x0F

ATTRIBUTE_NAMES = {
    ATTR_READ_ONLY: "READ_ONLY",
    ATTR_HIDDEN: "HIDDEN",
    ATTR_SYSTEM: "SYSTEM",
    ATTR_VOLUME_LABEL: "VOLUME_LABEL",
    ATTR_DIRECTORY: "DIRECTORY",
    ATTR_ARCHIVE: "ARCHIVE",
}

CATEGORIES = (
    "allocated",
    "deleted",
    "hidden",
    "unicode",
    "duplicate",
    "malformed",
    "encrypted-test",
    "browser-test",
)


def _short_name(display: str) -> bytes:
    base, dot, ext = display.rpartition(".")
    base = (base or display)[:8]
    ext = ext[:3] if dot else ""
    return base.encode("latin-1").ljust(8, b" ") + ext.encode("latin-1").ljust(3, b" ")


def _lfn_checksum(short_entry: bytes) -> int:
    return sum(short_entry[0:11]) % 256


def catalog() -> list[dict]:
    """Returns artifact specifications in root-directory insertion order."""
    return [
        {
            "display": "hello.txt",
            "short": "HELLO~1.TXT",
            "category": "allocated",
            "content": b"Reperio synthetic fixture; allocated.\n",
            "attributes": ATTR_ARCHIVE,
        },
        {
            "display": "deleted.txt",
            "short": "DELETED1.TXT",
            "category": "deleted",
            "content": b"Reperio synthetic fixture; deleted.\n",
            "attributes": ATTR_ARCHIVE,
            "deleted": True,
        },
        {
            "display": "hidden.txt",
            "short": "HIDDEN~1.TXT",
            "category": "hidden",
            "content": b"Reperio synthetic fixture; hidden.\n",
            "attributes": ATTR_ARCHIVE | ATTR_HIDDEN,
        },
        {
            "display": "na\u00efve-\u6587\u4ef6.txt",
            "short": "NAIVE~1.TXT",
            "category": "unicode",
            "lfn": "na\u00efve-\u6587\u4ef6.txt",
            "content": b"Reperio synthetic fixture; unicode name.\n",
            "attributes": ATTR_ARCHIVE,
        },
        {
            "display": "copy_a.txt",
            "short": "COPY_A~1.TXT",
            "category": "duplicate",
            "content": b"Reperio synthetic fixture; duplicate.\n",
            "attributes": ATTR_ARCHIVE,
        },
        {
            "display": "copy_b.txt",
            "short": "COPY_B~1.TXT",
            "category": "duplicate",
            "content": b"Reperio synthetic fixture; duplicate.\n",
            "attributes": ATTR_ARCHIVE,
        },
        {
            "display": "corrupt_lfn.txt",
            "short": "CORRUPT1.TXT",
            "category": "malformed",
            "lfn": "corrupt_long_name.txt",
            "lfn_broken_checksum": True,
            "content": b"Reperio synthetic fixture; malformed lfn.\n",
            "attributes": ATTR_ARCHIVE,
        },
        {
            "display": "damaged.dat",
            "short": "DAMAGE~1.DAT",
            "category": "malformed",
            "declared_size": 4096,
            "content": b"Reperio synthetic fixture; truncated body.\n",
            "attributes": ATTR_ARCHIVE,
        },
        {
            "display": "vault.bin",
            "short": "VAULT~1.BIN",
            "category": "encrypted-test",
            "content": _encrypted_test_payload(),
            "attributes": ATTR_ARCHIVE,
        },
        {
            "display": "browser_history.dat",
            "short": "BROWSH~1.DAT",
            "category": "browser-test",
            "content": (
                b"reperio.example.invalid /demo-user\n"
                b"2020-01-01T00:00Z visit demo#home\n"
                b"(synthetic browser history fixture)\n"
            ),
            "attributes": ATTR_ARCHIVE,
        },
        {
            "display": "browser_cookies.dat",
            "short": "BROWSH~2.DAT",
            "category": "browser-test",
            "content": (
                b"reperio.example.invalid session demo-user\n"
                b"(synthetic browser cookie fixture; inert, never a live session)\n"
            ),
            "attributes": ATTR_ARCHIVE,
        },
        {
            "display": "browser_bookmarks.dat",
            "short": "BROWSH~3.DAT",
            "category": "browser-test",
            "content": b"reperio.example.invalid /demo-user/start\n(synthetic bookmark fixture)\n",
            "attributes": ATTR_ARCHIVE,
        },
    ]


def _encrypted_test_payload() -> bytes:
    header = b"REPER8-ENC-TEST"
    filler = hashlib.sha256(b"reperio-fixture-vault-seed").digest() * 16
    payload = header + filler
    return payload[:BYTES_PER_SECTOR]


def _lfn_entries(filename: str, checksum: int) -> list[bytes]:
    units = [ord(character) for character in filename]
    chunks: list[list[int]] = []
    for start in range(0, len(units), 13):
        chunks.append(units[start : start + 13])
    entries: list[bytes] = []
    total = len(chunks)
    for index, chunk in enumerate(reversed(chunks)):
        first = index == 0
        order = 0x40 | total if first else total - index
        slots = [0xFFFF] * 13
        length = len(chunk)
        positions = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12]
        chunk_positions = positions[:length]
        for slot, value in zip(chunk_positions, chunk):
            slots[slot] = value
        if first and length < 13:
            slots[chunk_positions[-1] + 1] = 0x0000
        payload = bytearray(b"\x00" * 32)
        payload[0] = order
        payload[1:11] = b"".join(struct.pack("<H", slots[i]) for i in (0, 1, 2, 3, 4))
        payload[11] = ATTR_LFN
        payload[12] = 0
        payload[13] = checksum
        payload[14:26] = b"".join(struct.pack("<H", slots[i]) for i in (5, 6, 7, 8, 9, 10))
        payload[26:28] = struct.pack("<H", 0)
        payload[28:32] = b"".join(struct.pack("<H", slots[i]) for i in (11, 12))
        entries.append(bytes(payload))
    return entries


def _short_entry(spec: dict, folder_first_cluster: int) -> bytes:
    entry = bytearray(b"\x00" * 32)
    short_name = _short_name(spec["short"])
    entry[0:11] = short_name
    entry[11] = spec.get("attributes", ATTR_ARCHIVE)
    entry[12] = 0
    entry[13] = 0
    entry[14:16] = struct.pack("<H", FIXED_CREATE_TIME)
    entry[16:18] = struct.pack("<H", FIXED_DATE)
    entry[18:20] = struct.pack("<H", FIXED_DATE)
    entry[20:22] = struct.pack("<H", (folder_first_cluster >> 16) & 0xFFFF)
    entry[22:24] = struct.pack("<H", FIXED_WRITE_TIME)
    entry[24:26] = struct.pack("<H", FIXED_DATE)
    size = spec.get("declared_size", len(spec["content"]))
    if spec.get("deleted"):
        entry[0] = 0xE5
        entry[26:28] = struct.pack("<H", 0)
        entry[28:32] = struct.pack("<I", size)
        return bytes(entry)
    entry[26:28] = struct.pack("<H", spec["first_cluster"] & 0xFFFF)
    entry[28:32] = struct.pack("<I", size)
    return bytes(entry)


def build_catalogue_bytes() -> tuple[bytes, list[dict]]:
    specs = catalog()
    next_cluster = 2
    for spec in specs:
        if not spec.get("deleted"):
            spec["first_cluster"] = next_cluster
            next_cluster += 1

    entries: list[bytes] = []
    lfn_checksums: dict[bytes, int] = {}
    for spec in specs:
        short_entry = _short_entry(spec, 0)
        lfn_checksums[_short_name(spec["short"])] = _lfn_checksum(short_entry)
    for spec in specs:
        if "lfn" in spec:
            checksum = lfn_checksums[_short_name(spec["short"])]
            if spec.get("lfn_broken_checksum"):
                checksum = (checksum + 1) % 256
            entries.extend(_lfn_entries(spec["lfn"], checksum))
        entries.append(_short_entry(spec, 0))

    volume_label = bytearray(b"\x00" * 32)
    volume_label[0:11] = VOLUME_LABEL.encode("ascii").ljust(11, b" ")
    volume_label[11] = ATTR_VOLUME_LABEL
    volume_label[23] = FIXED_WRITE_TIME & 0xFF
    volume_label[24] = (FIXED_WRITE_TIME >> 8) & 0xFF
    volume_label[25] = FIXED_DATE & 0xFF
    volume_label[26] = (FIXED_DATE >> 8) & 0xFF
    all_entries = [bytes(volume_label), *entries]
    root_bytes = b"".join(all_entries)
    terminator = b"\x00" * 32
    root_bytes += terminator
    root_dir = root_bytes.ljust(ROOT_DIR_SECTORS * BYTES_PER_SECTOR, b"\x00")

    fat_values = [0xFF0 | MEDIA_DESCRIPTOR, 0xFFF]
    for spec in specs:
        if spec.get("deleted"):
            continue
        fat_values.append(0xFFF)
    fat_values.extend([0] * (TOTAL_CLUSTERS - (len(fat_values) - 2)))
    fat_one = _encode_fat(fat_values).ljust(SECTORS_PER_FAT * BYTES_PER_SECTOR, b"\x00")
    fat_bytes = fat_one * NUMBER_OF_FATS

    data_sector_start = RESERVED_SECTORS + NUMBER_OF_FATS * SECTORS_PER_FAT + ROOT_DIR_SECTORS
    data_bytes = bytearray(b"\x00" * ((TOTAL_SECTORS - data_sector_start) * BYTES_PER_SECTOR))
    cluster_size = SECTORS_PER_CLUSTER * BYTES_PER_SECTOR
    for spec in specs:
        if spec.get("deleted"):
            continue
        offset = (spec["first_cluster"] - 2) * cluster_size
        content = spec["content"][:cluster_size]
        data_bytes[offset : offset + len(content)] = content

    boot = _boot_sector()
    image = boot + fat_bytes + root_dir + bytes(data_bytes)
    return image, specs


def _encode_fat(values: list[int]) -> bytes:
    out = bytearray()
    padded = values + [0] if len(values) % 2 else values
    for index in range(0, len(padded), 2):
        low = padded[index]
        high = padded[index + 1]
        out += bytes([low & 0xFF, ((low >> 8) & 0x0F) | ((high & 0x0F) << 4), (high >> 4) & 0xFF])
    return bytes(out)


def _boot_sector() -> bytes:
    boot = bytearray(b"\x00" * BYTES_PER_SECTOR)
    boot[0:3] = b"\xeb\x3c\x90"
    boot[3:11] = b"REPERIO "
    boot[11:13] = struct.pack("<H", BYTES_PER_SECTOR)
    boot[13] = SECTORS_PER_CLUSTER
    boot[14:16] = struct.pack("<H", RESERVED_SECTORS)
    boot[16] = NUMBER_OF_FATS
    boot[17:19] = struct.pack("<H", ROOT_ENTRY_COUNT)
    boot[19:21] = struct.pack("<H", TOTAL_SECTORS)
    boot[21] = MEDIA_DESCRIPTOR
    boot[22:24] = struct.pack("<H", SECTORS_PER_FAT)
    boot[24:26] = struct.pack("<H", SECTORS_PER_TRACK)
    boot[26:28] = struct.pack("<H", NUMBER_OF_HEADS)
    boot[28:32] = struct.pack("<I", 0)
    boot[32:36] = struct.pack("<I", 0)
    boot[36] = 0
    boot[37] = 0
    boot[38:40] = struct.pack("<H", 0)
    boot[40] = 0x29
    boot[41:45] = struct.pack("<I", VOLUME_SERIAL)
    boot[45:56] = VOLUME_LABEL.encode("ascii").ljust(11, b" ")
    boot[56:64] = b"FAT12   "
    boot[510:512] = b"\x55\xaa"
    return bytes(boot)


def build_image() -> tuple[bytes, list[dict]]:
    image, specs = build_catalogue_bytes()
    return image, specs


def image_sha256(image: bytes) -> str:
    return hashlib.sha256(image).hexdigest()


def cluster_data_sector(cluster: int) -> int:
    return FIRST_DATA_SECTOR + (cluster - 2) * SECTORS_PER_CLUSTER


def cluster_offset(cluster: int) -> int:
    return cluster_data_sector(cluster) * BYTES_PER_SECTOR


if __name__ == "__main__":
    import sys
    from pathlib import Path

    if len(sys.argv) != 2:
        raise SystemExit(f"usage: {sys.argv[0]} OUTPUT_IMAGE_PATH")
    image, _ = build_image()
    Path(sys.argv[1]).write_bytes(image)
    print(f"wrote {len(image)} bytes sha256={image_sha256(image)}")
