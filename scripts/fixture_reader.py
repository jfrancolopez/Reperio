#!/usr/bin/env python3
"""Read-only synthetic fixture reader (RPR-008).

Parses a FAT12 fixture image produced by fixture_builder without executing or
writing anything: boot sector, FAT12 chains, and root directory entries
(including LFN decoding, hidden attributes, deleted markers, and truncation).
Used to derive machine-readable expected results for the hash-pinned manifest.
"""

from __future__ import annotations

import hashlib
import struct

from fixture_builder import (
    ATTR_DIRECTORY,
    ATTR_LFN,
    ATTR_VOLUME_LABEL,
    ATTRIBUTE_NAMES,
)


def parse_boot(image: bytes) -> dict:
    bytes_per_sector = struct.unpack_from("<H", image, 11)[0]
    return {
        "bytes_per_sector": bytes_per_sector,
        "sectors_per_cluster": image[13],
        "reserved_sectors": struct.unpack_from("<H", image, 14)[0],
        "num_fats": image[16],
        "root_entries": struct.unpack_from("<H", image, 17)[0],
        "total_sectors": struct.unpack_from("<H", image, 19)[0],
        "media": image[21],
        "sectors_per_fat": struct.unpack_from("<H", image, 22)[0],
        "volume_serial": struct.unpack_from("<I", image, 41)[0],
        "volume_label": image[45:56].decode("ascii", errors="replace").rstrip(),
    }


def read_fat(image: bytes, boot: dict) -> list[int]:
    fat_start = boot["reserved_sectors"] * boot["bytes_per_sector"]
    fat_size = boot["sectors_per_fat"] * boot["bytes_per_sector"]
    raw = image[fat_start : fat_start + fat_size]
    values: list[int] = []
    count = len(raw) * 2 // 3
    for index in range(count):
        offset = (index * 3) // 2
        word = int.from_bytes(raw[offset : offset + 2], "little")
        values.append(word & 0x0FFF if index % 2 == 0 else word >> 4)
    return values


def read_directory(image: bytes, boot: dict) -> list[dict]:
    bytes_per_sector = boot["bytes_per_sector"]
    root_start = (
        boot["reserved_sectors"] + boot["num_fats"] * boot["sectors_per_fat"]
    ) * bytes_per_sector
    root_region = image[root_start : root_start + boot["root_entries"] * 32]
    data_start = root_start + boot["root_entries"] * 32

    fat_values = read_fat(image, boot)
    findings: list[dict] = []
    pending_lfn: list[tuple[int, list[int]]] = []

    def decode_short(entry: bytes) -> str:
        raw = entry[0:8].rstrip(b" ").decode("latin-1") or "?"
        ext = entry[8:11].rstrip(b" ").decode("latin-1")
        return f"{raw}.{ext}" if ext else raw

    def chain_clusters(first: int) -> list[int]:
        chain: list[int] = []
        seen: set[int] = set()
        cursor = first
        while cursor not in (0, 0xFFF) and cursor not in seen and cursor < len(fat_values):
            chain.append(cursor)
            seen.add(cursor)
            next_cursor = fat_values[cursor]
            if next_cursor in (0, 0xFFF):
                break
            cursor = next_cursor
        return chain

    def read_content(chain: list[int], limit: int) -> tuple[int, bytes]:
        collected = bytearray()
        for cluster in chain:
            offset = data_start + (cluster - 2) * bytes_per_sector
            collected += image[offset : offset + bytes_per_sector]
        raw = bytes(collected)
        content = raw[:limit]
        return len(content), content

    for index in range(boot["root_entries"]):
        offset = index * 32
        entry = root_region[offset : offset + 32]
        if entry[0] == 0x00:
            break
        attr = entry[11]
        if attr == 0x0F or attr == ATTR_LFN:
            raw_units = entry[1:11] + entry[14:26] + entry[28:32]
            units = [
                struct.unpack_from("<H", raw_units, offset)[0]
                for offset in range(0, len(raw_units), 2)
            ]
            pending_lfn.append((entry[13], units))
            continue

        checksum = sum(entry[0:11]) % 256
        lfn_units: list[int] = []
        lfn_checksum_ok = True
        saw_lfn = bool(pending_lfn)
        if pending_lfn:
            for stored_checksum, units in pending_lfn:
                if stored_checksum == checksum:
                    lfn_units.extend(units)
                else:
                    lfn_checksum_ok = False
            pending_lfn = []

        attributes = [name for bit, name in sorted(ATTRIBUTE_NAMES.items()) if attr & bit]
        short_name = decode_short(entry)
        size = struct.unpack_from("<I", entry, 28)[0]
        first_cluster = struct.unpack_from("<H", entry, 26)[0] + (
            struct.unpack_from("<H", entry, 20)[0] << 16
        )

        if entry[0] == 0xE5:
            deleted_short = "?" + decode_short(entry)[1:]
            findings.append(
                {
                    "name": deleted_short,
                    "short_name": deleted_short,
                    "state": "deleted",
                    "attributes": attributes,
                    "size": size,
                    "read_bytes": None,
                    "sha256": None,
                    "first_cluster": None,
                    "cluster_chain": None,
                }
            )
            continue

        if attr & ATTR_VOLUME_LABEL or attr & ATTR_DIRECTORY:
            continue

        if lfn_units and lfn_checksum_ok:
            display_name = "".join(chr(unit) for unit in lfn_units if unit not in (0x0000, 0xFFFF))
        else:
            display_name = short_name

        chain = chain_clusters(first_cluster)
        read_bytes, content = read_content(chain, size)
        state = "allocated"
        if saw_lfn and not lfn_checksum_ok:
            state = "lfn-checksum-mismatch"
        elif read_bytes < size:
            state = "truncated"

        findings.append(
            {
                "name": display_name,
                "short_name": short_name,
                "state": state,
                "attributes": attributes,
                "size": size,
                "read_bytes": read_bytes,
                "sha256": hashlib.sha256(content).hexdigest() if content else None,
                "first_cluster": first_cluster,
                "cluster_chain": chain or None,
            }
        )

    return findings


def read_image(image: bytes) -> dict:
    boot = parse_boot(image)
    return {
        "boot": boot,
        "findings": read_directory(image, boot),
    }


if __name__ == "__main__":
    import sys
    from pathlib import Path

    if len(sys.argv) != 2:
        raise SystemExit(f"usage: {sys.argv[0]} IMAGE_PATH")
    result = read_image(Path(sys.argv[1]).read_bytes())
    for finding in result["findings"]:
        print(
            f"{finding['name']!r} state={finding['state']} "
            f"attrs={','.join(finding['attributes']) or '-'} "
            f"size={finding['size']} read={finding['read_bytes']} "
            f"sha256={finding['sha256']}"
        )
