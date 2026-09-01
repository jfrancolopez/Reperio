# Synthetic fixture framework (RPR-008)

## Purpose

The fixture framework produces a tiny, fully deterministic FAT12 disk image
that exercises every artifact category the recovery pipeline must find without
requiring real media or personal data:

| Category | Artifact | Reader result |
| --- | --- | --- |
| allocated | `hello.txt` (`HELLO~1.TXT`) | `allocated`, content hash pinned |
| deleted | `deleted.txt` (`?ELETED1.TXT`) | `deleted` (first name byte `0xE5`) |
| hidden | `hidden.txt` (`HIDDEN~1.TXT`) | `HIDDEN` + `ARCHIVE` attributes |
| unicode | `naïve-文件.txt` (`NAIVE~1.TXT`) | long filename decoded via UTF-16LE LFN entries |
| duplicate | `copy_a.txt` / `copy_b.txt` | identical content and sha256 across two names |
| malformed | `corrupt_lfn.txt` (`CORRUPT1.TXT`) | `lfn-checksum-mismatch` (deliberate checksum break) |
| malformed | `damaged.dat` (`DAMAGE~1.DAT`) | `truncated` (declared 4096 B, one 512 B cluster present) |
| encrypted-test | `vault.bin` (`VAULT~1.BIN`) | `allocated`; header `REPER8-ENC-TEST` plus inert sha256 filler |
| browser-test | `browser_history/cookies/bookmarks` | `allocated`, synthetic non-PII payloads |

No artifact contains real personal information or a live password. The
encrypted-test fixture uses a documented inert marker string and a hash-derived
filler only.

## Determinism contract

- Image geometry is fixed: 1.44 MB (1,474,560 bytes), 512-byte sectors, one
  sector per cluster, one reserved sector, two FATs, 224 root entries, 9
  sectors per FAT, media descriptor `0xF0`.
- Volume label `REPERIO`, serial `0x12345678`.
- All timestamps are fixed values (write time `0x0000`, date `0x0021`); there
  are **no** variable timestamps, no UUIDs, no randomness, and no build-order
  dependence, so rebuilding the image is byte-for-byte reproducible.
- The one documented exclusion style from earlier plans (real-world
  timestamps/UUIDs) is deliberately not present in this fixture; every byte is
  pinned. If a future fixture needs time-variant content it must be derived
  deterministically from the fixture inputs.

## Files

- `scripts/fixture_builder.py` — dependency-free pure-Python FAT12 image
  builder. Emits the image in memory (`build_image()`); the CLI writes it to a
  path for local inspection only.
- `scripts/fixture_reader.py` — read-only FAT12 parser. Parses boot sector,
  12-bit FAT, root directory (LFN decode, deleted, hidden, truncation), walks
  cluster chains, and reports per-file sha256 and state.
- `scripts/fixtures_check.py` — the gate orchestrator. Rebuilds the image twice
  and proves byte-identity, derives the reader findings, attaches categories,
  and compares against the pinned manifest. `--emit` regenerates the manifest
  after a reviewed builder/schema change and must not be used to paper over
  drift.
- `fixtures/expected/fixture-manifest.json` — the committed, hash-pinned
  expected results (image hash, size, per-finding name/state/sha256/cluster
  chain, category coverage). Versioned against
  `scripts/schemas/fixture-manifest.schema.json` (v1) by the schema
  compatibility gate.
- `scripts/tests/test_fixtures.py` — determinism, manifest-match, category
  coverage, and malformed-state tests.

## Safety properties

- Images are held in memory; the builder/reader never touch a real block
  device or mount a filesystem.
- The reader is dependency-free and parses the byte buffer read-only.
- Fixture hashes and names are inert; the encrypted-test marker is not a
  credential.

## FAT12 recovery acceptance (RPR-182)

The scanner's dedicated read-only FAT12 adapter recognizes only exact DOS BPB
matches for these initial floppy geometries:

| Conventional capacity | Bytes | Tracks/heads/sectors | Cluster size |
| --- | ---: | --- | ---: |
| 360 KiB | 368,640 | 40/2/9 | 1,024 bytes |
| 720 KiB | 737,280 | 80/2/9 | 1,024 bytes |
| 1.2 MB | 1,228,800 | 80/2/15 | 512 bytes |
| 1.44 MB | 1,474,560 | 80/2/18 | 512 bytes |

Capacity alone is never treated as geometry. A mismatched BPB, missing DOS/FAT12
signature, or unsupported capacity is refused rather than guessed. The adapter
compares both FAT copies, preserves valid short/long names and timestamps, labels
fragmented or partial allocated chains, and treats deleted multi-cluster chains
as contiguous candidates with explicit fragmentation uncertainty. Reused
deleted clusters are not exposed as recoverable extents.

Known or observed unreadable sectors remain visible as read gaps and split the
free-cluster ranges supplied to the existing PhotoRec adapter. The FAT12 module
accepts only a read-range interface; it exposes no source path opener, mount,
write, format, repair, or boot-sector rebuild operation. Generated geometry,
deleted/reused/fragmented, FAT-copy corruption, bad-sector, media-resume, and
pre/post source-hash tests live in `tests/test_fat12_recovery.py`.

## Commands

- `make fixture-check` (also part of `make quality`) — deterministic rebuild +
  manifest compare + coverage.
- `python3 scripts/fixtures_check.py --emit` — regenerate the pinned manifest
  after a reviewed change.
- `python3 scripts/fixture_builder.py OUT.img` and
  `python3 scripts/fixture_reader.py OUT.img` — local inspection loop.
