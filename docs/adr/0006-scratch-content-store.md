# ADR 0006 — Scratch/content-addressed store separate from source

Status: accepted (RPR-003)
Date: 2026-08-10

## Context

Deep scanning extracts allocated, deleted, carved, and derived content. This
produces possibly hundreds of gigabytes of recovered bytes that must be
available for preview, classification, OCR, and export. "Bytes"
sometimes repeat, so storing duplicates wastes space, and provenance
must be preserved per source occurrence. The store must never hold the source
device's own bytes logically or physically.

The master plan fixes that scratch/export storage is separate from the source
medium and that recovered bytes may only go there (master plan §2, §3.1 item 7,
§6.3, §7).

## Decision

A **content-addressed scratch store** on storage proven physically separate
from the source (`RPR-015`):

- Objects are stored once and named by SHA-256; every source finding retains
  its own provenance and reference to the shared content object (`RPR-039`).
- Extracted bytes and carved output are written atomically with quotas,
  reference counts, and partial-file cleanup limited to proven-incomplete owned
  temporary files.
- Completed recovered objects are never automatically deleted; uninstall
  preserves Reperio state unless the operator separately removes it.
- All output to this store is validated never to share the source's physical
  backing device.
- The store is the only origin of copies handed to sandboxed workers
  (previews, OCR, AI, export).

## Alternatives considered

- **RAM-only operation**: rejected by master plan §2; cannot support exhaustive
  carving or reliable resume on large disks.
- **Writing derivatives to the source**: rejected absolutely; violates the
  no-write invariant and `RPR-039` same-disk refusal.
- **Raw directory copies with per-finding filenames**: rejected; loses
  deduplication, atomicity, quotas, and never-source validation.

## Consequences

- Deduplicated storage is shared across duplicate findings while provenance
  stays independent.
- The physical-separation resolver must run before any scan or export start
  and again when the store's ancestry could change.
- Disk-space accounting (quotas) is required so a compromised or runaway parser
  cannot exhaust the store.

## Reversal conditions

Reversed if the content store is replaced by a different storage model; the new
model must preserve never-source separation, deduplication, atomicity, quotas,
and completed-copy retention, and requires a new ADR plus tests.
