# ADR 0005 — One source medium per instance

Status: accepted (RPR-003)
Date: 2026-08-10

## Context

Reperio scans one physical source medium per instance. A source may be a disk,
SSD, flash drive, memory card, optical disc, floppy, or validated legacy
adapter. One reader containing one inserted medium counts as one source. The
product requires an operator to confirm exact identity before scanning and to
treat a replaced disc/card/floppy in the same reader as a new source, never a
silent resume (master plan §2, §9.2).

## Decision

Exactly **one active source medium per Reperio instance** is supported:

- One active source is enforced by the control plane (`RPR-028`); a second
  simultaneous source requires a second isolated instance.
- Sequential one-at-a-time media cases remain available in the same catalog.
- Source identity binds checkpoints to the full medium identity (device facts,
  geometry, TOC/session facts, sampled fingerprint, media-change generation),
  not to the reader path (`RPR-178`, `RPR-180`).
- Replacing media never resumes or starts automatically; a different medium in
  the same reader requires a fresh selection and case.

## Alternatives considered

- **Multiple concurrent sources per instance**: rejected by the confirmed
  product decision (master plan §2) and by complexity in identity, checkpoint,
  read-only verification, and I/O scheduling. Sequential cases with a "finish
  this medium, insert the next" workflow (`RPR-187`) preserve operator
  convenience.
- **Resume by reader path alone**: rejected as unsafe; a swapped same-capacity
  medium must not inherit a prior case's checkpoint.

## Consequences

- Case, checkpoint, and audit records must track medium identity and
  change-generation explicitly.
- Multi-device RAID scanning (`RPR-142`, `RPR-175`) is a planned exception that
  requires a redesigned source/case schema and its own ADR when approved.

## Reversal conditions

Reversed if multi-source or multi-member RAID scanning is approved; a new ADR
is required, plus schema migration, identity/checkpoint redesign, and updates
to the threat model and UI source selectors.
