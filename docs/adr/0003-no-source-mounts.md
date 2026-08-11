# ADR 0003 — No source mounts in the core workflow

Status: accepted (RPR-003)
Date: 2026-08-10

## Context

Reperio must never write to a selected source medium. Mounting a filesystem,
even read-only, exposes a large kernel-surface to hostile source metadata, can
interact with journal replay and automounts, and risks re-mounting read-write.
Filesystem analysis is more predictable and auditable when done by parsers
against the raw device byte stream.

## Decision

The core scanning workflow **never mounts** the source filesystem. Filesystem,
partition, optical-session, and floppy analysis is performed by read-only
parsers against the device (`The Sleuth Kit` initially, plus dedicated optical
and legacy adapters, master plan §7 Stage C). The scanner opens the device
`O_RDONLY` only. The control plane, workers, AI, and export code never receive
a device handle.

Exceptions are prohibited without a new ADR and an automated proof that the
mount cannot write. There are no planned exceptions for the core workflow.

## Alternatives considered

- **Read-only mounts** (loop/block mount with `ro`): rejected because it
  enlarges the trusted kernel surface, can trigger journal replay behavior on
  some filesystems, and complicates the no-write proof. Parsers such as TSK
  already provide the needed normalization without mounting.
- **Full forensic imaging**: rejected by master plan §2 (direct scan; no
  forensic image). Imaging also writes large files that stress failing media.

## Consequences

- Filesystem coverage depends on the quality and maintenance of the parser
  adapters (TSK and complements), which must be pinned and fixture-tested per
  format before claims are made.
- Deleted-entry and metadata recovery require filesystem-aware parsers rather
  than mount-based tools.
- The no-mount property is provable by the `RPR-020`/`RPR-153` suites and by
  container profiles that deny mount capability entirely.

## Reversal conditions

Reversed if a validated exception (for example, a read-only decrypted-view
adapter in `RPR-133`/`RPR-166`) is approved with an ADR and an automated
no-write proof. Any approved mount remains read-only, network-less,
capability-less, and inside the scanner sandbox.
