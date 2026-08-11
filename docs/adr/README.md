# Architecture Decision Records

This directory records accepted Reperio architecture decisions. Every ADR
states its context, decision, alternatives considered, consequences, and
reversal conditions. Diagrams in ADRs must agree with the master plan and the
threat model.

| ADR | Decision | Status |
|---|---|---|
| [0001 — Project license](0001-project-license.md) | Apache-2.0 project license with a machine-checkable dependency-license gate | accepted (RPR-001) |
| [0002 — Linux host controller](0002-linux-host-control.md) | Narrow privileged `hostd` is the only source-touching component | accepted (RPR-003) |
| [0003 — No source mounts](0003-no-source-mounts.md) | Core workflow never mounts the source; parsers run against the device | accepted (RPR-003) |
| [0004 — SQLite durable jobs](0004-sqlite-durable-jobs.md) | SQLite WAL catalog with migrations, durable jobs, checkpoints, and event outbox | accepted (RPR-003) |
| [0005 — One source per instance](0005-single-source-per-instance.md) | One active source medium per instance; sequential cases in one catalog | accepted (RPR-003) |
| [0006 — Scratch content store](0006-scratch-content-store.md) | Content-addressed scratch store proven physically separate from the source | accepted (RPR-003) |
| [0007 — Tool sandboxes](0007-tool-sandboxes.md) | Version-pinned sandboxed execution for all third-party tools and parsers | accepted (RPR-003) |
| [0008 — Optional AI](0008-optional-ai.md) | Deterministic fallback; AI optional, provider-agnostic, privacy-gated | accepted (RPR-003) |

ADRs are added by planning tasks such as `RPR-003` and by explicit
architecture-change decisions; every new ADR must pass a documentation-link
check.
