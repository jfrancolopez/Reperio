# ADR 0004 — SQLite durable jobs and state

Status: accepted (RPR-003)
Date: 2026-08-10

## Context

Reperio is a single-operator, single-source application whose core promise is
progressive, resumable deep scanning over long periods. It needs durable,
transactable state for the catalog, findings, review state, jobs/leases,
checkpoints, events, and configuration. It does not need a distributed
database, message broker, or job scheduler.

## Decision

SQLite in WAL mode is the control-plane store (master plan §6.2):

- Numbered forward migrations from the first schema with a schema-version table
  and backup-before-upgrade hook (`RPR-022`).
- Durable jobs claimed by one worker at a time via atomic leasing, heartbeats,
  capped exponential retries, and idempotency keys (`RPR-023–024`).
- Versioned checkpoints stored in the same catalog (`RPR-025`).
- A transactional event outbox feeds SSE and notification adapters (`RPR-026`).
- Foreign keys on, WAL configured, canonical timestamps/enums, paths stored as
  data rather than identifiers (`RPR-021`).

Long-running work is represented as durable database jobs rather than in-memory
tasks or an external queue.

## Alternatives considered

- **PostgreSQL/Redis/Celery/Kubernetes**: rejected by master plan §6.2 as
  unjustified for one operator and one scanner; they add operational burden and
  network attack surface.
- **Custom binary state files**: rejected; they lack transactions, WAL crash
  safety, migrations, and queryability.
- **In-memory state with periodic save**: rejected because it cannot survive
  host crashes or provide resumability, which is a core product promise.

## Consequences

- One writer at a time per database file; concurrent readers are fine in WAL.
- Optional future scaling must preserve the durable-job contract; the
  decision does not prevent replacing SQLite behind the same contracts later.
- Database files are runtime state and are excluded from Git
  (`.gitignore`, repository validator).

## Reversal conditions

Reversed if the architecture adopts multi-node operation or needs a scale
that SQLite cannot meet; the job and event contracts must remain unchanged, and
a migration ADR plus compatibility tests are required.
