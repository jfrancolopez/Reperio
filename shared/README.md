# shared — shared schemas and helpers

Owner: cross-package contracts, versioned schemas, and placeholder helpers.

- **Source of truth:** `RPR-021`–`RPR-025`, later schema tasks.
- **Status:** placeholder health entry point (`RPR-004`) plus the initial SQLite
  catalog schema contract (`RPR-021`).
- Contains `shared.placeholder` used by every package's health entry point so
  package entry points stay consistent and free of feature logic.
- Contains `shared.catalog_schema`, the first normalized SQLite catalog schema;
  migrations and schema-version tracking start in `RPR-022`.
- Contains `shared.job_state`, the durable job state machine plus leases,
  retries, and idempotency for `RPR-023`–`RPR-024`.
- Contains `shared.checkpoints`, versioned checkpoint storage for `RPR-025`.
