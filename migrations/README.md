# migrations — numbered schema migrations

Owner: forward migration runner, schema-version table, backup-before-upgrade
hook, and compatibility policy.

- **Source of truth:** `RPR-022`.
- **Status:** forward migration runner with the initial schema migration.
- `migrations.runner` owns `schema_migrations`, backup-before-upgrade behavior,
  transactional migration application, and worker readiness checks.
