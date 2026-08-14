# Reperio implementation backlog

Status: master backlog
Companion specification: `docs/MASTER_PLAN.md`
Task size target: approximately 0.5–2 focused engineering days for a capable agent, excluding external review

## How to execute this backlog

- Work in dependency and milestone order. Task IDs are permanent references, not an exact schedule; later planning additions may have higher IDs while belonging to an earlier milestone.
- Run exactly one active implementation task with one implementation agent at a time. Do not assign independent tasks in parallel or create parallel agent worktrees unless the owner explicitly changes this operating decision.
- Finish, validate, review, and record the current task before starting the next. An agent must not absorb neighboring tasks without being assigned them.
- Task packets, repository commands, fixtures, and completion evidence must be vendor/model agnostic. The checked-in repository must contain all required context; do not depend on a particular agent product, private memory, or proprietary-only capability.
- Before editing, the agent reads `AGENTS.md`, the assigned task, its dependencies, and the relevant master-plan section.
- If an acceptance criterion is ambiguous, write or update a contract/ADR before implementation. Do not silently choose behavior that weakens read-only safety.
- Every public JSON object, database change, tool wrapper, and command output has a versioned schema or fixture.
- A tool being installed is not completion. A fixture must prove normalized output and the failure path.
- Tasks marked `P0` block safe scanning. `P1` forms the first useful product. `P2` adds the requested deep feature set. `P3` expands platforms and convenience. These labels schedule engineering dependencies and risk; they do not assign lower value to any recovered-content category.

## Definition of done for every task

1. The scoped implementation and documentation are complete.
2. Acceptance criteria have automated tests unless explicitly identified as a manual release check.
3. Tests include at least one failure, malformed-input, or interruption case where relevant.
4. No secret, real user data, or source-disk write path was added.
5. Linting, type checks, focused tests, and affected integration tests pass.
6. New dependencies are pinned and record source, license, architecture availability, and security boundary.
7. The completion report uses the format in `AGENTS.md` and lists follow-up IDs instead of adding scope.

## Milestones

| Milestone | Outcome | Primary IDs |
|---|---|---|
| M0 Safety/contracts | Repository, contracts, fixtures, demonstrated no-write boundary, and removable-media identity | RPR-001–020, RPR-178–180 |
| M1 Allocated Windows/removable MVP | NTFS/FAT/exFAT disk and flash inventory, catalog, wallet/vault/key location, live review, local export | RPR-021–054, RPR-058, RPR-105–108, RPR-116–121, RPR-127–130, RPR-181, RPR-187 |
| M2 Deep Windows/removable media | Deleted entries, trash, carving/resume, browser history, optical/floppy recovery, previews/OCR, notifications | RPR-042–082, RPR-109–115, RPR-122–132, RPR-160–165, RPR-169–174, RPR-182–188 |
| M3 Intelligence/protected files | Multi-model enrichment, semantic search, password workflows | RPR-083–104, RPR-157–159 |
| M4 macOS/Linux/mobile/legacy | Additional filesystems, platform artifacts, complex storage, and legacy media adapters | RPR-133–144, RPR-166–168, RPR-175–177, RPR-189–191 |
| M5 Release | Signed multi-architecture install, fault testing, docs, acceptance | RPR-145–156 |

---

## Epic A — foundation and contracts

### RPR-001 — Select the Reperio project license `[P0, M0]`

- **Status:** complete
- **Depends:** none.
- **Deliver:** an ADR selecting the project license; a dependency-intake checklist covering reciprocal licenses, separate-process use, image redistribution, notices, and source-offer obligations.
- **Acceptance:** root license file exists; README no longer says undecided; CI can reject dependencies missing license metadata.
- **Tests:** run the metadata checker against one allowed and one intentionally rejected fixture dependency.

### RPR-002 — Write the source-write threat model `[P0, M0]`

- **Status:** complete
- **Depends:** none.
- **Deliver:** assets, trust boundaries, attacker/failure scenarios, explicit prohibited operations, and mitigations spanning host, kernel, container, process, API, UI, tools, AI, scratch, and exports.
- **Acceptance:** every invariant in master-plan section 3 maps to at least one preventive control and one verification; residual risks are named.
- **Tests:** document the concrete negative tests later implemented by RPR-020 and RPR-153.

### RPR-003 — Record core architecture ADRs `[P0, M0]`

- **Status:** complete
- **Depends:** RPR-002.
- **Deliver:** ADRs for Linux-first host control, no source mounts, SQLite durable jobs, single source per instance, scratch/content store, tool sandboxes, and optional AI.
- **Acceptance:** each ADR includes context, decision, alternatives, consequences, and reversal conditions; diagrams agree with the master plan.
- **Tests:** documentation-link checker confirms all referenced ADRs exist.

### RPR-004 — Scaffold the monorepo `[P0, M0]`

- **Status:** complete
- **Depends:** RPR-003.
- **Deliver:** top-level packages for `hostd`, `api`, `scanner`, `worker`, `web`, shared schemas, migrations, tests, fixtures, packaging, and docs; no feature implementation.
- **Acceptance:** each package has a minimal entry point and ownership README; one command reports all package versions.
- **Tests:** clean checkout installs developer dependencies and starts placeholder health processes without privileged device access.

### RPR-005 — Establish developer quality commands `[P0, M0]`

- **Status:** complete
- **Depends:** RPR-004.
- **Deliver:** pinned formatting, lint, type-check, unit-test, frontend-test, schema-check, and docs-check commands with a single aggregate target.
- **Acceptance:** commands work on Linux `amd64`; no command rewrites user files except the explicit formatter.
- **Tests:** CI runs each command independently and the aggregate target.

### RPR-006 — Create continuous integration baseline `[P0, M0]`

- **Status:** complete
- **Depends:** RPR-005.
- **Deliver:** unprivileged pull-request CI for backend/frontend tests, schema compatibility, dependency license metadata, secret scanning, and container build smoke tests.
- **Acceptance:** least-privilege CI has no production credentials, raw devices, or privileged containers; artifacts have retention limits.
- **Tests:** a deliberately broken schema compatibility fixture demonstrates the gate fails.

### RPR-007 — Define configuration and capability schemas `[P0, M0]`

- **Status:** complete
- **Depends:** RPR-004.
- **Deliver:** versioned schemas for application settings, scan policy, capabilities, tool availability, resource limits, network exposure, and feature flags; environment overrides are documented.
- **Acceptance:** unknown keys and invalid combinations produce actionable errors; secrets are references rather than inline values.
- **Tests:** round-trip defaults plus invalid source/destination, auth, provider, and resource cases.

### RPR-008 — Build the synthetic fixture framework `[P0, M0]`

- **Status:** complete
- **Depends:** RPR-004, RPR-005.
- **Deliver:** reproducible scripts/manifests for tiny safe disk/filesystem fixtures containing allocated, deleted, hidden, Unicode, duplicate, malformed, encrypted-test, and browser-test artifacts.
- **Acceptance:** fixtures contain no real personal information or live passwords; expected results are machine-readable and hash-pinned.
- **Tests:** rebuild twice and compare expected deterministic hashes, with documented exclusions for filesystem timestamps/UUIDs.

---

## Epic B — Linux host controller and no-write boundary

### RPR-009 — Define the host-controller protocol `[P0, M0]`

- **Status:** complete
- **Depends:** RPR-002, RPR-003, RPR-007.
- **Deliver:** authenticated/versioned Unix-socket request and response schemas for device listing, safety inspection, read-only preparation, scanner launch/status/stop, and reconnect.
- **Acceptance:** no generic command execution, path passthrough, mount, write, repair, or arbitrary container arguments exist in the protocol.
- **Tests:** contract tests reject unknown methods, path traversal, stale device IDs, extra launch flags, and incompatible versions.

### RPR-010 — Enumerate Linux block devices `[P0, M0]`

- **Status:** complete
- **Depends:** RPR-009.
- **Deliver:** host implementation using udev/sysfs/`lsblk`-equivalent data to list whole disks and child partitions with sanitized facts.
- **Acceptance:** loop, USB, SATA, NVMe, SD/card readers, optical, floppy, device-mapper, and partition relationships are represented; empty readers and transient/media-change events do not crash listing.
- **Tests:** mocked sysfs fixtures plus privileged CI loop-device coverage.

### RPR-011 — Implement stable device identity `[P0, M0]`

- **Status:** complete
- **Depends:** RPR-010.
- **Deliver:** resolution through `/dev/disk/by-id` plus model, serial/WWN where available, size, logical/physical sector sizes, transport, and parent topology.
- **Acceptance:** scan APIs use opaque stable IDs, not mutable `/dev/sdX` names; missing serial uses a documented weaker identity and warning.
- **Tests:** reorder simulated device names and prove the same stable ID resolves correctly; collision cases are rejected.

### RPR-012 — Add sampled source fingerprinting `[P0, M0]`

- **Status:** complete
- **Depends:** RPR-011, RPR-008.
- **Deliver:** deterministic sampled-sector fingerprint definition and implementation that reads only non-secret bounded ranges alongside immutable device facts.
- **Acceptance:** fingerprints detect a same-size replacement fixture; sampling does not scan the full disk or log sampled bytes.
- **Tests:** matching, one-sector-changed, truncated, unreadable-sample, and sector-size-change fixtures.

### RPR-013 — Deny active system disks by default `[P0, M0]`

- **Status:** complete
- **Depends:** RPR-010, RPR-011.
- **Deliver:** detection of disks backing `/`, `/boot`, Reperio state, container storage, swap, and active critical mounts.
- **Acceptance:** default launch refuses those disks and lists reasons; override is a separate explicit policy with tests and a persistent warning.
- **Tests:** device-tree fixtures for direct partition, LVM, mdraid, bind mount, and container-storage ancestry.

### RPR-014 — Report mounts, holders, and stacked storage `[P0, M0]`

- **Status:** complete
- **Depends:** RPR-010.
- **Deliver:** read-only inspection of mount modes, open holders, LVM/device-mapper, mdraid, and child relationships.
- **Acceptance:** preparation cannot claim safe status while a source child is mounted read-write or has an unsupported holder.
- **Tests:** loop devices mounted RO/RW, nested device-mapper fixture, and disappearing mount race.

### RPR-015 — Prove scratch/destination physical separation `[P0, M0]`

- **Status:** complete
- **Depends:** RPR-013, RPR-014.
- **Deliver:** resolver that maps any local state/scratch/export path to backing physical disks and compares them to source ancestry.
- **Acceptance:** scan/export start refuses same-disk destinations, including a different partition, LVM logical volume, bind mount, or symlinked path.
- **Tests:** same filesystem, sibling partition, LVM, mdraid, network filesystem, unmounted/nonexistent destination, and symlink fixtures.

### RPR-016 — Enforce and verify kernel read-only state `[P0, M0]`

- **Status:** complete
- **Depends:** RPR-011, RPR-014.
- **Deliver:** host operation equivalent to `BLKROSET`, followed by independent verification for the whole disk and discovered children.
- **Acceptance:** launch stops if read-only cannot be set or verified; audit records facts without source bytes.
- **Tests:** privileged loop-device test verifies writes fail after preparation and normal writes resume only after test teardown outside Reperio.

### RPR-017 — Add read-only disk-health inspection `[P1, M1]`

- **Status:** complete
- **Depends:** RPR-010.
- **Deliver:** sandboxed `smartctl` adapter that parses JSON where supported and normalizes health, temperature, reallocated/pending/uncorrectable sectors, NVMe warnings, and bridge limitations.
- **Acceptance:** health failure warns and can require acknowledgment but never starts a SMART self-test or writes device settings.
- **Tests:** ATA, NVMe, USB-no-SMART, malformed JSON, timeout, and missing-tool fixtures.

### RPR-018 — Create append-only host safety audit `[P0, M0]`

- **Status:** complete
- **Depends:** RPR-009, RPR-016.
- **Deliver:** local append-only records for device resolution, system-disk decision, mount/holder checks, destination separation, read-only verification, and exact scanner sandbox profile.
- **Acceptance:** log rotation preserves ordering; values are redacted and cannot include credentials or sampled bytes.
- **Tests:** tampered/truncated log detection and concurrent event ordering.

### RPR-019 — Launch the fixed scanner sandbox `[P0, M0]`

- **Status:** complete
- **Depends:** RPR-009, RPR-015, RPR-016, RPR-018.
- **Deliver:** Docker/Podman launch with one read-only device, no network, all capabilities dropped, non-root UID plus necessary read group, read-only root, bounded tmpfs/scratch, PID/memory/CPU limits, and immutable image digest.
- **Acceptance:** callers cannot alter image, entry point, devices, mounts, network, capabilities, or security profile; scanner cannot see Docker socket or host secrets.
- **Tests:** inspect runtime configuration and attempt network, capability, root, extra-device, source-write, rootfs-write, and resource-exhaustion operations.

### RPR-020 — Build the no-source-write integration suite `[P0, M0]`

- **Status:** complete
- **Depends:** RPR-008, RPR-013–019.
- **Deliver:** destructive-to-fixture-only test harness that snapshots a loop disk, tries all plausible Reperio write paths, runs a minimal scan, and byte-compares the source afterward.
- **Acceptance:** every attempted write fails; source hash is unchanged; the suite runs only against a verified disposable fixture and refuses real disks.
- **Tests:** include malicious adapter attempt, compromised API payload, same-disk scratch, symlink swap, device renumber, and scanner restart.

---

## Epic C — catalog, API, durable jobs, and state

### RPR-021 — Create the initial SQLite schema `[P0, M1]`

- **Status:** complete
- **Depends:** RPR-003, RPR-007.
- **Deliver:** normalized tables and constraints for sources, cases, volumes, entries, contents, findings, evidence, jobs, events, review actions, artifacts, derivatives, exports, and audit references.
- **Acceptance:** foreign keys are on, WAL is configured, timestamps and enums have canonical representation, and paths are never primary identifiers.
- **Tests:** schema creation, constraint failures, Unicode/null-byte-safe path representation, and concurrent read/write smoke test.

### RPR-022 — Establish numbered database migrations `[P0, M1]`

- **Status:** complete
- **Depends:** RPR-021.
- **Deliver:** forward migration runner, schema-version table, transaction behavior, backup-before-upgrade hook, and compatibility policy.
- **Acceptance:** fresh and existing databases reach the same schema; failed migration rolls back and does not start workers.
- **Tests:** upgrade from empty and prior fixture, injected migration failure, already-current, future-version refusal.

### RPR-023 — Implement the durable job state machine `[P0, M1]`

- **Status:** complete
- **Depends:** RPR-021.
- **Deliver:** pending/leased/running/paused/retrying/completed/completed-warning/failed/cancelled transitions, immutable job input, attempts, and structured errors.
- **Acceptance:** invalid transitions are rejected; safe stop is distinct from failure; completed stages are not silently rerun.
- **Tests:** full transition matrix, concurrent claim, process death, and retry exhaustion.

### RPR-024 — Add leases, retries, and idempotency `[P0, M1]`

- **Status:** complete
- **Depends:** RPR-023.
- **Deliver:** atomic worker leasing, heartbeat/expiry, capped exponential retry with error classes, and stage idempotency keys.
- **Acceptance:** two workers cannot own one job; an expired job can resume without duplicate normalized records.
- **Tests:** race, clock skew boundary, duplicate submission, transient/permanent error, and worker-kill scenarios.

### RPR-025 — Add versioned checkpoint storage `[P0, M1]`

- **Status:** complete
- **Depends:** RPR-023, RPR-024.
- **Deliver:** atomic checkpoint blobs/JSON with tool version, source fingerprint, cursor, counters, integrity hash, and supersession history.
- **Acceptance:** corrupt, wrong-device, wrong-tool-version, or unsupported checkpoint is rejected with a clear restart-stage option.
- **Tests:** atomic crash simulation, corruption, old schema migration, and source mismatch.

### RPR-026 — Implement event outbox and SSE `[P1, M1]`

- **Status:** complete
- **Depends:** RPR-021, RPR-023.
- **Deliver:** transactional outbox, ordered per-case sequence, retention/compaction, SSE endpoint, last-event resume, and polling fallback contract.
- **Acceptance:** job state and its event cannot diverge; reconnect receives missed events once without requiring all findings in the stream.
- **Tests:** reconnect, duplicate delivery tolerance, retention boundary, slow client, and API restart.

### RPR-027 — Scaffold the versioned FastAPI service `[P0, M1]`

- **Status:** complete
- **Depends:** RPR-007, RPR-021, RPR-022.
- **Deliver:** `/api/v1`, request IDs, structured errors, OpenAPI generation, size/time limits, health/readiness, and static-UI serving boundary.
- **Acceptance:** no debug trace or secret reaches clients by default; OpenAPI is checked into/generated in CI for compatibility review.
- **Tests:** malformed JSON, oversized request, timeout, unknown route, and readiness during migration.

### RPR-028 — Add source and scan-case endpoints `[P1, M1]`

- **Status:** complete
- **Depends:** RPR-009, RPR-027.
- **Deliver:** device list/detail, source confirmation token, scan configuration preview, start, status, pause/resume/safe-stop, and reconnect endpoints.
- **Acceptance:** start requires recent safety facts and an exact-device confirmation; one active source per instance is enforced.
- **Tests:** stale token, swapped device, already-active case, hostd unavailable, unsupported device, and valid lifecycle.

### RPR-029 — Add finding query endpoints `[P1, M1]`

- **Status:** complete
- **Depends:** RPR-021, RPR-027.
- **Deliver:** cursor pagination, stable sort, compound filters, category/count facets, system-noise toggle, content/provenance detail, and FTS placeholder.
- **Acceptance:** query plans remain indexed; cursors do not skip/duplicate rows during concurrent ingest.
- **Tests:** empty/million-row synthetic data, concurrent inserts, Unicode search, invalid filters, and authorization mode toggle.

### RPR-030 — Implement dismiss, restore, and undo `[P1, M1]`

- **Status:** complete
- **Depends:** RPR-021, RPR-029.
- **Deliver:** reversible event-based review state for individual IDs, explicit ID sets, and saved-query snapshots.
- **Acceptance:** no content or finding row is deleted; undo restores exact prior state; new findings are not accidentally affected by an old query snapshot.
- **Tests:** bulk action, partial overlap, repeated undo, concurrent ingest, and permission-disabled API.

### RPR-031 — Implement the host secret store `[P0, M1]`

- **Status:** complete
- **Depends:** RPR-007, RPR-027.
- **Deliver:** generated master key or OS keyring integration, encrypted-at-rest secret values, opaque references, rotation/delete, masked display, and file permissions.
- **Acceptance:** secrets never appear in SQLite exports, logs, OpenAPI examples, process arguments, events, or support bundles.
- **Tests:** restart/decrypt, wrong key, rotation, redaction snapshot, and permissions audit.

### RPR-032 — Add diagnostics and safe state backup `[P2, M2]`

- **Status:** complete
- **Depends:** RPR-022, RPR-027, RPR-031.
- **Deliver:** redacted support bundle plus consistent backup/restore of catalog, checkpoints, settings, and optional derivatives while workers are paused.
- **Acceptance:** source content and secrets are excluded by default; restore validates version/integrity and cannot select/start a disk.
- **Tests:** live backup refusal/pause path, corrupt archive, newer schema, redaction, and restore round trip.

---

## Epic D — scanner and filesystem recovery

### RPR-033 — Define scanner/control-plane message contracts `[P0, M1]`

- **Status:** complete
- **Depends:** RPR-007, RPR-019, RPR-023.
- **Deliver:** versioned JSON-lines or equivalent protocol for hello/capabilities, stage start, batch findings, progress, checkpoint, warning, error, pause, and completion.
- **Acceptance:** batches are bounded, replay/idempotency is defined, malformed worker output cannot inject logs or SQL.
- **Tests:** golden messages, version mismatch, truncated batch, oversized field, invalid encoding, and duplicate replay.

### RPR-034 — Implement the deep-stage scheduler `[P0, M1]`

- **Status:** complete
- **Depends:** RPR-023–025, RPR-033.
- **Deliver:** dependency graph and conservative I/O concurrency for validation, volumes, enumeration, artifacts, enrichment, carving, and finalization.
- **Acceptance:** there is one product scan mode; stage parallelism never starts carving before destination/safety checks and is configurable by capability.
- **Tests:** graph order, pause propagation, failed optional stage, mandatory-stage failure, and restart with completed dependencies.

### RPR-035 — Implement source validation inside scanner `[P0, M1]`

- **Status:** complete
- **Depends:** RPR-012, RPR-016, RPR-033.
- **Deliver:** scanner independently verifies device is block-special, opens only `O_RDONLY`, checks read-only flag/fingerprint/size/sectors, and reports capabilities.
- **Acceptance:** mismatch exits before parsers run; source path cannot be replaced with a regular writable file or symlink.
- **Tests:** valid fixture, symlink swap, writable loop, wrong fingerprint, wrong sector size, permission failure.

### RPR-036 — Integrate partition discovery `[P1, M1]`

- **Status:** complete
- **Depends:** RPR-033, RPR-035.
- **Deliver:** TSK-backed GPT/MBR/extended/Apple/BSD partition reader with normalized offsets, lengths, labels/types, allocation status, and warnings.
- **Acceptance:** no TestDisk repair/write command is exposed; overlapping/invalid entries remain reportable without crashing.
- **Tests:** GPT, MBR, hybrid, extended, corrupt primary/backup GPT, unpartitioned, and sector-size fixtures.

### RPR-037 — Wrap The Sleuth Kit filesystem enumeration `[P1, M1]`

- **Status:** complete
- **Depends:** RPR-036.
- **Deliver:** pinned TSK adapter that identifies supported filesystems and streams batches of entries with stable volume/object/parent IDs.
- **Acceptance:** adapter uses direct block offsets, never mounts; tool stderr/exit/progress are normalized and bounded.
- **Tests:** NTFS, FAT, exFAT fixtures plus unsupported and corrupt volume behavior.

### RPR-038 — Normalize filesystem entries and paths `[P1, M1]`

- **Status:** complete
- **Depends:** RPR-021, RPR-037.
- **Deliver:** canonical model for raw/display path bytes, Unicode, parent relationships, type, attributes, owner IDs, sizes, allocation state, raw timestamps, timezone state, and extents.
- **Acceptance:** duplicate names, invalid Unicode, alternate streams, orphan parents, and path traversal strings are representable without filesystem use.
- **Tests:** golden normalization corpus and property tests over arbitrary byte names.

### RPR-039 — Build the content-addressed scratch store `[P1, M1]`

- **Status:** complete
- **Depends:** RPR-015, RPR-021, RPR-038.
- **Deliver:** atomic extracted-object writes, SHA-256 naming/metadata, quotas, reference counts, partial-file cleanup, and never-source validation.
- **Acceptance:** identical bytes share storage while retaining all provenance; no caller supplies final filesystem paths; completed recovered objects are never automatically deleted, and cleanup is limited to proven-incomplete owned temporary files.
- **Tests:** duplicate/concurrent extraction, disk full, crash mid-write, hash mismatch, symlink attack, same-disk refusal.

### RPR-040 — Extract allocated file content read-only `[P1, M1]`

- **Status:** complete
- **Depends:** RPR-037–039.
- **Deliver:** bounded streaming extraction from TSK object/attribute to scratch with size, SHA-256, sparse handling, and I/O error status.
- **Acceptance:** zero-length, huge, partial, and metadata-only entries are explicit; extraction never blocks catalog entry creation.
- **Tests:** allocated files, sparse fixture, bad extent, interruption/resume, and source byte-compare.

### RPR-041 — Support NTFS-specific entries `[P1, M1]`

- **Status:** complete
- **Depends:** RPR-037–040.
- **Deliver:** alternate data streams, resident data, compressed/sparse flags, reparse points, hard links, MFT metadata, DOS names, hidden/system flags, and Recycle Bin linkage where available.
- **Acceptance:** ADS are distinct findings with parent provenance; links are not followed on the host.
- **Tests:** synthetic NTFS fixture covering each feature and malformed attribute behavior.

### RPR-042 — Ingest filesystem-deleted and orphan entries `[P1, M2]`

- **Status:** complete
- **Depends:** RPR-037–040.
- **Deliver:** deleted/orphan enumeration, content extraction where extents remain available, recovery health, and original-name/timestamp provenance.
- **Acceptance:** allocated and deleted records cannot be conflated; overwritten/partial extraction is labeled, not silently accepted.
- **Tests:** intact deleted, partially overwritten, zeroed metadata, orphan, duplicate-content, and unrecoverable fixtures.

### RPR-043 — Complete FAT32 and exFAT coverage `[P1, M1]`

- **Status:** complete
- **Depends:** RPR-037–040.
- **Deliver:** filesystem-specific normalization for long names, deleted entries, timestamps/timezone ambiguity, cluster chains, and volume labels.
- **Acceptance:** limitations are visible per finding; malformed cluster loops are bounded.
- **Tests:** FAT32/exFAT allocated/deleted/fragmented/Unicode/corrupt-chain fixtures.

### RPR-044 — Add bad-sector and I/O-error handling `[P0, M2]`

- **Status:** complete
- **Depends:** RPR-033, RPR-040.
- **Deliver:** normalized read-error ranges, retry/backoff policy, temperature/error threshold hooks, skip-with-gap behavior, counters, and operator-visible warnings.
- **Acceptance:** infinite retry is impossible; a damaged range does not discard already cataloged results; no automatic repair command runs.
- **Tests:** fault-injected EIO/timeout/short-read/recovery and escalating-error pause.

### RPR-045 — Implement pause, safe stop, and restart `[P1, M2]`

- **Status:** complete
- **Depends:** RPR-025, RPR-033, RPR-034, RPR-044.
- **Deliver:** cooperative stage pause, subprocess signal/timeout policy, atomic checkpoint, safe stop, restart, and UI-visible reason.
- **Acceptance:** already committed batches survive; unsafe force-kill occurs only after timeout and preserves last good checkpoint.
- **Tests:** pause during enumeration/extraction, kill -9, host restart, corrupt checkpoint, and source reconnect.

### RPR-046 — Integrate PhotoRec scripted carving `[P1, M2]`

- **Status:** complete
- **Depends:** RPR-019, RPR-035, RPR-039, RPR-044.
- **Deliver:** pinned PhotoRec CLI adapter for whole unallocated/selected ranges, configured signatures, separate scratch destination, log parsing, and resource limits.
- **Acceptance:** source is read-only; recovered output never shares source; interactive repair features are absent.
- **Tests:** deleted JPEG/PDF/ZIP fixtures, unknown raw disk, no-space destination, timeout, malformed output.

### RPR-047 — Preserve and validate PhotoRec resume state `[P1, M2]`

- **Status:** complete
- **Depends:** RPR-025, RPR-045, RPR-046.
- **Deliver:** durable `photorec.ses` handling, source/tool/config binding, backup, resume invocation, and progress normalization.
- **Acceptance:** wrong disk/config/version cannot reuse a session; successful interruption resumes beyond the last durable position when supported.
- **Tests:** clean pause, process kill, corrupt session, wrong source, upgraded tool, and completed-session restart.

### RPR-048 — Ingest carved output progressively `[P1, M2]`

- **Status:** complete
- **Depends:** RPR-039, RPR-046.
- **Deliver:** watch stable completed files, hash/store, create carved provenance with sector/range where available, and queue classification/enrichment before carving ends.
- **Acceptance:** partially-written output is not ingested as complete; duplicate bytes link instead of vanishing.
- **Tests:** growing file, rename/finalize, duplicate allocated file, corrupt/zero-length output, scanner restart.

### RPR-049 — Detect lost-volume and corruption candidates `[P2, M2]`

- **Status:** complete
- **Depends:** RPR-036, RPR-046.
- **Deliver:** read-only signature scan for plausible lost partitions/filesystems and a confidence model that can schedule bounded parser/carving attempts without modifying tables.
- **Acceptance:** candidates are clearly separate from current partition entries; overlaps and false positives are visible.
- **Tests:** deleted partition, stale signature, overlapping candidates, random data, encrypted volume.

---

## Epic E — deterministic classification and artifact locators

### RPR-050 — Implement content-signature and MIME detection `[P1, M1]`

- **Status:** complete
- **Depends:** RPR-039, RPR-040.
- **Deliver:** libmagic/Magika-evaluation adapter with extension comparison, confidence, mismatch evidence, and bounded sample reads.
- **Acceptance:** extension alone never controls a dangerous parser; unknown and conflicting results remain explicit.
- **Tests:** renamed executable/image/document, polyglot test fixture, empty, truncated, random, and huge sparse files.

### RPR-051 — Discover OS installations and user profiles `[P1, M1]`

- **Status:** complete
- **Depends:** RPR-038.
- **Deliver:** deterministic Windows installation/user/profile locator first, with normalized artifact ownership and well-known directory evidence.
- **Acceptance:** multiple installations and renamed/moved profiles are supported; SIDs and display names remain distinct.
- **Tests:** multiple users, old `Documents and Settings`, missing registry, portable user folder, and duplicate username fixtures.

### RPR-052 — Create versioned Windows noise rules `[P1, M1]`

- **Status:** complete
- **Depends:** RPR-050, RPR-051.
- **Deliver:** data-driven rules for OS components, WinSxS, drivers, DLLs, fonts, icons/wallpapers, update caches, browser caches, temp, package stores, and application-generated assets.
- **Acceptance:** rules lower default visibility but never delete or permanently hide; each match has a human-readable reason and override.
- **Tests:** golden personal-vs-system corpus including personal files placed in unusual/system directories.

### RPR-053 — Build deterministic interest/noise scoring `[P1, M1]`

- **Status:** complete
- **Depends:** RPR-050–052.
- **Deliver:** pure versioned scoring engine combining path, owner, type, metadata, state, application, and rule signals into independent scores/evidence/confidence.
- **Acceptance:** same inputs/version produce same output; no AI result is required; score thresholds are configuration, not hard deletion; no user-data category is deprioritized solely by its category label, while OS/cache noise requires explainable path/application evidence.
- **Tests:** golden table, boundary values, missing evidence, contradictory signals, and rules-version migration.

### RPR-054 — Assign core categories `[P1, M1]`

- **Status:** complete
- **Depends:** RPR-050, RPR-053.
- **Deliver:** multi-label taxonomy for media, documents, archives, messages/email, browser, backups/mobile, wallets/vaults/keys, software/code/databases, deleted/carved, corrupted, unknown, and system/noise.
- **Acceptance:** one finding may occupy several relevant tabs; category evidence is queryable and explainable; every category remains reachable in All Findings and no category is silently excluded because of an implementation-priority label.
- **Tests:** representative and ambiguous fixtures; category version stored.

### RPR-055 — Inventory installed software and utilities `[P2, M2]`

- **Status:** complete
- **Depends:** RPR-051, RPR-054.
- **Deliver:** Windows uninstall registry, application directories, package evidence, portable app signatures, version/publisher/install-time provenance, and related user-data links.
- **Acceptance:** inventory is evidence-based, not execution; duplicates across architecture/users collapse with provenance.
- **Tests:** MSI-style, Store app, portable app, incomplete uninstall, and false-positive folder fixtures.

### RPR-056 — Locate backups, virtual machines, and sync roots `[P2, M2]`

- **Status:** complete
- **Depends:** RPR-038, RPR-051, RPR-054.
- **Deliver:** locators for Windows Backup, File History, common disk/VM images, phone backup software, OneDrive/Dropbox-like roots, and generic backup catalogs/archives.
- **Acceptance:** nested disks/backups are inventoried and scheduled only by explicit bounded policy; recursion loops are impossible.
- **Tests:** renamed backups, nested image, broken catalog, symlink-like filesystem entry, and huge backup set.

### RPR-057 — Locate iTunes/Finder and Android backup layouts `[P2, M2]`

- **Status:** complete
- **Depends:** RPR-056.
- **Deliver:** detect hashed iOS backup folders/Manifest data, encryption state, device facts, and common Android backup/extraction layouts.
- **Acceptance:** detection succeeds before optional iLEAPP/ALEAPP integration; unsupported/encrypted backups remain visible.
- **Tests:** multiple devices, partial backup, encrypted test backup, moved folder, and false-positive manifest.

### RPR-058 — Locate wallets, vaults, keys, and certificates `[P1, M1]`

- **Status:** complete
- **Depends:** RPR-050, RPR-051, RPR-054.
- **Deliver:** a versioned, extensible locator registry for Bitcoin Core legacy/descriptor wallet directories, `wallet.dat` and backups; Electrum and validated Bitcoin-family layouts; Ethereum/Web3 Secret Storage JSON keystores; validated browser-extension vault evidence; BIP32/BIP39-style recovery-material and private-key export indicators; hardware-wallet companion/backups; password vaults; SSH/GPG keys; certificates; and later chain-specific plugins. Apply it to normalized allocated, Trash/Recycle Bin, deleted, carved, browser-profile, application-data, archive, backup, attachment, document, image, and OCR findings as those ingestion stages become available.
- **Acceptance:** each result carries exact evidence, confidence, source/recovery state, sensitivity, and related application/profile data; weak filename or generic “wallet” text alone is low confidence; locator hooks work for later deleted/carved/OCR ingestion without schema redesign; seeds, private keys, decrypted values, and passwords never enter logs, notifications, remote AI/model requests, or general search text; detection never claims value/balance, executes wallet software, contacts a network, signs data, or broadcasts a transaction.
- **Tests:** safe synthetic Bitcoin Core legacy/descriptor, Electrum-family, Web3 JSON keystore, browser-vault evidence, recovery-indicator, renamed, encrypted, deleted/carved-origin, decoy-name, false-positive mnemonic prose, incomplete artifact, redaction, and no-network fixtures.

### RPR-059 — Add exact and perceptual duplicate groups `[P2, M2]`

- **Depends:** RPR-039, RPR-054, RPR-072.
- **Deliver:** exact SHA-256 groups plus image perceptual hashes and bounded video keyframe similarity, with canonical preview selection and all provenance retained.
- **Acceptance:** deduplication never discards a finding or source path; similarity thresholds are visible/configurable.
- **Tests:** exact duplicates, resized/cropped/rotated images, near/far video frames, corrupt media, and hash collision test seam.

---

## Epic F — browser-history subsystem

### RPR-060 — Define browser artifact schemas `[P1, M2]`

- **Status:** complete
- **Depends:** RPR-021, RPR-051.
- **Deliver:** normalized browser profile, visit, download, bookmark, search, session/tab, cookie metadata, cache, and extension schemas with raw provenance and recovery confidence.
- **Acceptance:** raw timestamp/value and normalized UTC/display timezone coexist; reusable session tokens are excluded from default schemas.
- **Tests:** schema golden files for Chromium, Firefox, legacy Windows, and Safari-shaped inputs.

### RPR-061 — Locate all Windows browser profiles `[P1, M2]`

- **Status:** complete
- **Depends:** RPR-051, RPR-060.
- **Deliver:** locators for Chrome, Edge, Brave, Opera, Vivaldi, Chromium, Firefox, Tor Browser, portable variants, multiple users, and multiple profiles.
- **Acceptance:** profile facts include owning OS user, browser/version evidence, path/object IDs, and companion files.
- **Tests:** default/profile-numbered, portable, renamed, partial, multiple install, and decoy folder fixtures.

### RPR-062 — Parse Chromium-family artifacts `[P1, M2]`

- **Status:** complete
- **Depends:** RPR-039, RPR-060, RPR-061, RPR-070.
- **Deliver:** read-only copied SQLite/JSON parsers for visits, typed counts, transitions/referrers, downloads, bookmarks, search terms, sessions/tabs, cache metadata, and extensions.
- **Acceptance:** schema-version differences degrade per field/table rather than losing the whole profile; provenance includes row/table/parser version.
- **Tests:** versioned Chrome/Edge/Brave synthetic profiles, malformed DB, locked-style WAL set, and missing tables.

### RPR-063 — Parse Firefox-family artifacts `[P1, M2]`

- **Status:** complete
- **Depends:** RPR-039, RPR-060, RPR-061, RPR-070.
- **Deliver:** places/history, visits, bookmarks, downloads, searches, session restore, cache metadata, and extension facts from copied profile artifacts.
- **Acceptance:** container/private-context identifiers and timestamp units are normalized without overstating private-history recovery.
- **Tests:** versioned Firefox/Tor synthetic profiles, corrupt SQLite, missing session, WAL, and multiple profiles.

### RPR-064 — Parse legacy IE and Edge WebCache `[P2, M2]`

- **Status:** complete
- **Depends:** RPR-060, RPR-061, RPR-070.
- **Deliver:** isolated parser adapter for WebCache/ESE and favorites/download evidence with parser-version provenance.
- **Acceptance:** unsupported/corrupt databases produce an artifact record and warning; tool failures do not block other browsers.
- **Tests:** safe ESE fixture, missing logs, corrupt page, timeout, and no-artifact case.

### RPR-065 — Include WAL/SHM and recoverable deleted SQLite rows `[P2, M2]`

- **Status:** complete
- **Depends:** RPR-062, RPR-063.
- **Deliver:** consistent copied DB+WAL+SHM handling and separately labeled validated freelist/unallocated-row recovery adapter.
- **Acceptance:** carved rows require stronger validation and lower confidence; duplicates link to live rows.
- **Tests:** uncheckpointed WAL, stale WAL, deleted rows, random page false positives, and duplicate recovery.

### RPR-066 — Normalize URLs, domains, and browser time `[P1, M2]`

- **Status:** complete
- **Depends:** RPR-060, RPR-062, RPR-063.
- **Deliver:** canonical URL display/search fields, IDN safety, domain/eTLD grouping, query/fragment policy, raw/UTC/local timestamps, visit-collapse logic, and timezone notes.
- **Acceptance:** original URL is preserved; normalization cannot turn different origins into one misleading record.
- **Tests:** IDN/punycode, malformed URL, file URL, IPv6, encoded query, DST boundary, multiple timestamp epochs.

### RPR-067 — Add browser query and aggregation API `[P1, M2]`

- **Status:** complete
- **Depends:** RPR-027, RPR-060, RPR-066.
- **Deliver:** cursor queries and facets by user/browser/profile/type/domain/date, histogram, summary counts, and links to related file findings.
- **Acceptance:** filters are composable and stable during ingest; source row/provenance is retrievable.
- **Tests:** large synthetic history, concurrent ingest, date/timezone bounds, related download, and empty profiles.

### RPR-068 — Export browser CSV, JSON, and HTML `[P1, M2]`

- **Depends:** RPR-060, RPR-066, RPR-067, RPR-107.
- **Deliver:** complete/current-filter exports with field dictionary, timezone/provenance notes, escaping, counts, and standalone passive HTML.
- **Acceptance:** spreadsheet-formula injection and HTML/script injection are neutralized; no reusable auth tokens export by default.
- **Tests:** malicious URL/title, Unicode, million-row streaming CSV, filtered export, and deterministic JSON schema.

### RPR-069 — Cross-validate browser parsers `[P1, M2]`

- **Status:** complete
- **Depends:** RPR-062–065.
- **Deliver:** comparison harness against pinned Plaso/Hindsight or another approved parser for synthetic profiles; mismatch report and supported-version matrix.
- **Acceptance:** critical visit/download timestamps and URLs have documented validation; discrepancies remain visible rather than silently choosing a tool.
- **Tests:** golden comparison for each claimed browser family and known intentional differences.

---

## Epic G — safe enrichment, previews, OCR, and archives

### RPR-070 — Build the generic parser sandbox runner `[P0, M2]`

- **Status:** complete
- **Depends:** RPR-019, RPR-031, RPR-039.
- **Deliver:** fixed tool profiles, copy-only input, no network/capabilities/root, read-only root, per-job scratch, CPU/memory/PID/time/output/nesting limits, structured stdout, and cleanup.
- **Acceptance:** tools cannot access source device, control-plane DB, other jobs, host secrets, or arbitrary network; profile arguments are allowlisted.
- **Tests:** malicious parser tries each forbidden access plus fork bomb, output flood, timeout, path traversal, and crash.

### RPR-071 — Integrate Apache Tika `[P1, M2]`

- **Depends:** RPR-050, RPR-070.
- **Deliver:** pinned sandbox adapter for type, metadata, and text from supported copied documents, with parser chain, truncation, and errors.
- **Acceptance:** extraction is bounded and does not render/execute macros or embedded active content; nested extraction follows limits.
- **Tests:** DOCX/XLSX/PPTX/PDF/RTF/text/email, encrypted, malformed, zip bomb, and timeout fixtures.

### RPR-072 — Integrate ExifTool and ffprobe `[P1, M2]`

- **Depends:** RPR-070.
- **Deliver:** normalized image/audio/video metadata, dimensions/duration/codecs, creation/device/location/editor tags, raw values, and warnings.
- **Acceptance:** read-only flags are fixed; metadata never directly becomes HTML; oversized/recursive metadata is bounded.
- **Tests:** JPEG/HEIC/TIFF/RAW/MP4/MOV/audio, GPS, malformed media, misleading extension, timeout.

### RPR-073 — Generate tiered image thumbnails `[P1, M2]`

- **Depends:** RPR-039, RPR-070, RPR-072.
- **Deliver:** libvips-based embedded/small/large derivative jobs, content-hash cache, aspect ratio, orientation/color handling, and priority-on-open.
- **Acceptance:** enumeration never waits for thumbnails; decompression bombs and huge dimensions are limited; output is a safe format.
- **Tests:** common/RAW/HEIC/animated/CMYK/rotated/huge/corrupt images, duplicates, cache hit, and resource limit.

### RPR-074 — Generate safe full-screen media derivatives `[P1, M2]`

- **Depends:** RPR-070, RPR-072, RPR-073.
- **Deliver:** larger image preview, bounded video transcode/keyframes, audio waveform/preview, derivative provenance, and HTTP range support for derivatives only.
- **Acceptance:** the browser never receives source executable/active formats inline; failures fall back to metadata/download-only.
- **Tests:** video/audio codecs, malformed containers, huge duration, active SVG/HTML renamed as image, and range requests.

### RPR-075 — Render PDFs and documents safely `[P1, M2]`

- **Depends:** RPR-070, RPR-071.
- **Deliver:** sandboxed PDF-to-image page rendering, first-page thumbnails, lazy additional pages, extracted-text alignment where feasible, and no active PDF delivery.
- **Acceptance:** encrypted/corrupt/huge PDFs report status; page/time limits are configurable.
- **Tests:** text/scanned/encrypted/signed/malformed/JavaScript-bearing/large-page PDF and office preview fallback.

### RPR-076 — Add OCR for images and scanned PDFs `[P1, M2]`

- **Depends:** RPR-071, RPR-073, RPR-075.
- **Deliver:** Tesseract/OCRmyPDF adapter on copies/derivatives, English+Spanish packs initially, page regions/text/confidence, and OCR need detection.
- **Acceptance:** no output writes beside the source; existing text is preserved/separated; low-confidence OCR is labeled.
- **Tests:** English, Spanish, mixed, rotated, low quality, existing text, handwriting limitation, timeout, and corrupt image.

### RPR-077 — Detect extracted-text language `[P2, M2]`

- **Depends:** RPR-071, RPR-076.
- **Deliver:** local language identification with confidence, sample-size threshold, mixed-language support, and raw evidence.
- **Acceptance:** unknown/short text is not force-labeled; detection does not require remote AI.
- **Tests:** English, Spanish, three other languages, mixed, numeric/short/gibberish, and OCR noise.

### RPR-078 — Add local and provider translation `[P2, M3]`

- **Depends:** RPR-077, RPR-083, RPR-093.
- **Deliver:** on-demand/background side-by-side translation to configured English or Spanish, local model first, caching, source-language/confidence, and provider policy.
- **Acceptance:** original text remains visible; remote translation requires privacy gate; unsupported language is explicit.
- **Tests:** local translation, remote-disabled, provider failure, long document chunking, mixed language, cache version.

### RPR-079 — Add local audio/video transcription `[P2, M3]`

- **Depends:** RPR-070, RPR-072, RPR-074.
- **Deliver:** optional local speech-to-text adapter with CPU-safe defaults, language/time segments/confidence, pause/resume chunks, and extracted audio derivative.
- **Acceptance:** unsupported hardware disables capability cleanly; no cloud upload without configured provider policy.
- **Tests:** English/Spanish/other language, silence, long chunk resume, corrupt audio, CPU-only capability.

### RPR-080 — Inspect archives safely `[P1, M2]`

- **Depends:** RPR-070.
- **Deliver:** list archive members, encryption state, compression ratios, nested-depth plan, password need, and optional extraction to per-job scratch with traversal/symlink/bomb limits.
- **Acceptance:** absolute paths, `..`, links, device nodes, extreme expansion/count/depth are refused; listing alone cannot escape sandbox.
- **Tests:** ZIP/7z/RAR/tar/gzip, encrypted, nested, traversal, symlink, duplicate names, bomb, malformed archive.

### RPR-081 — Detect protected/encrypted artifacts `[P1, M3]`

- **Depends:** RPR-050, RPR-071, RPR-080.
- **Deliver:** normalized protected status and format/version/KDF metadata for archives, PDFs, Office/OpenDocument, wallets/vaults/keys/backups, and whole-volume signatures where supported.
- **Acceptance:** entropy alone is only weak evidence; compressed data is not mislabeled with high confidence.
- **Tests:** protected/unprotected pairs, high-entropy compressed files, corrupt headers, renamed formats, unsupported encryption.

### RPR-082 — Repair or regenerate only scratch copies `[P2, M3]`

- **Depends:** RPR-039, RPR-070, RPR-071–075.
- **Deliver:** plugin contract for bounded copy repair (media remux, archive recovery attempt, PDF rebuild, image decode/re-encode), original-content linkage, and quality status.
- **Acceptance:** repair tools receive only scratch copies; repaired outputs never replace originals and are labeled derived/possibly lossy.
- **Tests:** successful and failed safe fixtures, source-path denial, output explosion, and provenance retention.

---

## Epic H — AI routing, comparison, and semantic search

### RPR-083 — Define model-provider and task contracts `[P1, M3]`

- **Depends:** RPR-007, RPR-031.
- **Deliver:** capability discovery and structured request/result/error schemas for text, vision, embeddings, translation, classification, summarization, with time/size/privacy limits.
- **Acceptance:** providers cannot request tools or paths; every result names provider/model/task/prompt/schema version and evidence references.
- **Tests:** provider contract golden cases, malformed output, unsupported modality, timeout, and secret redaction.

### RPR-084 — Build provider settings and health checks `[P1, M3]`

- **Depends:** RPR-031, RPR-083.
- **Deliver:** ordered named profiles, enablement, endpoint/model, eligible workloads/categories, local/remote flag, weight, timeout, limits, and non-content health tests.
- **Acceptance:** unlimited primary/secondary/tertiary profiles are supported; remote is off until acknowledged.
- **Tests:** duplicate names, unreachable endpoint, wrong model, remote gate, reorder, disabled provider.

### RPR-085 — Implement OpenAI-compatible LAN endpoint adapter `[P1, M3]`

- **Depends:** RPR-083, RPR-084.
- **Deliver:** configurable base URL/model adapter for compatible local services with structured output, vision/embedding capability negotiation, streaming disabled unless needed, and retries.
- **Acceptance:** private/LAN endpoints may use no key; TLS/auth options use secret references; arbitrary URL redirects are controlled.
- **Tests:** mock llama.cpp/vLLM/LM-Studio-shaped responses, no-key, auth, malformed JSON, 429/500, redirect/SSRF policy.

### RPR-086 — Implement Ollama adapter `[P1, M3]`

- **Depends:** RPR-083, RPR-084.
- **Deliver:** native tags/capability check, model selection, JSON schema prompting/validation, embeddings, image support where declared, and cancellation.
- **Acceptance:** missing model gives setup guidance; Reperio never auto-pulls a large model without explicit admin action.
- **Tests:** mock list/generate/embed, missing model, invalid output, cancellation, endpoint unavailable.

### RPR-087 — Create versioned AI task prompts and schemas `[P1, M3]`

- **Depends:** RPR-053, RPR-054, RPR-083.
- **Deliver:** bounded tasks for classification, tags, summary, relevance explanation, translation, media description, and artifact hints; deterministic inputs cite extracted evidence.
- **Acceptance:** prompts say models cannot delete/hide or infer certainty; outputs are schema-validated and confidence/evidence are required.
- **Tests:** golden prompt snapshots, injection-bearing file text, missing fields, excessive labels, unsupported language.

### RPR-088 — Add batching, cache, and budget controls `[P1, M3]`

- **Depends:** RPR-083, RPR-087.
- **Deliver:** cache key by content/input/prompt/provider/model/version, bounded batching/chunking, per-provider concurrency, retry budget, cancellation, and usage metrics.
- **Acceptance:** a rescan does not resend unchanged content; provider outage cannot block deterministic scan completion.
- **Tests:** cache hit/miss/version change, partial batch failure, cancellation, rate limit, and restart.

### RPR-089 — Fan out identical tasks to multiple models `[P1, M3]`

- **Depends:** RPR-084, RPR-088.
- **Deliver:** independent parallel/sequential fan-out according to resource policy, immutable shared input package, per-opinion storage, and partial success.
- **Acceptance:** one model never sees another's answer; primary failure does not discard secondary success.
- **Tests:** 3 providers agree/disagree/fail/timeout in combinations; ordering and stored provenance.

### RPR-090 — Compute and display model consensus `[P2, M3]`

- **Depends:** RPR-089.
- **Deliver:** deterministic agreement metrics for categorical tags and normalized summaries, weighted consensus with minimum evidence, and explicit disagreement state.
- **Acceptance:** consensus cannot modify deterministic score, dismiss state, or visibility; every aggregate links to opinions.
- **Tests:** unanimous, split, weighted tie, malformed opinion, low confidence, single provider.

### RPR-091 — Generate local embeddings `[P2, M3]`

- **Depends:** RPR-071, RPR-076, RPR-083, RPR-088.
- **Deliver:** local embedding worker for text chunks/media descriptions with model/dimension/version metadata, batching, cache, and CPU-compatible mode.
- **Acceptance:** no embeddings are required for ordinary filters/FTS; model changes create a new index namespace.
- **Tests:** deterministic mock, long chunking, empty text, model change, interruption, ARM capability fallback.

### RPR-092 — Implement semantic search `[P2, M3]`

- **Depends:** RPR-029, RPR-091.
- **Deliver:** portable vector-index adapter selected by ADR, hybrid FTS/vector ranking, filters, citations to matching chunks, and graceful disablement.
- **Acceptance:** semantic results explain matched content; permissions/category filters apply before display.
- **Tests:** relevant/irrelevant corpus, filters, index rebuild, missing vector backend, million-vector performance target.

### RPR-093 — Add remote-provider privacy gate `[P0, M3]`

- **Depends:** RPR-031, RPR-083, RPR-084.
- **Deliver:** explicit admin acknowledgment, per-provider/category/data-size policy, outbound payload preview/redaction option, audit, and a hard distinction between local/LAN/remote.
- **Acceptance:** remote calls are impossible before acknowledgment; changing endpoint from private to public re-triggers acknowledgment.
- **Tests:** DNS/IP classification cases, redirect, policy deny, category deny, revoke, and audit redaction.

### RPR-094 — Evaluate official subscription CLI adapters `[P2, M3]`

- **Depends:** RPR-083, RPR-093.
- **Deliver:** provider-by-provider ADR validating current terms, supported authentication, headless/unattended behavior, structured output, quotas, credential isolation, cancellation, and a shared official-CLI adapter boundary.
- **Acceptance:** only unmodified official clients and user-initiated login may be proposed; token scraping/proxying is forbidden; a provider that disallows the intended integration is recorded as `unsupported` rather than worked around.
- **Tests:** contract mock and manual legal/terms checklist; implementation is split into RPR-157–159 so no agent must solve all providers at once.

---

## Epic I — password recovery and decrypted copies

### RPR-095 — Model protected targets and audit jobs `[P1, M3]`

- **Depends:** RPR-021, RPR-081.
- **Deliver:** target/format/KDF/cost/capability/status, supplied-secret-set references, engine strategy, checkpoint, resource budget, result-secret reference, and audit events.
- **Acceptance:** detection and auditing are separate; jobs are opt-in and never include plaintext secrets in rows/events.
- **Tests:** state transitions, unsupported format, duplicate target, secret deletion, and restart.

### RPR-096 — Try operator-supplied passwords safely `[P1, M3]`

- **Depends:** RPR-031, RPR-070, RPR-080, RPR-095.
- **Deliver:** named secret sets and format-specific verification/extraction using stdin/file-descriptor mechanisms instead of command arguments.
- **Acceptance:** attempted/recovered values never reach logs/process listings; successful output goes to separate scratch.
- **Tests:** correct/wrong/multiple, Unicode, empty, process crash, redaction, and encrypted archive/PDF fixtures.

### RPR-097 — Manage dictionaries, rules, masks, and combinations `[P1, M3]`

- **Depends:** RPR-031, RPR-095.
- **Deliver:** settings inventory with source/license/hash/size/language, ordered strategies, rule/mask validation, estimated search space, enablement, and import limits.
- **Acceptance:** no wordlist downloads occur without explicit admin action; arbitrary shell syntax is rejected.
- **Tests:** valid/invalid masks, huge import, duplicate dictionary, hash change, license metadata missing.

### RPR-098 — Wrap format-to-audit-material helpers `[P1, M3]`

- **Depends:** RPR-070, RPR-081, RPR-095.
- **Deliver:** allowlisted `*2john`/`*2hashcat` adapters for selected archive/PDF/Office/key/wallet formats with normalized engine/mode metadata.
- **Acceptance:** helpers receive copied target only; extracted material is classified secret and never downloadable by default.
- **Tests:** supported pairs, wrong detection, malformed target, helper timeout/crash, secret redaction.

### RPR-099 — Integrate John the Ripper worker `[P1, M3]`

- **Depends:** RPR-097, RPR-098.
- **Deliver:** pinned isolated engine, wordlist/rule/incremental job plans, pot/session handling in secret storage, progress, pause/resume, and recovered-secret reference.
- **Acceptance:** CPU/resource budgets enforced; no account-hash auditing beyond explicitly supported protected artifacts unless separately approved.
- **Tests:** recover synthetic archive/PDF, pause/resume, exhaustion/no-match, timeout, engine crash, redaction.

### RPR-100 — Integrate Hashcat capability and worker `[P2, M3]`

- **Depends:** RPR-097, RPR-098.
- **Deliver:** GPU/CPU/device capability check, allowed modes, benchmark-derived warnings, resource/temperature policy, session restore, and normalized progress.
- **Acceptance:** unsupported hardware disables cleanly; engine never receives the source device/medium; workload cannot starve scanner beyond configured policy.
- **Tests:** mocked CPU/GPU capability, synthetic recovery, pause/resume, wrong mode, OOM/thermal signal, no-match.

### RPR-101 — Schedule and checkpoint password work `[P1, M3]`

- **Depends:** RPR-023–025, RPR-099, RPR-100.
- **Deliver:** background priority, time windows, max duration/candidates, pause during disk-heavy work, strategy continuation, and notification-safe events.
- **Acceptance:** no operator input is required after initial strategy; exhaustion and skipped strategies are reported.
- **Tests:** restart, scheduled window, budget reached, scan contention, engine switch, notification payload.

### RPR-102 — Store/reveal recovered secrets safely `[P0, M3]`

- **Depends:** RPR-031, RPR-095–101.
- **Deliver:** encrypted secret reference, explicit UI reveal/copy, auto-hide, optional non-persistence, delete-secret action that leaves audit/result status.
- **Acceptance:** unauthenticated LAN mode shows a critical warning before reveal; secrets never enter browser URL/history or telemetry.
- **Tests:** reveal permissions modes, clipboard UI test, log/event/support-bundle redaction, key rotation, delete.

### RPR-103 — Recursively ingest decrypted outputs `[P1, M3]`

- **Depends:** RPR-039, RPR-080, RPR-096, RPR-102.
- **Deliver:** link decrypted scratch copy to protected original, rerun bounded detection/archive/document pipeline with depth/size limits, and preserve password target state.
- **Acceptance:** original is never replaced; recursion/bombs are bounded; repeated successful password is reusable only through explicit secret-set policy.
- **Tests:** encrypted nested archive, duplicate decrypted content, depth limit, wrong output, restart.

### RPR-104 — Add wallet/vault-specific protected formats `[P1, M3]`

- **Depends:** RPR-058, RPR-081, RPR-098–103.
- **Deliver:** researched, fixture-backed plugins for an explicit supported-format matrix covering the protected wallet/vault/key families prioritized by RPR-058, metadata-only inventory, supported password verification, safe redacted display, and a related-item export bundle with exact selected bytes, provenance, checksums, duplicate relationships, and verification state.
- **Acceptance:** each advertised format/version has license/source/version facts and a synthetic fixture; recovered secrets follow RPR-102 controls; unsupported versions remain visible; no secret reaches a remote model; no balance/network lookup, signing, or transaction broadcast occurs.
- **Tests:** locked/unlocked/corrupt/versioned synthetic artifacts, unsupported version, false positives, bundle verification, remote-provider denial, and secret redaction.

---

## Epic J — exports and notifications

### RPR-105 — Define destinations and export contracts `[P0, M1]`

- **Depends:** RPR-015, RPR-021, RPR-031.
- **Deliver:** local/rclone destination profiles, capability/verification flags, secret references, export snapshot/items/status, and source-separation recheck.
- **Acceptance:** destination is validated at submission and execution; immutable selected finding set is recorded.
- **Tests:** local/network/object profiles, missing secret, source path, changed mount ancestry, and invalid capability.

### RPR-106 — Implement verified local export `[P1, M1]`

- **Depends:** RPR-039, RPR-105.
- **Deliver:** streaming copy to a temporary destination name, fsync/atomic finalize where supported, size+SHA-256 verification, progress, and partial cleanup/resume policy.
- **Acceptance:** only extracted/recovered content is copied; failure never marks item complete; source and scratch remain unchanged.
- **Tests:** success, destination disk full, disconnect, existing collision, permission error, corrupted copy seam, same-disk race.

### RPR-107 — Generate export paths and manifests `[P1, M1]`

- **Depends:** RPR-038, RPR-054, RPR-105, RPR-106.
- **Deliver:** safe hierarchy preservation, destination-specific sanitization/collision rules, carved naming, JSON/CSV manifests, hashes, provenance, statuses, tool/app versions.
- **Acceptance:** path traversal, reserved names, case collisions, long paths, invalid Unicode, and formula injection are handled and recorded.
- **Tests:** cross-platform path corpus, duplicate names, malicious names, deterministic manifest, partial failure.

### RPR-108 — Export while scanning continues `[P1, M2]`

- **Depends:** RPR-024, RPR-039, RPR-106, RPR-107.
- **Deliver:** export queue accepts only content currently ready, waits/retries selected pending extraction, and never locks scanner catalog ingest for long operations.
- **Acceptance:** completion accurately reports ready/exported/waiting/failed; dynamic saved-search export is separately explicit.
- **Tests:** concurrent ingest/export, selected content becomes ready, scan pause, export restart, finding dismissed mid-export.

### RPR-109 — Integrate rclone destinations `[P2, M2]`

- **Depends:** RPR-031, RPR-070, RPR-105–108.
- **Deliver:** pinned rclone adapter with allowlisted copy/check operations, generated per-job config, local/SMB/SFTP/FTP/WebDAV/S3/common cloud capability checks, resume/retry, and redacted output.
- **Acceptance:** no `sync` or delete flags; FTP warns plaintext; credentials never enter arguments/logs; verification limitations recorded.
- **Tests:** mock remotes plus local SFTP/S3 test services, interruption/resume, checksum/no-checksum, credential redaction, forbidden command.

### RPR-110 — Add export configuration and status API `[P1, M2]`

- **Depends:** RPR-027, RPR-105–109.
- **Deliver:** destination create/test/update/delete, export submit/status/pause/resume, item errors, manifest download, and current-filter snapshot endpoints.
- **Acceptance:** test writes only a disposable probe to destination, never source; destination deletion does not delete exported files.
- **Tests:** all lifecycle states, remote unavailable, secret rotation, filter snapshot, manifest access.

### RPR-111 — Define notification rules and event summaries `[P1, M2]`

- **Depends:** RPR-026, RPR-031.
- **Deliver:** configurable start/progress/heartbeat/count/high-value-sensitive-count/health/disconnect/pause/failure/export/password-success/completion rules, throttling, quiet hours, and redacted templates.
- **Acceptance:** no filenames, URLs, document text, thumbnails, wallet identifiers, recovery phrases, keys, or passwords by default; high-value/sensitive alerts contain counts and a local UI link only; delivery failure cannot affect job state.
- **Tests:** rule matching, threshold once, throttle, quiet hours, redaction, delivery-failure outbox.

### RPR-112 — Integrate Apprise notifications `[P1, M2]`

- **Depends:** RPR-070, RPR-111.
- **Deliver:** pinned Apprise library/sidecar adapter, secret-backed service URLs, test notification, delivery attempt/backoff, and normalized errors.
- **Acceptance:** email/webhook and at least one self-hosted route fixture work; service URLs are never returned after creation.
- **Tests:** local SMTP/webhook fixtures, bad secret, timeout, retry, message truncation, redaction.

### RPR-113 — Implement progress and completion summaries `[P1, M2]`

- **Depends:** RPR-026, RPR-034, RPR-111, RPR-112.
- **Deliver:** credible stage percent rules, activity-only fallback, elapsed heartbeat, finding/category counts, warnings, export counts, and local UI link.
- **Acceptance:** no fabricated ETA/percentage without denominator; completion distinguishes warnings/failures/unsupported stages.
- **Tests:** known/unknown denominator, restart, stage skip/failure, heartbeat throttle, final summary snapshot.

### RPR-114 — Add browser-report export integration `[P1, M2]`

- **Depends:** RPR-068, RPR-107–110.
- **Deliver:** browser reports as export items with selected filters, manifests, stable filenames, verification, and progressive generation.
- **Acceptance:** report generation is passive/safe and repeatable; filter/timezone snapshot recorded.
- **Tests:** complete/filter export, HTML injection corpus, remote destination, interrupted generation.

### RPR-115 — Add export audit and verification dashboard data `[P1, M2]`

- **Depends:** RPR-105–114.
- **Deliver:** immutable per-attempt facts, verified/unverified/failed counts, destination capability, retry history, and manifest hash.
- **Acceptance:** “complete” cannot hide unverified/failed items; retry creates a linked attempt.
- **Tests:** mixed outcomes, destination no checksum, retry success, manifest tamper detection.

---

## Epic K — web interface

### RPR-116 — Establish UI design system `[P1, M1]`

- **Depends:** RPR-004.
- **Deliver:** accessible tokens/components for typography, spacing, color/status, buttons, inputs, dialogs, tables, cards, chips, skeletons, toasts, and dark/light support if retained.
- **Acceptance:** components meet keyboard/focus/contrast basics and do not copy third-party branding/assets.
- **Tests:** component stories/screenshots, keyboard tests, automated accessibility scan.

### RPR-117 — Build application shell and navigation `[P1, M1]`

- **Depends:** RPR-027, RPR-116.
- **Deliver:** responsive sidebar/top status, all planned tabs, case/source context, connection state, SSE reconnect, and route-level loading/error boundaries.
- **Acceptance:** critical read-only state and unauthenticated-LAN warning are persistently discoverable.
- **Tests:** routing, refresh/deep link, API unavailable, SSE reconnect, narrow viewport, keyboard navigation.

### RPR-118 — Build new-scan device wizard `[P0, M1]`

- **Depends:** RPR-028, RPR-116, RPR-117, RPR-178–180.
- **Deliver:** source cards grouped by disk, flash/card, optical, floppy/legacy reader, with reader/media identity, model/serial/size/transport/geometry or sessions, mount/system/health, exact-source confirmation, scratch separation, safety checks, configuration summary, and start.
- **Acceptance:** ambiguous or changed media cannot start; system disk/failed RO/same-disk destination blockers are clear; replacing a disc/floppy in the same reader requires fresh selection; no scan starts automatically.
- **Tests:** valid disk/flash/optical/floppy, swapped/stale media, empty reader, mounted RW, system disk, missing serial, health unavailable/warning, hostd unavailable.

### RPR-119 — Build live-scan dashboard `[P1, M1]`

- **Depends:** RPR-026, RPR-028, RPR-113, RPR-117.
- **Deliver:** stage list, current activity, credible progress, counters, warnings/errors, read-only/source facts, pause/resume/safe-stop, and live new-finding samples.
- **Acceptance:** no misleading progress; control states follow job state; results links work before completion.
- **Tests:** all job states, unknown percentage, reconnect, retry warning, source disconnect, completion with warnings.

### RPR-120 — Build virtualized findings table `[P1, M1]`

- **Depends:** RPR-029, RPR-116, RPR-117.
- **Deliver:** cursor pagination, stable sorting, columns for path/type/size/date/state/scores/confidence/category/export, row selection, and detail link.
- **Acceptance:** handles million-row synthetic catalog without loading all rows; concurrent ingest does not jump selection.
- **Tests:** performance budget, keyboard selection, new rows, empty/error/loading, long/Unicode paths.

### RPR-121 — Build filters, facets, FTS, and saved views `[P1, M1]`

- **Depends:** RPR-029, RPR-120.
- **Deliver:** user/volume/category/date/size/allocation/encrypted/corrupt/duplicate/interest/noise/export/dismiss facets, text search, chips, reset, URL/share-local state, saved views.
- **Acceptance:** “include system/noise” is explicit; filter state is reflected in counts and export snapshots.
- **Tests:** combinations, zero results, browser back/forward, invalid URL state, concurrent facet changes.

### RPR-122 — Build media masonry gallery `[P1, M2]`

- **Depends:** RPR-073, RPR-074, RPR-116, RPR-121.
- **Deliver:** virtualized responsive masonry, aspect placeholders, infinite cursor load, select without opening, keyboard navigation, date/device/location groups, duplicate indicators.
- **Acceptance:** missing thumbnails do not cause layout thrash; original/source active content is never rendered.
- **Tests:** 100k synthetic items, variable ratios, failed thumbnail, selection/range, narrow viewport, accessibility.

### RPR-123 — Build document/PDF view `[P1, M2]`

- **Depends:** RPR-071, RPR-075–078, RPR-121.
- **Deliver:** document cards/table, safe rendered page viewer, extracted/OCR text, language, side-by-side translation, metadata, page navigation, search-in-document.
- **Acceptance:** source PDF/HTML is not embedded; encrypted/unsupported/corrupt states have clear actions/status.
- **Tests:** text/scanned/encrypted/active/malformed documents, translation off/fail, large page count.

### RPR-124 — Build browser-history tab `[P1, M2]`

- **Depends:** RPR-067, RPR-068, RPR-116, RPR-121.
- **Deliver:** user/browser/profile summaries, timeline/table, domain/date histogram and facets, visit/download/bookmark/session types, related findings, export current/all.
- **Acceptance:** provenance/confidence/timezone are visible; large histories are virtualized.
- **Tests:** multiple users/profiles, malformed URLs, deleted rows, million events, filtered export.

### RPR-125 — Build remaining category tabs `[P1, M2]`

- **Depends:** RPR-054–058, RPR-116, RPR-121, RPR-186.
- **Deliver:** messages/email, archives/encrypted, backups/mobile, first-class wallets/vaults/keys, software/code/databases, Trash/Recycle Bin, deleted/carved, unknown/unsupported views using shared primitives and category-specific summaries. The wallet view groups family/application, OS user/profile, allocated/deleted/carved/protected state, confidence, related artifacts, and export readiness without revealing secrets in list views.
- **Acceptance:** every finding is reachable in All Findings; unsupported artifacts remain visible; sensitive labels do not hide content; wallet summaries never imply balance or successful recovery when only locator evidence exists.
- **Tests:** representative state fixtures and cross-tab multi-label item.

### RPR-126 — Build full-screen finding inspector `[P1, M2]`

- **Depends:** RPR-072–078, RPR-090, RPR-116.
- **Deliver:** safe preview/lightbox, metadata/text/OCR/translation/transcript, provenance, score explanation, duplicate/related navigation, model opinions/consensus, export/dismiss controls.
- **Acceptance:** no active source content runs; every AI statement is labeled; next/previous respects current result set.
- **Tests:** each media/document state, no preview, model disagreement, keyboard/swipe, active content attack fixture.

### RPR-127 — Implement bulk selection, dismiss/undo, and export interactions `[P1, M1]`

- **Depends:** RPR-030, RPR-108, RPR-120–126.
- **Deliver:** explicit IDs/select-page/select-filter snapshot, sticky action bar, dismiss confirmation, undo toast/history, restore view, add-to-export with readiness summary.
- **Acceptance:** action scope is always shown; dismiss remains reversible; export can begin on ready subset.
- **Tests:** virtualized range selection, filter changes, concurrent ingest, undo, partial-ready export, dismissed export.

### RPR-128 — Build destination and export UI `[P1, M2]`

- **Depends:** RPR-110, RPR-115, RPR-116.
- **Deliver:** destination setup/test, capability/warning display, export queue/progress/items/errors/retry, verification summary, and manifest download.
- **Acceptance:** secrets are write-only/masked; FTP and unverified outputs warn; destination deletion wording says remote files remain.
- **Tests:** local/SFTP/S3-shaped profiles, invalid secret, partial failure, retry, verification states.

### RPR-129 — Build settings and capability UI `[P1, M2]`

- **Depends:** RPR-007, RPR-084, RPR-097, RPR-111, RPR-117.
- **Deliver:** scan resources, providers/order/privacy, dictionaries/strategies, destinations, notifications, optional admin password/LAN binding, tools/capabilities, diagnostics.
- **Acceptance:** dangerous privacy/network choices explain impact and require acknowledgment; settings validation mirrors server schema.
- **Tests:** provider reorder, remote gate, auth enable/disable, invalid resource, capability missing, secret masking.

### RPR-130 — Add single-admin optional authentication `[P1, M2]`

- **Depends:** RPR-031, RPR-027, RPR-117, RPR-129.
- **Deliver:** default-off single password, secure hash, login/session/CSRF/rate limits/logout, subnet/bind configuration, warning when LAN+no-auth, and no user management.
- **Acceptance:** enabling auth protects API/SSE/previews/exports/secrets; no default password; disabling requires current admin confirmation when enabled.
- **Tests:** login/logout/session expiry/CSRF/brute-rate, API direct access, SSE, password rotate, no-auth warning.

### RPR-131 — Add notification settings and delivery history UI `[P1, M2]`

- **Depends:** RPR-111–113, RPR-116, RPR-129.
- **Deliver:** route setup/test, event rules/thresholds/quiet hours, redacted delivery status/errors, and enable/disable.
- **Acceptance:** no full service URL/secret is redisplayed; test payload contains no finding data.
- **Tests:** rule editor, test success/failure, masking, quiet hours, delivery history pagination.

### RPR-132 — Complete accessibility/responsiveness/performance pass `[P1, M2]`

- **Depends:** RPR-117–131.
- **Deliver:** keyboard maps, focus management, screen-reader labels, contrast/reduced motion, tablet breakpoints, bundle/performance budgets, million-row/gallery profiling.
- **Acceptance:** agreed automated accessibility threshold passes; primary workflows complete without mouse; no tab loads unbounded result sets.
- **Tests:** automated a11y, keyboard E2E, responsive screenshots, Lighthouse-equivalent, large-data benchmarks.

---

## Epic L — additional platforms, encryption, mobile, and complex storage

### RPR-133 — Detect and read-only unlock BitLocker `[P2, M3]`

- **Depends:** RPR-031, RPR-036, RPR-070, RPR-081, RPR-096.
- **Deliver:** detection, metadata, supplied recovery-key/password flow, isolated read-only decrypted view contract, and normal TSK enumeration of that view.
- **Acceptance:** original device remains kernel RO; unlock material is secret; no metadata repair/write; unsupported protector remains visible.
- **Tests:** synthetic locked/unlocked/wrong key/corrupt header, source byte-compare, restart.

### RPR-134 — Add APFS and HFS+ filesystem fixtures/enumeration `[P2, M4]`

- **Depends:** RPR-008, RPR-037–040.
- **Deliver:** validated TSK/secondary adapter coverage, APFS containers/volumes, HFS+ entries, deleted capability matrix, mac timestamp/path normalization.
- **Acceptance:** claimed features have fixtures; unsupported snapshots/encryption are explicit.
- **Tests:** allocated/deleted/Unicode/resource-fork/corrupt/encrypted-signature fixtures.

### RPR-135 — Discover macOS installations, users, and artifacts `[P2, M4]`

- **Depends:** RPR-051, RPR-134, RPR-186.
- **Deliver:** macOS system/user profiles, application support, aliases, Finder metadata, installed apps, cloud roots, Time Machine evidence, and linkage to normalized Trash records from RPR-186.
- **Acceptance:** mac system noise rules are versioned and reversible like Windows rules.
- **Tests:** multiple users, moved home, case sensitivity, Time Machine layout, partial installation.

### RPR-136 — Parse Safari history and downloads `[P2, M4]`

- **Depends:** RPR-060, RPR-065–069, RPR-135.
- **Deliver:** Safari profiles/history/bookmarks/downloads/sessions/cache metadata normalized to browser schema with mac epoch/timezone handling.
- **Acceptance:** version differences and deleted recovery confidence are visible.
- **Tests:** versioned synthetic Safari profiles, WAL, corrupt/missing files, multiple users.

### RPR-137 — Parse Photos, iMessage, Mail, and WhatsApp media links `[P2, M4]`

- **Depends:** RPR-057, RPR-070, RPR-134, RPR-135.
- **Deliver:** isolated locators/parsers linking library/database records to media/attachments with user/account/thread provenance where safely available.
- **Acceptance:** databases are copied before parsing; missing media stays as record; no message is sent or account contacted.
- **Tests:** synthetic libraries/databases, missing attachment, schema versions, corrupt DB, duplicate media.

### RPR-138 — Integrate iLEAPP for iOS backups `[P2, M4]`

- **Depends:** RPR-057, RPR-070, RPR-096, RPR-103.
- **Deliver:** pinned MIT-licensed CLI sandbox, selected modules/profile, encrypted-backup password handoff, normalized result importer, raw report retention policy.
- **Acceptance:** iLEAPP failure does not lose detected backup; tool cannot network/source access; each imported artifact links to backup/path.
- **Tests:** synthetic unencrypted/encrypted/partial backup, wrong password, unsupported module, report importer.

### RPR-139 — Add ext2/3/4 filesystem coverage `[P2, M4]`

- **Depends:** RPR-008, RPR-037–043.
- **Deliver:** allocated/deleted/orphan entry normalization, UID/GID/mode/xattrs/symlinks/sparse/extents, timestamps, and corruption behavior.
- **Acceptance:** host never follows source symlinks or device nodes; deleted limitations documented per ext version.
- **Tests:** ext2/3/4 fixtures with deleted/Unicode/xattr/symlink/sparse/corrupt journal.

### RPR-140 — Discover Linux users and application artifacts `[P2, M4]`

- **Depends:** RPR-051, RPR-139, RPR-186.
- **Deliver:** `/home` and passwd-derived users, browsers, desktop app data, email, SSH/GPG, containers/VMs, package/application inventory, Linux noise rules, and linkage to normalized freedesktop Trash records from RPR-186.
- **Acceptance:** ownership/display identity distinction preserved; system paths remain accessible through noise toggle.
- **Tests:** multiple distros/user layouts, moved home, container data, partial `/etc`, false positives.

### RPR-141 — Detect and read-only unlock LUKS/LVM `[P2, M4]`

- **Depends:** RPR-031, RPR-036, RPR-070, RPR-081, RPR-096, RPR-139.
- **Deliver:** LVM metadata inspection, LUKS detection, supplied-secret read-only mapping, logical-volume discovery, and teardown.
- **Acceptance:** mapping is explicitly read-only; no `fsck`, repair, activation-write, or source metadata change.
- **Tests:** synthetic LVM/LUKS, wrong key, multiple LVs, corrupt metadata, source byte-compare, teardown after crash.

### RPR-142 — Add read-only mdraid discovery/assembly spike `[P3, M4]`

- **Depends:** RPR-002, RPR-014, RPR-036.
- **Deliver:** safety ADR, metadata-family capability matrix, multi-device identity contract, read-only assembly prototype against fixtures, and decision on product integration.
- **Acceptance:** no production support claim until source-write suite covers every member; one-source-per-instance exception is explicitly redesigned if approved.
- **Tests:** RAID1/5 synthetic fixtures, missing member, wrong order, degraded, byte-compare.

### RPR-143 — Define DVR/proprietary plugin API `[P3, M4]`

- **Depends:** RPR-033, RPR-039, RPR-070.
- **Deliver:** signed/allowlisted isolated plugin manifest for detection, read-only range input, normalized recordings/files, checkpoints, capabilities, and license facts.
- **Acceptance:** plugins cannot request device writes/network/general shell; unsupported raw disks remain visible/carvable.
- **Tests:** safe sample plugin, malicious permission requests, crash/resume, invalid output, version mismatch.

### RPR-144 — Validate `arm64` capability matrix `[P2, M4]`

- **Depends:** relevant completed adapters RPR-037–112.
- **Deliver:** CI/build/test matrix for control plane and each tool on ARM64, RPi-class resource profiles, unsupported-feature flags, and remote-worker guidance.
- **Acceptance:** ARM release never advertises a missing tool; core scan can run without local LLM/GPU.
- **Tests:** native/emulated ARM build plus selected filesystem, export, UI, and capability fixtures.

---

## Epic M — packaging, security, reliability, and release

### RPR-145 — Implement version-pinned installer `[P1, M5]`

- **Depends:** RPR-019, RPR-027, RPR-130.
- **Deliver:** inspectable install script/package flow, prerequisite/architecture checks, signed manifest verification, digest-pinned images, Arch Linux/Omarchy and Ubuntu/Debian systemd profiles, a validated Unraid lifecycle/template profile, directories/permissions, URLs, status, and uninstall instructions.
- **Acceptance:** Linux is the only scanner-host target; macOS/Windows are browser clients only; the installer never lists/selects/scans a disk automatically; Unraid active array/parity/cache/boot and Reperio state/scratch devices are ineligible as sources; reinstall is idempotent; failure rolls back only files it created; uninstall preserves catalog, checkpoints, scratch, and exports unless the operator runs a separate explicit owned-state removal command.
- **Tests:** clean Arch/Omarchy and Ubuntu/Debian installs, Unraid profile validation, upgrade handoff, unsupported non-Linux host/OS/arch, protected NAS-device rejection, bad signature/digest, occupied port, and rootful/rootless container-runtime variants.

### RPR-146 — Build signed multi-architecture OCI releases `[P1, M5]`

- **Depends:** RPR-006, RPR-144, RPR-145.
- **Deliver:** separate control/scanner/tool images, minimal bases, non-root defaults, immutable version labels/digests, provenance/signatures, amd64/arm64 manifests.
- **Acceptance:** scanner image has no network client requirement and no destructive disk utilities exposed; runtime versions match manifest.
- **Tests:** image policy scan, signature verify, architecture smoke, sandbox startup, unexpected binary inventory.

### RPR-147 — Generate SBOM, notices, and source offers `[P0, M5]`

- **Depends:** RPR-001, RPR-146.
- **Deliver:** per-image SBOM, dependency/tool licenses, attribution/notices, reciprocal-license source/offer artifacts as required, and release diff.
- **Acceptance:** unknown/prohibited license or missing source blocks release.
- **Tests:** license-policy fixture, SBOM completeness against image packages/binaries, notice link check.

### RPR-148 — Add dependency and parser security patch policy `[P0, M5]`

- **Depends:** RPR-006, RPR-070, RPR-146.
- **Deliver:** vulnerability scanning, severity/exception policy, parser update cadence, digest rebuild process, and emergency advisory/disable mechanism.
- **Acceptance:** known critical parser vulnerability without documented mitigation blocks release; adapters can be disabled by capability manifest.
- **Tests:** injected vulnerable package fixture, exception expiry, disabled adapter behavior.

### RPR-149 — Test migrations, upgrades, and rollback `[P1, M5]`

- **Depends:** RPR-022, RPR-032, RPR-145.
- **Deliver:** supported upgrade matrix, automatic state backup, migration validation, app/image rollback procedure, and checkpoint/tool compatibility handling.
- **Acceptance:** rollback never rolls database backward unsafely; incompatible versions stop with recovery steps.
- **Tests:** last two supported versions, failed migration, interrupted upgrade, old checkpoint, backup restore.

### RPR-150 — Add comprehensive fault-injection suite `[P0, M5]`

- **Depends:** RPR-020, RPR-024–026, RPR-044–048, RPR-106–113.
- **Deliver:** automated source disconnect/reconnect, EIO/slow reads, scratch/destination full, worker/API/host reboot, corrupt DB/checkpoint, parser hang/crash, provider outage, export/notification interruption.
- **Acceptance:** prior committed findings survive; state is truthful; no source change; retry loops are bounded.
- **Tests:** each named fault produces expected state/event and passes source byte comparison.

### RPR-151 — Run parser fuzzing and active-content security tests `[P0, M5]`

- **Depends:** RPR-070–082, RPR-116–132.
- **Deliver:** fuzz/property corpus for paths, archive members, parser JSON, URLs, metadata, images, PDFs, and UI escaping; browser CSP/security headers.
- **Acceptance:** crashes stay within sandbox; active content cannot execute in UI origin; findings remain catalogable after parser failure.
- **Tests:** seeded malicious corpus, HTML/SVG/PDF/script polyglots, formula injection, decompression bombs, oversized metadata.

### RPR-152 — Benchmark deep scan and UI scalability `[P1, M5]`

- **Depends:** RPR-034–059, RPR-120–132.
- **Deliver:** reproducible HDD/SSD/RPi profiles, million-entry catalog, 100k media, browser million-event, scratch use, memory/CPU/I/O, and regression budgets.
- **Acceptance:** prioritize completeness and bounded resources over speed; no unbounded memory/table load; UI interactions meet documented targets.
- **Tests:** benchmark CI smoke plus scheduled full runs and regression report.

### RPR-153 — Complete source-write penetration review `[P0, M5]`

- **Depends:** RPR-002, RPR-020, all device/tool/export tasks.
- **Deliver:** independent review of protocol, hostd, container flags, device permissions, parser profiles, path resolution, source/destination races, APIs, plugins, AI, and update channel.
- **Acceptance:** no unresolved path can write source; findings are fixed or release-blocking with explicit owner.
- **Tests:** rerun and extend RPR-020 using review attack cases; preserve report and exact release digest.

### RPR-154 — Write operator and administrator documentation `[P1, M5]`

- **Depends:** RPR-118–145.
- **Deliver:** install/update/uninstall for Arch Linux/Omarchy, Ubuntu/Debian, and validated Unraid deployments; Linux-only scanner-host and cross-platform browser-client boundaries; supported platforms/filesystems; attach/select; read-only proof; scratch sizing; resume/reconnect; review/dismiss/undo; wallet handling; exports; browser reports; AI privacy; passwords; notifications; auth/LAN; limitations; troubleshooting.
- **Acceptance:** no promise of complete recovery; failing-disk warning, wallet-secret handling, category-neutral retention, protected NAS devices, and no-wipe boundary are prominent; commands are version-pinned and tested.
- **Tests:** docs command validation, link check, fresh-operator walkthrough, screenshots/version check.

### RPR-155 — Create release acceptance fixture suite `[P0, M5]`

- **Depends:** RPR-008, RPR-133–144, RPR-146–154.
- **Deliver:** signed expected-results suite for every advertised filesystem/browser/artifact/destination/architecture, wallet-locator/protected-format claim, and Linux host profile, plus install-to-export end-to-end workflow.
- **Acceptance:** release manifest lists only passing capabilities; Arch Linux/Omarchy, Ubuntu/Debian, and Unraid claims are distinct; macOS/Windows are identified only as browser clients; failures remove/disable claims rather than being waived silently.
- **Tests:** full matrix on exact release images/digests, wallet redaction/no-network checks, Linux host-profile fixtures, and source byte comparison before/after.

### RPR-156 — Cut the first release candidate `[P1, M5]`

- **Depends:** RPR-145–155 and all tasks selected for the release scope.
- **Deliver:** tagged RC, signed artifacts/images/manifest/SBOM/notices, changelog, known limitations, upgrade/rollback, and acceptance report.
- **Acceptance:** all P0 gates pass; no critical vulnerability or source-write finding; capability claims match the tested matrix; installation command is reproducible.
- **Tests:** clean install on amd64 and arm64 Linux, NTFS deep end-to-end scan, progressive review/export, restart/resume, browser report, final byte-identical source proof.

---

## Epic N — extended intelligence, artifacts, and storage coverage

These IDs were added after the original milestone numbering. Schedule them by their listed milestone and dependencies, not after M5 merely because their IDs are higher.

### RPR-157 — Implement experimental Codex CLI subscription adapter `[P2, M3]`

- **Depends:** RPR-083–094.
- **Deliver:** adapter invoking the official Codex CLI with an operator-completed ChatGPT login, structured non-interactive result handling, capability/plan status, cancellation, sandboxed input package, and credential-store isolation.
- **Acceptance:** never copies or parses auth tokens; never mounts the operator's general home into a worker; remains experimental and removable; API-key/OpenAI-compatible adapters remain separate.
- **Tests:** mocked CLI success/error/quota/login-expired/cancel output plus manual login checklist from official documentation and privacy-gate verification.

### RPR-158 — Implement experimental Claude Code subscription adapter `[P2, M3]`

- **Depends:** RPR-083–094.
- **Deliver:** adapter invoking the unmodified official Claude Code client authenticated by the operator's supported Claude Pro/Max login, with structured output, fixed working directory, no tools, cancellation, and isolated credential access.
- **Acceptance:** no OAuth harvesting/proxy; no discovered file path or source device is exposed; feature disables cleanly if current terms or client behavior do not permit it.
- **Tests:** mocked success/error/quota/login-expired/cancel output, prompt-injection fixture, manual current-terms/auth checklist.

### RPR-159 — Implement experimental Gemini CLI subscription adapter `[P2, M3]`

- **Depends:** RPR-083–094.
- **Deliver:** adapter invoking the unmodified official Gemini CLI with operator Google login, structured output, fixed input package, tools disabled, cancellation, and isolated cached credentials.
- **Acceptance:** never piggybacks Gemini OAuth into a custom API or proxy; respects provider quotas/terms; unsupported headless or organizational accounts show actionable capability status.
- **Tests:** mocked success/error/quota/login-expired/cancel output, terms-policy denial path, and manual auth checklist.

### RPR-160 — Parse Windows activity and user-interaction artifacts `[P2, M2]`

- **Depends:** RPR-039, RPR-051, RPR-070, RPR-186.
- **Deliver:** isolated parsers for registry hives, LNK files, jump lists, recent documents, shell bags, Windows Timeline, prefetch, selected event logs, and links to normalized Recycle Bin evidence from RPR-186.
- **Acceptance:** artifacts support classification and related-file links without claiming the timestamp proves a human action; parser/version/raw source are retained.
- **Tests:** synthetic multi-user fixtures for every advertised artifact, corrupt/missing hive/log, version differences, and cross-parser comparison.

### RPR-161 — Discover and inspect Volume Shadow Copies read-only `[P2, M2]`

- **Depends:** RPR-036–040, RPR-070, RPR-160.
- **Deliver:** VSS detection and a proven read-only snapshot-view adapter, snapshot metadata, bounded enumeration policy, deduplication against current files, and historical provenance.
- **Acceptance:** no snapshot creation/deletion/resize/expose-write command exists; unsupported/corrupt VSS remains an artifact; snapshot recursion is bounded.
- **Tests:** synthetic NTFS with snapshots, deleted historical file, duplicate content, corrupt catalog, source byte comparison.

### RPR-162 — Parse Windows email and desktop messaging stores `[P2, M2]`

- **Depends:** RPR-039, RPR-050–054, RPR-070–071.
- **Deliver:** locators and sandboxed parsers/importers for PST/OST where legally distributable tooling exists, Thunderbird/mbox/EML, Windows Mail artifacts, and prioritized desktop messaging databases/media; link attachments to findings.
- **Acceptance:** account contact is impossible; unsupported encrypted/proprietary stores remain inventoried; messages, contacts, folders, timestamps, and attachments retain provenance.
- **Tests:** safe synthetic mail/message fixtures, multiple accounts, missing attachment, corrupt/encrypted store, malicious HTML email.

### RPR-163 — Integrate ALEAPP for Android backup/extraction layouts `[P2, M2]`

- **Depends:** RPR-057, RPR-070, RPR-138.
- **Deliver:** pinned ALEAPP CLI sandbox, selected modules/profile, normalized importer, artifact/media links, and raw-report retention policy for detected Android extractions/backups.
- **Acceptance:** tool has no source-device or network access; failures preserve the detected backup artifact; each result cites module/tool/version/source path.
- **Tests:** safe synthetic extraction with Chrome/messages/media, partial/corrupt layout, unsupported module, importer failure.

### RPR-164 — Inventory source repositories, code, and databases `[P2, M2]`

- **Depends:** RPR-038, RPR-050–054, RPR-070–071.
- **Deliver:** detect Git and other common repository metadata, programming-language/project manifests, SQLite and common database/backups/dumps, schema/table summary from copies, and safe repository facts without running hooks/builds.
- **Acceptance:** secrets in code are not transmitted by default; no database extension, hook, macro, build, or migration executes; unsupported database files remain visible.
- **Tests:** synthetic Git/project/database fixtures, bare repo, large DB, corrupt DB, malicious SQLite extension reference, symlink-like entry.

### RPR-165 — Recursively inspect nested disk and virtual-machine images `[P2, M2]`

- **Depends:** RPR-039, RPR-049, RPR-056, RPR-070.
- **Deliver:** safe read-only adapters for prioritized raw/VHD/VHDX/VMDK/ISO containers from scratch copies, nested-source identity, depth/size/work budgets, and normalized child volumes/findings.
- **Acceptance:** no hypervisor starts; no image mounts write; differencing/backing paths cannot escape the content store; recursion is opt-in/bounded.
- **Tests:** raw/VHDX/VMDK/ISO safe fixtures, missing backing file, path traversal backing reference, corrupt image, depth limit.

### RPR-166 — Detect and read-only unlock FileVault/APFS encryption `[P2, M4]`

- **Depends:** RPR-031, RPR-070, RPR-081, RPR-096, RPR-134.
- **Deliver:** encryption/protector metadata, supplied password/recovery-key flow, isolated read-only decrypted APFS view using a validated implementation, and normal enumeration linkage.
- **Acceptance:** original device remains kernel read-only; no container/volume metadata repair occurs; unsupported protector is visible and does not block raw carving policy.
- **Tests:** safe encrypted APFS fixtures with correct/wrong key, multiple volumes, corrupt metadata, restart, source byte comparison.

### RPR-167 — Add XFS and Btrfs coverage `[P3, M4]`

- **Depends:** RPR-008, RPR-037–044, RPR-139.
- **Deliver:** evaluated read-only parser adapters, allocated entry metadata, subvolume/snapshot/reflink facts where available, deletion-recovery capability matrix, and normalized errors.
- **Acceptance:** support claims are per-feature/per-version; no `xfs_repair`, `btrfs check --repair`, writable mount, or balance/scrub command exists.
- **Tests:** synthetic XFS/Btrfs allocated/snapshot/reflink/corrupt/deleted fixtures and source byte comparison.

### RPR-168 — Add ZFS/storage-appliance discovery spike `[P3, M4]`

- **Depends:** RPR-002, RPR-014–020, RPR-143.
- **Deliver:** safety ADR and prototype for read-only pool/dataset/snapshot discovery, member-device identity, supported versions/features, and NAS/appliance artifact locators.
- **Acceptance:** no pool import is advertised unless proven non-writing for all members; otherwise emit detectable/unsupported records and carving options.
- **Tests:** synthetic pool fixtures, missing member, encrypted dataset, corrupt labels, byte comparison.

### RPR-169 — Label potentially dangerous recovered content `[P2, M2]`

- **Depends:** RPR-050, RPR-054, RPR-070.
- **Deliver:** offline YARA-rule and optional ClamAV adapters, rule/signature version, malware/suspicious labels, confidence, and safe download warning; no automatic deletion/quarantine.
- **Acceptance:** scanning is local/no-network unless signature update is explicitly run; findings remain exportable after warning; tool cannot execute content.
- **Tests:** standard harmless test signatures, malformed file, timeout, false-positive override label, signature update separation.

### RPR-170 — Add optional known-file reference sets `[P3, M2]`

- **Depends:** RPR-039, RPR-052–054.
- **Deliver:** offline import/index adapter for licensed known-system/application hash sets such as an operator-provided NSRL dataset, version/source/license metadata, match evidence, and update workflow.
- **Acceptance:** reference sets only affect noise evidence, never deletion; no dataset download is automatic; unsupported hashes do not weaken SHA-256 integrity.
- **Tests:** small synthetic reference set, match/nonmatch, dataset update, corrupt import, license metadata missing.

### RPR-171 — Build a global activity timeline and map `[P2, M3]`

- **Depends:** RPR-060–069, RPR-072, RPR-137, RPR-160–162.
- **Deliver:** normalized cross-artifact timeline API/UI combining files, browser, messages, media metadata, application artifacts, and optional geolocation with source/confidence filters.
- **Acceptance:** raw and normalized timestamps/timezones remain visible; inferred event relationships are labeled; map tiles work offline by default or require a remote privacy acknowledgment.
- **Tests:** DST/epoch/missing timezone, contradictory times, duplicate events, GPS/no-GPS, million-event performance.

### RPR-172 — Add local media clustering and related-content intelligence `[P2, M3]`

- **Depends:** RPR-059, RPR-073–074, RPR-091–092.
- **Deliver:** optional local-only visual/audio similarity clusters, burst/event grouping, screenshots/documents/memes/photo-type labels, and related-item navigation; face grouping is a separate explicit opt-in capability.
- **Acceptance:** clustering never hides or identifies people by name; all groups are reversible views with model/version/threshold evidence.
- **Tests:** safe synthetic visual clusters, duplicates versus similar items, changed model, no accelerator, opt-in face-group isolation.

### RPR-173 — Add saved-search and automatic-interest notification rules `[P2, M3]`

- **Depends:** RPR-053–054, RPR-087–092, RPR-111–113, RPR-121.
- **Deliver:** operator-defined deterministic/semantic saved searches that can notify on new matches, with threshold/debounce, payload redaction, and per-rule provider requirements.
- **Acceptance:** a model outage cannot pause scanning; notification never auto-exports/dismisses; rule evaluation version is recorded.
- **Tests:** deterministic/semantic match, new-ingest trigger, duplicate suppression, provider failure, redacted payload.

### RPR-174 — Evaluate and integrate bulk feature extraction `[P3, M2]`

- **Depends:** RPR-019, RPR-044–049, RPR-070.
- **Deliver:** safety/license/maintenance evaluation of `bulk_extractor`, followed by a network-isolated adapter if approved for URLs, email addresses, domains, and other useful raw features with source offsets and strict sensitive-data categories.
- **Acceptance:** raw feature lists are opt-in views, bounded, and never treated as confirmed user records; tool writes only scratch and cannot access network.
- **Tests:** safe synthetic raw features, false-positive/random data, huge output limit, malformed source range, restart.

### RPR-175 — Implement validated multi-device RAID scanning `[P3, M4]`

- **Depends:** successful RPR-142 decision, RPR-020, RPR-036–049.
- **Deliver:** revised case/source schema for a fixed member set, per-member stable identity/read-only proof, read-only virtual assembly, degraded-state rules, checkpoint fingerprint, and normal downstream scanning.
- **Acceptance:** all members pass no-write checks; assembly cannot start with ambiguous/reordered/replaced members; no RAID metadata update command exists.
- **Tests:** RAID1/5/6/10 safe fixtures, missing/replaced member, wrong order, restart, source byte comparison for every member.

### RPR-176 — Implement the first DVR/CCTV recovery plugin `[P3, M4]`

- **Depends:** RPR-143, RPR-174.
- **Deliver:** choose one documented/high-value DVR format from available authorized fixtures, implement read-only recording discovery/carving, timestamps/channel metadata, safe video derivative, checkpoint, and plugin documentation.
- **Acceptance:** capability claim is exact to vendor/format/version; unknown formats remain raw/carving candidates; recovered video writes only scratch.
- **Tests:** allocated/deleted/partial/corrupt recordings, timestamp uncertainty, resume, malicious metadata, source byte comparison.

### RPR-177 — Cross-validate carving and manage custom signatures `[P3, M4]`

- **Depends:** RPR-046–049, RPR-070.
- **Deliver:** evaluated second carving engine or corpus-based cross-validation, versioned custom PhotoRec signature packs, false-positive metrics, format enable/disable settings, and safe contribution guide.
- **Acceptance:** a custom signature cannot invoke code or arbitrary output paths; format support is evidence-based and records fragmentation limitations.
- **Tests:** positive/negative corpus per added signature, duplicate provenance, partial/fragmented files, resume compatibility.

---

## Epic O — removable, optical, floppy, and legacy media

These tasks extend the same one-source, read-only pipeline to media that may have no serial number, may be replaced inside a reusable reader, or may expose sessions/tracks rather than a normal partition table. They do not authorize imaging, mounting, formatting, blanking, burning, repair, or source writes.

### RPR-178 — Extend the source identity contract to removable media `[P0, M0]`

- **Depends:** RPR-007, RPR-009–012.
- **Deliver:** versioned source-kind and media-identity schemas for fixed disks, USB flash, card readers/media, optical drives/discs, floppy drives/media, and legacy adapters; separate reusable reader identity from inserted-medium identity; include capacity, sector/block size, geometry, write-protect signals, TOC/session facts, sampled fingerprint, and media-change generation.
- **Acceptance:** no API treats `/dev/sdX`, `/dev/sr0`, or `/dev/fd0` alone as identity; missing serials use documented evidence and warnings; inserting a different same-capacity disc/card/floppy in the same reader produces a distinct source identity.
- **Tests:** stable USB serial, SD card without serial, two same-size cards, optical disc swap in one drive, floppy swap, empty reader, changed TOC, unreadable fingerprint sample, identity-schema compatibility.

### RPR-179 — Enumerate and enforce read-only removable sources `[P0, M0]`

- **Depends:** RPR-013–020, RPR-178.
- **Deliver:** host-controller discovery/preparation for flash/card, optical, and floppy devices; hotplug/media-change reporting; automount/holder detection; kernel/device read-only verification; physical lock/capability reporting; fixed allowlisted read-only operations for geometry and optical TOC.
- **Acceptance:** scan launch fails when read-only status or medium identity cannot be proven; physical SD lock and write-once optical media are informational defense-in-depth, not substitutes for kernel/process denial; no eject, burn, blank, format, packet-write, repair, or generic ioctl/API exists.
- **Tests:** mocked udev/sysfs for populated/empty readers, mounted RW/RO card, write-lock states, optical writer with RW disc, floppy, unplug race, media swap race, and hardware/virtual source byte comparison before/after attempted writes.

### RPR-180 — Persist media, session, and replacement-aware checkpoints `[P0, M1]`

- **Depends:** RPR-021–025, RPR-178–179.
- **Deliver:** catalog migrations for `source_devices`, inserted `source_media`, media-change generations, geometry, optical tracks/sessions, and replacement/disconnect events; checkpoint keys bind to full medium identity rather than reader path.
- **Acceptance:** a scan can resume after reinserting the same verified medium; a changed fingerprint, geometry, TOC, session table, or capacity blocks resume and offers a new case; prior findings remain browsable when the source is absent.
- **Tests:** same-medium reinsertion, same reader/different medium, same capacity/different samples, added optical session, changed floppy geometry, unreadable sample, migration round trip, interrupted checkpoint.

### RPR-181 — Run the deep pipeline on USB flash and memory cards `[P1, M1]`

- **Depends:** RPR-036–054, RPR-178–180.
- **Deliver:** partitioned and partitionless/superfloppy scanning for USB flash, SD/microSD, CompactFlash, Memory Stick, SmartMedia, MMC, Microdrive, and similar Linux block media; reuse validated FAT16/32, exFAT, NTFS, and ext adapters; run filesystem deleted-entry recovery followed by bounded unallocated/whole-medium carving and normal classification/export.
- **Acceptance:** allocated, hidden, trashed, deleted, and carved findings have distinct provenance; camera/DCIM and portable-backup content ranks usefully without hiding other files; UI states TRIM, garbage-collection, wear-leveling, and continued-use limits without declaring unrecoverable blocks “clean.”
- **Tests:** partitioned FAT32 SD, partitionless exFAT card, FAT16 camera card, NTFS USB, deleted/fragmented/overwritten files, lost partition, corrupt boot sector, disconnect/resume, same-source byte comparison, export to separate storage.

### RPR-182 — Add FAT12 floppy enumeration and deleted recovery `[P2, M2]`

- **Depends:** RPR-008, RPR-037–049, RPR-178–180.
- **Deliver:** DOS FAT12/superfloppy geometry detection, allocated/deleted directory entry normalization, deleted cluster-chain confidence, bad-sector handling, and raw carving for readable unallocated sectors; support exact validated capacities/geometries first.
- **Acceptance:** ambiguous geometry is not guessed silently; original names/timestamps are preserved only when metadata survives; reused, fragmented, partial, and bad-sector files are labeled; no filesystem repair or boot-sector rebuild function is exposed.
- **Tests:** generated 360 KiB/720 KiB/1.2 MiB/1.44 MiB fixtures as supported, deleted allocated/reused/fragmented files, bad sectors, corrupt FAT copies, non-DOS signature, swap/resume denial, source byte comparison.

### RPR-183 — Inventory optical drives, tracks, and sessions `[P2, M2]`

- **Depends:** RPR-019–020, RPR-070, RPR-178–180.
- **Deliver:** fixed read-only libcdio/xorriso-equivalent inspection adapters for CD, DVD, and Blu-ray media type/state, data versus audio tracks, TOC, addressable session starts/sizes, writer capabilities, readable range, and media fingerprint; normalize each data session/track as a scan target.
- **Acceptance:** single-session, multisession, mixed-mode, overwritable, quick-blanked, blank, empty-drive, unsupported, and firmware-blocked states are distinguishable; an optical writer never receives an output drive or write/blank/format command.
- **Tests:** synthetic/sacrificial single and multisession CD, DVD/BD-shaped metadata, mixed-mode, formatted DVD-RW single-visible-state, quick-blanked/zero-size response, disc swap, malicious tool output, timeout, no-write proof.

### RPR-184 — Enumerate ISO 9660, UDF, and previous optical sessions `[P2, M2]`

- **Depends:** RPR-037–040, RPR-070, RPR-183.
- **Deliver:** read-only ISO 9660/Joliet/Rock Ridge and UDF adapters; enumerate every addressable historical session/directory tree; link files hidden/removed by newer sessions; normalize names, timestamps, extents, session provenance, duplicates, and parser limitations without mounting.
- **Acceptance:** the newest session is not assumed to be the only evidence; identical content across sessions deduplicates bytes but preserves every provenance record; unsupported UDF versions and overwritable media without visible history remain explicit findings/capabilities.
- **Tests:** ISO/Joliet/Rock Ridge Unicode, multisession add/remove/rename, duplicate extents, UDF allocated/deleted where supported, malformed descriptors, conflicting timestamps, mixed data tracks, parser disagreement, source byte comparison.

### RPR-185 — Recover readable deleted and raw optical content `[P2, M2]`

- **Depends:** RPR-046–049, RPR-070, RPR-183–184.
- **Deliver:** addressable older-session recovery, UDF/metadata deleted-entry recovery where validated, and PhotoRec-compatible carving over readable optical sector ranges with slow/bad-sector progress, partial outputs, source offsets, and durable checkpoints.
- **Acceptance:** quick-blanked media is attempted only when the drive exposes readable sectors; fully overwritten or firmware-hidden ranges are labeled unavailable rather than empty; retries are bounded and never block already recovered findings; all output goes to separate scratch/export storage.
- **Tests:** obsolete previous-session file, quick-blanked readable-range fixture, overwritten negative fixture, scratched/bad-sector map, partial carved file, drive returning zero capacity, disconnect/reinsert, resume, byte-identical source proof.

### RPR-186 — Normalize Recycle Bin and Trash across platforms `[P1, M2]`

- **Depends:** RPR-039, RPR-051, RPR-070.
- **Deliver:** isolated parsers/locators for Windows `$Recycle.Bin` metadata/payload pairs, macOS user and volume Trash layouts, and freedesktop `files`/`info` Trash layouts; normalize platform/user, original path, deletion time, metadata/payload link, and present/deleted/carved recovery state.
- **Acceptance:** “currently in trash” and “filesystem-deleted after trash was emptied” are separate states; missing metadata or payload remains visible; original paths are treated as untrusted data and never used as host output paths; recovered trash items appear in a dedicated filter/tab and normal categories.
- **Tests:** multiple users/volumes, Windows paired/orphan metadata and payload, macOS/freedesktop layouts, Unicode/path traversal, missing/corrupt info, trashed then filesystem-deleted payload, carved duplicate, timestamp uncertainty.

### RPR-187 — Build the removable-media selection and batch workflow `[P1, M1]`

- **Depends:** RPR-118–121, RPR-178–181.
- **Deliver:** non-technical source selector grouping disks, flash/cards, optical, and floppy/legacy readers; media/reader facts, session/geometry summary, read-only proof, identity-strength warning, capacity-aware scratch estimate, insertion/removal state, and one-at-a-time “finish this medium, insert the next” case workflow.
- **Acceptance:** replacing media never resumes or starts automatically; the operator can browse/export completed prior cases while scanning the next medium; empty readers and unsupported media explain what is needed; no erase, format, initialize, burn, blank, repair, or source-delete control exists.
- **Tests:** USB/SD/optical/floppy cards, empty/swap/disconnect/reinsert, same-reader new medium, unsupported format, insufficient scratch, prior-case navigation, keyboard/accessibility, destructive-label/API absence.

### RPR-188 — Establish the removable-media acceptance matrix `[P1, M2]`

- **Depends:** RPR-008, RPR-178–187.
- **Deliver:** reproducible generated fixtures, optional sacrificial-hardware procedure, and signed expected-results matrix for every advertised flash/card, optical filesystem/session, floppy geometry, trash layout, reader architecture, disconnect, bad-sector, and read-only property.
- **Acceptance:** no capability appears in the UI/release manifest without a passing positive, malformed/negative, resume, and source-byte comparison case; fixtures contain no real personal data and generated disk/media images remain outside Git.
- **Tests:** deterministic fixture rebuilds, full adapter matrix on amd64/arm64 where supported, pre/post hashes, tool-version change, missing hardware skip truthfulness, deliberate unsupported-capability rejection.

### RPR-189 — Define the legacy removable-media plugin contract `[P3, M4]`

- **Depends:** RPR-033, RPR-070, RPR-143, RPR-178–180.
- **Deliver:** source-kind detection and isolated range-reader/plugin contract for Zip/Jaz, LS-120/SuperDisk, magneto-optical, non-DOS floppy, and other block-addressable legacy media; include geometry/encoding/version capabilities, checkpoint, normalized entries, and exact support claims.
- **Acceptance:** unknown media stays visible and eligible for safe raw carving; a plugin cannot mount, write, format, repair, issue generic device commands, or claim a family from a weak signature; adapters are separately removable and license reviewed.
- **Tests:** safe sample plugin, false signature, geometry mismatch, malicious permission request, crash/resume, output flood, unknown-media fallback, source byte comparison.

### RPR-190 — Implement the first evidence-backed legacy-media adapter `[P3, M4]`

- **Depends:** RPR-182, RPR-188–189.
- **Deliver:** select one high-value legacy block format based on authorized media and compatible hardware—such as a specific Zip/Jaz, LS-120, magneto-optical, or non-DOS floppy filesystem—and implement exact read-only allocated/deleted recovery, raw fallback, fixtures, and capability documentation.
- **Acceptance:** the claim names the exact media/filesystem/version and reader constraints; no generic “all legacy media” claim; unsupported variants remain inventory/raw-carving candidates; recovered output uses separate scratch.
- **Tests:** allocated/deleted/partial/corrupt fixture, wrong geometry/version, bad sector, disconnect/resume, unknown variant, source byte comparison, cross-tool comparison when available.

### RPR-191 — Evaluate sequential tape and non-data optical extraction `[P3, M4]`

- **Depends:** RPR-002, RPR-070, RPR-178–180, RPR-183, RPR-189.
- **Deliver:** feasibility ADR and prototype boundary for DAT/DLT/LTO or other available sequential tape plus audio/mixed-mode optical tracks; document Linux hardware access, positioning/read commands, identity, resume, output formats, licensing, drive-cleaning/firmware risks, and whether each belongs in Reperio.
- **Acceptance:** block-media support never implies tape support; no production claim or adapter proceeds without compatible authorized hardware and a no-write test; unsupported/audio-only content is inventoried truthfully; extraction writes only scratch.
- **Tests:** mocked command/protocol fixtures, media swap, read error, end-of-data, resume-position mismatch, malicious metadata, unsupported hardware, and a manual sacrificial-media byte/no-write checklist if the spike advances.

---

## Recommended first agent assignments

Do not begin feature coding with the UI. The safest initial sequence is:

1. RPR-001, then RPR-002. Review and record each task before starting the next.
2. RPR-003 after threat-model review.
3. RPR-004–008 to create the executable skeleton and fixtures.
4. RPR-009–020 and RPR-178–180 in dependency order until fixed and removable source no-write/identity suites pass.
5. RPR-021–035 for catalog/job/scanner contracts.
6. RPR-036–040 and RPR-181 for the first read-only disk/flash allocated-file path.
7. RPR-050–054, then RPR-058, RPR-105–107, and RPR-116–121 for the first useful review/export loop with early wallet/vault/key inventory.

No agent should integrate PhotoRec, archive parsers, password tools, AI providers, or remote destinations before the generic safety and sandbox dependencies named in those tasks are complete.
