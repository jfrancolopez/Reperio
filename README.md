# Reperio

**Find what matters before the disk is gone.**

[![Repository quality gates](https://github.com/jfrancolopez/Reperio/actions/workflows/quality-gates.yml/badge.svg)](https://github.com/jfrancolopez/Reperio/actions/workflows/quality-gates.yml)

Reperio is a local-first, read-only disk discovery and recovery workstation for authorized personal and company media. It is designed to turn an old Windows, macOS, Linux, mobile-backup, DVR, RAID, or raw disk into a searchable, progressively populated catalog—then help one operator copy and verify the material worth keeping.

> **Current stage:** product direction and implementation backlog are complete; runtime implementation has not started. Reperio is not yet installable or safe to use on a real disk.

## At a glance

| Goal | Reperio's approach |
|---|---|
| Find everything useful | Inventory allocated, hidden, deleted, orphaned, carved, encrypted, corrupted, and application-managed artifacts. |
| Avoid system noise | Keep every finding available while ranking user-created and user-manipulated material above operating-system, cache, and application boilerplate. |
| Recover before reuse | Preview, dismiss, search, and export findings while a resumable deep scan continues in the background. |
| Preserve the source | Enforce read-only access at the host, kernel, container, process, API, and product-design layers. Reperio will never include wiping or source repair. |
| Stay local by default | Discovery is deterministic and offline. Local or LAN AI is optional; separately enabled remote providers receive only explicit derived content. |
| Remain easy to operate | One disk and one operator per instance, a LAN-accessible web UI, progressive results, notifications, and verified exports to separate storage. |

## The operator experience

1. Attach one authorized source disk to a supported Linux host.
2. Start a signed, version-pinned Reperio release.
3. Identify the disk by model, serial, size, transport, and stable device path.
4. Confirm the source is kernel read-only and scratch/export storage is physically separate.
5. Leave the exhaustive scan running; reconnect or resume after interruption.
6. Browse live findings by photos, video, documents, browser activity, messages, backups, wallets, software, archives, and other useful categories.
7. Export selected originals plus provenance and checksums. Verify the copy independently before deciding what happens to the disk outside Reperio.

Reperio never wipes, formats, repairs, repartitions, remounts writable, or deletes from the selected source. Dismissing an item only hides its catalog record and is undoable.

## Planned capabilities

- Allocated-file inventory plus deleted-entry recovery, lost partition discovery, unallocated-space carving, corruption assessment, duplicates, and hidden content.
- Windows-first discovery followed by macOS, Linux, mobile backups, nested virtual disks, RAID, DVR/CCTV, and storage-appliance formats.
- Browser history across operating-system users, browsers, and profiles, with timeline/search/detail views and CSV, JSON, and full-report export.
- Safe photo and video galleries, full-screen derivatives, document/PDF reading, metadata, OCR, transcription, language detection, and translation.
- Recognition of iPhone/Android backups, iMessage, WhatsApp, mail, source code, databases, password vaults, wallets, keys, certificates, and protected archives.
- Opt-in, resource-limited local password auditing with operator-supplied passwords, wordlists, rules, and combinations.
- Search, explainable ranking, semantic enrichment, and comparison across zero, one, or several local, LAN, or explicitly enabled remote models.
- Live progress, thresholds, completion/failure notifications, reversible bulk dismissal, and export before the scan finishes.
- Local disk, NAS, SFTP/FTP, WebDAV, S3-compatible, cloud, and other supported remote destinations, with copy verification and manifests.

## Architecture boundary

```mermaid
flowchart LR
    UI["LAN web interface"] --> API["Unprivileged control plane"]
    API --> DB["Catalog and resumable jobs"]
    API --> HOST["Narrow Linux host controller"]
    HOST -->|"read-only device"| SCAN["Network-isolated scanner"]
    SCAN -->|"findings"| DB
    SCAN -->|"copies only"| SCRATCH["Separate scratch storage"]
    SCRATCH --> WORKERS["Sandboxed preview, OCR, and parsing workers"]
    WORKERS --> AI["Optional local, LAN, or remote model adapters"]
    DB --> EXPORT["Verified export worker"]
    SCRATCH --> EXPORT
    EXPORT --> DEST["Separate local or remote destination"]
```

Only the small Linux host controller can identify and prepare a physical device. The scanner receives that device read-only, without network access. Preview, AI, export, and notification processes never receive a source-device handle. Full trust boundaries and limitations are in the [master plan](docs/MASTER_PLAN.md).

## Safety model

Reperio treats both the disk and its content as hostile:

- The source is selected by stable identity, set kernel read-only, opened `O_RDONLY`, and never mounted in the core workflow.
- Discovered binaries, scripts, macros, shortcuts, extensions, HTML, SVG, and active documents are never executed or served directly.
- Third-party parsers run non-root, without capabilities or network, with a read-only root, bounded resources and output, and strict timeouts.
- Originals, carved bytes, thumbnails, OCR, indexes, reports, checkpoints, logs, and exports can only go to Reperio-owned storage proven separate from the source.
- AI can explain, compare, cluster, translate, and rank; it cannot control discovery completeness, delete data, or permanently hide a finding.
- Real disk content, credentials, runtime state, recovery output, source images, databases, model files, and wordlists are prohibited from Git.

Direct scanning still stresses the original disk. Failing media can deteriorate, and overwritten, TRIM-discarded, physically unreadable, fragmented, or strongly encrypted data may be unrecoverable. Reperio reports evidence and confidence; it is not a forensic-certification product.

## Building with agents

Git and the protected `main` branch are the implementation source of truth. Agents receive one `RPR-NNN` task at a time and must follow its contracts, acceptance criteria, tests, and safety boundaries.

```sh
git switch -c codex/rpr-nnn-short-name
make validate
```

Start with [agent onboarding](docs/AGENT_START_HERE.md), use the [task packet template](docs/AGENT_TASK_TEMPLATE.md), and follow [the contribution workflow](CONTRIBUTING.md). The same dependency-free validation runs on every pull request; GitHub adds full-history secret scanning and dependency review.

## Project map

| Document | Purpose |
|---|---|
| [Master plan](docs/MASTER_PLAN.md) | Product decisions, safety invariants, architecture, pipeline, UX, providers, release model, and honest limitations. |
| [Implementation backlog](docs/BACKLOG.md) | 177 small, dependency-ordered tasks with deliverables, acceptance criteria, and tests. |
| [Requirements traceability](docs/TRACEABILITY.md) | Maps every confirmed requirement to specification sections and backlog coverage. |
| [Agent start guide](docs/AGENT_START_HERE.md) | Exact workflow for giving bounded work to implementation agents. |
| [Agent task template](docs/AGENT_TASK_TEMPLATE.md) | Reusable task packet that smaller models can follow without guessing. |
| [Repository rules](AGENTS.md) | Non-negotiable safety, hostile-content, testing, and scope rules for every agent. |
| [Contributing](CONTRIBUTING.md) | Branch, validation, pull-request, dependency, and completion-report process. |
| [GitHub setup](docs/GITHUB_SETUP.md) | One-time ruleset and repository-security settings needed after the first push. |
| [Pre-push audit](docs/REPOSITORY_AUDIT.md) | Point-in-time repository findings, implemented controls, and remaining manual actions. |
| [Security policy](SECURITY.md) | Private vulnerability reporting and current support boundaries. |

## Delivery sequence

1. **M0 — Safety and contracts:** prove the no-write boundary, create synthetic fixtures, and establish schemas and repository quality gates.
2. **M1 — Allocated Windows MVP:** inventory NTFS/FAT/exFAT, show live findings, and export verified local copies.
3. **M2 — Deep Windows:** add deleted recovery, carving/resume, browser history, previews, OCR, application artifacts, and notifications.
4. **M3 — Intelligence and protected files:** add multi-model enrichment, semantic search, and bounded password workflows.
5. **M4 — macOS, Linux, mobile, RAID, and DVR:** expand only when fixture-backed support proves each capability.
6. **M5 — Release:** signed multi-architecture images, a version-pinned installer, fault testing, operator documentation, and acceptance evidence.

## Authorization and license

Use Reperio only on media you own or are explicitly authorized to examine. The operator is responsible for applicable workplace policy, privacy, retention, and legal requirements.

No project license has been selected yet. Until `RPR-001` is complete and a root license is committed, no permission is granted to copy, modify, or redistribute the project beyond rights provided by applicable law.
