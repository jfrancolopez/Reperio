# Reperio implementation rules

These rules apply to every task and every file in this repository.

## Source-disk safety is the first invariant

- Never add a wipe, erase, delete-from-source, format, initialize, optical burn/blank, partition-write, filesystem-repair, or source-remount-write operation.
- Open the source block device and every source file read-only. Do not rely on a UI promise; enforce the rule at the kernel, container, process, and code levels.
- Do not mount a source filesystem in the core workflow. Use read-only filesystem parsers against the block device. A future exception requires a new architecture decision and automated proof that it cannot write.
- Never pass the source device into a general-purpose AI tool, script console, archive extractor, preview renderer, or network-enabled process.
- Recovered files, thumbnails, OCR products, indexes, reports, checkpoints, and logs must go to dedicated scratch or export storage, never to the source device.
- Do not automatically delete completed recovered copies. Cleanup may remove only proven-incomplete files in Reperio-owned temporary storage under a documented policy; uninstall preserves state by default.
- Before any copy or export, prove that the destination is not the selected source medium, its reader-backed device, or one of its child partitions.
- “Dismiss” is a reversible catalog flag. It must never remove the original, a recovered copy, or the only metadata record.
- If an implementation proposal conflicts with these rules, stop and document the conflict instead of weakening a guardrail.

## Treat all source-media content as hostile

- Never execute a discovered binary, script, macro, shortcut, installer, browser extension, or document action.
- Run third-party parsers and preview generators without network access, without Linux capabilities, as a non-root user, with a read-only root filesystem, bounded CPU/memory/PIDs/output, and a timeout.
- Serve safe derivatives in the UI. Do not render source HTML, SVG, scripts, or active document content directly in the browser.
- Keep passwords, provider sessions, destination credentials, and notification secrets out of logs, task payloads, exported reports, and source control.

## Task discipline for smaller agents

- Work on one backlog task ID at a time. Read that task, its dependencies, and linked contract sections before editing.
- Do not implement adjacent backlog tasks merely because they seem convenient.
- Preserve public schemas and interfaces defined by completed dependency tasks. If a schema must change, add a migration and update contracts and tests.
- Prefer deterministic parsing and rules. AI may enrich or rank findings but may not be the sole mechanism that discovers files or hides them.
- Add or update tests for every acceptance criterion. Include failure and interruption paths, not only the happy path.
- Do not claim support for a filesystem, browser, encryption format, destination, architecture, or model provider without a fixture-backed integration test.
- Pin third-party tool and container versions by immutable release or digest. Record license and source information.
- Keep commits scoped to one task ID when possible and reference the ID in the commit message.

## GitOps and repository hygiene

- Git `main` is the implementation source of truth. Begin assigned work from current protected `main` on a branch named `<actor>/rpr-nnn-short-name`; never implement directly on `main`.
- Inspect branch and working-tree status before editing. Preserve unrelated user or agent changes and do not rewrite history belonging to another task.
- Do not stage, commit, push, open a pull request, alter remote settings, or publish an artifact unless the assigned task explicitly authorizes that action. When authorized, never push directly to `main`.
- Run `make validate`, focused task tests, and affected integration tests before reporting completion. Do not weaken, skip, or edit a quality gate merely to make a branch pass.
- `.gitignore` is convenience, not a security boundary. Never force-add or rename around policy for source data, recovered content, disk images, runtime databases, logs, models, wordlists, secrets, credentials, or personal information.
- Test only with minimal deterministic synthetic fixtures. Any intentionally secret-like test value must be documented, inert, and scoped so the secret scanner's expected failure can be tested without teaching it to ignore broad patterns.
- GitHub Actions must use safe pull-request triggers, explicit least-privilege permissions, job timeouts, non-persistent checkout credentials, and external actions pinned to a full commit SHA.
- Production/device credentials and privileged/raw-device access are prohibited in pull-request CI. A later release workflow must be isolated from untrusted changes and reviewed as a separate backlog task.
- Follow `CONTRIBUTING.md` and `docs/AGENT_START_HERE.md`; use the pull-request template as the minimum evidence contract.

## Standard completion report

Every completed task should report:

1. Task ID and outcome.
2. Files and public interfaces changed.
3. Tests executed and their results.
4. Safety properties affected and how they were verified.
5. Known limitations or follow-up backlog IDs.
