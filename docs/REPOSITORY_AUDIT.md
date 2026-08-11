# Pre-push repository audit

Audit date: 2026-08-10

## Snapshot reviewed

- Remote: `git@github.com:jfrancolopez/Reperio.git`
- Default branch: `main`
- The repository bootstrap and planning contracts are maintained directly on `main` at the owner's direction.
- The current development workflow is one checkout, one implementation agent, and one backlog task at a time; no parallel worktrees or task branches are assumed.
- The GitHub repository is publicly reachable.
- Repository files cannot prove current server-side ruleset settings. The matching direct-`main` owner-mode checklist must be verified in GitHub settings.
- GitHub Actions runs repository policy and full-history secret scanning on every `main` push; dependency review also runs in optional pull-request mode.
- No scanner, API, web application, container, privileged host service, package manifest, release, or real disk fixture exists yet.

This is a point-in-time audit, not a permanent status page. Use `git status`, the current task diff, and GitHub checks for the current state.

## Findings and disposition

| Finding | Risk | Disposition on this branch |
|---|---|---|
| No ignore rules | Secrets, source-media content, runtime state, and large recovery artifacts could be added accidentally. | Added layered ignore rules for secrets, credentials, state, scratch, exports, disk images, databases, models, wordlists, build output, logs, and editor files. |
| Ignore rules alone are bypassable | `git add -f` or a renamed file can still enter history. | Added a dependency-free validator that inspects tracked and untracked candidate files for prohibited paths/types, secret signatures, symlinks, size, and hygiene. |
| No continuous integration | Agents could claim completion without a common validation result. | Added a pull-request/`main` workflow with repository policy, checksum-verified worktree/full-history Gitleaks, and dependency review jobs. |
| Workflow supply-chain risk | Mutable action tags can be retargeted; broad tokens can amplify compromise. | Every Action is pinned to a full commit SHA; workflow permissions are read-only, checkout credentials are not persisted, and jobs have timeouts. Local policy blocks unsafe triggers, write permissions, mutable Actions, and expression interpolation in shell steps. |
| No dependency update automation | Pinned Actions could become stale unnoticed. | Added weekly Dependabot updates for the GitHub Actions ecosystem. |
| Server-side `main` settings are not represented in Git | Force pushes or deletion could damage the audit trail. | The setup checklist blocks force pushes/deletion while permitting the requested sequential owner pushes. Local pre-push validation and post-push Actions are mandatory; optional PR enforcement is documented separately. |
| No private vulnerability route | Sensitive reports could be posted publicly. | Added `SECURITY.md` and a private-security-advisory contact route. |
| Documentation was correct but sparse at entry | New operators and small implementation agents could overestimate current readiness or miss navigation. | Rebuilt the README, added agent onboarding, GitHub setup, and this audit while preserving the master plan/backlog as the authoritative contracts. |
| No selected project license | Redistribution and dependency policy are unresolved. | Resolved by `RPR-001`: the project is licensed under Apache-2.0 (`LICENSE`), the decision is recorded in `docs/adr/0001-project-license.md`, and a machine-checkable dependency-license gate now runs inside `make validate`. |

## What `make validate` now proves

- Candidate repository files contain no supported high-confidence credential signatures.
- Reperio runtime/recovery roots, disk-image formats, private key/keystore formats, and runtime databases are absent.
- Repository files are below 5 MiB and symbolic links are absent.
- UTF-8 text hygiene, final newlines, and Git whitespace checks pass.
- Local Markdown links resolve within the repository.
- The backlog defines every `RPR-001` through `RPR-191` exactly once and documentation references no undefined numeric task.
- JSON and shell scripts have valid syntax.
- The dependency license gate (`scripts/check_dependency_licenses.py`) validates the dependency registry against the Apache-2.0 license policy, including the missing-metadata and reciprocal-license rejection fixtures.
- Workflows use safe triggers, read-only permissions, immutable Action SHAs, bounded jobs, and no direct GitHub-context expression inside shell commands.

These checks are repository guardrails, not proof that future application code is correct. `RPR-005` established the pinned quality commands (format/lint/type-check/unit/frontend/schema/docs checks and their aggregate target) and CI now runs them on every push. `RPR-006` remains partially open for the schema failing-fixture and container smoke gates.

## Remaining controls and recurring checks

1. Before every authorized `main` push, review the full task diff and run focused tests, `make validate`, and `make secret-scan`; run `make workflow-lint` whenever workflow files change.
2. After every push, confirm `repository-policy` and `secret-scan` pass for the exact commit before starting another task. Correct failures with a new commit rather than rewriting history.
3. Apply and periodically verify [the GitHub repository setup checklist](GITHUB_SETUP.md), especially force-push/deletion protection.
4. Keep the dependency registry complete and current; every new dependency must pass the license gate and the intake checklist before it is committed.
5. Add application linters, tests, schema compatibility, license metadata, container smoke tests, and artifact retention as the RPR-004–006 scaffold is implemented.

No secret scanner can guarantee that a credential is harmless. If a real secret is ever committed, rotate or revoke it immediately before considering history cleanup.
