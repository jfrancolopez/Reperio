# Pre-push repository audit

Audit date: 2026-08-10

## Snapshot reviewed

- Remote: `https://github.com/jfrancolopez/Reperio.git`
- Default branch: `main`
- Remote baseline: commit `7ed66b5` (`Initial commit`)
- The baseline `main` matched `origin/main` before this hardening pass.
- The planning documents were local and uncommitted; work was initially isolated on `codex/repository-hardening`, then moved to `main` at the owner's direction for the one-time repository bootstrap. The unused local branch is removed after the verified push.
- The GitHub repository is publicly reachable.
- GitHub currently reports `main` as unprotected, with no required status checks. This remains true until the server-side checklist is applied after the first workflow run.
- No scanner, API, web application, container, privileged host service, package manifest, release, or real disk fixture exists yet.

This is a point-in-time audit, not a permanent status page. Use `git status`, the pull-request diff, and GitHub checks for the current state.

## Findings and disposition

| Finding | Risk | Disposition on this branch |
|---|---|---|
| No ignore rules | Secrets, disk content, runtime state, and large recovery artifacts could be added accidentally. | Added layered ignore rules for secrets, credentials, state, scratch, exports, disk images, databases, models, wordlists, build output, logs, and editor files. |
| Ignore rules alone are bypassable | `git add -f` or a renamed file can still enter history. | Added a dependency-free validator that inspects tracked and untracked candidate files for prohibited paths/types, secret signatures, symlinks, size, and hygiene. |
| No continuous integration | Agents could claim completion without a common validation result. | Added a pull-request/`main` workflow with repository policy, checksum-verified worktree/full-history Gitleaks, and dependency review jobs. |
| Workflow supply-chain risk | Mutable action tags can be retargeted; broad tokens can amplify compromise. | Every Action is pinned to a full commit SHA; workflow permissions are read-only, checkout credentials are not persisted, and jobs have timeouts. Local policy blocks unsafe triggers, write permissions, mutable Actions, and expression interpolation in shell steps. |
| No dependency update automation | Pinned Actions could become stale unnoticed. | Added weekly Dependabot updates for the GitHub Actions ecosystem. |
| Remote `main` is unprotected | Direct or unreviewed changes could make Git cease to be the source of truth. | Added contributor and agent workflows, task/PR templates, CODEOWNERS, and an exact server-side ruleset checklist. Remote enforcement remains a required manual GitHub setting after the first workflow run. |
| No private vulnerability route | Sensitive reports could be posted publicly. | Added `SECURITY.md` and a private-security-advisory contact route. |
| Documentation was correct but sparse at entry | New operators and small implementation agents could overestimate current readiness or miss navigation. | Rebuilt the README, added agent onboarding, GitHub setup, and this audit while preserving the master plan/backlog as the authoritative contracts. |
| No selected project license | Redistribution and dependency policy are unresolved. | Still open by design as `RPR-001`; the README clearly states that no license has been granted yet. |

## What `make validate` now proves

- Candidate repository files contain no supported high-confidence credential signatures.
- Reperio runtime/recovery roots, disk-image formats, private key/keystore formats, and runtime databases are absent.
- Repository files are below 5 MiB and symbolic links are absent.
- UTF-8 text hygiene, final newlines, and Git whitespace checks pass.
- Local Markdown links resolve within the repository.
- The backlog defines every `RPR-001` through `RPR-177` exactly once and documentation references no undefined numeric task.
- JSON and shell scripts have valid syntax.
- Workflows use safe triggers, read-only permissions, immutable Action SHAs, bounded jobs, and no direct GitHub-context expression inside shell commands.

These checks are repository guardrails, not proof that future application code is correct. `RPR-005` and `RPR-006` remain open until the scaffolded backend/frontend/schema/container test suites and their deliberate failure fixtures exist.

## Remaining actions before treating `main` as protected

1. Review this branch's full diff and run `make validate` plus `make secret-scan`; the latter downloads and verifies pinned Gitleaks when it is not already installed.
   Run `make workflow-lint` whenever workflow files change.
2. Commit and push only after explicit approval.
3. Open a pull request and let all workflow jobs execute.
4. Apply [the GitHub repository setup checklist](GITHUB_SETUP.md), then make the three checks required on `main`.
5. Complete `RPR-001` before accepting dependency or redistribution choices.
6. Add application linters, tests, schema compatibility, license metadata, container smoke tests, and artifact retention as the RPR-004–006 scaffold is implemented.

No secret scanner can guarantee that a credential is harmless. If a real secret is ever committed, rotate or revoke it immediately before considering history cleanup.
