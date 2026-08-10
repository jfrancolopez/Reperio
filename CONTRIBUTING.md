# Contributing to Reperio

Reperio uses Git as its implementation source of truth. Every code, schema, workflow, dependency, and product-contract change should be reviewable as a small pull request tied to the master backlog.

## Before starting

1. Read [the repository rules](AGENTS.md), the selected task in [the backlog](docs/BACKLOG.md), and its linked sections in [the master plan](docs/MASTER_PLAN.md).
2. Confirm every dependency task is complete. Do not work around a missing contract with an undocumented local interface.
3. Begin from the latest protected `main` and create a branch named `<actor>/rpr-nnn-short-name`, such as `codex/rpr-020-source-write-tests`.
4. Keep one backlog task per branch and pull request whenever practical.

Use [the agent task packet](docs/AGENT_TASK_TEMPLATE.md) or the GitHub agent-task issue form to give an implementation agent the full objective, boundaries, contracts, acceptance criteria, and tests.

## Local quality gate

Run the same dependency-free policy checks used in CI:

```sh
make validate
```

This checks repository hygiene, dangerous file types and paths, high-confidence secret signatures, local documentation links, backlog identifiers, workflow security, JSON and shell syntax, file size, symbolic links, and whitespace. Run the stronger worktree and Git-history scan too; the command uses an installed Gitleaks or downloads the pinned release and verifies its checksum:

```sh
make secret-scan
```

Application-specific formatters, linters, unit tests, integration tests, migration checks, and generated-client checks will be added to `make validate` as their components enter the repository. A task is not complete merely because the repository-level policy gate passes.

Lint GitHub Actions with the pinned, checksum-verified Actionlint release after changing a workflow:

```sh
make workflow-lint
```

## Pull-request flow

1. Rebase or update the branch from current `main` without rewriting other contributors' work.
2. Run `make validate` and every task-specific test.
3. Open a pull request using the repository template and reference the exact `RPR-NNN` task.
4. Let the GitHub quality gates finish. Resolve failures in the branch; never bypass or disable a gate to merge a feature.
5. Review the diff for source-write paths, parser/network boundary changes, credentials, recovered content, unpinned dependencies, and undocumented interface changes.
6. Merge only after required checks pass and the acceptance criteria have evidence. Delete the merged feature branch; preserve tags and release artifacts.

Direct pushes, force pushes, and branch deletion should be disabled for `main` with the ruleset described in [GitHub repository setup](docs/GITHUB_SETUP.md). Repository files cannot activate those server-side settings by themselves.

## Commit and dependency discipline

- Reference the task ID in commits, for example `feat(scanner): RPR-038 inventory allocated files`.
- Do not mix unrelated cleanup with the assigned task.
- Never commit actual source-disk data, recovered files, browser history, passwords, model transcripts, logs, database state, disk images, credentials, or private keys.
- Generate synthetic fixtures during tests; keep them minimal, deterministic, and free of real personal data.
- Pin tools and OCI images to immutable versions or digests. Pin GitHub Actions to a full 40-character commit SHA and retain the release tag in a comment for Dependabot.
- Record dependency source, version, license, supported architecture, sandbox needs, and removal path as required by `RPR-001` and later adapter tasks.
- Schema and API changes require a migration or compatibility plan plus updated contracts and tests.

## Reporting results

Every completed task reports the files and interfaces changed, exact tests and results, affected safety invariants, known limits, and follow-up task IDs. Do not claim a platform or file-format capability without its fixture-backed integration test.
