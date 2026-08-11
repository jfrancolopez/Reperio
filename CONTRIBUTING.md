# Contributing to Reperio

Reperio uses Git `main` as its implementation source of truth. The current owner workflow is deliberately sequential: one checkout, one implementation agent, one backlog task, and one reviewed commit at a time. Pull requests remain available for external contributions or a future multi-review workflow, but they are not required for the owner's present single-agent workflow.

## Before starting

1. Read [the repository rules](AGENTS.md), the selected task in [the backlog](docs/BACKLOG.md), and its linked sections in [the master plan](docs/MASTER_PLAN.md).
2. Confirm no other implementation agent/task is active and every dependency task is complete on `main`. Do not work around a missing contract with an undocumented local interface.
3. Confirm the one checkout is on current `main` with a clean or understood working tree. Do not create a worktree or task branch unless the owner explicitly selects PR mode.
4. Prepare one task packet containing everything a capable coding agent needs. The task may not depend on a particular model/vendor, private conversation history, or another agent's memory.

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

## Current owner flow: sequential `main`

1. Implement only the assigned `RPR-NNN` task and provide progress checkpoints for owner review.
2. Run focused tests, `make validate`, `make secret-scan`, and every affected integration test.
3. Review the complete diff for source-write paths, parser/network boundary changes, wallet/credential exposure, recovered content, unpinned dependencies, undocumented interfaces, and neighboring-task scope.
4. When the task authorizes publication, stage only its files, create one task-referenced commit directly on `main`, and push normally. Never force-push or rewrite a published commit.
5. Confirm the GitHub Actions quality gates pass. If they fail, keep the same task active, add a corrective commit, and re-run the checks before beginning another task.
6. Record the standard completion report and only then assign the next task.

This mode intentionally trades pre-merge GitHub enforcement for the owner's requested one-checkout workflow. Local gates are therefore mandatory before every push, while GitHub Actions supply independent post-push validation. Configure the matching server-side settings in [GitHub repository setup](docs/GITHUB_SETUP.md).

## Optional pull-request flow

Use this only when the owner requests a branch/PR or an external contributor needs review:

1. Create `<actor>/rpr-nnn-short-name` from current `main`; keep one task on the branch.
2. Run the same local and task-specific gates, open a pull request using the template, and reference the exact task.
3. Resolve all GitHub checks and review findings without weakening a gate.
4. Merge only with acceptance evidence, then delete the task branch. Do not run a second implementation task in parallel merely because it has another branch.

## Commit and dependency discipline

- Reference the task ID in commits, for example `feat(scanner): RPR-038 inventory allocated files`.
- Keep every user-data category reachable. Backlog priority labels control engineering order, not the value of recovered material.
- Do not mix unrelated cleanup with the assigned task.
- Never commit actual source-disk data, recovered files, browser history, wallet files, seeds, private keys, keystores, passwords, model transcripts, logs, database state, disk images, or credentials.
- Generate synthetic fixtures during tests; keep them minimal, deterministic, and free of real personal data.
- Pin tools and OCI images to immutable versions or digests. Pin GitHub Actions to a full 40-character commit SHA and retain the release tag in a comment for Dependabot.
- Record dependency source, version, license, supported architecture, sandbox needs, and removal path according to the [dependency intake checklist](docs/DEPENDENCY_INTAKE.md), which `RPR-001` introduced; entries must pass the license gate before committing.
- Schema and API changes require a migration or compatibility plan plus updated contracts and tests.

## Reporting results

Every completed task reports the files and interfaces changed, exact tests and results, affected safety invariants, known limits, and follow-up task IDs. Do not claim a platform or file-format capability without its fixture-backed integration test.
