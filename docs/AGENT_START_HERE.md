# Agent start guide

This guide turns the Reperio master backlog into bounded, reviewable work for implementation agents, including smaller models that should not be expected to infer missing architecture.

The current operating mode is one implementation agent on one task at a time. Task packets are portable across Codex, OpenCode, and other capable coding agents: repository files must supply all context, and no step may rely on vendor-specific memory or an unrecorded prior conversation.

## Source-of-truth order

When instructions appear to conflict, stop and resolve the conflict in this order:

1. The no-source-write and hostile-content rules in `AGENTS.md` and master-plan section 3.
2. The product and architecture contracts in `docs/MASTER_PLAN.md`.
3. The assigned task's dependencies, deliverables, acceptance criteria, and tests in `docs/BACKLOG.md`.
4. Completed schemas, ADRs, and interfaces from dependency tasks.
5. The task issue or prompt.

An agent must not silently weaken a higher source to satisfy a lower one. Update both the master plan and backlog through a separate approved planning change if the product decision truly changes.

## Prepare one task

1. Select the earliest unblocked backlog task for the target milestone.
2. Confirm no other implementation task/agent is active and every `Depends` task is completed in `main`, not merely present in uncommitted or branch-only state.
3. Copy [the task packet template](AGENT_TASK_TEMPLATE.md) into a GitHub issue or agent prompt.
4. Copy the exact task objective, every acceptance criterion, and every named test. Split compound criteria into observable checkboxes without weakening them.
5. Add the exact master-plan sections and completed contracts the agent must read.
6. Name neighboring tasks that are explicitly out of scope.
7. Identify the existing fixtures and commands the agent must use. Never provide real recovered content as a fixture.
8. Confirm the single checkout is on current `main` and its existing changes are understood. Do not create a branch, worktree, or parallel assignment unless the owner explicitly selects the optional PR workflow.

If a dependency, schema, fixture, license decision, safety rule, or acceptance criterion is missing, the task is not ready. Route that gap to the appropriate earlier backlog task instead of asking the implementation agent to invent it.

## Agent execution loop

The agent should follow this order:

1. Read `AGENTS.md`, the assigned backlog entry, required master-plan sections, and completed dependency contracts.
2. Inspect current branch and working-tree status. Preserve unrelated changes and work in the single authorized `main` checkout; do not create parallel task state.
3. Restate the objective, in-scope files/interfaces, out-of-scope neighboring tasks, and safety properties affected.
4. Add or identify tests for every acceptance criterion before claiming completion.
5. Implement the smallest coherent change that satisfies the assigned task.
6. Run focused tests, then `make validate`, then affected integration tests.
7. Review the final diff for source writes, mounts, execution of discovered content, new network paths, secrets, personal data, generated data, unpinned dependencies, schema drift, and hidden scope expansion.
8. Give the owner the standard completion evidence. If publication is authorized, create one scoped task commit on `main`, push normally, and confirm GitHub Actions before the next task begins; use the pull-request template only when PR mode was selected.

The agent may ask for clarification when a decision materially changes product behavior. It should not wait for routine input, broaden the task, or substitute AI output for deterministic discovery.

## Review gate

A reviewer verifies all of the following before the task is committed/pushed or, in optional PR mode, merged:

- The task packet identifies one backlog task, no second implementation task ran in parallel, and all dependencies are already on `main`.
- Every acceptance criterion has test or manual-release evidence.
- Happy, malformed/hostile, failure, and interruption behavior is covered where relevant.
- A source-touching change has explicit negative proof that writes fail.
- New public schemas and interfaces are versioned; data changes include migrations and compatibility checks.
- New tools/actions/images are immutably pinned, license-reviewed, sandboxed, and fixture-backed.
- No actual source-media content, history, passwords, tokens, provider sessions, logs, images, databases, large artifacts, or recovery outputs are present.
- Wallet files, seed phrases, private keys, keystores, and decrypted vault values did not enter logs, fixtures, notifications, remote AI requests, task transcripts, or Git.
- Documentation and `docs/TRACEABILITY.md` remain accurate.
- Local gates pass before push and required GitHub checks pass afterward without bypass, permission expansion, or a reduced test scope.

## Definition of a useful completion report

The final report names:

1. The `RPR-NNN` task and outcome.
2. Every changed file and public interface.
3. Exact test commands and their pass/fail results.
4. Safety invariants affected and the evidence that protects them.
5. Limitations, deferred behavior, and follow-up task IDs.

“Implemented,” “tests pass,” or “should work” without this evidence is not a completion report.

## Common failure patterns

- **Starting a later feature before its safety contracts:** return to the missing dependency task.
- **Using a real old disk as a test fixture:** generate a tiny deterministic synthetic fixture instead.
- **Assuming `.gitignore` prevents leaks:** it can be bypassed; run repository validation and full-history secret scanning.
- **Adding a generic privileged helper or shell:** expose only a narrow, allowlisted, versioned host-controller operation.
- **Mounting read-only because parsing is easier:** the core design requires filesystem parsers against a read-only device.
- **Giving a parser, previewer, or AI the raw device:** those workers receive only bounded copies or safe derivatives from separate scratch storage.
- **Treating an AI score as discovery truth:** deterministic inventory remains visible; ranking is explainable and reversible.
- **Treating backlog priority as content value:** priorities order implementation work; every user-data category stays reachable and wallet sensitivity adds protection, not concealment.
- **Assuming a particular coding agent remembers earlier decisions:** put the decision, contract, fixture, and command in the repository task packet.
- **Claiming a format from a library import:** prove normalized output and malformed/failure behavior with fixtures.
- **Finishing only the happy path:** interruption, resource limits, partial recovery, and truthful errors are product behavior.
- **Changing CI to make a task pass:** fix the implementation; policy changes require their own reviewed security rationale.
