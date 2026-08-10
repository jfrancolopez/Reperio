# Agent task packet template

Copy this template into an issue or agent prompt. Replace every bracketed value. Do not remove the safety section.

```markdown
# [RPR-NNN] [Exact backlog title]

## Objective

[One paragraph copied or faithfully restated from the backlog.]

## Required reading

- `AGENTS.md`
- `docs/MASTER_PLAN.md` sections [numbers]
- `docs/BACKLOG.md` task [RPR-NNN]
- Completed dependency contracts: [IDs and file links]

## Dependencies and starting assumptions

- Required completed tasks: [IDs]
- Existing interfaces that must be preserved: [schemas/endpoints/classes]
- Test fixtures to use: [fixture IDs]
- Do not implement: [neighboring/follow-up task IDs]
- Execution mode: one active implementation agent, one task, single `main` checkout; no parallel task/agent/worktree
- Publication authorization: [report only / stage and commit / stage, commit, push, and verify CI]

## Development-agent neutrality

- This packet and the checked-in repository contain all required context.
- The implementation and tests must not depend on Codex, OpenCode, or any other coding-agent/model vendor.
- If a named agent-only capability appears necessary, replace it with a repository command/contract or report the missing prerequisite instead of inventing hidden behavior.

## Deliverables

1. [Concrete code/schema/document output]
2. [Concrete tests]
3. [Documentation or contract update]

## Acceptance criteria

- [Copy every acceptance criterion from the backlog and split compound clauses into checkboxes.]
- [Add observable task-specific criteria; do not weaken the backlog.]

## Required tests

- Happy path: [case]
- Malformed/hostile input: [case]
- Failure/interruption: [case]
- Regression/contract: [case]
- Source-write verification, if the task touches device/content/path/tool/export code: [case]

## Safety constraints

- The source device and source files are read-only.
- No mount, write, repair, wipe, initialize, format, optical burn/blank, or source deletion path may be added.
- No untrusted discovered content may execute or receive network access.
- No credentials, recovered passwords, provider sessions, source bytes, or personal content may enter logs, fixtures, or source control.
- Wallet files, seeds, private keys, keystores, and decrypted vault values may not enter logs, notifications, remote AI requests, task transcripts, general search text, fixtures, or source control. Do not query balances, sign data, or broadcast transactions.
- Recovered/derived output goes only to validated separate scratch/export storage.
- AI output cannot dismiss, delete, or make a finding inaccessible.
- Engineering priority and interest/noise scores do not determine content value; every finding remains reachable and any system/noise suppression is explainable and reversible.

## Completion response

Report:

1. Outcome and task ID.
2. Files and public interfaces changed.
3. Exact test commands and results.
4. Safety controls affected and evidence they still hold.
5. Known limitations and follow-up IDs.
6. If publication was authorized: commit ID, push result, and GitHub Actions result. Do not start another task while a check is failing or pending.
```

## Reviewer checklist

- The agent stayed inside the assigned task.
- Every dependency was actually present, not mocked around without agreement.
- All acceptance criteria have evidence.
- Failure behavior is truthful and bounded.
- The implementation added no generic shell, arbitrary path, unpinned tool, source write, or secret leak.
- Database/API/schema changes include migration and compatibility checks where required.
- A claimed format/platform capability has a positive and malformed fixture.
- Documentation and traceability remain accurate.
