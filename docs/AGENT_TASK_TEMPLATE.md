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
- No mount, write, repair, wipe, format, or source deletion path may be added.
- No untrusted discovered content may execute or receive network access.
- No credentials, recovered passwords, provider sessions, source bytes, or personal content may enter logs, fixtures, or source control.
- Recovered/derived output goes only to validated separate scratch/export storage.
- AI output cannot dismiss, delete, or make a finding inaccessible.

## Completion response

Report:

1. Outcome and task ID.
2. Files and public interfaces changed.
3. Exact test commands and results.
4. Safety controls affected and evidence they still hold.
5. Known limitations and follow-up IDs.
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
