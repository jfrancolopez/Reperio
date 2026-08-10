## Backlog task

- Task: `RPR-NNN`
- Objective:
- Dependencies confirmed:

## What changed

Describe the behavior, contracts, migrations, and documentation changed by this pull request.

## Evidence

- [ ] `make validate` passes locally.
- [ ] Task-specific tests were added or updated and pass.
- [ ] Failure and interruption behavior was tested where relevant.
- [ ] The acceptance criteria in `docs/BACKLOG.md` are satisfied.

Commands and results:

```text
make validate
```

## Safety review

- [ ] No source-media write, mount, repair, wipe, initialize, format, optical burn/blank, or delete path was added.
- [ ] No recovered content, disk image, runtime database, wordlist, credential, token, or personal data is included.
- [ ] Discovered content is never executed and remains isolated from network-enabled workers.
- [ ] New third-party actions, tools, images, and dependencies are immutably pinned and documented.
- [ ] Scratch/export destination separation is preserved if this change touches paths, storage, or copying.
- [ ] AI output cannot delete, dismiss, or make a finding inaccessible.

## Compatibility and follow-up

- Public interfaces changed:
- Known limitations:
- Follow-up task IDs:
