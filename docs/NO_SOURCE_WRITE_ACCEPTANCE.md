# No-source-write release acceptance

Status: approved execution plan for the incomplete `RPR-020` integration suite.

## Boundary

The checked-in `scripts/no_source_write_suite.py` is a synthetic contract
preflight. It is not loop-device, container-runtime, or release evidence. The
real `RPR-020` suite runs only in an owner-approved disposable Linux acceptance
environment after `RPR-146` provides the signed scanner image and exact digest.

This lane must never run in GitHub Actions or another untrusted CI environment.
It must never receive production credentials, a personal disk, recovered data,
or a host with unrelated removable media attached. The scanner image is already
present locally and the runtime uses `--pull=never`; acceptance execution does
not fetch an image or enable scanner network access.

## Provisioning Contract

Fixture provisioning and teardown are external operator actions, not Reperio
host-controller features. The operator provides an ephemeral Linux VM or
dedicated acceptance host with:

- the exact `RPR-008` deterministic FAT12 image generated under a new private
  temporary root;
- one read-only loop mapping backed by that image, with no partitions or
  filesystems mounted;
- no other removable or loop devices available to the test account;
- separate Reperio state, scratch, report, and audit storage;
- the signed `RPR-146` scanner image already installed by immutable digest; and
- a recorded kernel, distribution, architecture, Docker/Podman version, Reperio
  commit, and scanner manifest digest.

Reperio must not create a writable loop mapping, restore writable state, detach
the loop mapping, reset the image, mount the fixture, or delete acceptance
evidence. The external operator owns those lifecycle actions and destroys the
ephemeral environment after preserving the reviewed report.

## Admission Proof

The future acceptance runner fails before launching any process unless every
condition below is true:

1. The host is Linux and an explicit release-acceptance flag is present.
2. The process is not running in GitHub Actions or another detected CI context.
3. The selected kernel object is block-special and named `loopN`.
4. Sysfs exposes one loop backing file under the private acceptance root.
5. The backing file is regular, privately owned, single-linked, exact-size, and
   byte-identical to the pinned `RPR-008` SHA-256 fixture.
6. The loop device and every discovered child report kernel read-only state.
7. Mount/holder inspection is complete and reports no mount or unsafe holder.
8. State, scratch, audit, and report destinations are physically separate from
   the selected source ancestry.
9. The locally installed scanner image digest exactly matches the signed
   `RPR-146` manifest; tag-only or caller-provided image references are refused.
10. A full read-only source snapshot succeeds immediately before the attack
    matrix. Any identity, size, generation, or fingerprint change aborts.

Bare `/dev/sdX` paths, symlink-only claims, operator-provided expected hashes,
non-loop block devices, writable loop mappings, and unknown backing files are
never accepted as test fixtures.

## Attack Matrix

The acceptance run must execute every named `RPR-020` case, not a simulated
equivalent:

1. Launch a bounded malicious adapter in the scanner isolation profile. It tries
   write opens, write syscalls, and write-capable ioctls against every visible
   device; every attempt must fail.
2. Submit compromised launch payloads for image, entry point, arguments,
   devices, mounts, network, capabilities, user, security options, environment,
   and resource limits; hostd must reject them or launch only the fixed profile.
3. Inspect the running container and prove one read-only source device, no
   Docker/Podman socket, no host mounts or secrets, no network, no capabilities,
   fixed non-root UID/read GID, read-only root, bounded tmpfs, and bounded
   PID/memory/CPU settings.
4. Exercise same-disk scratch through sibling, child, LVM, bind, and symlink
   topologies; scan start must refuse each case before container launch.
5. Swap destination symlinks and simulate device renumbering between checks;
   identity and physical-ancestry revalidation must refuse stale state.
6. Kill and restart the scanner with the same verified identity, then repeat the
   malicious adapter checks and a minimal fixture scan.

The source is read only throughout. No repair, format, mount, remount, wipe,
partition-write, filesystem-write, TRIM, optical burn/blank, or source cleanup
operation belongs in the runner.

## Evidence Contract

The runner writes a versioned JSON report and append-only safety audit to the
dedicated report destination. The report contains only sanitized facts:

- schema version, `RPR-020`, Reperio commit, signed scanner digest, runtime and
  host versions;
- fixture manifest hash and size, opaque source ID, major:minor, and verified
  read-only/mount/holder facts;
- exact fixed sandbox profile hash and inspected runtime controls;
- each named attack, attempted/blocked counts, bounded errors, and pass/fail;
- source SHA-256 before launch, after every restart, and after completion;
- audit segment hashes and overall result.

`passed` is true only when every admission proof and attack passes and every
source hash equals the pinned fixture hash. Missing, skipped, unsupported,
timed-out, or partially collected evidence fails acceptance. Reports never
contain source bytes, credentials, host environment values, personal paths, or
runtime authentication files and are never uploaded automatically.

## Release Gate

`RPR-020` remains incomplete until the runner, fixtures, negative tests, and one
reviewed report exist. `RPR-153` reruns and extends the matrix independently;
`RPR-155` preserves the final report against the exact release digest. A failed
or unavailable acceptance environment blocks release rather than weakening the
matrix or substituting the synthetic preflight.
