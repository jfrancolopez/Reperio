# Reperio source-write and untrusted-content threat model

Status: accepted planning contract (RPR-002)
Plan version: 1.0
Companion: master plan section 3 (non-negotiable safety invariants)

## 1. Purpose and scope

This model proves how Reperio's non-negotiable safety properties will hold even
if a component is compromised. It names the assets an attacker or a failing
component could touch, the trust boundaries between components, the attacker and
failure scenarios that matter, the operations that are permanently prohibited,
and, for every invariant in master plan section 3, at least one preventive
control and one verification. Residual risks that cannot be fully eliminated are
named explicitly rather than hidden.

The implementation of the negative tests enumerated here is deliberately
assigned to two later backlog tasks:

- `RPR-020` builds the destructive-to-fixture-only no-source-write integration
  suite.
- `RPR-153` performs the independent source-write penetration review.

The exact concrete tests for those tasks are defined in section 8. Until they
exist, no release may claim the invoked devices/tools are safe.

## 2. Assets

| Asset | Sensitivity | Primary defender |
|---|---|---|
| Source medium and its contents | Highest: user data, may contain hostile content | Host controller, scanner, kernel read-only |
| Reader device handle and device identity | High | Host controller narrow protocol |
| Catalog, checkpoints, event outbox | High: contains finding records | Control plane, SQLite, jobs |
| Extracted/carved scratch copies | High: recovered bytes | Content store, sandbox workers |
| Derivatives (thumbnails, OCR, transcripts, renders) | Medium | Worker sandboxes |
| Destination credentials and provider sessions | High | Host secret store |
| Wallet secrets, seeds, private keys, keystores, decrypted vault values | Critical | Secret store + redaction policy |
| Operator/admin password and LAN exposure | High | Auth, bind configuration |
| Model input/output and optional remote AI | Medium/High | Privacy gate, provider adapters |
| Append-only safety audit | High integrity | Host controller audit store |

No asset is more important than the guarantee that the selected source medium is
never written, remounted writable, repaired, wiped, initialized, formatted,
burned, or blanked by Reperio, even when a parser, the UI, AI, or the API is
malicious.

## 3. Trust boundaries

```
MEME: trust flow
  Browser UI  --[HTTP+SSE]-->  API/control plane  --SQL-->  SQLite catalog/jobs
  API/control plane  --narrow Unix socket-->  hostd (privileged, small)
  hostd  --read-only device only-->  scanner container (no network, no caps)
  scanner  --normalized findings-->  catalog
  scanner  --copies only-->  scratch
  scratch  -->  sandboxed workers (preview, OCR, parse, AI adapters)
  workers  -->  optional local/LAN/remote models
  control plane  -->  export worker -->  destination
  control plane  -->  notification adapter
```

Hostile content is treated as untrusted at every boundary. The browser never
renders active source content. Workers never receive a source-device handle.
The API never receives a device path by reference. The scanner is the only
process that touches the source, and it is ephemeral, network-isolated,
capability-less, and read-only.

## 4. Attacker and failure scenarios

Categories of adversary and of component failure are modeled together because a
"failure" of a parsing tool, the network, or the kernel is equivalent to an
attacker controlling that component's outputs.

| ID | Scenario | Example threat action |
|---|---|---|
| S1 | Compromised UI/client | Crafted API call attempts to select a system disk, request a source path, or write a destination onto the source |
| S2 | Compromised API/control plane | Supplies stale device IDs, path traversal, arbitrary launch flags, or extra mount/device args to hostd |
| S3 | Compromised parser/tool worker | Tries to reach the source device, host secrets, Docker socket, arbitrary network; forks bombs or floods output |
| S4 | Malicious source content | Named as executable/document/archive/image; tries to escape a sandbox or execute in the UI origin |
| S5 | Symlink/ﬁle-card attack | A scratch or export path is replaced by a symlink to the source midway through a job |
| S6 | Same-disk destination attack | A destination path, partition, LVM LV, mdraid member, or symlink resolves to the source backing device |
| S7 | Device renumbering/swap race | `/dev/sdX` changes, or a different medium replaces the selected one in a reader between checks |
| S8 | Malicious/compromised host controller | The narrow hostd is fully compromised and attempts an arbitrary write or mount |
| S9 | Kernel/device failure | A read returns EIO, an ioctl misbehaves, or read-only verification fails |
| S10 | CI/fixture misuse | A test attempts to run against a real disk rather than a disposable fixture |
| S11 | AI/provider compromise | A model request returns instructions or the provider is given a path/tool it should not receive |
| S12 | Export worker compromise | Attempts to write back to source or marks an unverified copy complete |

## 5. Explicitly prohibited operations (now and permanently)

These operations exist nowhere in Reperio: no API route, command, plugin
permission, UI control, helper, or script may perform them against the selected
source medium or any of its child partitions:

- Write, wipe, erase, format, initialize, or create a filesystem
- Delete from or truncate the source
- Repair, fix, or rebuild source metadata (filesystem, partition table, boot
  sector)
- Mount any source filesystem (including read-only mounts) in the core workflow
- Burn, blank, or write optical media; packet-write; change media sessions
- Partition-table modification; LVM/mdadm metadata updates; `fsck`
- Remount a source child read-write
- Open the source device with write intent from any component at any time
- Pass the source device, a writable device handle, or arbitrary raw paths to a
  general-purpose tool, script console, archive extractor, preview renderer, or
  network-enabled process
- Execute a discovered binary, script, macro, shortcut, installer, browser
  extension, or active document
- Start a SMART self-test or change any device setting on the source

The source-touching call set is a fixed allowlist implemented by the host
controller and enforced by container profiles for the scanner (section 7.3).

## 6. Invariant-to-control mapping

Every requirement in master plan section 3 maps to at least one *preventive
control* (design/enforced at runtime) and one *verification* (a test or check).

### 6.1 No source writes (master plan §3.1)

| # | Invariant (abridged) | Preventive control | Verification |
|---|---|---|---|
| N1 | Stable identity via `/dev/disk/by-id` or reader+media facts; bare `/dev/sdX` never sufficient | `hostd` resolves opaque stable IDs (RPR-011) and removable-media identity (RPR-178); API accepts only opaque IDs | RPR-011 reorder/collision tests; RPR-178 disc/card-swap identity tests; RPR-020 symlink/device renumber cases |
| N2 | Kernel read-only is set and verified before scanning | `hostd` `BLKROSET` + independent verification for whole disk and children (RPR-016) | RPR-016 privileged loop test proving writes fail after preparation; RPR-020 attempts each write path |
| N3 | No read-write mounts of source or children during scan | RPR-014 mount/holder inspection blocks preparation while mounted RW | RPR-014 mounted RO/RW loop fixtures; RPR-118 host UI blocker |
| N4 | Control plane/UI/AI/export/notifications never receive a device handle | Architecture boundary: only scanner receives the device (RPR-019); hostd narrow protocol (RPR-009) | RPR-070 malicious-parser forbidden-access tests; RPR-009 contract tests reject extra devices/args |
| N5 | Scanner opens `O_RDONLY`, device-cgroup read only, no capabilities, no network | Fixed container spec by digest; all capabilities dropped; no network; read-group only (RPR-019); scanner re-validates `O_RDONLY` + RO flag (RPR-035) | RPR-019 network/capability/root/extra-device/source-write attempts; RPR-035 symlink/writable-loop mismatch tests |
| N6 | Parsers used, never mounted | TSK/optical/legacy adapters parse offsets against the device (RPR-036–043, RPR-184) | RPR-020 no-mount proof; fixture integration tests per filesystem |
| N7 | Recovered/carved bytes go only to proven-separate scratch/export | RPR-015 path-to-physical-disk resolver refuses same-disk destinations; RPR-039 content store never-source validation | RPR-015 same/parent/LVM/mdraid/NFS/symlink fixtures; RPR-039 same-disk refusal and symlink-attack tests |
| N8 | No destructive source operation exists anywhere | Narrow allowlisted protocol (RPR-009); no such route/UI/plugin | RPR-009 unknown-method/path-traversal rejection; RPR-153 full penetration review |
| N9 | Automated tests use sacrificial fixtures and prove writes fail on loop/optical/floppy fixtures | RPR-020 harness snapshots a disposable loop disk, attempts every plausible write path, byte-compares after | RPR-020 byte-compare suite; RPR-153 rerun; RPR-155 release acceptance byte comparison |

### 6.2 Untrusted-content isolation (master plan §3.2)

| # | Invariant | Preventive control | Verification |
|---|---|---|---|
| C1 | No discovered program/macro/script/active document executes | No execution surface for discovered content; document/metadata workers only parse copies | RPR-070 malicious-parser suite; RPR-151 active-content UI/polyglot tests |
| C2 | Every third-party parser runs pinned, no network, no capabilities, non-root, RO root, bounded scratch/CPU/memory/PIDs/output, timeout | Generic sandbox runner with fixed tool profiles (RPR-070); digest-pinned images | RPR-070 fork-bomb/output-flood/timeout/path-traversal/crash tests |
| C3 | Archives never extract into shared paths without traversal/symlink/bomb checks | Archive worker validates members, links, expansion limits (RPR-080) | RPR-080 path-traversal/symlink/bomb/nesting fixtures |
| C4 | UI never renders source HTML/SVG/JS or active PDF | Only safe derivatives/escaped text served; browser never receives originals inline (RPR-073–075, RPR-151) | RPR-074 active-file-attack fixture; RPR-151 CSP/security-header tests |

### 6.3 Export separation (master plan §3.3)

| # | Invariant | Preventive control | Verification |
|---|---|---|---|
| E1 | Catalog presence is never "backed up" | Export requires copy+verification; queue tracks ready/verified state (RPR-105–108) | RPR-108 readiness states; RPR-115 verification counts |
| E2 | Export completes only after size+SHA-256 verification where supported | Verified local export finalizes only after verification (RPR-106); rclone check where supported (RPR-109) | RPR-106 corruption-seam/collision tests; RPR-109 checksum/no-checksum tests |
| E3 | Manifest records failures and unsupported verification | Manifest schema carries per-item verification state and tool/app versions (RPR-107) | RPR-107 deterministic-manifest/partial-failure tests; RPR-115 manifest-tamper test |
| E4 | Source never silently used as scratch/export | RPR-015 resolver runs inside scan/export start; content store refuses source ancestry (RPR-039) | RPR-015 same-disk/symlink fixtures rerun at export submission (RPR-105) |

## 7. Mitigations by layer

### 7.1 Host and kernel
- Read-only enforcement: `BLKROSET` plus independent re-verification (N2).
- Identity resolution against `/dev/disk/by-id` + media facts; bare paths never
  identity (N1).
- System-disk denial for disks backing `/`, `/boot`, Reperio state, container
  storage, swap (RPR-013), with an explicit strongly worded override.
- Mount/holder inspection before preparation (RPR-014).

### 7.2 Container and process
- One fixed scanner image by immutable digest; caller cannot alter image,
  entry point, devices, mounts, network, capabilities, or security profile
  (RPR-019).
- Device cgroup read-only; no capabilities; no network; non-root UID with read
  group; read-only root; bounded tmpfs/scratch; PID/memory/CPU limits.
- Scanner independently re-validates source (RPR-035) before any parser runs.

### 7.3 API and UI
- Narrow versioned Unix-socket protocol with no generic command execution, path
  passthrough, mount, write, repair, or arbitrary container args (RPR-009).
- Control plane holds no device handle; finds reference only opaque IDs.
- UI surfaces read-only proofs, mounted state, and identity-strength warnings;
  all blocked states are explicit (RPR-118).
- Optional single-admin auth + bind/subnet controls for LAN exposure (RPR-130).

### 7.4 Tools
- Pinned, digest-verified adapters; separate-process use for reciprocal
  licenses (RPR-001, `docs/DEPENDENCY_INTAKE.md`).
- Parser sandbox with no source device, no network, no capabilities, non-root,
  read-only root, resource limits and timeouts (RPR-070).

### 7.5 AI
- Local/LAN/remote are distinct; remote requires privacy gate with explicit
  acknowledgment and per-provider/category/size policy (RPR-093).
- Models receive only explicit extracted text or safe derivatives, never paths
  or tools; wallet secrets never reach remote providers (RPR-058, RPR-093).
- AI cannot control discovery completeness or deletion (RPR-087).

### 7.6 Scratch and exports
- Physical-disk separation resolver before scan and export starts (RPR-015,
  RPR-105).
- Content-addressed store, never-source validation, quotas, partial-file
  cleanup limited to proven-incomplete owned temporaries; completed recovered
  objects are never automatically deleted (RPR-039).
- Verified local/remote exports with manifests and verification state (RPR-106,
  RPR-109, RPR-115).

## 8. Negative tests to be implemented by RPR-020 and RPR-153

These are the concrete, named tests the two later tasks must implement. They
are documentation now and code later; each maps to the invariants it proves.

### 8.1 `RPR-020` no-source-write integration suite

Harness: destructive-to-fixture-only; snapshots a disposable loop disk; runs a
minimal scan; byte-compares the source afterward. Refuses real disks.

1. **Malicious adapter attempt** (N5, N7): a mock parser attempts to `open`
   every device node under `/dev` and issue write ioctls; all must fail; source
   hash unchanged.
2. **Compromised API payload** (N2, N8): an attacker-controlled API object
   tries to add mounts, devices, capabilities, network, entry changes, or
   arbitrary launch arguments through the launch request; the fixed spec wins
   and the launch either succeeds with the immutable spec or fails.
3. **Same-disk scratch** (N7, E4): scratch configured on a source child
   partition/LV/bind-mount/symlink; scan start refuses.
4. **Symlink swap** (S5, E4): export/scratch path replaced with a symlink to
   the source mid-job; resolved physical ancestry is re-checked and refuses.
5. **Device renumbering** (N1): simulated rename of `/dev/disk/by-path`/`/dev/sdX`
   during a case; stable ID resolution must not follow the wrong device.
6. **Scanner restart** (N9): kill the scanner, restart with same identity, and
   byte-compare the source after another run.

### 8.2 `RPR-153` independent penetration review

1. **Protocol review** (N8): every method/field of the hostd protocol is
   reviewed for write/repair/mount/arbitrary-command capability; unknown
   methods and path traversal are exercised.
2. **Container flags and device permissions** (N5): inspect the actual runtime
   config of the launched scanner for devices, cgroups, capabilities, mounts,
   network, image digest.
3. **Parser profiles** (C2): each tool profile is verified to have no escape
   (device, network, rootfs, cap, env) using malicious fixtures.
4. **Path resolution races** (N7, E4, S5): source/destination races and symlink
   swap under load.
5. **APIs and plugins** (N8): every API route and future plugin manifest is
   audited for destructive capability.
6. **AI boundary** (C4): confirm models cannot request tools/paths and wallet
   secrets never leave the host.
7. **Update channel** (C2): the signed/version-pinned update path cannot be
   redirected; images are digest-immutable.
8. **Fault-injection complement** (S9, S7): source disconnect/reconnect and
   device rename during scanning keep prior committed findings and fail safe.

### 8.3 Regression harness
- Every attempted write fails; source hash unchanged; suite runs only against a
  verified disposable fixture; never against a real disk.
- Findings already cataloged survive parser/API/host failure and restart
  (Fault-injection coverage in `RPR-150`).

## 9. Residual risks (named, not hidden)

| Risk | Why it remains | Mitigation | Owner |
|---|---|---|---|
| Kernel/controller bug still writes | No software can absolutely guarantee kernel behavior | Defense in depth: `O_RDONLY` + BLKROSET + capability-less container + `make` suite proving writes fail; penetration review (RPR-153) | RPR-016, RPR-020, RPR-153 |
| Physical hardware write path is not observable in software | TRIM/garbage-collection continue on some devices | Documented honest limitations (master plan §4); no delete/repair exists so Reperio itself cannot trigger them | RPR-154 |
| Compromised privileged host controller | hostd is the smallest privileged component and must run privileged | Narrow allowlisted protocol, append-only audit, no shell/parsing/AI in hostd; RPR-153 review | RPR-009, RPR-018, RPR-153 |
| A future feature weakens a boundary | Road-map drift | Reviewer gate in `AGENTS.md`; conflict rule stops implementation and documents the conflict | Review gate |
| Optical/floppy media have firmware state not visible from Linux | Overwrite limits and quick-blanked sectors are drive/firmware dependent | Honest capability reporting, kernel/device write denial remains mandatory, no blank/burn commands | RPR-183, RPR-185 |
| LAN exposure without auth | Auth is optional by design | Persistent warning, single-admin auth, bind/subnet restrictions, documentation | RPR-130, RPR-154 |
| Third-party parser CVE | Parsers are less trusted than Reperio code | Pinned digests, sandboxes, patch/emergency-disable policy | RPR-070, RPR-148 |

## 10. Traceability

- Proposal risk: no risk raised. This document is the implementation contract
  for the defenses named in `docs/BACKLOG.md` (`RPR-009`–`RPR-020`,
  `RPR-035`, `RPR-039`, `RPR-070`, and `RPR-153`).
- Reversal: any change that adds a write, mount, repair, or generic privileged
  operation to a source-touching surface is blocked unless this model is
  updated and the owner approves the ADR/migration first.
