# hostd — Linux host controller

Owner: the smallest privileged component. Only `hostd` may touch kernel device
state: identity resolution, mount/holder inspection, kernel read-only
verification, SMART where supported, and launching the fixed scanner container.

- **Source of truth:** `docs/adr/0002-linux-host-control.md`, `RPR-009`–`RPR-020`.
- **Status:** placeholder service entry point (`RPR-004`) with implemented,
  unit-tested host safety libraries; no Unix-socket daemon or integrated device
  workflow yet.
- **Health check:** `python -m hostd` (refuses any `--device` argument).
- **Language note:** implemented in Python to match the control-plane stack. A
  future ADR may move `hostd` to a native binary if privileged-binary isolation
  requirements demand it (see ADR 0002 reversal conditions).
- **Boundary:** no parsing, AI, preview, export, shell, or generic ioctl surface.
- **Protocol:** `hostd.protocol` validates the versioned Unix-socket envelopes;
  see `docs/HOSTD_PROTOCOL.md`.
- **Enumeration:** `hostd.block_devices` reads sanitized sysfs-shaped block
  facts for `RPR-010`; later modules consume these facts for safety decisions.
- **Identity:** `hostd.identity` resolves opaque stable source IDs from WWN,
  serial, `/dev/disk/by-id`, and weaker warned immutable facts for `RPR-011`.
- **Fingerprinting:** `hostd.fingerprint` computes bounded sampled-sector hashes
  with `O_RDONLY` access for `RPR-012`; sampled bytes are never returned.
- **System disk denial:** `hostd.system_disks` refuses active root, boot, state,
  container-storage, and swap ancestry by default for `RPR-013`.
- **Storage inspection:** `hostd.storage_inspection` reports source-related
  mounts, holders, device-mapper, and mdraid facts for `RPR-014`.
- **Destination separation:** `hostd.destination_separation` proves local
  scratch/export paths do not share the source ancestry for `RPR-015`.
- **Read-only preparation:** `hostd.read_only` sets and verifies kernel
  read-only state for whole disks and children for `RPR-016`.
- **Safety audit:** `hostd.safety_audit` appends redacted, hash-chained safety
  records and verifies ordering/tamper evidence for `RPR-018`.
- **Scanner sandbox:** `hostd.scanner_sandbox` validates, audits, and invokes an
  immutable Docker/Podman launch profile with one identity-bound read-only source
  device for `RPR-019`. It uses `--pull=never`; release image publication and
  runtime manifests remain deferred to `RPR-146`.
- **No-source-write suite:** `scripts/no_source_write_suite.py` runs the
  disposable-fixture byte-compare harness for `RPR-020`.

## Sampled fingerprint v2

Fingerprint record schema v2 uses `reperio-sampled-sector-sha256-v2`. It selects
at most the first, middle, and last logical sectors while always leaving part of
the source unread. The logical sector size is capped at 16 MiB. Each exact-length
sample is SHA-256 hashed in-process;
raw bytes and read-error messages are never returned. A usable final fingerprint
exists only when the nonempty sample set is entirely readable. It is SHA-256 of
UTF-8 canonical JSON containing the algorithm name, immutable sanitized device
facts, and ordered sample metadata/digests (sorted keys, compact separators,
ASCII escapes, and no non-finite numbers).
