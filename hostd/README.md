# hostd — Linux host controller

Owner: the smallest privileged component. Only `hostd` may touch kernel device
state: identity resolution, mount/holder inspection, kernel read-only
verification, SMART where supported, and launching the fixed scanner container.

- **Source of truth:** `docs/adr/0002-linux-host-control.md`, `RPR-009`–`RPR-020`.
- **Status:** placeholder runtime (`RPR-004`) with protocol contract (`RPR-009`);
  no device implementation.
- **Health check:** `python -m hostd` (refuses any `--device` argument).
- **Language note:** implemented in Python to match the control-plane stack. A
  future ADR may move `hostd` to a native binary if privileged-binary isolation
  requirements demand it (see ADR 0002 reversal conditions).
- **Boundary:** no parsing, AI, preview, export, shell, or generic ioctl surface.
- **Protocol:** `hostd.protocol` validates the versioned Unix-socket envelopes;
  see `docs/HOSTD_PROTOCOL.md`.
- **Enumeration:** `hostd.block_devices` reads sanitized sysfs-shaped block
  facts for `RPR-010`; stable identity and safety decisions are later tasks.
- **Identity:** `hostd.identity` resolves opaque stable source IDs from
  `/dev/disk/by-id` and immutable facts for `RPR-011`.
- **Fingerprinting:** `hostd.fingerprint` computes bounded sampled-sector hashes
  with `O_RDONLY` access for `RPR-012`; sampled bytes are never returned.
- **System disk denial:** `hostd.system_disks` refuses active root, boot, state,
  container-storage, and swap ancestry by default for `RPR-013`.
