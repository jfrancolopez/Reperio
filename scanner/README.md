# scanner — ephemeral scanner worker

Owner: the network-isolated process that receives the selected source device
read-only and emits normalized findings to the catalog.

- **Source of truth:** `docs/MASTER_PLAN.md` §3.1 and §6.3, `RPR-033`–`RPR-049`.
- **Status:** scanner/control-plane message contract (`RPR-033`) plus placeholder
  health entry point.
- **Health check:** `python -m scanner` (refuses any `--device` argument).
- **Boundary:** `O_RDONLY` only; no HTTP; no capabilities; no network; no
  provider/destination credentials. Recovery output goes only to proven-separate
  scratch storage.
- **Protocol:** `scanner.messages` defines the bounded versioned JSON-lines
  contract emitted by scanner workers.
- **Scheduler:** `scanner.scheduler` defines the single deep-scan stage graph and
  conservative I/O planning contract for `RPR-034`.
- **Source validation:** `scanner.source_validation` independently verifies the
  selected source is still block-special, read-only, and fingerprint-matched for
  `RPR-035` before parser stages run.
- **Partition discovery:** `scanner.partition_discovery` wraps bounded `mmls`
  output from The Sleuth Kit into normalized read-only partition extents for
  `RPR-036`; no repair/write command surface is exposed.
