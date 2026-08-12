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
