# scanner — ephemeral scanner worker

Owner: the network-isolated process that receives the selected source device
read-only and emits normalized findings to the catalog.

- **Source of truth:** `docs/MASTER_PLAN.md` §3.1 and §6.3, `RPR-033`–`RPR-049`.
- **Status:** placeholder skeleton (`RPR-004`); no feature implementation.
- **Health check:** `python -m scanner` (refuses any `--device` argument).
- **Boundary:** `O_RDONLY` only; no HTTP; no capabilities; no network; no
  provider/destination credentials. Recovery output goes only to proven-separate
  scratch storage.
