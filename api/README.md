# api — control-plane REST API

Owner: versioned REST API, SQLite catalog/jobs, SSE, and static-UI serving.

- **Source of truth:** `docs/MASTER_PLAN.md` §6.2, `RPR-027`–`RPR-032`.
- **Status:** placeholder skeleton (`RPR-004`); no feature implementation.
- **Health check:** `python -m api` (refuses any `--device` argument).
- **Boundary:** never receives a source-device handle or destination/device
  paths by reference; communicates with `hostd` only over the narrow Unix-socket
  protocol (`RPR-009`).
