# hostd — Linux host controller

Owner: the smallest privileged component. Only `hostd` may touch kernel device
state: identity resolution, mount/holder inspection, kernel read-only
verification, SMART where supported, and launching the fixed scanner container.

- **Source of truth:** `docs/adr/0002-linux-host-control.md`, `RPR-009`–`RPR-020`.
- **Status:** placeholder skeleton (`RPR-004`); no feature implementation.
- **Health check:** `python -m hostd` (refuses any `--device` argument).
- **Language note:** implemented in Python to match the control-plane stack. A
  future ADR may move `hostd` to a native binary if privileged-binary isolation
  requirements demand it (see ADR 0002 reversal conditions).
- **Boundary:** no parsing, AI, preview, export, shell, or generic ioctl surface.
