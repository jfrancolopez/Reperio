# worker — sandboxed enrichment workers

Owner: preview, OCR, parse, AI-adapter, export, and notification workers that
operate only on copies/derivatives in scratch storage.

- **Source of truth:** `docs/MASTER_PLAN.md` §6.4, `RPR-070`–`RPR-082`,
  `RPR-091`–`RPR-113`.
- **Status:** placeholder skeleton (`RPR-004`); no feature implementation.
- **Health check:** `python -m worker` (refuses any `--device` argument).
- **Boundary:** never receives a source-device handle; runs sandboxed with
  bounded resources; network disabled unless the configured provider requires it.
