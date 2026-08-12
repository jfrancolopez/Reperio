# worker — sandboxed enrichment workers

Owner: preview, OCR, parse, AI-adapter, export, and notification workers that
operate only on copies/derivatives in scratch storage.

- **Source of truth:** `docs/MASTER_PLAN.md` §6.4, `RPR-070`–`RPR-082`,
  `RPR-091`–`RPR-113`.
- **Status:** placeholder skeleton (`RPR-004`); no feature implementation.
- **Health check:** `python -m worker` (refuses any `--device` argument).
- **Boundary:** never receives a source-device handle; runs sandboxed with
  bounded resources; network disabled unless the configured provider requires it.
- **Content signatures:** `worker.content_signature` provides deterministic,
  bounded MIME/signature detection with extension-mismatch evidence for
  `RPR-050`; extension alone never selects a dangerous parser.
- **Windows profiles:** `worker.windows_profiles` locates Windows installations
  and user profile roots from normalized path evidence for `RPR-051`, keeping
  SIDs and display names distinct.
- **Windows noise rules:** `worker.windows_noise_rules` applies versioned,
  reversible Windows OS/cache/package noise visibility rules for `RPR-052`.
