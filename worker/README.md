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
- **Interest scoring:** `worker.interest_scoring` combines deterministic path,
  owner, type, state, application, and noise-rule signals into independent
  versioned interest/noise scores for `RPR-053`.
- **Core categories:** `worker.core_categories` assigns versioned, explainable
  multi-label finding categories for `RPR-054` without hiding any category from
  All Findings.
- **Software inventory:** `worker.software_inventory` builds evidence-only
  Windows application and utility inventory records for `RPR-055` from inert
  normalized paths and metadata; it never executes recovered binaries.
- **Backup locators:** `worker.backup_locators` inventories Windows Backup,
  File History, VM/disk images, phone backups, sync roots, and generic backup
  artifacts for `RPR-056`; nested scheduling is explicit and bounded.
- **Mobile backups:** `worker.mobile_backups` detects iTunes/Finder iOS backup
  folders and Android backup layouts for `RPR-057` using inert path/manifest
  metadata; encrypted and unsupported backups remain visible.
