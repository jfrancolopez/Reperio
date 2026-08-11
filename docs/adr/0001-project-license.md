# ADR 0001 — Project license selection

Status: accepted (RPR-001)
Date: 2026-08-10

## Context

Reperio is a local-first, read-only media discovery and recovery application. Its
monorepo will eventually include a Python control plane, a React web UI, an
ephemeral scanner, sandboxed third-party parsing tools, and signed OCI images.

No license had been selected. `README.md` stated that no permission was granted
to copy, modify, or redistribute the project until `RPR-001` was complete.

Known design constraints relevant to license choice:

- The master plan (`docs/MASTER_PLAN.md` §14) intends to run GPL or other
  reciprocal-licensed tools (The Sleuth Kit, PhotoRec, John the Ripper,
  Hashcat, and others) as **separate, unmodified programs** to avoid linkage
  into Reperio's own code.
- The product is a single-operator, LAN-accessible web application rather than
  a distributed network service.
- Dependency redistribution responsibilities (image redistribution, NOTICE
  files, source offers) must be documented and machine-checkable before any
  dependency is accepted.
- The repository must stay auditable and dependency-free at build time; the
  license policy gate must run without external network access.

## Decision

Adopt **Apache License 2.0** as the Reperio project license.

A permissive license was chosen because:

1. **Copyleft components remain separate processes.** GPL/AGPL tools are
   invoked as pinned, unmodified external binaries through sandboxed adapters
   (master plan §6.3, §14). Apache-2.0 therefore does not conflict with the
   intended tool strategy.
2. **Patent grant.** Apache-2.0 includes an explicit patent grant, reducing
   downstream uncertainty for a security- and recovery-focused tool.
3. **Widespread ecosystem compatibility.** Apache-2.0 is compatible with the
   expected control-plane, web, and container stack and with most third-party
   licenses under review.
4. **Documented attribution practice.** Apache-2.0 codifies NOTICE and
   attribution requirements that map directly to the dependency-intake
   checklist this task delivers.

## Consequences

- All repository code is contributed under Apache-2.0 (per §5, contributions are
  granted under the same license).
- The `LICENSE` file at the repository root is the canonical license text.
- A machine-checkable dependency-license gate (`scripts/check_dependency_licenses.py`)
  rejects dependencies that are missing license metadata or that fall outside
  the approved policy in `scripts/dependency-license-policy.json`.
- Reciprocal licenses are acceptable **only** as declared separate-process or
  separately-distributed components that satisfy the intake checklist in
  `docs/DEPENDENCY_INTAKE.md`, never as linked or vendored source.
- Container image redistribution must retain NOTICE/attribution and satisfy any
  source-offer obligations of included components (checked at release time by
  `RPR-147`).

## Alternatives considered

- **GPL-3.0 / AGPL-3.0**: rejected because the intended use of separate GPL
  processes does not require a copyleft project license, and a copyleft project
  license would impose share-alike obligations on downstream adopters and
  integrations without improving the safety model.
- **MIT**: rejected because it lacks Apache-2.0's patent grant and its
  documented NOTICE/attribution machinery, which this product needs for
  containerized redistribution.
- **No license / proprietary**: rejected because the repository is public and
  the backlog requires an open, auditable license gate.

## Reversal conditions

This decision is reversed if the owner decides that downstream derivatives must
be share-alike (GPL-3.0 or AGPL-3.0). Such a change requires updating the root
`LICENSE` file, the ADR, the intake checklist, the policy configuration, and
reviewing every already-accepted dependency for compatibility. It must be
approved and recorded before any release.
