# ADR 0008 — Optional, privacy-gated AI with deterministic fallback

Status: accepted (RPR-003)
Date: 2026-08-10

## Context

Reperio's discovery, classification, ordering, and safety are deterministic and
must never depend on AI being available. AI is a runtime enhancement: it can
explain, compare, cluster, translate, and rank, but it cannot enumerate the
filesystem, delete or hide a finding, or control completion (master plan §2,
§7 Stage I, §11).

Multiple providers are possible (none, OpenAI-compatible LAN endpoint, Ollama,
generic embeddings, official adapters). Remote providers must be opt-in with
explicit acknowledgment, and wallet/secret material must never leave the host.

## Decision

AI is **optional at runtime** and implemented through a provider- and
model-agnostic adapter layer (`RPR-083`–`RPR-094`):

- Deterministic pipeline runs with zero providers; AI degrades to
  deterministic behavior when unavailable.
- Multiple ordered named provider profiles with workload eligibility, local vs
  remote distinction, and a privacy gate that blocks remote calls until the
  operator acknowledges `RPR-093`.
- Models receive only explicit extracted text, metadata, or safe derivatives —
  never filesystem access, tools, paths, or the source device.
- Wallet secrets, seeds, private keys, keystores, and decrypted vault values
  are never sent to any model or provider; local models receive only explicitly
  redacted derivatives.
- Calls are batched and cached by content hash/prompt/provider/model/version so
  provider outages cannot block deterministic scan completion.

## Alternatives considered

- **AI-only discovery or classification**: rejected; violates the invariant
  that AI cannot control discovery completeness.
- **Mandatory AI dependency**: rejected; the product must work fully
  offline/deterministically.
- **Allowing remote AI by default**: rejected; privacy gate (`RPR-093`) is
  mandatory, and only the operator's explicit acknowledgment enables remote
  providers.

## Consequences

- Model inputs/outputs are stored as opinions with provenance, provider/model
  versions, confidence, and evidence; consensus can never alter scores,
  dismissal, or visibility.
- A remote provider may receive selected content only after explicit
  acknowledgment; retention is configurable.
- Deterministic scores/categories remain the source of truth for navigation.

## Reversal conditions

Reversed if AI becomes mandatory for any required message or if a provider may
receive source-device handles, tools, paths, wallet secrets, or the ability to
delete/hide findings. That would violate master plan §3 and §11 and requires a
new ADR plus threat-model update.
