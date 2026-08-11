# Dependency intake checklist

Status: accepted (RPR-001)
Applies to every software dependency, tool, OCI base, Python package, npm
package, or separately executed third-party program that Reperio ships or
automatically downloads.

A dependency is **not considered accepted** until all of the following are
checked, the canonical form is recorded in `docs/dependency-registry.json`, and
the machine gate (`scripts/check_dependency_licenses.py`) passes.

## 1. Identity and provenance

- [ ] Exact immutable version (a tag, commit, or digest), never `latest` or a
      mutable ref.
- [ ] Authoritative source URL and, for binaries/images, the release artifact
      URL.
- [ ] Verified checksum/digest or signature for downloaded artifacts is
      recorded.
- [ ] License identifier is a valid SPDX expression; a raw file such as
      `LICENSE.txt` is not a substitute for the SPDX metadata.

## 2. License compatibility with the project license (Apache-2.0)

- [ ] The dependency's license is listed under `allowed` in
      `scripts/dependency-license-policy.json`, **or**
- [ ] The dependency's license is listed under `separate_process_allowed` and
      the intake records that it is used **only** as a separate, unmodified
      program (never linked, monkey-patched, or vendored into Reperio source),
      **or** an explicit, reviewed exception is recorded instead of being
      silently allowed.
- [ ] Tier-1 approved SPDX IDs include: `Apache-2.0`, `MIT`, `BSD-2-Clause`,
      `BSD-3-Clause`, `ISC`, `0BSD`, `MPL-2.0`, `Python-2.0`, `EPL-2.0`,
      `LGPL-2.1-only`, `LGPL-3.0-only`.
- [ ] Tier-2 separate-process SPDX IDs include: `GPL-2.0-only`, `GPL-3.0-only`,
      `AGPL-3.0-only`. A tier-2 license in a linked/vendored role is rejected.

## 3. Reciprocal licenses and separate-process use

For any reciprocal-licensed (GPL/AGPL/LGPL-family) tool:

- [ ] It is executed as a separate unmodified program through a sandboxed
      adapter (master plan §6.3, §14).
- [ ] Reperio does not import, link, vendor, or distribute its source.
- [ ] The tool's license, version, and the exact adapters that invoke it are
      recorded, and its own license texts/NOTICE are retained at release time.
- [ ] If the tool or its container image is redistributed, the source offer or
      corresponding-source disclosure required by the tool's license is
      prepared before release (`RPR-147`).

## 4. Image redistribution and notices

- [ ] Every base image, tool image, and binary layer is digest-pinned and
      recorded by source and license.
- [ ] NOTICE/attribution text for each included component is collected and
      retained; a future SBOM release task packages it.
- [ ] No component is bundled in a way that silently converts its license
      obligations (for example, copyleft source distribution) onto downstream
      users.

## 5. Architecture, sandbox, and security boundary

- [ ] Supported architectures (`amd64`, `arm64`, ...) are recorded.
- [ ] The required sandbox profile is recorded (no network, non-root, read-only
      root, no source device, resource limits) when the component parses
      untrusted content.
- [ ] Known CVEs or maintenance status are assessed and recorded, matching the
      later `RPR-148` patch policy.
- [ ] The dependency never receives a source-device handle, provider or
      destination credentials, or wallet secret material.

## 6. Removal path

- [ ] A concrete removal path is noted: the capability that depends on the
      component and how scanning degrades (capability disabled) if it is
      removed.

## Checklist enforcement

- [ ] `make validate` runs `scripts/check_dependency_licenses.py` against
      `docs/dependency-registry.json` and the policy file.
- [ ] The checker is exercised by two fixtures: one fully allowed dependency
      and one intentionally rejected dependency (missing license metadata).
- [ ] A dependency missing license metadata, recorded with an unknown SPDX ID,
      or using a tier-2 license in a linked role fails the gate and is not
      accepted.
