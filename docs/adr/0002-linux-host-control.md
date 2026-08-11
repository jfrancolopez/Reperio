# ADR 0002 — Linux-first host controller

Status: accepted (RPR-003)
Date: 2026-08-10

## Context

Reperio must identify, prepare, and hand a physical source medium read-only to
an ephemeral scanner, and it must enforce a no-write guarantee. A component
with privileged device access is therefore unavoidable, but it must be the
smallest possible privileged surface: no parsing, no AI, no preview, no export,
no general shell.

The master plan restricts the scanner host to Linux (Arch Linux/Omarchy and
Ubuntu/Debian first, validated Unraid/NAS profile) and treats macOS/Windows as
browser clients only (master plan §5, §6.1).

## Decision

A narrow, privileged **Linux host controller (`hostd`)** is the only component
that may touch kernel device state. Its responsibilities are allowlisted:

- Observe block-device and removable-media add/remove/change events and report
  sanitized reader and inserted-medium facts.
- Resolve a selected stable identity to the current kernel path without
  trusting the path as identity.
- Report parent/child relationships, mounts, holders, RAID/LVM membership,
  capacity, geometry, transport, model/serial, optical TOC/sessions, and
  media-change generation.
- Read SMART/health where supported.
- Set and verify the kernel read-only flag.
- Launch, monitor, pause, resume, and stop the single scanner with a fixed
  container specification.
- Refuse internal system disks by default.
- Maintain an append-only safety audit.

The control plane communicates with `hostd` only over a narrow, versioned
Unix-socket protocol (`RPR-009`) and never mounts the Docker socket. There is no
shell, arbitrary command execution, path passthrough, or generic ioctl surface.

## Alternatives considered

- **Control plane performs device operations directly**: rejected because it
  would privilege parsing/AI/export code, violating the trust boundaries in
  `docs/THREAT_MODEL.md` (§7).
- **Windows/macOS host controller**: rejected by master plan §5.3; raw-device
  scanning is Linux-only in the foreseeable roadmap.
- **A general privileged helper/shell**: rejected as a violation of the narrow
  allowlisted-controller rule in `AGENTS.md`.

## Consequences

- Only `hostd` needs privileged access; everything else runs unprivileged.
- Any new device operation must be added to the allowlist and the threat model
  before implementation.
- Linux is the only scanner host; browser clients may run anywhere.

## Reversal conditions

This decision is reversed if raw-device scanning is extended to Windows/macOS
or if `hostd` gains general-purpose capability. Either change requires a new
ADR, a threat-model update, and fixture-backed hardware acceptance tests.
