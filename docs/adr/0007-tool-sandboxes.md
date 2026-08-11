# ADR 0007 — Version-pinned sandboxed tool execution

Status: accepted (RPR-003)
Date: 2026-08-10

## Context

Reperio parses hostile source content with many third-party tools (TSK,
PhotoRec, Tika, ExifTool, ffprobe, libvips, FFmpeg, Tesseract, OCRmyPDF,
libarchive/7-Zip, John the Ripper, rclone, Apprise, and future plugins). Any
parser could be a target or a buggy component. Tools must therefore run with
the same guarantees as the scanner itself: no source device, no network, no
capabilities, non-root, read-only root, bounded resources, and a timeout
(master plan §3.2, §6.4).

## Decision

Every third-party tool executes through a **generic, version-pinned sandbox
runner** (`RPR-070`) with:

- Fixed per-tool profiles; arguments are allowlisted per profile.
- Copy-only input from the content store; no source-device handle anywhere in
  the worker.
- No network, no Linux capabilities, non-root UID, read-only root filesystem.
- Bounded CPU, memory, PID, output, nesting, and time limits with structured
  stdout and cleanup.
- Tools and images pinned by immutable release or digest with license and
  architecture recorded (`RPR-001`, `docs/DEPENDENCY_INTAKE.md`).
- Separate sandbox profiles per category (document/archive, media, OCR,
  transcription, browser artifacts, AI, password audit).

Tools with reciprocal licenses run as separate, unmodified programs, never
linked or vendored (ADR 0001).

## Alternatives considered

- **Running tools in the control-plane process**: rejected; a parser crash or
  exploit would then control the catalog and control plane.
- **Unprivileged processes without sandboxes**: rejected; lacks resource limits
  and isolation, and cannot guarantee no network/device access.
- **One shared container for all tools**: rejected; a single compromised
  profile would grant access to every tool's capabilities.

## Consequences

- Each tool capability must be declared in the sandbox profile, so adding a
  tool is an explicit, reviewed change.
- Performance overhead is accepted in exchange for isolation; enumeration
  never blocks on thumbnail/preview work.
- A `RPR-070` malicious-parser suite (forbidden access, fork bomb, output
  flood, timeout, path traversal, crash) proves the boundary.

## Reversal conditions

Reversed if a tool must run with network access or a device handle; such a tool
cannot be a parser and requires a new ADR plus a network-separation review
(network-enabled workers never receive arbitrary paths or a source device,
master plan §6.4).
