# Host-controller protocol (RPR-009)

Status: contract for `RPR-009`; no device implementation.

The control plane talks to `hostd` over a local Unix socket using one versioned
JSON envelope. Authentication is represented by `unix_peer_credentials`; the
future socket server must verify peer credentials out of band and must not place
secret bearer values in the message body.

Allowed request methods are fixed in `hostd.protocol.METHODS` and mirrored by
`scripts/schemas/hostd-protocol.schema.json`:

| Method | Purpose | Required params |
|---|---|---|
| `list_devices` | Return sanitized source candidates. | none |
| `inspect_safety` | Inspect current safety facts for one opaque source. | `source_id`, `observed_generation` |
| `prepare_read_only` | Set/verify read-only state after current safety inspection and operator confirmation. | `source_id`, `observed_generation`, `safety_inspection_id`, `operator_confirmation_token` |
| `launch_scanner` | Launch the future fixed scanner sandbox for one prepared source. | `source_id`, `observed_generation`, `safety_inspection_id`, `readonly_preparation_id`, `scan_case_id`, `scratch_separation_id`, `resource_profile` |
| `scanner_status` | Query a fixed scanner session. | `scanner_session_id` |
| `stop_scanner` | Request safe stop of a fixed scanner session. | `scanner_session_id`, `reason` |
| `reconnect` | Reattach to a prior case only when source generation still matches. | `scan_case_id`, `source_id`, `observed_generation` |

The protocol deliberately has no method or field for shell commands, arbitrary
paths, mounts, writes, repairs, generic ioctls, extra devices, custom container
images, entry points, capabilities, network flags, or caller-supplied scanner
arguments. Source references are opaque Reperio IDs plus a media/device
generation. A request naming a known source with an old generation is rejected as
stale before any later source-touching operation can run.

Contract tests live in `tests/test_hostd_protocol.py` and cover every valid
method, unknown methods, path-like strings, stale source generations, Boolean
generation confusion, extra launch flags, incompatible schema versions, exact
success/error response shapes, and parity between the Python allowlist and each
method-specific JSON Schema parameter definition.
