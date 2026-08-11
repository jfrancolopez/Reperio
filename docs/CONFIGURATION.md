# Reperio configuration contract

Status: contract for RPR-007 (configuration and capability schemas). Reader: implementation agents and CI.

## Documents

Every versioned configuration document lives in [`config/`](../config/) with a matching versioned JSON Schema in [`scripts/schemas/`](../scripts/schemas/). A document's `schema_version` must equal the `/v<N>` embedded in its schema `$id`; `scripts/schema-check.py` and `scripts/config_validator.py` enforce this on every `make validate` and `make quality`.

| Document | Schema | Purpose |
|---|---|---|
| `config/application-settings.json` | `application-settings.schema.json` | Storage paths, authentication, locale, AI provider order, export destinations |
| `config/scan-policy.json` | `scan-policy.schema.json` | One deep-scan mode; carving, trash reconstruction, score threshold, partial-output retention |
| `config/capabilities.json` | `capabilities.schema.json` | Host capability manifest bound to tools, network requirement, and resource profile |
| `config/tool-availability.json` | `tool-availability.schema.json` | Adventable third-party tool matrix (immutable versions, sandbox profile, enabled flag) |
| `config/resource-limits.json` | `resource-limits.schema.json` | Defaults and named profiles for CPU/memory/PID/scratch/time/output bounds |
| `config/network-exposure.json` | `network-exposure.schema.json` | Local-network UI reachability, bind address, port, allowed subnets |
| `config/feature-flags.json` | `feature-flags.schema.json` | Runtime feature gates (AI, local models, cloud AI, notifications, experimental) |

## Secrets are references, never inline

Secret-capable fields (`auth.password`, `ai_providers[].api_key`, `destinations[].credentials`) accept only a `SecretReference` object:

```json
{
  "kind": "secret_reference",
  "ref": "env:REPERIO_AI_API_KEY",
  "description": "Credential kept outside the repository and outside config files"
}
```

The `ref` names a location (`env:<NAME>` or `vault:<key>`) whose value is resolved at runtime by the secret store. A plain string in a secret-capable field is a schema type error; an empty `ref` is rejected. Config files, logs, and task payloads never contain the secret value itself.

## Unknown keys and invalid combinations

Schemas set `additionalProperties: false`, so unknown keys fail with an actionable `unknown key` message identifying the offending path. Cross-document combination rules in `scripts/config_validator.py` reject, with reasons:

- `storage.state` and `storage.scratch` must differ (scratch never on the source medium).
- A non-loopback `bind_address` requires `auth.enabled`.
- `auth.enabled: true` requires a password `SecretReference`; `auth.enabled: false` forbids one.
- Remote destinations (`sftp`/`s3`/`webdav`) require a credentials `SecretReference`.
- Remote AI providers require `network_exposure.network_enabled`; any configured provider requires `feature-flags.ai_enabled`.
- `feature-flags.cloud_ai` / `local_models` require `ai_enabled`; `cloud_ai` requires network.
- Every `capabilities[].tool_id` must exist in `tool-availability.tools`; every tool/capability `resource_profile` must exist in `resource-limits.profiles`.
- A capability with `network_required: true` requires `network_exposure.network_enabled`.
- Resource limits are bounded (e.g. `cpu_quota_percent` in 1..100, positive memory/PID/scratch/time/output).

## Environment overrides

Scalar settings may be overridden with `REPERIO_`-prefixed environment variables. Overrides must satisfy the same schema and combination rules; they are applied after reading the JSON defaults and before validation. A secret value is never supplied inline via an override that names the value; instead the related environment variable holds the reference target (for example `REPERIO_AUTH_PASSWORD_REF=env:MY_OPERATOR_PASSWORD`, with `MY_OPERATOR_PASSWORD` set in the operator's secret store).

| Setting | Default | Override |
|---|---|---|
| `storage.state` | `/var/lib/reperio` | `REPERIO_STORAGE_STATE` |
| `storage.scratch` | `/var/lib/reperio/scratch` | `REPERIO_STORAGE_SCRATCH` |
| `auth.enabled` | `false` | `REPERIO_AUTH_ENABLED` |
| `auth.password` ref | — | `REPERIO_AUTH_PASSWORD_REF` |
| `network.network_enabled` | `false` | `REPERIO_NETWORK_ENABLED` |
| `network.bind_address` | `127.0.0.1` | `REPERIO_NETWORK_BIND_ADDRESS` |
| `network.port` | `8787` | `REPERIO_NETWORK_PORT` |
| `scan_policy.carving_enabled` | `true` | `REPERIO_SCAN_POLICY_CARVING_ENABLED` |
| `scan_policy.trash_reconstruction` | `true` | `REPERIO_SCAN_POLICY_TRASH_RECONSTRUCTION` |
| `feature_flags.ai_enabled` | `false` | `REPERIO_FEATURE_FLAGS_AI_ENABLED` |
| `feature_flags.cloud_ai` | `false` | `REPERIO_FEATURE_FLAGS_CLOUD_AI` |

Boolean overrides accept `1`/`true`/`yes`/`on` and `0`/`false`/`no`/`off`. Invalid override values fail validation with the underlying schema message.

## Relationship to later work

- `RPR-019–020` consume the capabilities manifest and resource profiles to launch sandboxed tools.
- `RPR-021+` implement catalog/schema versioning using the same `scripts/schemas/` gate.
- `RPR-178–180` keep tool availability and capability claims truthful against the fixture/hardware matrix.
