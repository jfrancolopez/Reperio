#!/usr/bin/env python3
"""Configuration contract validation for RPR-007.

Loads the canonical defaults under ``config/``, validates each document against
its versioned schema (reusing the RPR-006 schema gate), then applies
cross-document combination rules so invalid source/destination, auth, provider,
and resource combinations fail with actionable messages before they reach a
scanner host. Secrets must always be SecretReference objects: inline secret
values are rejected by the application-settings schema and by policy.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import check_schema_compat as compat  # noqa: E402

CONFIG_DIR = ROOT / "config"
CONFIG_STEMS = (
    "application-settings",
    "scan-policy",
    "capabilities",
    "tool-availability",
    "resource-limits",
    "network-exposure",
    "feature-flags",
)

LOOPBACK_OR_LOCALHOST = {"127.0.0.1", "localhost", "::1", "::ffff:127.0.0.1"}
REMOTE_DESTINATION_KINDS = {"sftp", "s3", "webdav"}


def _load(path: Path) -> dict:
    with path.open(encoding="utf-8") as handle:
        data = json.load(handle)
    if not isinstance(data, dict):
        raise SystemExit(f"{path.relative_to(ROOT)}: expected a JSON object")
    return data


def load_configuration(root: Path = CONFIG_DIR) -> dict[str, dict]:
    documents: dict[str, dict] = {}
    for stem in CONFIG_STEMS:
        documents[stem] = _load(root / f"{stem}.json")
    return documents


def check_config_documents(documents: dict[str, dict]) -> list[str]:
    failures: list[str] = []
    used: set[str] = set()
    for stem, document in documents.items():
        if stem not in CONFIG_STEMS:
            failures.append(f"config: unknown document {stem!r}")
            continue
        used.add(stem)
        failures.extend(check_document_against_schema(stem, document))
    for stem in CONFIG_STEMS:
        if stem not in used:
            failures.append(f"config: missing document {stem!r}")
    return failures


def check_document_against_schema(stem: str, document: dict) -> list[str]:
    failures: list[str] = []
    schema_path = (compat.SCHEMAS_DIR / f"{stem}.schema.json").resolve()
    if not schema_path.exists():
        return [f"{stem}: no schema found at {schema_path.relative_to(ROOT)}"]
    try:
        schema = compat.load_document(schema_path)
    except (OSError, json.JSONDecodeError) as error:
        return [f"{stem}: cannot read schema: {error}"]

    schema_version = compat.schema_version_from_id(schema.get("$id"))
    if schema_version is None:
        failures.append(f"{schema_path.relative_to(ROOT)}: $id must end in /v<N>")
    data_version = document.get("schema_version")
    if data_version != schema_version:
        failures.append(
            f"{stem}: schema_version {data_version!r} does not match schema "
            f"{schema_path.relative_to(ROOT)} version {schema_version!r}"
        )
    failures.extend(compat.validate_schema(schema, schema, document, stem))
    return failures


def check_config_set(documents: dict[str, dict]) -> list[str]:
    failures: list[str] = []
    failures.extend(check_config_documents(documents))

    settings = documents.get("application-settings")
    capabilities = documents.get("capabilities")
    tool_availability = documents.get("tool-availability")
    resource_limits = documents.get("resource-limits")
    network = documents.get("network-exposure")
    flags = documents.get("feature-flags")

    if settings is not None:
        storage = settings.get("storage")
        if isinstance(storage, dict):
            state = storage.get("state")
            scratch = storage.get("scratch")
            if state == scratch:
                failures.append(
                    "application-settings.storage.state and .scratch must be distinct "
                    "paths (scratch on the source medium is prohibited)"
                )

        destinations = settings.get("destinations")
        if isinstance(destinations, list):
            for index, destination in enumerate(destinations):
                if not isinstance(destination, dict):
                    continue
                kind = destination.get("kind")
                label = f"application-settings.destinations[{index}]"
                if kind in REMOTE_DESTINATION_KINDS and not destination.get("credentials"):
                    failures.append(
                        f"{label}: {kind!r} destination requires a credentials SecretReference"
                    )

    if settings is not None:
        auth = settings.get("auth")
        if isinstance(auth, dict):
            if auth.get("enabled") is False and "password" in auth:
                failures.append(
                    "application-settings.auth.password is set while auth.enabled is "
                    "false; enable auth or remove the password reference"
                )
            if auth.get("enabled") is True and "password" not in auth:
                failures.append(
                    "application-settings.auth.enabled requires a password SecretReference"
                )

    if settings is not None and network is not None and flags is not None:
        providers = settings.get("ai_providers")
        if isinstance(providers, list):
            remote = [provider for provider in providers if provider.get("mode") == "remote"]
            if remote and network.get("network_enabled") is not True:
                failures.append(
                    "application-settings.ai_providers contains remote provider(s) "
                    "but network-exposure.network_enabled is false"
                )
            if providers and flags.get("ai_enabled") is not True:
                failures.append(
                    "application-settings.ai_providers is configured but "
                    "feature-flags.ai_enabled is false"
                )

    if flags is not None:
        if flags.get("cloud_ai") is True and flags.get("ai_enabled") is not True:
            failures.append("feature-flags.cloud_ai requires feature-flags.ai_enabled")
        if flags.get("local_models") is True and flags.get("ai_enabled") is not True:
            failures.append("feature-flags.local_models requires feature-flags.ai_enabled")
        if (
            flags.get("cloud_ai") is True
            and network is not None
            and network.get("network_enabled") is not True
        ):
            failures.append("feature-flags.cloud_ai requires network-exposure.network_enabled")

    if network is not None:
        if network.get("network_enabled") is True:
            bind_address = network.get("bind_address")
            if bind_address not in LOOPBACK_OR_LOCALHOST and (
                settings is None or settings.get("auth", {}).get("enabled") is not True
            ):
                failures.append(
                    "network-exposure: a non-loopback bind_address requires "
                    "application-settings.auth.enabled (UI without auth on the LAN "
                    "is prohibited)"
                )

    if capabilities is not None and tool_availability is not None and resource_limits is not None:
        tool_ids = {
            tool.get("id") for tool in tool_availability.get("tools", []) if isinstance(tool, dict)
        }
        profile_ids = set(resource_limits.get("profiles", {}))
        for index, capability in enumerate(capabilities.get("capabilities", [])):
            if not isinstance(capability, dict):
                continue
            label = f"capabilities.capabilities[{index}]"
            if capability.get("tool_id") not in tool_ids:
                failures.append(
                    f"{label}: tool_id {capability.get('tool_id')!r} is not listed in "
                    "tool-availability.tools"
                )
            if capability.get("resource_profile") not in profile_ids:
                failures.append(
                    f"{label}: resource_profile {capability.get('resource_profile')!r} "
                    "is not defined in resource-limits.profiles"
                )
            if capability.get("network_required") is True and (
                network is None or network.get("network_enabled") is not True
            ):
                failures.append(
                    f"{label}: capability {capability.get('id')!r} requires network but "
                    "network-exposure.network_enabled is false"
                )

    if tool_availability is not None and resource_limits is not None:
        profile_ids = set(resource_limits.get("profiles", {}))
        for index, tool in enumerate(tool_availability.get("tools", [])):
            if not isinstance(tool, dict):
                continue
            if tool.get("resource_profile") not in profile_ids:
                failures.append(
                    f"tool-availability.tools[{index}]: resource_profile "
                    f"{tool.get('resource_profile')!r} is not defined in "
                    "resource-limits.profiles"
                )

    return failures


def validate_config(root: Path = CONFIG_DIR) -> list[str]:
    documents = load_configuration(root)
    return check_config_set(documents)


def main() -> int:
    parser = argparse.ArgumentParser(description="Reperio configuration contract gate")
    parser.add_argument("--config-dir", type=Path, default=CONFIG_DIR)
    args = parser.parse_args()

    failures = validate_config(args.config_dir)
    if failures:
        print("FAIL: configuration contract")
        for failure in failures:
            print(f"  - {failure}")
        return 1
    print("PASS: configuration contract")
    return 0


if __name__ == "__main__":
    sys.exit(main())
