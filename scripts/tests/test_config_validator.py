#!/usr/bin/env python3

from __future__ import annotations

import copy
import json
import sys
import typing as t
import unittest
from pathlib import Path

REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPOSITORY_ROOT / "scripts"))

import config_validator as config  # noqa: E402

CONFIG_DIR = REPOSITORY_ROOT / "config"


def load_defaults() -> dict[str, dict]:
    documents: dict[str, dict] = {}
    for stem in config.CONFIG_STEMS:
        with (CONFIG_DIR / f"{stem}.json").open(encoding="utf-8") as handle:
            documents[stem] = json.load(handle)
    return documents


def secret_reference(ref: str, description: str = "test secret") -> dict:
    return {"kind": "secret_reference", "ref": ref, "description": description}


class ConfigurationContractTests(unittest.TestCase):
    def test_defaults_validate_without_failures(self) -> None:
        documents = load_defaults()

        failures = config.check_config_set(documents)

        self.assertEqual([], failures)

    def test_defaults_round_trip_preserves_document(self) -> None:
        for stem, document in load_defaults().items():
            re_encoded = json.loads(json.dumps(document))
            self.assertEqual(document, re_encoded, f"{stem} did not round-trip")

    def _with_document(self, stem: str, mutate: t.Callable[[dict], dict]) -> dict[str, dict]:
        documents = load_defaults()
        documents[stem] = mutate(documents[stem])
        return documents

    def test_unknown_key_produces_actionable_error(self) -> None:
        documents = load_defaults()
        documents["application-settings"]["bogus_setting"] = True

        failures = config.check_config_set(documents)

        self.assertTrue(
            any("unknown key 'bogus_setting'" in failure for failure in failures),
            failures,
        )

    def test_destination_with_inline_secret_is_rejected(self) -> None:
        documents = load_defaults()
        documents["application-settings"]["destinations"] = [
            {
                "name": "inline-secret-dest",
                "kind": "sftp",
                "target": "sftp://host.example/srv",
                "credentials": "actually-a-secret-value",
            }
        ]

        failures = config.check_config_set(documents)

        self.assertTrue(any("credentials" in failure for failure in failures), failures)
        self.assertTrue(
            any(
                "expected type 'object'" in failure or "SecretReference" in failure
                for failure in failures
            ),
            failures,
        )

    def test_remote_destination_requires_credentials_reference(self) -> None:
        documents = load_defaults()
        documents["application-settings"]["destinations"] = [
            {
                "name": "no-creds-dest",
                "kind": "s3",
                "target": "s3://bucket/path",
            }
        ]

        failures = config.check_config_set(documents)

        self.assertTrue(any("requires a credentials" in failure for failure in failures))

    def test_auth_password_while_disabled_is_rejected(self) -> None:
        documents = load_defaults()
        documents["application-settings"]["auth"] = {
            "enabled": False,
            "password": secret_reference("env:REPERIO_AUTH_PASSWORD"),
        }

        failures = config.check_config_set(documents)

        self.assertTrue(any("auth.enabled is false" in failure for failure in failures))

    def test_auth_enabled_requires_password_reference(self) -> None:
        documents = load_defaults()
        documents["application-settings"]["auth"] = {"enabled": True}

        failures = config.check_config_set(documents)

        self.assertTrue(any("requires a password" in failure for failure in failures))

    def test_remote_ai_provider_requires_network(self) -> None:
        documents = load_defaults()
        documents["application-settings"]["ai_providers"] = [
            {
                "name": "remote-provider",
                "provider": "example-provider",
                "model": "example-model",
                "mode": "remote",
                "api_key": secret_reference("env:REPERIO_AI_API_KEY"),
            }
        ]
        documents["feature-flags"]["ai_enabled"] = True

        failures = config.check_config_set(documents)

        self.assertTrue(
            any("network-exposure.network_enabled is false" in failure for failure in failures)
        )

    def test_ai_provider_without_ai_enabled_is_rejected(self) -> None:
        documents = load_defaults()
        documents["application-settings"]["ai_providers"] = [
            {
                "name": "local-provider",
                "provider": "local",
                "model": "local-model",
                "mode": "local",
                "api_key": secret_reference("vault:local-key"),
            }
        ]

        failures = config.check_config_set(documents)

        self.assertTrue(any("feature-flags.ai_enabled is false" in failure for failure in failures))

    def test_resource_limit_out_of_range_is_rejected(self) -> None:
        documents = load_defaults()
        documents["resource-limits"]["defaults"]["cpu_quota_percent"] = 0

        failures = config.check_config_set(documents)

        self.assertTrue(any("below minimum" in failure for failure in failures))

    def test_capability_referencing_missing_tool_is_rejected(self) -> None:
        documents = load_defaults()
        documents["capabilities"]["capabilities"][0]["tool_id"] = "no-such-tool"

        failures = config.check_config_set(documents)

        self.assertTrue(
            any("not listed in tool-availability.tools" in failure for failure in failures)
        )

    def test_capability_requiring_network_without_network_is_rejected(self) -> None:
        documents = load_defaults()
        documents["capabilities"]["capabilities"][0]["network_required"] = True

        failures = config.check_config_set(documents)

        self.assertTrue(any("requires network" in failure for failure in failures))

    def test_scratch_and_state_must_differ(self) -> None:
        documents = load_defaults()
        documents["application-settings"]["storage"]["scratch"] = "/var/lib/reperio"

        failures = config.check_config_set(documents)

        self.assertTrue(any("must be distinct paths" in failure for failure in failures))

    def test_non_loopback_bind_without_auth_is_rejected(self) -> None:
        documents = load_defaults()
        documents["network-exposure"]["network_enabled"] = True
        documents["network-exposure"]["bind_address"] = "0.0.0.0"

        failures = config.check_config_set(documents)

        self.assertTrue(any("non-loopback bind_address" in failure for failure in failures))

    def test_missing_config_document_is_rejected(self) -> None:
        documents = copy.deepcopy(load_defaults())
        del documents["feature-flags"]

        failures = config.check_config_set(documents)

        self.assertTrue(any("missing document 'feature-flags'" in failure for failure in failures))


if __name__ == "__main__":
    unittest.main()
