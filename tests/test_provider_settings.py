#!/usr/bin/env python3

from __future__ import annotations

import unittest

from worker import provider_settings


def profile_record(name: str, **overrides: object) -> dict[str, object]:
    record: dict[str, object] = {
        "name": name,
        "enabled": True,
        "mode": "local",
        "endpoint": "local",
        "model": "mock-model-v1",
        "tasks": ["classification", "summarization"],
        "categories": ["documents", "media"],
        "weight": 10,
        "timeout_seconds": 60,
        "api_key_ref": None,
    }
    record.update(overrides)
    return record


def settings(
    records: list[dict[str, object]] | None = None, *, remote_acknowledged: bool = False
) -> provider_settings.ProviderSettings:
    return provider_settings.normalize_provider_settings(
        records or [profile_record("primary")], remote_acknowledged=remote_acknowledged
    )


class ProviderSettingsTests(unittest.TestCase):
    def test_duplicate_names_are_rejected(self) -> None:
        with self.assertRaisesRegex(
            provider_settings.ProviderSettingsError, "defined more than once"
        ):
            provider_settings.normalize_provider_settings(
                [profile_record("primary"), profile_record("primary")]
            )

    def test_invalid_profile_name_is_rejected(self) -> None:
        with self.assertRaisesRegex(
            provider_settings.ProviderSettingsError, "not a safe identifier"
        ):
            provider_settings.normalize_provider_settings([profile_record("bad name")])

    def test_remote_profile_requires_acknowledgment(self) -> None:
        unacked = settings(
            [profile_record("remote", mode="remote", endpoint="https://api.example.invalid")],
            remote_acknowledged=False,
        )
        with self.assertRaisesRegex(
            provider_settings.ProviderSettingsError, "explicit acknowledgment"
        ):
            provider_settings.ensure_remote_gate(unacked)

        acked = settings(
            [profile_record("remote", mode="remote", endpoint="https://api.example.invalid")],
            remote_acknowledged=True,
        )
        provider_settings.ensure_remote_gate(acked)  # should not raise

    def test_remote_gate_passes_when_only_local_enabled(self) -> None:
        local_only = settings([profile_record("primary")], remote_acknowledged=False)
        provider_settings.ensure_remote_gate(local_only)

    def test_remote_endpoint_cannot_use_local_endpoint(self) -> None:
        with self.assertRaisesRegex(
            provider_settings.ProviderSettingsError, "local endpoint cannot"
        ):
            provider_settings.normalize_provider_settings(
                [profile_record("remote", mode="remote", endpoint="local")]
            )

    def test_inline_secret_is_rejected(self) -> None:
        with self.assertRaisesRegex(provider_settings.ProviderSettingsError, "never inline"):
            provider_settings.normalize_provider_settings(
                [
                    profile_record(
                        "remote",
                        mode="remote",
                        endpoint="https://x.invalid",
                        api_key_ref="AKIAINLINE",
                    )
                ]
            )

    def test_vault_secret_reference_is_accepted(self) -> None:
        profiles = provider_settings.normalize_provider_settings(
            [
                profile_record(
                    "remote",
                    mode="remote",
                    endpoint="https://api.example.invalid",
                    api_key_ref="vault:abc123def456",
                )
            ]
        )
        self.assertEqual("vault:abc123def456", profiles.profiles[0].api_key_ref)

    def test_missing_model_and_endpoint_are_rejected(self) -> None:
        with self.assertRaisesRegex(provider_settings.ProviderSettingsError, "model"):
            provider_settings.normalize_provider_settings([profile_record("primary", model="")])
        with self.assertRaisesRegex(provider_settings.ProviderSettingsError, "endpoint"):
            provider_settings.normalize_provider_settings(
                [profile_record("remote", mode="remote", endpoint="")]
            )

    def test_unsupported_task_and_category_are_rejected(self) -> None:
        with self.assertRaisesRegex(provider_settings.ProviderSettingsError, "unknown keyword"):
            provider_settings.normalize_provider_settings(
                [profile_record("primary", tasks=["transmogrify"])]
            )
        with self.assertRaisesRegex(provider_settings.ProviderSettingsError, "unknown keyword"):
            provider_settings.normalize_provider_settings(
                [profile_record("primary", categories=["vapor"])]
            )

    def test_remote_profile_without_secret_warns(self) -> None:
        profiles = settings(
            [profile_record("remote", mode="remote", endpoint="https://api.example.invalid")]
        )
        warnings = provider_settings.validate_provider_settings(profiles)
        self.assertIn("remote:remote_profile_without_secret_reference", warnings)

    def test_unlimited_primary_secondary_tertiary_selection(self) -> None:
        records = [
            profile_record("a", weight=30),
            profile_record("b", weight=20),
            profile_record("c", weight=10),
            profile_record("d", weight=5),
            profile_record("e", weight=1),
        ]
        routed = settings(records)
        primary, secondary, tertiary = provider_settings.select_primary_secondary_tertiary(
            routed, "classification"
        )
        assert primary is not None
        assert secondary is not None
        assert tertiary is not None
        self.assertEqual("a", primary.name)
        self.assertEqual("b", secondary.name)
        self.assertEqual("c", tertiary.name)
        self.assertEqual(
            ["a", "b", "c", "d", "e"],
            [
                profile.name
                for profile in provider_settings.route_profiles(routed, "classification")
            ],
        )

    def test_disabled_profiles_are_not_routed(self) -> None:
        records = [
            profile_record("a", weight=30),
            profile_record("disabled", weight=100, enabled=False),
        ]
        routed = settings(records)
        self.assertEqual(
            ["a"], [p.name for p in provider_settings.route_profiles(routed, "classification")]
        )

    def test_ineligible_task_is_not_routed(self) -> None:
        routed = settings([profile_record("text-only", tasks=["text"])])
        self.assertEqual([], list(provider_settings.route_profiles(routed, "vision")))

    def test_reorder_profiles(self) -> None:
        routed = settings([profile_record("a"), profile_record("b"), profile_record("c")])
        reordered = provider_settings.reorder_profiles(routed, ["c", "a", "b"])
        self.assertEqual(["c", "a", "b"], [p.name for p in reordered.profiles])

    def test_reorder_requires_exact_set(self) -> None:
        routed = settings([profile_record("a"), profile_record("b")])
        with self.assertRaisesRegex(provider_settings.ProviderSettingsError, "exactly once"):
            provider_settings.reorder_profiles(routed, ["a"])


class ProviderHealthCheckTests(unittest.TestCase):
    def test_reachable_endpoint_with_present_model(self) -> None:
        routed = settings([profile_record("primary")])
        result = provider_settings.health_check(
            routed.profiles[0],
            lambda endpoint, model: {"reachable": True, "model_status": "present"},
        )
        self.assertTrue(result.reachable)
        self.assertEqual("present", result.model_status)
        self.assertEqual([], list(result.warnings))

    def test_unreachable_endpoint_reports_status(self) -> None:
        routed = settings([profile_record("primary")])
        result = provider_settings.health_check(
            routed.profiles[0],
            lambda endpoint, model: {"reachable": False, "model_status": "unknown"},
        )
        self.assertFalse(result.reachable)
        self.assertIn("endpoint_unreachable", result.warnings)

    def test_wrong_model_is_reported_as_missing(self) -> None:
        routed = settings([profile_record("primary", model="gpt-something-else")])
        result = provider_settings.health_check(
            routed.profiles[0],
            lambda endpoint, model: {"reachable": True, "model_status": "missing"},
        )
        self.assertTrue(result.reachable)
        self.assertEqual("missing", result.model_status)

    def test_health_check_never_receives_content(self) -> None:
        captured: list[tuple[str, str]] = []

        def checker(endpoint: str, model: str) -> dict:
            captured.append((endpoint, model))
            return {"reachable": True, "model_status": "present"}

        routed = settings([profile_record("primary")])
        provider_settings.health_check(routed.profiles[0], checker)
        self.assertEqual([("local", "mock-model-v1")], captured)

    def test_checker_failure_is_a_health_status(self) -> None:
        routed = settings([profile_record("primary")])

        def boom(endpoint: str, model: str) -> dict:
            raise TimeoutError("hang")

        result = provider_settings.health_check(routed.profiles[0], boom)
        self.assertFalse(result.reachable)
        self.assertTrue(any(w.startswith("health_check_error:") for w in result.warnings))


if __name__ == "__main__":
    unittest.main()
