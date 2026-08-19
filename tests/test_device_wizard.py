#!/usr/bin/env python3

from __future__ import annotations

import unittest
from typing import Any

from shared import media_identity
from worker.device_wizard import (
    DEVICE_WIZARD_VERSION,
    DeviceWizardError,
    build_source_card,
    configuration_summary,
    confirm_source,
    group_sources,
    media_change_status,
    source_group,
    wizard_state,
)

FINGERPRINT_ONE = "a" * 64
FINGERPRINT_TWO = "b" * 64


def identity(
    *, fingerprint: str | None = FINGERPRINT_ONE, capacity: int = 32 * 1024 * 1024
) -> dict[str, Any]:
    signals = media_identity.normalize_medium_signals(
        {"size_bytes": capacity, "sampled_fingerprint_sha256": fingerprint}
    )
    return media_identity.medium_identity_record(
        "reader_1", signals, identity_strength="reader-plus-medium"
    )


def device(**overrides: Any) -> dict[str, Any]:
    dev: dict[str, Any] = {
        "source_id": "src_1",
        "reader_id": "reader_1",
        "device_type": "sd_card",
        "transport": "mmc",
        "removable": True,
        "read_only": True,
        "read_only_verified": True,
        "size_bytes": 32 * 1024 * 1024,
        "model": "ACME Card",
        "serial": "SN-123",
        "major_minor": "179:0",
        "medium_identity": identity(),
        "health_state": "passed",
        "health_reasons": [],
    }
    dev.update(overrides)
    return dev


class GroupTests(unittest.TestCase):
    def test_source_group_classification(self) -> None:
        self.assertEqual("disk", source_group("fixed_disk"))
        self.assertEqual("flash", source_group("usb_flash"))
        self.assertEqual("flash", source_group("memory_card"))
        self.assertEqual("optical", source_group("optical_disc"))
        self.assertEqual("floppy", source_group("floppy_media"))
        self.assertEqual("floppy", source_group("legacy_medium"))

    def test_unknown_source_kind_rejected(self) -> None:
        with self.assertRaisesRegex(DeviceWizardError, "unknown_source_kind"):
            source_group("nonsense")

    def test_group_sources_in_ordered_groups(self) -> None:
        devices = [
            device(source_id="flash_1", device_type="sd_card"),
            device(source_id="disk_1", device_type="disk", removable=False),
            device(source_id="optical_1", device_type="optical"),
            device(source_id="floppy_1", device_type="floppy"),
        ]
        groups = group_sources(devices)
        self.assertEqual(["disk", "flash", "optical", "floppy"], [g for g, _ in groups])
        self.assertEqual(["disk_1"], [c.source_id for c in groups[0][1]])
        self.assertEqual(["flash_1"], [c.source_id for c in groups[1][1]])


class SourceCardTests(unittest.TestCase):
    def test_valid_disk_card(self) -> None:
        card = build_source_card(device(source_id="disk_1", device_type="disk", removable=False))
        self.assertEqual("disk", card.group)
        self.assertTrue(card.medium_present)
        self.assertTrue(card.medium_identity_proven)
        self.assertEqual("reader-plus-medium", card.identity_strength)
        self.assertEqual(32 * 1024 * 1024, card.capacity_bytes)

    def test_valid_flash_card_facts(self) -> None:
        card = build_source_card(
            device(
                source_id="flash_1",
                device_type="usb_storage",
                removable=True,
                model="USB Drive",
                serial="USB-SN",
                transport="usb",
            )
        )
        self.assertEqual("flash", card.group)
        self.assertEqual("USB Drive", card.model)
        self.assertEqual("USB-SN", card.serial)
        self.assertEqual("usb", card.transport)

    def test_optical_and_floppy_geometry(self) -> None:
        optical = build_source_card(
            device(
                source_id="opt_1",
                device_type="optical",
                medium_identity=identity(capacity=700 * 1024 * 1024),
            )
        )
        self.assertEqual("optical", optical.group)
        self.assertEqual(700 * 1024 * 1024, optical.capacity_bytes)
        floppy = build_source_card(
            device(
                source_id="floppy_1",
                device_type="floppy",
                medium_identity=identity(capacity=1440 * 1024),
            )
        )
        self.assertEqual("floppy", floppy.group)

    def test_empty_reader(self) -> None:
        card = build_source_card(
            device(
                source_id="empty_1",
                medium_identity=identity(fingerprint=None, capacity=0),
            )
        )
        self.assertFalse(card.medium_present)
        eligibility = confirm_source(card, confirmation=None)
        self.assertEqual("empty", eligibility.state)
        self.assertIn("no_medium_present", eligibility.block_reasons)

    def test_missing_serial_presented_with_warning(self) -> None:
        card = build_source_card(device(serial=None))
        self.assertIsNone(card.serial)
        self.assertTrue(any("serial" in w for w in card.identity_warnings))

    def test_health_states(self) -> None:
        for state, expected_warning in [
            ("passed", None),
            ("warning", "health_warning"),
            ("unavailable", "health_unavailable"),
            ("failed", "health_failed"),
        ]:
            with self.subTest(state=state):
                card = build_source_card(device(health_state=state))
                if expected_warning is None:
                    self.assertNotIn("health_", card.warnings)
                else:
                    self.assertIn(expected_warning, card.warnings)

    def test_missing_field_rejected(self) -> None:
        with self.assertRaisesRegex(DeviceWizardError, "source_id"):
            build_source_card({"device_type": "sd_card", "removable": True})


class MediaChangeTests(unittest.TestCase):
    def test_same_medium(self) -> None:
        card = build_source_card(device())
        previous = identity()
        self.assertEqual("same_medium", media_change_status(card, previous).status)

    def test_replaced_medium_requires_fresh_selection(self) -> None:
        card = build_source_card(device(medium_identity=identity(fingerprint=FINGERPRINT_TWO)))
        previous = identity(fingerprint=FINGERPRINT_ONE)
        change = media_change_status(card, previous)
        self.assertEqual("replaced_medium", change.status)
        eligibility = confirm_source(
            card,
            confirmation={"source_id": "src_1", "media_change_generation": 2},
            previous_record=previous,
        )
        self.assertIn("media_changed", eligibility.block_reasons)
        self.assertEqual("blocked", eligibility.state)

    def test_changed_capacity_blocks_start(self) -> None:
        card = build_source_card(
            device(medium_identity=identity(fingerprint=FINGERPRINT_ONE, capacity=64 * 1024 * 1024))
        )
        previous = identity(fingerprint=FINGERPRINT_ONE, capacity=32 * 1024 * 1024)
        change = media_change_status(card, previous)
        self.assertEqual("changed_signals", change.status)
        eligibility = confirm_source(card, confirmation=None, previous_record=previous)
        self.assertIn("media_changed", eligibility.block_reasons)

    def test_unproven_without_fingerprint(self) -> None:
        card = build_source_card(device(medium_identity=identity(fingerprint=None, capacity=32)))
        previous = identity(fingerprint=None, capacity=32)
        self.assertEqual("unproven", media_change_status(card, previous).status)


class ConfirmSourceTests(unittest.TestCase):
    def test_ready_with_valid_confirmation(self) -> None:
        card = build_source_card(device(media_change_generation=1))
        eligibility = confirm_source(
            card, confirmation={"source_id": "src_1", "media_change_generation": 1}
        )
        self.assertEqual("ready", eligibility.state)
        self.assertEqual((), eligibility.block_reasons)

    def test_confirmation_required_without_match(self) -> None:
        card = build_source_card(device())
        eligibility = confirm_source(card, confirmation=None)
        self.assertEqual("blocked", eligibility.state)
        self.assertIn("confirmation_required", eligibility.block_reasons)

    def test_stale_confirmation_rejected(self) -> None:
        card = build_source_card(
            device(
                medium_identity=identity(fingerprint=FINGERPRINT_TWO),
                media_change_generation=1,
            )
        )
        stale = {"source_id": "src_1", "media_change_generation": 0}
        eligibility = confirm_source(card, confirmation=stale)
        self.assertIn("confirmation_required", eligibility.block_reasons)

    def test_fresh_confirmation_accepted_for_new_medium(self) -> None:
        card = build_source_card(
            device(
                medium_identity=identity(fingerprint=FINGERPRINT_TWO),
                media_change_generation=2,
            )
        )
        fresh = {"source_id": "src_1", "media_change_generation": 2}
        eligibility = confirm_source(card, confirmation=fresh)
        self.assertEqual("ready", eligibility.state)

    def test_system_disk_blocker_is_clear(self) -> None:
        card = build_source_card(
            device(
                source_id="sys_1",
                device_type="disk",
                removable=False,
                is_system_disk=True,
                system_uses=["/", "swap"],
            )
        )
        eligibility = confirm_source(
            card,
            confirmation={"source_id": "sys_1", "media_change_generation": 1},
        )
        self.assertIn("system_disk", eligibility.block_reasons)

    def test_failed_read_only_blocker_is_clear(self) -> None:
        card = build_source_card(device(read_only_verified=False))
        eligibility = confirm_source(card, confirmation=None)
        self.assertIn("read_only_not_verified", eligibility.block_reasons)

    def test_mounted_read_write_blocker(self) -> None:
        card = build_source_card(device(mount_points=["/mnt/usb"], read_only=False))
        self.assertTrue(card.mounted)
        self.assertFalse(card.mounted_read_only)
        eligibility = confirm_source(
            card,
            confirmation={"source_id": "src_1", "media_change_generation": 1},
        )
        self.assertIn("source_mounted_read_write", eligibility.block_reasons)

    def test_health_failed_blocks_start(self) -> None:
        card = build_source_card(device(health_state="failed"))
        eligibility = confirm_source(
            card,
            confirmation={"source_id": "src_1", "media_change_generation": 1},
        )
        self.assertIn("health_failed", eligibility.block_reasons)

    def test_same_disk_destination_blocker(self) -> None:
        card = build_source_card(device(major_minor="8:0"))
        destination = {"disk_key": "8:0"}
        eligibility = confirm_source(
            card,
            confirmation={"source_id": "src_1", "media_change_generation": 1},
            destination=destination,
        )
        self.assertIn("destination_on_source_disk", eligibility.block_reasons)

    def test_separate_destination_is_allowed(self) -> None:
        card = build_source_card(device(major_minor="8:0"))
        destination = {"disk_key": "9:0"}
        eligibility = confirm_source(
            card,
            confirmation={"source_id": "src_1", "media_change_generation": 1},
            destination=destination,
        )
        self.assertEqual("ready", eligibility.state)

    def test_ambiguous_identity_cannot_start(self) -> None:
        card = build_source_card(
            device(
                medium_identity=media_identity.medium_identity_record(
                    "reader_1",
                    media_identity.normalize_medium_signals({"size_bytes": 32 * 1024 * 1024}),
                    identity_strength="reader-facts",
                )
            )
        )
        self.assertFalse(card.medium_identity_proven)
        eligibility = confirm_source(card, confirmation=None)
        self.assertEqual("ambiguous", eligibility.state)
        self.assertIn("medium_identity_unproven", eligibility.block_reasons)


class WizardStateTests(unittest.TestCase):
    def test_no_scan_starts_automatically(self) -> None:
        state = wizard_state([device()])
        self.assertFalse(state["auto_started"])
        self.assertFalse(state["can_start"])
        self.assertIn("confirmation_required", state["cards"][0]["block_reasons"])

    def test_single_ready_source_can_start(self) -> None:
        state = wizard_state(
            [device()],
            confirmations={"src_1": {"source_id": "src_1", "media_change_generation": 1}},
        )
        self.assertTrue(state["can_start"])
        self.assertEqual([], state["cannot_start_reasons"])

    def test_multiple_sources_require_exactly_one(self) -> None:
        state = wizard_state(
            [
                device(source_id="src_1"),
                device(source_id="src_2", reader_id="reader_2"),
            ],
            confirmations={
                "src_1": {"source_id": "src_1", "media_change_generation": 1},
                "src_2": {"source_id": "src_2", "media_change_generation": 1},
            },
        )
        self.assertFalse(state["can_start"])
        self.assertIn("one_source_required", state["cannot_start_reasons"])

    def test_wizard_version(self) -> None:
        self.assertEqual("device-wizard-v1", DEVICE_WIZARD_VERSION)


class ConfigurationSummaryTests(unittest.TestCase):
    def test_summary_reflects_safety_facts(self) -> None:
        card = build_source_card(device())
        summary = configuration_summary(
            card,
            destination={"separate_from_source": True, "kind": "local"},
            scratch={"separate_from_source": True, "kind": "local"},
        )
        self.assertEqual("src_1", summary["source"]["source_id"])
        self.assertTrue(summary["destination"]["separate_from_source"])
        self.assertTrue(summary["scratch"]["separate_from_source"])
        self.assertTrue(summary["safety"]["read_only_verified"])
        self.assertEqual("default", summary["resource_profile"])


if __name__ == "__main__":
    unittest.main()
