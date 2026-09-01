#!/usr/bin/env python3

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from hostd import block_devices, identity, system_disks
from tests.test_hostd_block_devices import make_disk, make_partition


def identified_disk(root: Path, name: str, major_minor: str, child: tuple[str, str] | None) -> dict:
    disk = make_disk(root, name, major_minor, transport="sata", model=name)
    if child is not None:
        make_partition(disk, child[0], child[1])
    return identity.attach_stable_identities(
        block_devices.list_block_devices(root), root / "missing"
    )[0]


class HostdSystemDiskDenialTests(unittest.TestCase):
    def test_direct_root_partition_denies_parent_disk(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            source = identified_disk(Path(tmp), "sda", "8:0", ("sda1", "8:1"))

        protected = system_disks.protected_uses_from_mounts(
            [{"mount_point": "/", "major_minor": "8:1"}]
        )
        evaluation = system_disks.evaluate_system_disk_denial(source, protected)

        self.assertTrue(evaluation["denied_by_default"])
        self.assertEqual("critical_mount:/", evaluation["denial_reasons"][0]["reason"])

    def test_boot_mount_denies_parent_disk(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            source = identified_disk(Path(tmp), "sda", "8:0", ("sda2", "8:2"))

        protected = system_disks.protected_uses_from_mounts(
            [{"mount_point": "/boot", "major_minor": "8:2"}]
        )
        evaluation = system_disks.evaluate_system_disk_denial(source, protected)

        self.assertTrue(evaluation["override_required"])
        self.assertEqual("critical_mount:/boot", evaluation["denial_reasons"][0]["reason"])

    def test_separate_active_usr_mount_denies_parent_disk(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            source = identified_disk(Path(tmp), "sda", "8:0", ("sda2", "8:2"))

        protected = system_disks.protected_uses_from_mounts(
            [{"mount_point": "/usr", "major_minor": "8:2"}]
        )
        evaluation = system_disks.evaluate_system_disk_denial(source, protected)

        self.assertTrue(evaluation["denied_by_default"])
        self.assertEqual("critical_mount:/usr", evaluation["denial_reasons"][0]["reason"])

    def test_lvm_ancestry_denies_physical_member(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            source = identified_disk(Path(tmp), "sda", "8:0", ("sda2", "8:2"))

        protected = system_disks.protected_uses_from_mounts(
            [{"mount_point": "/", "major_minor": "253:0"}]
        )
        evaluation = system_disks.evaluate_system_disk_denial(
            source, protected, ancestry={"253:0": ["8:2"]}
        )

        self.assertTrue(evaluation["denied_by_default"])

    def test_mdraid_ancestry_denies_member_disk(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            source = identified_disk(Path(tmp), "sdb", "8:16", ("sdb1", "8:17"))

        protected = system_disks.protected_uses_from_mounts(
            [{"mount_point": "/", "major_minor": "9:0"}]
        )
        evaluation = system_disks.evaluate_system_disk_denial(
            source, protected, ancestry={"9:0": ["8:17", "8:33"]}
        )

        self.assertTrue(evaluation["denied_by_default"])

    def test_bind_mounted_reperio_state_denies_source(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            source = identified_disk(Path(tmp), "sda", "8:0", ("sda1", "8:1"))

        protected = system_disks.protected_uses_from_mounts(
            [{"mount_point": "/srv/reperio/state", "major_minor": "8:1"}],
            state_paths=["/srv/reperio/state"],
        )
        evaluation = system_disks.evaluate_system_disk_denial(source, protected)

        self.assertTrue(evaluation["denied_by_default"])
        self.assertEqual("reperio_state", evaluation["denial_reasons"][0]["reason"])

    def test_parent_mount_backing_reperio_state_denies_source(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            source = identified_disk(Path(tmp), "sda", "8:0", ("sda1", "8:1"))

        protected = system_disks.protected_uses_from_mounts(
            [{"mount_point": "/srv", "major_minor": "8:1"}],
            state_paths=["/srv/reperio/state"],
        )

        evaluation = system_disks.evaluate_system_disk_denial(source, protected)
        self.assertTrue(evaluation["denied_by_default"])
        self.assertEqual("reperio_state", evaluation["denial_reasons"][0]["reason"])

    def test_container_storage_ancestry_denies_source(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            source = identified_disk(Path(tmp), "sda", "8:0", ("sda3", "8:3"))

        protected = system_disks.protected_uses_from_mounts(
            [{"mount_point": "/var/lib/docker", "major_minor": "253:2"}]
        )
        evaluation = system_disks.evaluate_system_disk_denial(
            source, protected, ancestry={"253:2": ["8:3"]}
        )

        self.assertTrue(evaluation["denied_by_default"])
        self.assertEqual("container_storage", evaluation["denial_reasons"][0]["reason"])

    def test_parent_mount_backing_container_storage_is_protected(self) -> None:
        protected = system_disks.protected_uses_from_mounts(
            [{"mount_point": "/var/lib", "major_minor": "8:3"}]
        )

        self.assertEqual("container_storage", protected[0]["reason"])

    def test_paths_are_normalized_before_protection_decisions(self) -> None:
        protected = system_disks.protected_uses_from_mounts(
            [{"mount_point": "/var/lib/docker/../unrelated", "major_minor": "8:3"}]
        )

        self.assertEqual([], protected)

    def test_active_swap_denies_source(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            source = identified_disk(Path(tmp), "sda", "8:0", ("sda4", "8:4"))

        protected = system_disks.protected_uses_from_swaps([{"major_minor": "8:4"}])
        evaluation = system_disks.evaluate_system_disk_denial(source, protected)

        self.assertTrue(evaluation["denied_by_default"])
        self.assertEqual("active_swap", evaluation["denial_reasons"][0]["reason"])

    def test_unrelated_disk_is_allowed_by_default(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            source = identified_disk(Path(tmp), "sdb", "8:16", ("sdb1", "8:17"))

        protected = system_disks.protected_uses_from_mounts(
            [{"mount_point": "/", "major_minor": "8:1"}]
        )
        evaluation = system_disks.evaluate_system_disk_denial(source, protected)

        self.assertFalse(evaluation["denied_by_default"])

    def test_override_requires_explicit_policy_and_warning(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            source = identified_disk(Path(tmp), "sda", "8:0", ("sda1", "8:1"))

        protected = system_disks.protected_uses_from_mounts(
            [{"mount_point": "/", "major_minor": "8:1"}]
        )
        evaluation = system_disks.evaluate_system_disk_denial(source, protected)

        with self.assertRaisesRegex(system_disks.SystemDiskOverrideError, "denied"):
            system_disks.require_system_disk_override(evaluation, {})

        with self.assertRaisesRegex(system_disks.SystemDiskOverrideError, "acknowledgment"):
            system_disks.require_system_disk_override(
                evaluation,
                {
                    "allow_system_disk": True,
                    "operator_acknowledged": "yes",
                    "persistent_warning": system_disks.SYSTEM_DISK_OVERRIDE_WARNING,
                },
            )

        decision = system_disks.require_system_disk_override(
            evaluation,
            {
                "allow_system_disk": True,
                "operator_acknowledged": True,
                "persistent_warning": system_disks.SYSTEM_DISK_OVERRIDE_WARNING,
            },
        )
        self.assertTrue(decision["override_used"])
        self.assertEqual(
            [system_disks.SYSTEM_DISK_OVERRIDE_WARNING], decision["persistent_warnings"]
        )
        self.assertEqual(evaluation["denial_reasons"], decision["denial_reasons"])


if __name__ == "__main__":
    unittest.main()
