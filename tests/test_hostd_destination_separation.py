#!/usr/bin/env python3

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from hostd import block_devices, destination_separation, identity
from tests.test_hostd_block_devices import make_disk, make_partition, write


def source_disk(root: Path) -> dict:
    disk = make_disk(root / "sys", "sda", "8:0", transport="sata", model="source")
    make_partition(disk, "sda1", "8:1")
    make_partition(disk, "sda2", "8:2", start=8192)
    return identity.attach_stable_identities(
        block_devices.list_block_devices(root / "sys"), root / "missing"
    )[0]


class HostdDestinationSeparationTests(unittest.TestCase):
    def test_same_filesystem_is_refused(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = source_disk(root)
            dest = root / "source-mount" / "export"
            dest.mkdir(parents=True)

            result = destination_separation.evaluate_destination_separation(
                source,
                dest,
                mounts=[
                    {
                        "mount_point": str(root / "source-mount"),
                        "major_minor": "8:1",
                        "fstype": "ext4",
                    }
                ],
            )

        self.assertFalse(result["separate"])
        self.assertEqual("destination_shares_source_physical_disk", result["blockers"][0]["reason"])

    def test_sibling_partition_is_refused(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = source_disk(root)
            dest = root / "sibling" / "export"
            dest.mkdir(parents=True)

            result = destination_separation.evaluate_destination_separation(
                source,
                dest,
                mounts=[
                    {"mount_point": str(root / "sibling"), "major_minor": "8:2", "fstype": "ext4"}
                ],
            )

        self.assertFalse(result["separate"])

    def test_lvm_logical_volume_on_source_is_refused(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = source_disk(root)
            dest = root / "lv" / "export"
            dest.mkdir(parents=True)

            result = destination_separation.evaluate_destination_separation(
                source,
                dest,
                mounts=[
                    {"mount_point": str(root / "lv"), "major_minor": "253:0", "fstype": "ext4"}
                ],
                holders={"8:2": [{"major_minor": "253:0", "holder_type": "device_mapper"}]},
            )

        self.assertFalse(result["separate"])
        self.assertIn("8:2", result["destination_ancestry"])

    def test_mdraid_on_source_member_is_refused(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = source_disk(root)
            dest = root / "md" / "export"
            dest.mkdir(parents=True)

            result = destination_separation.evaluate_destination_separation(
                source,
                dest,
                mounts=[{"mount_point": str(root / "md"), "major_minor": "9:0", "fstype": "ext4"}],
                holders={"8:1": [{"major_minor": "9:0", "holder_type": "mdraid"}]},
            )

        self.assertFalse(result["separate"])

    def test_network_filesystem_is_allowed_with_warning(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = source_disk(root)
            dest = root / "nas" / "export"
            dest.mkdir(parents=True)

            result = destination_separation.evaluate_destination_separation(
                source,
                dest,
                mounts=[
                    {"mount_point": str(root / "nas"), "major_minor": "0:42", "fstype": "nfs4"}
                ],
            )

        self.assertTrue(result["separate"])
        self.assertIn(
            "network_filesystem_physical_separation_not_locally_provable", result["warnings"]
        )

    def test_bind_mount_on_source_is_refused(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = source_disk(root)
            dest = root / "bind" / "export"
            dest.mkdir(parents=True)

            result = destination_separation.evaluate_destination_separation(
                source,
                dest,
                mounts=[
                    {"mount_point": str(root / "bind"), "major_minor": "8:1", "fstype": "none"}
                ],
            )

        self.assertFalse(result["separate"])
        self.assertEqual("destination_shares_source_physical_disk", result["blockers"][0]["reason"])

    def test_unmounted_destination_is_refused(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = source_disk(root)
            dest = root / "unmounted" / "export"
            dest.mkdir(parents=True)

            result = destination_separation.evaluate_destination_separation(source, dest, mounts=[])

        self.assertFalse(result["separate"])
        self.assertEqual("destination_not_mounted", result["blockers"][0]["reason"])

    def test_nonexistent_destination_is_refused(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = source_disk(root)
            dest = root / "missing" / "export"

            result = destination_separation.evaluate_destination_separation(
                source,
                dest,
                mounts=[{"mount_point": str(root), "major_minor": "8:99", "fstype": "ext4"}],
            )

        self.assertFalse(result["separate"])
        self.assertEqual("destination_path_missing", result["blockers"][0]["reason"])

    def test_symlinked_path_to_source_is_refused(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = source_disk(root)
            source_export = root / "source-mount" / "export"
            source_export.mkdir(parents=True)
            link = root / "link-export"
            link.symlink_to(source_export)

            result = destination_separation.evaluate_destination_separation(
                source,
                link,
                mounts=[
                    {
                        "mount_point": str(root / "source-mount"),
                        "major_minor": "8:1",
                        "fstype": "ext4",
                    }
                ],
            )

        self.assertFalse(result["separate"])
        self.assertEqual("destination_shares_source_physical_disk", result["blockers"][0]["reason"])

    def test_separate_local_disk_is_allowed(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = source_disk(root)
            dest = root / "other-disk" / "export"
            dest.mkdir(parents=True)

            result = destination_separation.evaluate_destination_separation(
                source,
                dest,
                mounts=[
                    {
                        "mount_point": str(root / "other-disk"),
                        "major_minor": "8:99",
                        "fstype": "ext4",
                    }
                ],
            )

        self.assertTrue(result["separate"])

    def test_missing_source_topology_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            dest = root / "other"
            dest.mkdir()

            result = destination_separation.evaluate_destination_separation(
                {},
                dest,
                mounts=[{"mount_point": str(dest), "major_minor": "8:99", "fstype": "ext4"}],
            )

        self.assertFalse(result["separate"])
        self.assertEqual("missing_source_topology", result["blockers"][0]["reason"])

    def test_selected_device_mapper_source_includes_physical_ancestry(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            dest = root / "physical"
            dest.mkdir()
            source = {"source_id": "source_dm", "major_minor": "253:0", "children": []}

            result = destination_separation.evaluate_destination_separation(
                source,
                dest,
                mounts=[{"mount_point": str(dest), "major_minor": "8:2", "fstype": "ext4"}],
                holders={"8:2": [{"major_minor": "253:0", "holder_type": "device_mapper"}]},
            )

        self.assertFalse(result["separate"])
        self.assertIn("8:2", result["source_ancestry"])

    def test_live_resolver_uses_mountinfo_and_holder_facts(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = source_disk(root)
            dest = root / "lv" / "export"
            dest.mkdir(parents=True)
            mountinfo = root / "mountinfo"
            mountinfo.write_text(
                f"37 25 253:0 / {root / 'lv'} rw,relatime - ext4 /dev/dm-0 rw\n",
                encoding="utf-8",
            )
            write(root / "sys-dev" / "8:2" / "holders" / "dm-0" / "dev", "253:0")

            result = destination_separation.evaluate_live_destination_separation(
                source,
                dest,
                mountinfo_path=mountinfo,
                sys_dev_block=root / "sys-dev",
            )

        self.assertFalse(result["separate"])
        self.assertTrue(result["inspection_complete"])

    def test_live_resolver_failure_cannot_claim_separation(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = source_disk(root)
            dest = root / "other"
            dest.mkdir()

            result = destination_separation.evaluate_live_destination_separation(
                source,
                dest,
                mountinfo_path=root / "missing-mountinfo",
                sys_dev_block=root / "missing-sysfs",
            )

        self.assertFalse(result["separate"])
        self.assertFalse(result["inspection_complete"])


if __name__ == "__main__":
    unittest.main()
