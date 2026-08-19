#!/usr/bin/env python3

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from hostd import block_devices, identity
from shared import destination_contract
from tests.test_hostd_block_devices import make_disk, make_partition

ID = "dest_" + "a" * 32
SNAPSHOT_ID = "snap_" + "b" * 32
EXPORT_ID = "exp_" + "c" * 32
CASE_ID = "case_" + "d" * 32
MANIFEST = "e" * 64
CREATED_AT = "2026-01-01T00:00:00Z"


def local_profile(secret_ref: str | None = None) -> dict:
    return destination_contract.destination_profile(
        destination_id=ID,
        kind="local",
        label="Internal export drive",
        secret_ref=secret_ref,
        created_at=CREATED_AT,
    )


def source_disk(root: Path) -> dict:
    disk = make_disk(root / "sys", "sda", "8:0", transport="sata", model="source")
    make_partition(disk, "sda1", "8:1")
    return identity.attach_stable_identities(
        block_devices.list_block_devices(root / "sys"), root / "missing"
    )[0]


class DestinationContractTests(unittest.TestCase):
    def test_local_profile_is_valid(self) -> None:
        profile = local_profile()
        result = destination_contract.validate_destination_profile(profile)
        self.assertTrue(result.valid, result.warnings)
        self.assertEqual(1, profile["schema_version"])

    def test_remote_profile_requires_secret_reference(self) -> None:
        profile = destination_contract.destination_profile(
            destination_id=ID,
            kind="sftp",
            label="NAS",
            secret_ref="vault:abc123def456",
            created_at=CREATED_AT,
        )
        self.assertTrue(destination_contract.validate_destination_profile(profile).valid)

    def test_missing_secret_for_remote_destination_is_rejected(self) -> None:
        profile = destination_contract.destination_profile(
            destination_id=ID,
            kind="s3",
            label="Object store",
            created_at=CREATED_AT,
        )
        result = destination_contract.validate_destination_profile(profile)
        self.assertFalse(result.valid)
        self.assertIn("missing_secret_for_remote_destination", result.warnings)

    def test_inline_secret_is_rejected(self) -> None:
        profile = local_profile(secret_ref="AKIAINLINESECRET")
        result = destination_contract.validate_destination_profile(profile)
        self.assertFalse(result.valid)
        self.assertIn("secret_ref_must_be_opaque_vault_reference", result.warnings)

    def test_local_destination_cannot_carry_secret(self) -> None:
        profile = local_profile(secret_ref="vault:abc123def456")
        result = destination_contract.validate_destination_profile(profile)
        self.assertFalse(result.valid)
        self.assertIn("local_destination_cannot_have_secret", result.warnings)

    def test_unknown_kind_and_bad_id_are_rejected(self) -> None:
        profile = local_profile()
        profile["kind"] = "teleport"
        profile["destination_id"] = "not-an-opaque-id"
        result = destination_contract.validate_destination_profile(profile)
        self.assertFalse(result.valid)
        self.assertIn("unknown_destination_kind", result.warnings)
        self.assertIn("invalid_destination_id", result.warnings)

    def test_invalid_capability_is_rejected(self) -> None:
        profile = local_profile()
        profile["capabilities"].append({"name": "burn_source", "supported": True, "detail": ""})
        result = destination_contract.validate_destination_profile(profile)
        self.assertFalse(result.valid)
        self.assertIn("unknown_capability:burn_source", result.warnings)

    def test_unsupported_schema_version_is_rejected(self) -> None:
        profile = local_profile()
        profile["schema_version"] = 99
        self.assertFalse(destination_contract.validate_destination_profile(profile).valid)


class ExportSnapshotAndStatusTests(unittest.TestCase):
    def test_immutable_snapshot_records_item_set(self) -> None:
        snapshot = destination_contract.export_snapshot(
            snapshot_id=SNAPSHOT_ID,
            case_id=CASE_ID,
            filter_snapshot={"status": ["new"], "category": ["photo"]},
            item_ids=["item_1", "item_2"],
            manifest_sha256=MANIFEST,
            created_at=CREATED_AT,
        )
        result = destination_contract.validate_export_snapshot(snapshot)
        self.assertTrue(result.valid, result.warnings)
        self.assertEqual(["item_1", "item_2"], snapshot["item_ids"])

    def test_snapshot_without_item_ids_is_rejected(self) -> None:
        snapshot = {
            "schema_version": 1,
            "snapshot_id": SNAPSHOT_ID,
            "case_id": CASE_ID,
            "filter_snapshot": {},
            "item_ids": "not-a-list",
            "manifest_sha256": MANIFEST,
            "created_at": CREATED_AT,
        }
        self.assertFalse(destination_contract.validate_export_snapshot(snapshot).valid)

    def test_bad_manifest_hash_is_rejected(self) -> None:
        snapshot = destination_contract.export_snapshot(
            snapshot_id=SNAPSHOT_ID,
            case_id=CASE_ID,
            filter_snapshot={},
            item_ids=[],
            manifest_sha256="z" * 64,
            created_at=CREATED_AT,
        )
        self.assertFalse(destination_contract.validate_export_snapshot(snapshot).valid)

    def test_status_counts_are_complete(self) -> None:
        status = destination_contract.export_status(
            export_id=EXPORT_ID,
            snapshot_id=SNAPSHOT_ID,
            state="completed",
            counts={"ready": 0, "exported": 5, "waiting": 0, "failed": 1},
            items=[{"item_id": "item_1", "status": "exported"}],
            created_at=CREATED_AT,
            updated_at=CREATED_AT,
        )
        result = destination_contract.validate_export_status(status)
        self.assertTrue(result.valid, result.warnings)
        self.assertEqual(1, status["counts"]["failed"])

    def test_unknown_export_state_is_rejected(self) -> None:
        status = destination_contract.export_status(
            export_id=EXPORT_ID,
            snapshot_id=SNAPSHOT_ID,
            state="vaporizing",
            counts={"ready": 0, "exported": 0, "waiting": 0, "failed": 0},
            items=[],
            created_at=CREATED_AT,
            updated_at=CREATED_AT,
        )
        self.assertFalse(destination_contract.validate_export_status(status).valid)


class SourceSeparationRecheckTests(unittest.TestCase):
    def test_source_path_destination_is_blocked(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = source_disk(root)
            dest = root / "export"
            dest.mkdir()

            result = destination_contract.recheck_source_separation(
                str(dest),
                source,
                mounts=[{"mount_point": str(root), "major_minor": "8:0", "fstype": "ext4"}],
            )

        self.assertFalse(result["separate"])
        self.assertEqual("destination_shares_source_physical_disk", result["blockers"][0]["reason"])

    def test_separate_destination_is_allowed(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = source_disk(root)
            dest = root / "other" / "export"
            dest.mkdir(parents=True)

            result = destination_contract.recheck_source_separation(
                str(dest),
                source,
                mounts=[
                    {
                        "mount_point": str(root / "other"),
                        "major_minor": "8:32",
                        "fstype": "ext4",
                    }
                ],
            )

        self.assertTrue(result["separate"], result["blockers"])

    def test_changed_mount_ancestry_reblocks_destination(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = source_disk(root)
            dest = root / "export"
            dest.mkdir()

            before = destination_contract.recheck_source_separation(
                str(dest),
                source,
                mounts=[
                    {
                        "mount_point": str(root / "export"),
                        "major_minor": "8:32",
                        "fstype": "ext4",
                    }
                ],
            )
            after = destination_contract.recheck_source_separation(
                str(dest),
                source,
                mounts=[
                    {
                        "mount_point": str(root / "export"),
                        "major_minor": "8:1",
                        "fstype": "ext4",
                    }
                ],
            )

        self.assertTrue(before["separate"])
        self.assertFalse(after["separate"])
        self.assertEqual("destination_shares_source_physical_disk", after["blockers"][0]["reason"])

    def test_network_filesystem_warns_without_claiming_proof(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = source_disk(root)
            dest = root / "nas" / "export"
            dest.mkdir(parents=True)

            result = destination_contract.recheck_source_separation(
                str(dest),
                source,
                mounts=[
                    {
                        "mount_point": str(root / "nas"),
                        "major_minor": "8:64",
                        "fstype": "nfs",
                    }
                ],
            )

        self.assertTrue(result["separate"])
        self.assertIn(
            "network_filesystem_physical_separation_not_locally_provable", result["warnings"]
        )


if __name__ == "__main__":
    unittest.main()
