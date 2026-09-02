#!/usr/bin/env python3

from __future__ import annotations

import os
import stat
import tempfile
import unittest
from collections.abc import Mapping
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

from hostd import block_devices, identity, read_only
from tests.test_hostd_block_devices import make_disk, make_partition


class FakeReadOnlyOps:
    def __init__(
        self,
        *,
        fail_set: set[str] | None = None,
        fail_verify: set[str] | None = None,
        false_verify: set[str] | None = None,
    ) -> None:
        self.fail_set = fail_set or set()
        self.fail_verify = fail_verify or set()
        self.false_verify = false_verify or set()
        self.set_calls: list[str] = []
        self.verify_calls: list[str] = []

    def set_read_only(self, target: Mapping[str, str]) -> None:
        self.set_calls.append(target["major_minor"])
        if target["major_minor"] in self.fail_set:
            raise read_only.ReadOnlyOperationError("synthetic set failure")

    def verify_read_only(self, target: Mapping[str, str]) -> bool:
        self.verify_calls.append(target["major_minor"])
        if target["major_minor"] in self.fail_verify:
            raise read_only.ReadOnlyOperationError("synthetic verify failure")
        return target["major_minor"] not in self.false_verify


def source_with_children(root: Path) -> dict:
    disk = make_disk(root / "sys", "sda", "8:0", transport="sata", model="source")
    make_partition(disk, "sda1", "8:1")
    make_partition(disk, "sda2", "8:2", start=8192)
    return identity.attach_stable_identities(
        block_devices.list_block_devices(root / "sys"), root / "missing"
    )[0]


class HostdReadOnlyPreparationTests(unittest.TestCase):
    SAFE_STORAGE = {
        "safe_for_preparation": True,
        "inspection_complete": True,
        "blockers": [],
    }

    def test_sets_and_verifies_whole_disk_and_children(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            source = source_with_children(Path(tmp))

        ops = FakeReadOnlyOps()
        result = read_only.prepare_read_only(source, ops=ops, storage_state=self.SAFE_STORAGE)

        self.assertTrue(result["prepared"])
        self.assertEqual(["8:0", "8:1", "8:2"], ops.set_calls)
        self.assertEqual(["8:0", "8:1", "8:2"], ops.verify_calls)
        self.assertEqual(["8:0", "8:1", "8:2"], result["audit"]["verified_major_minors"])

    def test_stops_preparation_when_storage_state_has_blockers(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            source = source_with_children(Path(tmp))

        ops = FakeReadOnlyOps()
        result = read_only.prepare_read_only(
            source,
            ops=ops,
            storage_state={"blockers": [{"reason": "source_mounted_read_write"}]},
        )

        self.assertFalse(result["prepared"])
        self.assertEqual([], ops.set_calls)
        self.assertEqual("storage_state_blocked", result["blockers"][0]["reason"])

    def test_set_failure_blocks_launch(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            source = source_with_children(Path(tmp))

        result = read_only.prepare_read_only(
            source, ops=FakeReadOnlyOps(fail_set={"8:1"}), storage_state=self.SAFE_STORAGE
        )

        self.assertFalse(result["prepared"])
        self.assertEqual("read_only_set_failed", result["blockers"][0]["reason"])

    def test_verify_exception_blocks_launch(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            source = source_with_children(Path(tmp))

        result = read_only.prepare_read_only(
            source, ops=FakeReadOnlyOps(fail_verify={"8:2"}), storage_state=self.SAFE_STORAGE
        )

        self.assertFalse(result["prepared"])
        self.assertEqual("read_only_verify_failed", result["blockers"][0]["reason"])

    def test_false_verification_blocks_launch(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            source = source_with_children(Path(tmp))

        result = read_only.prepare_read_only(
            source, ops=FakeReadOnlyOps(false_verify={"8:0"}), storage_state=self.SAFE_STORAGE
        )

        self.assertFalse(result["prepared"])
        self.assertEqual("read_only_verify_false", result["blockers"][0]["reason"])

    def test_invalid_kernel_names_are_not_targeted(self) -> None:
        source = {
            "source_id": "source_test",
            "kernel_name": "../sda",
            "major_minor": "8:0",
            "children": [{"kernel_name": "sda1", "major_minor": "8:1"}],
        }
        ops = FakeReadOnlyOps()

        result = read_only.prepare_read_only(source, ops=ops, storage_state=self.SAFE_STORAGE)

        self.assertFalse(result["prepared"])
        self.assertEqual("invalid_source_target", result["blockers"][0]["reason"])
        self.assertEqual([], ops.set_calls)

    def test_duplicate_target_identity_is_not_targeted(self) -> None:
        source = {
            "source_id": "source_test",
            "kernel_name": "sda",
            "major_minor": "8:0",
            "children": [{"kernel_name": "sda1", "major_minor": "8:0"}],
        }
        ops = FakeReadOnlyOps()

        result = read_only.prepare_read_only(source, ops=ops, storage_state=self.SAFE_STORAGE)

        self.assertFalse(result["prepared"])
        self.assertEqual("duplicate_source_target", result["blockers"][0]["reason"])
        self.assertEqual([], ops.set_calls)

    def test_audit_contains_no_source_bytes_or_device_paths(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            source = source_with_children(Path(tmp))

        result = read_only.prepare_read_only(
            source, ops=FakeReadOnlyOps(), storage_state=self.SAFE_STORAGE
        )

        audit_repr = repr(result["audit"])
        self.assertNotIn("/dev/", audit_repr)
        self.assertNotIn("source bytes", audit_repr)

    def test_missing_storage_inspection_blocks_all_ioctls(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            source = source_with_children(Path(tmp))
        ops = FakeReadOnlyOps()

        result = read_only.prepare_read_only(source, ops=ops)

        self.assertFalse(result["prepared"])
        self.assertEqual([], ops.set_calls)
        self.assertEqual("storage_state_blocked", result["blockers"][0]["reason"])

    def test_linux_ioctl_ops_verify_opened_block_identity_and_read_only_state(self) -> None:
        opened = SimpleNamespace(st_mode=stat.S_IFBLK, st_rdev=os.makedev(8, 0))

        def ioctl(_fd: int, operation: int, value: object, _mutate: bool) -> int:
            if operation == read_only.BLKROGET:
                value[0] = 1  # type: ignore[index]
            return 0

        ops = read_only.LinuxIoctlReadOnlyOps(Path("/dev"))
        target = {"kernel_name": "sda", "major_minor": "8:0"}
        with (
            mock.patch.object(read_only.os, "open", return_value=41) as open_device,
            mock.patch.object(read_only.os, "fstat", return_value=opened),
            mock.patch.object(read_only.fcntl, "ioctl", side_effect=ioctl) as kernel_ioctl,
            mock.patch.object(read_only.os, "close") as close_device,
        ):
            ops.set_read_only(target)
            verified = ops.verify_read_only(target)

        self.assertTrue(verified)
        flags = open_device.call_args.args[1]
        self.assertEqual(os.O_RDONLY, flags & os.O_ACCMODE)
        self.assertTrue(flags & getattr(os, "O_CLOEXEC", 0))
        self.assertTrue(flags & getattr(os, "O_NOFOLLOW", 0))
        self.assertEqual(
            [read_only.BLKROSET, read_only.BLKROGET],
            [c.args[1] for c in kernel_ioctl.call_args_list],
        )
        self.assertEqual(2, close_device.call_count)

    def test_linux_ioctl_ops_reject_device_renumber_race(self) -> None:
        opened = SimpleNamespace(st_mode=stat.S_IFBLK, st_rdev=os.makedev(8, 16))
        ops = read_only.LinuxIoctlReadOnlyOps(Path("/dev"))

        with (
            mock.patch.object(read_only.os, "open", return_value=41),
            mock.patch.object(read_only.os, "fstat", return_value=opened),
            mock.patch.object(read_only.fcntl, "ioctl") as kernel_ioctl,
            mock.patch.object(read_only.os, "close") as close_device,
        ):
            with self.assertRaisesRegex(read_only.ReadOnlyOperationError, "identity changed"):
                ops.set_read_only({"kernel_name": "sda", "major_minor": "8:0"})

        kernel_ioctl.assert_not_called()
        close_device.assert_called_once_with(41)


if __name__ == "__main__":
    unittest.main()
