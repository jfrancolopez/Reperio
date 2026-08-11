#!/usr/bin/env python3

from __future__ import annotations

import tempfile
import unittest
from collections.abc import Mapping
from pathlib import Path

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
    def test_sets_and_verifies_whole_disk_and_children(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            source = source_with_children(Path(tmp))

        ops = FakeReadOnlyOps()
        result = read_only.prepare_read_only(source, ops=ops)

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

        result = read_only.prepare_read_only(source, ops=FakeReadOnlyOps(fail_set={"8:1"}))

        self.assertFalse(result["prepared"])
        self.assertEqual("read_only_set_failed", result["blockers"][0]["reason"])

    def test_verify_exception_blocks_launch(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            source = source_with_children(Path(tmp))

        result = read_only.prepare_read_only(source, ops=FakeReadOnlyOps(fail_verify={"8:2"}))

        self.assertFalse(result["prepared"])
        self.assertEqual("read_only_verify_failed", result["blockers"][0]["reason"])

    def test_false_verification_blocks_launch(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            source = source_with_children(Path(tmp))

        result = read_only.prepare_read_only(source, ops=FakeReadOnlyOps(false_verify={"8:0"}))

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

        result = read_only.prepare_read_only(source, ops=ops)

        self.assertTrue(result["prepared"])
        self.assertEqual(["8:1"], ops.set_calls)

    def test_audit_contains_no_source_bytes_or_device_paths(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            source = source_with_children(Path(tmp))

        result = read_only.prepare_read_only(source, ops=FakeReadOnlyOps())

        audit_repr = repr(result["audit"])
        self.assertNotIn("/dev/", audit_repr)
        self.assertNotIn("source bytes", audit_repr)


if __name__ == "__main__":
    unittest.main()
