#!/usr/bin/env python3
"""Destructive-to-fixture-only no-source-write harness for RPR-020."""

from __future__ import annotations

import hashlib
import stat
import tempfile
from collections.abc import Mapping
from pathlib import Path
from typing import Any

import fixture_builder
import fixture_reader

from hostd import (
    block_devices,
    destination_separation,
    identity,
    protocol,
    read_only,
    scanner_sandbox,
    storage_inspection,
)


class UnsafeFixtureError(ValueError):
    """Raised when the harness is pointed at anything other than its fixture."""


class FakeReadOnlyOps:
    def set_read_only(self, target: Mapping[str, str]) -> None:
        return None

    def verify_read_only(self, target: Mapping[str, str]) -> bool:
        return True


class NoSourceWriteHarness:
    """Run RPR-020 attacks against a verified disposable source fixture only."""

    def __init__(self, root: Path, source_path: Path, expected_sha256: str) -> None:
        self.root = root.resolve(strict=True)
        self.source_path = source_path.resolve(strict=True)
        self.expected_sha256 = expected_sha256
        self._assert_disposable_fixture()

    @classmethod
    def create(cls) -> NoSourceWriteHarness:
        root = Path(tempfile.mkdtemp(prefix="reperio-rpr020-"))
        image, _ = fixture_builder.build_image()
        source_path = root / "source.fixture"
        source_path.write_bytes(image)
        source_path.chmod(stat.S_IRUSR | stat.S_IRGRP | stat.S_IROTH)
        return cls(root, source_path, fixture_builder.image_sha256(image))

    @classmethod
    def from_existing(cls, root: Path, source_path: Path) -> NoSourceWriteHarness:
        expected_image, _ = fixture_builder.build_image()
        return cls(root, source_path, fixture_builder.image_sha256(expected_image))

    def run_all(self) -> dict[str, Any]:
        before = self._source_hash()
        results = {
            "malicious_adapter_attempt": self.malicious_adapter_attempt(),
            "compromised_api_payload": self.compromised_api_payload(),
            "same_disk_scratch": self.same_disk_scratch(),
            "symlink_swap": self.symlink_swap(),
            "device_renumber": self.device_renumber(),
            "scanner_restart": self.scanner_restart(),
            "minimal_scan": self.minimal_scan(),
        }
        after = self._source_hash()
        return {
            "source_hash_before": before,
            "source_hash_after": after,
            "source_unchanged": before == after == self.expected_sha256,
            "attempts": results,
        }

    def malicious_adapter_attempt(self) -> dict[str, Any]:
        blocked = 0
        try:
            with self.source_path.open("r+b") as handle:
                handle.write(b"X")
        except OSError:
            blocked += 1
        return {"attempted": 1, "blocked": blocked, "passed": blocked == 1}

    def compromised_api_payload(self) -> dict[str, Any]:
        request = {
            "schema_version": protocol.PROTOCOL_SCHEMA_VERSION,
            "request_id": "rpr020-api",
            "auth": {"kind": protocol.AUTH_KIND, "principal": "reperio-api"},
            "method": "launch_scanner",
            "params": {
                "source_id": "source_abcdefghijklmnop",
                "observed_generation": 1,
                "safety_inspection_id": "safe_abcdefghijklmnop",
                "readonly_preparation_id": "roprep_abcdefghijklmnop",
                "scan_case_id": "case_abcdefghijklmnop",
                "scratch_separation_id": "scratch_abcdefghijklmnop",
                "resource_profile": "default",
                "container_args": ["--privileged"],
            },
        }
        protocol_blocked = False
        try:
            protocol.validate_request(request, source_generations={"source_abcdefghijklmnop": 1})
        except protocol.ProtocolError:
            protocol_blocked = True

        source = self._source_device()
        preparation = read_only.prepare_read_only(
            source,
            ops=FakeReadOnlyOps(),
            storage_state=storage_inspection.inspect_storage_state(source),
        )
        spec = scanner_sandbox.build_scanner_launch(
            source,
            preparation,
            {
                "memory_limit_mib": 512,
                "pids_limit": 64,
                "scratch_limit_mib": 128,
                "cpu_quota_percent": 50,
            },
        )
        spec["network"] = "host"
        sandbox_blocked = False
        try:
            scanner_sandbox.validate_scanner_spec(spec)
        except scanner_sandbox.ScannerSandboxError:
            sandbox_blocked = True
        return {"passed": protocol_blocked and sandbox_blocked}

    def same_disk_scratch(self) -> dict[str, Any]:
        source = self._source_device()
        scratch = self.root / "scratch"
        scratch.mkdir(exist_ok=True)
        result = destination_separation.evaluate_destination_separation(
            source,
            scratch,
            mounts=[{"mount_point": str(self.root), "major_minor": "8:1", "fstype": "ext4"}],
        )
        return {"passed": result["separate"] is False, "blockers": result["blockers"]}

    def symlink_swap(self) -> dict[str, Any]:
        source_mount = self.root / "source-mount"
        source_mount.mkdir(exist_ok=True)
        target = source_mount / "export"
        target.mkdir(exist_ok=True)
        link = self.root / "safe-looking-export"
        if link.exists() or link.is_symlink():
            link.unlink()
        link.symlink_to(target)
        result = destination_separation.evaluate_destination_separation(
            self._source_device(),
            link,
            mounts=[{"mount_point": str(source_mount), "major_minor": "8:1", "fstype": "ext4"}],
        )
        return {"passed": result["separate"] is False, "blockers": result["blockers"]}

    def device_renumber(self) -> dict[str, Any]:
        first = self._identified_device("sda", "8:0", "usb-Reperio_Disk_123")
        second = self._identified_device("sdb", "8:16", "usb-Reperio_Disk_123")
        return {
            "passed": first["source_id"] == second["source_id"]
            and first["kernel_name"] != second["kernel_name"],
            "source_id": first["source_id"],
        }

    def scanner_restart(self) -> dict[str, Any]:
        source = self._source_device()
        prep = read_only.prepare_read_only(
            source,
            ops=FakeReadOnlyOps(),
            storage_state=storage_inspection.inspect_storage_state(source),
        )
        resources = {
            "memory_limit_mib": 512,
            "pids_limit": 64,
            "scratch_limit_mib": 128,
            "cpu_quota_percent": 50,
        }
        first = scanner_sandbox.build_scanner_launch(source, prep, resources)
        second = scanner_sandbox.build_scanner_launch(source, prep, resources)
        return {"passed": first == second and prep["prepared"] is True}

    def minimal_scan(self) -> dict[str, Any]:
        image = self.source_path.read_bytes()
        findings = fixture_reader.read_image(image)["findings"]
        return {"passed": bool(findings), "finding_count": len(findings)}

    def _source_device(self) -> dict[str, Any]:
        return self._identified_device("sda", "8:0", "usb-Reperio_Disk_123")

    def _identified_device(
        self, kernel_name: str, major_minor: str, by_id_name: str
    ) -> dict[str, Any]:
        sys_root = self.root / f"sys-{kernel_name}"
        dev_root = self.root / f"dev-{kernel_name}" / "by-id"
        disk = sys_root / kernel_name
        disk.mkdir(parents=True, exist_ok=True)
        _write(disk / "dev", major_minor)
        _write(disk / "size", str(fixture_builder.TOTAL_SECTORS))
        _write(disk / "removable", "1")
        _write(disk / "ro", "1")
        _write(disk / "queue" / "logical_block_size", "512")
        _write(disk / "queue" / "physical_block_size", "512")
        part = disk / f"{kernel_name}1"
        part.mkdir(exist_ok=True)
        _write(part / "partition", "1")
        _write(part / "dev", "8:1")
        _write(part / "start", "0")
        _write(part / "size", str(fixture_builder.TOTAL_SECTORS))
        dev_root.mkdir(parents=True, exist_ok=True)
        link = dev_root / by_id_name
        if link.is_symlink():
            link.unlink()
        if not link.exists():
            link.symlink_to(Path("..") / ".." / kernel_name)
        return identity.attach_stable_identities(
            block_devices.list_block_devices(sys_root), dev_root
        )[0]

    def _assert_disposable_fixture(self) -> None:
        try:
            self.source_path.relative_to(self.root)
        except ValueError as error:
            raise UnsafeFixtureError("source fixture must live under the harness root") from error
        if self.source_path.name != "source.fixture":
            raise UnsafeFixtureError("source fixture must use the harness-controlled filename")
        if self._source_hash() != self.expected_sha256:
            raise UnsafeFixtureError(
                "source fixture hash does not match the deterministic RPR-008 image"
            )

    def _source_hash(self) -> str:
        return hashlib.sha256(self.source_path.read_bytes()).hexdigest()


def _write(path: Path, value: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(value, encoding="utf-8")
