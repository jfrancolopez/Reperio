#!/usr/bin/env python3

from __future__ import annotations

import copy
import unittest

from hostd import scanner_sandbox


def source() -> dict:
    return {"source_id": "source_abc", "kernel_name": "sda", "major_minor": "8:0"}


def prepared() -> dict:
    return {"prepared": True, "targets": [{"major_minor": "8:0", "verified_read_only": True}]}


def resources() -> dict[str, int]:
    return {
        "memory_limit_mib": 512,
        "pids_limit": 64,
        "scratch_limit_mib": 1024,
        "cpu_quota_percent": 50,
    }


class HostdScannerSandboxTests(unittest.TestCase):
    def test_builds_fixed_docker_command_with_one_read_only_device(self) -> None:
        spec = scanner_sandbox.build_scanner_launch(source(), prepared(), resources())

        self.assertEqual(scanner_sandbox.SCANNER_IMAGE, spec["image"])
        self.assertEqual("none", spec["network"])
        self.assertEqual(["ALL"], spec["capabilities"]["drop"])
        self.assertEqual([], spec["capabilities"]["add"])
        self.assertTrue(spec["read_only_rootfs"])
        self.assertEqual("r", spec["devices"][0]["mode"])
        self.assertEqual([], spec["mounts"])
        self.assertIn("--network=none", spec["command"])
        self.assertIn("--cap-drop=ALL", spec["command"])
        self.assertIn("--read-only", spec["command"])

    def test_rejects_unprepared_source(self) -> None:
        with self.assertRaisesRegex(scanner_sandbox.ScannerSandboxError, "read-only prepared"):
            scanner_sandbox.build_scanner_launch(source(), {"prepared": False}, resources())

    def test_rejects_invalid_runtime(self) -> None:
        with self.assertRaisesRegex(scanner_sandbox.ScannerSandboxError, "runtime"):
            scanner_sandbox.build_scanner_launch(source(), prepared(), resources(), runtime="sh")

    def test_rejects_pathlike_kernel_name(self) -> None:
        bad_source = source()
        bad_source["kernel_name"] = "../sda"

        with self.assertRaisesRegex(scanner_sandbox.ScannerSandboxError, "kernel name"):
            scanner_sandbox.build_scanner_launch(bad_source, prepared(), resources())

    def test_spec_validation_rejects_image_override(self) -> None:
        spec = scanner_sandbox.build_scanner_launch(source(), prepared(), resources())
        modified = copy.deepcopy(spec)
        modified["image"] = "attacker/scanner:latest"

        with self.assertRaisesRegex(scanner_sandbox.ScannerSandboxError, "image"):
            scanner_sandbox.validate_scanner_spec(modified)

    def test_spec_validation_rejects_entrypoint_or_argument_override(self) -> None:
        spec = scanner_sandbox.build_scanner_launch(source(), prepared(), resources())
        modified = copy.deepcopy(spec)
        modified["args"] = ["/bin/sh"]

        with self.assertRaisesRegex(scanner_sandbox.ScannerSandboxError, "entrypoint"):
            scanner_sandbox.validate_scanner_spec(modified)

    def test_spec_validation_rejects_network_capability_and_root_overrides(self) -> None:
        spec = scanner_sandbox.build_scanner_launch(source(), prepared(), resources())
        for key, value, message in (
            ("network", "host", "network"),
            ("capabilities", {"drop": ["ALL"], "add": ["SYS_ADMIN"]}, "capabilities"),
            ("user", "0:0", "root"),
            ("read_only_rootfs", False, "read-only"),
        ):
            modified = copy.deepcopy(spec)
            modified[key] = value
            with self.assertRaisesRegex(scanner_sandbox.ScannerSandboxError, message):
                scanner_sandbox.validate_scanner_spec(modified)

    def test_spec_validation_rejects_extra_device_or_host_mount(self) -> None:
        spec = scanner_sandbox.build_scanner_launch(source(), prepared(), resources())
        extra_device = copy.deepcopy(spec)
        extra_device["devices"].append({"host": "/dev/sdb", "container": "/dev/extra", "mode": "r"})
        with self.assertRaisesRegex(scanner_sandbox.ScannerSandboxError, "one source"):
            scanner_sandbox.validate_scanner_spec(extra_device)

        host_mount = copy.deepcopy(spec)
        host_mount["mounts"] = [{"source": "/var/run/docker.sock", "target": "/sock"}]
        with self.assertRaisesRegex(scanner_sandbox.ScannerSandboxError, "host mounts"):
            scanner_sandbox.validate_scanner_spec(host_mount)

    def test_resource_limits_are_required(self) -> None:
        bad_resources = resources()
        bad_resources["memory_limit_mib"] = 0

        with self.assertRaisesRegex(scanner_sandbox.ScannerSandboxError, "memory"):
            scanner_sandbox.build_scanner_launch(source(), prepared(), bad_resources)

    def test_podman_command_uses_same_profile(self) -> None:
        spec = scanner_sandbox.build_scanner_launch(
            source(), prepared(), resources(), runtime="podman"
        )

        self.assertEqual("podman", spec["command"][0])
        scanner_sandbox.validate_scanner_spec(spec)


if __name__ == "__main__":
    unittest.main()
