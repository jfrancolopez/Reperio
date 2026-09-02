#!/usr/bin/env python3

from __future__ import annotations

import copy
import os
import stat
import subprocess
import tempfile
import unittest
from collections.abc import Sequence
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

from hostd import safety_audit, scanner_sandbox


def source() -> dict:
    return {
        "source_id": "source_abc",
        "kernel_name": "sda",
        "major_minor": "8:0",
        "children": [],
    }


def prepared() -> dict:
    return {
        "source_id": "source_abc",
        "prepared": True,
        "targets": [
            {
                "kernel_name": "sda",
                "major_minor": "8:0",
                "set_read_only": True,
                "verified_read_only": True,
            }
        ],
        "blockers": [],
    }


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
        self.assertIn("--pull=never", spec["command"])
        self.assertIn("--log-driver=none", spec["command"])
        self.assertNotIn("--privileged", spec["command"])
        self.assertFalse(any(argument.startswith("--env") for argument in spec["command"]))

    def test_rejects_unprepared_source(self) -> None:
        with self.assertRaisesRegex(scanner_sandbox.ScannerSandboxError, "read-only prepared"):
            scanner_sandbox.build_scanner_launch(source(), {"prepared": False}, resources())

    def test_rejects_preparation_for_another_or_incomplete_source(self) -> None:
        wrong_source = prepared()
        wrong_source["source_id"] = "source_other"
        with self.assertRaisesRegex(scanner_sandbox.ScannerSandboxError, "selected source"):
            scanner_sandbox.build_scanner_launch(source(), wrong_source, resources())

        incomplete = prepared()
        incomplete["targets"][0]["verified_read_only"] = False
        with self.assertRaisesRegex(scanner_sandbox.ScannerSandboxError, "not verified"):
            scanner_sandbox.build_scanner_launch(source(), incomplete, resources())

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
            ("security_options", [], "security options"),
        ):
            modified = copy.deepcopy(spec)
            modified[key] = value
            with self.assertRaisesRegex(scanner_sandbox.ScannerSandboxError, message):
                scanner_sandbox.validate_scanner_spec(modified)

    def test_spec_validation_rejects_extra_device_or_host_mount(self) -> None:
        spec = scanner_sandbox.build_scanner_launch(source(), prepared(), resources())
        extra_device = copy.deepcopy(spec)
        extra_device["devices"].append({"host": "/dev/sdb", "container": "/dev/extra", "mode": "r"})
        with self.assertRaisesRegex(
            scanner_sandbox.ScannerSandboxError, "prepared read-only source"
        ):
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

        bad_resources = resources()
        bad_resources["pids_limit"] = True
        with self.assertRaisesRegex(scanner_sandbox.ScannerSandboxError, "pids"):
            scanner_sandbox.build_scanner_launch(source(), prepared(), bad_resources)

    def test_spec_validation_rejects_command_device_tmpfs_and_resource_changes(self) -> None:
        spec = scanner_sandbox.build_scanner_launch(source(), prepared(), resources())
        changes: tuple[tuple[str, object, str], ...] = (
            ("command", ["docker", "run", "--privileged"], "command"),
            (
                "devices",
                [{"host": "/dev/sdb", "container": "/dev/reperio-source", "mode": "r"}],
                "prepared read-only source",
            ),
            ("tmpfs", [], "tmpfs"),
            (
                "resources",
                {**spec["resources"], "memory_limit_mib": 0},
                "memory",
            ),
        )
        for key, value, message in changes:
            modified = copy.deepcopy(spec)
            modified[key] = value
            with self.assertRaisesRegex(scanner_sandbox.ScannerSandboxError, message):
                scanner_sandbox.validate_scanner_spec(modified)

    def test_launch_audits_fixed_profile_and_runs_only_fixed_command(self) -> None:
        commands: list[tuple[str, ...]] = []
        process = object()

        def runner(command: Sequence[str]) -> object:
            commands.append(tuple(command))
            return process

        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "safety.jsonl"
            result = scanner_sandbox.launch_scanner(
                source(),
                prepared(),
                resources(),
                audit_log=safety_audit.SafetyAuditLog(path),
                runner=runner,
                identity_verifier=lambda _name, _major_minor: True,
            )
            audit = safety_audit.verify_audit_log(path)

        self.assertIs(process, result)
        self.assertEqual(1, len(commands))
        self.assertEqual("docker", commands[0][0])
        self.assertNotIn("--privileged", commands[0])
        self.assertEqual("scanner_sandbox_profile", audit["records"][0]["event"])
        self.assertNotIn("/dev/sda", repr(audit["records"][0]))

    def test_launch_refuses_changed_device_identity_before_runtime(self) -> None:
        runner = mock.Mock()
        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaisesRegex(scanner_sandbox.ScannerSandboxError, "identity changed"):
                scanner_sandbox.launch_scanner(
                    source(),
                    prepared(),
                    resources(),
                    audit_log=safety_audit.SafetyAuditLog(Path(tmp) / "safety.jsonl"),
                    runner=runner,
                    identity_verifier=lambda _name, _major_minor: False,
                )

        runner.assert_not_called()

    def test_audit_failure_blocks_runtime_launch(self) -> None:
        runner = mock.Mock()
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            target = root / "target"
            target.write_text("must-not-change", encoding="utf-8")
            path = root / "safety.jsonl"
            path.symlink_to(target)

            with self.assertRaises(safety_audit.AuditWriteError):
                scanner_sandbox.launch_scanner(
                    source(),
                    prepared(),
                    resources(),
                    audit_log=safety_audit.SafetyAuditLog(path),
                    runner=runner,
                    identity_verifier=lambda _name, _major_minor: True,
                )

            self.assertEqual("must-not-change", target.read_text(encoding="utf-8"))
        runner.assert_not_called()

    def test_runtime_failure_is_audited_and_returned_as_safe_error(self) -> None:
        def missing_runtime(_command: Sequence[str]) -> object:
            raise FileNotFoundError

        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "safety.jsonl"
            with self.assertRaisesRegex(scanner_sandbox.ScannerSandboxError, "launch failed"):
                scanner_sandbox.launch_scanner(
                    source(),
                    prepared(),
                    resources(),
                    audit_log=safety_audit.SafetyAuditLog(path),
                    runner=missing_runtime,
                    identity_verifier=lambda _name, _major_minor: True,
                )

            audit = safety_audit.verify_audit_log(path)
        self.assertEqual("scanner_sandbox_profile", audit["records"][0]["event"])

    def test_runtime_process_receives_no_host_environment_or_shell(self) -> None:
        with (
            mock.patch.dict(os.environ, {"AWS_SECRET_ACCESS_KEY": "must-not-pass"}),
            mock.patch.object(scanner_sandbox.subprocess, "Popen", return_value=object()) as popen,
        ):
            scanner_sandbox._run_scanner(("docker", "run"))

        kwargs = popen.call_args.kwargs
        self.assertNotIn("AWS_SECRET_ACCESS_KEY", kwargs["env"])
        self.assertNotIn("shell", kwargs)
        self.assertEqual(subprocess.DEVNULL, kwargs["stdin"])
        self.assertTrue(kwargs["close_fds"])

    def test_device_identity_check_opens_only_expected_block_device_read_only(self) -> None:
        opened = SimpleNamespace(st_mode=stat.S_IFBLK, st_rdev=os.makedev(8, 0))
        with (
            mock.patch.object(scanner_sandbox.os, "open", return_value=41) as open_device,
            mock.patch.object(scanner_sandbox.os, "fstat", return_value=opened),
            mock.patch.object(scanner_sandbox.os, "close") as close_device,
        ):
            verified = scanner_sandbox._verify_device_identity("sda", "8:0")

        self.assertTrue(verified)
        self.assertEqual("/dev/sda", open_device.call_args.args[0])
        flags = open_device.call_args.args[1]
        self.assertEqual(os.O_RDONLY, flags & os.O_ACCMODE)
        self.assertTrue(flags & getattr(os, "O_CLOEXEC", 0))
        self.assertTrue(flags & getattr(os, "O_NOFOLLOW", 0))
        close_device.assert_called_once_with(41)

    def test_podman_command_uses_same_profile(self) -> None:
        spec = scanner_sandbox.build_scanner_launch(
            source(), prepared(), resources(), runtime="podman"
        )

        self.assertEqual("podman", spec["command"][0])
        scanner_sandbox.validate_scanner_spec(spec)


if __name__ == "__main__":
    unittest.main()
