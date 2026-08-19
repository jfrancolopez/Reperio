#!/usr/bin/env python3

from __future__ import annotations

import unittest
from typing import Any

from worker.rclone_adapter import (
    RCLONE_VERSION,
    RcloneError,
    assert_no_forbidden_flag,
    build_command,
    build_job_config,
    capability_check,
    redact_output,
    resume_plan,
    retry_policy,
    run_rclone,
    verify_limitations,
)


class CapabilityTests(unittest.TestCase):
    def test_supported_remotes(self) -> None:
        for remote in ("local", "sftp", "smb", "ftp", "webdav", "s3", "google_drive"):
            capability = capability_check(remote)
            self.assertEqual(remote, capability.remote_type)

    def test_ftp_plaintext_warning(self) -> None:
        capability = capability_check("ftp")
        self.assertIsNotNone(capability.plaintext_warning)
        self.assertIn("plaintext", capability.plaintext_warning or "")

    def test_unsupported_remote_rejected(self) -> None:
        with self.assertRaisesRegex(RcloneError, "not supported"):
            capability_check("mystery-cloud")

    def test_checksum_support(self) -> None:
        self.assertTrue(capability_check("s3").supports_checksum)
        self.assertFalse(capability_check("ftp").supports_checksum)


class ConfigTests(unittest.TestCase):
    def test_job_config_contains_credentials(self) -> None:
        config = build_job_config(
            remote_type="sftp", credentials={"user": "alice", "pass": "hunter2secret"}
        )
        self.assertIn("[job-remote]", config)
        self.assertIn("type = sftp", config)
        self.assertIn("pass = hunter2secret", config)

    def test_command_never_inlines_credentials(self) -> None:
        invocation = build_command(
            remote_type="sftp",
            operation="copy",
            source="/scratch/job-1/src",
            destination="job-remote:backups",
            job_config="/scratch/job-1/rclone.conf",
            checksum=True,
        )
        self.assertNotIn("hunter2secret", " ".join(invocation["argv"]))
        self.assertIn("--config", invocation["argv"])
        self.assertIn("--checksum", invocation["argv"])
        self.assertFalse(invocation["credentials_in_argv"])

    def test_allowlisted_commands_only(self) -> None:
        for operation in ("copy", "check"):
            build_command(
                remote_type="s3",
                operation=operation,
                source="s",
                destination="d",
                job_config="c",
            )

    def test_forbidden_command_rejected(self) -> None:
        with self.assertRaisesRegex(RcloneError, "not allowed"):
            build_command(
                remote_type="s3",
                operation="delete",
                source="s",
                destination="d",
                job_config="c",
            )

    def test_sync_never_passes_guard(self) -> None:
        with self.assertRaisesRegex(RcloneError, "forbidden"):
            assert_no_forbidden_flag("sync")

    def test_delete_never_passes_guard(self) -> None:
        with self.assertRaisesRegex(RcloneError, "forbidden"):
            assert_no_forbidden_flag("delete")


class ResumeTests(unittest.TestCase):
    def test_retry_policy_budgeted(self) -> None:
        self.assertTrue(retry_policy(0))
        self.assertFalse(retry_policy(3))

    def test_resume_from_checkpoint(self) -> None:
        plan = resume_plan({"transferred_items": 7, "total_items": 10}, attempt=1)
        self.assertTrue(plan["resume"])
        self.assertEqual(3, plan["remaining_items"])

    def test_exhausted_budget(self) -> None:
        plan = resume_plan({"transferred_items": 7, "total_items": 10}, attempt=3)
        self.assertEqual("exhausted", plan["status"])
        self.assertFalse(plan["resume"])


class RunTests(unittest.TestCase):
    def test_success(self) -> None:
        invocation = build_command(
            remote_type="s3", operation="copy", source="s", destination="d", job_config="c"
        )
        outcome = run_rclone(invocation, lambda req: {"returncode": 0, "output": "Copied 1 file"})
        self.assertEqual("ok", outcome["status"])

    def test_timeout(self) -> None:
        invocation = build_command(
            remote_type="s3", operation="copy", source="s", destination="d", job_config="c"
        )
        outcome = run_rclone(invocation, lambda req: {"timed_out": True})
        self.assertEqual("timed_out", outcome["status"])

    def test_crash(self) -> None:
        invocation = build_command(
            remote_type="s3", operation="copy", source="s", destination="d", job_config="c"
        )

        def broken(req: Any) -> dict[str, Any]:
            raise RuntimeError("segfault")

        outcome = run_rclone(invocation, broken)
        self.assertEqual("crashed", outcome["status"])

    def test_credential_redaction(self) -> None:
        invocation = build_command(
            remote_type="s3", operation="copy", source="s", destination="d", job_config="c"
        )
        outcome = run_rclone(
            invocation,
            lambda req: {"returncode": 0, "output": "password=hunter2secret file copied"},
        )
        self.assertNotIn("hunter2secret", outcome["output"])
        self.assertIn("[redacted]", outcome["output"])

    def test_redact_output(self) -> None:
        redacted = redact_output("token=supersecrettoken12345 and more")
        self.assertNotIn("supersecrettoken12345", redacted)


class VerifyTests(unittest.TestCase):
    def test_checksum_limitation_recorded(self) -> None:
        limitation = verify_limitations("ftp", checksum_requested=True)
        self.assertFalse(limitation["checksum_available"])
        self.assertIsNotNone(limitation["limitation"])
        self.assertIsNotNone(limitation["plaintext_warning"])

    def test_checksum_available_recorded(self) -> None:
        limitation = verify_limitations("s3", checksum_requested=True)
        self.assertTrue(limitation["checksum_available"])
        self.assertIsNone(limitation["limitation"])

    def test_version_constant(self) -> None:
        self.assertEqual("rclone-adapter-v1", RCLONE_VERSION)


if __name__ == "__main__":
    unittest.main()
