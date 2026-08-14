from __future__ import annotations

import copy
import tempfile
import unittest
from pathlib import Path

from worker import parser_sandbox


class FakeParserRuntime:
    def __init__(self, result: parser_sandbox.ParserProcessResult) -> None:
        self.result = result
        self.calls: list[tuple[tuple[str, ...], int]] = []

    def run(
        self, command: tuple[str, ...], timeout_seconds: int
    ) -> parser_sandbox.ParserProcessResult:
        self.calls.append((command, timeout_seconds))
        return self.result


class WorkerParserSandboxTests(unittest.TestCase):
    def test_builds_fixed_no_network_no_device_copy_only_profile(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            scratch, copied = scratch_input(Path(tmp))

            spec = parser_sandbox.build_parser_sandbox(
                profile_name="metadata-json",
                copied_input=copied,
                job_scratch=scratch,
                resource_profile=resources(),
            )

            self.assertEqual("none", spec["network"])
            self.assertEqual([], spec["devices"])
            self.assertEqual(["ALL"], spec["capabilities"]["drop"])
            self.assertTrue(spec["read_only_rootfs"])
            self.assertEqual("ro", spec["mounts"][0]["mode"])
            self.assertIn("--network=none", spec["command"])
            parser_sandbox.validate_parser_spec(spec)

    def test_rejects_source_device_control_db_secret_and_network_attempts(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            scratch, copied = scratch_input(Path(tmp))
            spec = parser_sandbox.build_parser_sandbox(
                profile_name="metadata-json",
                copied_input=copied,
                job_scratch=scratch,
                resource_profile=resources(),
            )
            for injected in ("/dev/sda", "catalog.sqlite3", "master.key", "--network=host"):
                modified = copy.deepcopy(spec)
                modified["command"] = (*modified["command"], injected)
                with self.assertRaises(parser_sandbox.ParserSandboxError):
                    parser_sandbox.validate_parser_spec(modified)

    def test_rejects_input_not_copied_to_job_scratch(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            scratch, _ = scratch_input(root)
            outside = root / "source" / "file.pdf"
            outside.parent.mkdir()
            outside.write_bytes(b"source")

            with self.assertRaises(parser_sandbox.ParserSandboxError) as captured:
                parser_sandbox.build_parser_sandbox(
                    profile_name="metadata-json",
                    copied_input=outside,
                    job_scratch=scratch,
                    resource_profile=resources(),
                )

            self.assertEqual("input_not_copied", captured.exception.code)

    def test_output_flood_timeout_crash_and_structured_stdout_are_labeled(self) -> None:
        spec = parser_sandbox.build_parser_sandbox(
            profile_name="metadata-json",
            copied_input=scratch_input(Path(tempfile.mkdtemp()))[1],
            job_scratch=Path(tempfile.gettempdir()),
            resource_profile=resources(),
        )
        complete = parser_sandbox.run_parser_sandbox(
            spec, FakeParserRuntime(parser_sandbox.ParserProcessResult(0, b'{"ok":true}\n'))
        )
        flooded = dict(spec)
        flooded["max_stdout_bytes"] = 1
        timeout = parser_sandbox.run_parser_sandbox(
            spec, FakeParserRuntime(parser_sandbox.ParserProcessResult(124, b"", timed_out=True))
        )
        crash = parser_sandbox.run_parser_sandbox(
            spec, FakeParserRuntime(parser_sandbox.ParserProcessResult(1, b"boom"))
        )
        flood = parser_sandbox.run_parser_sandbox(
            flooded, FakeParserRuntime(parser_sandbox.ParserProcessResult(0, b"{}\n"))
        )

        self.assertEqual("complete", complete.status)
        self.assertEqual(({"ok": True},), complete.records)
        self.assertEqual("timeout", timeout.status)
        self.assertIn("parser_timeout", timeout.warnings)
        self.assertEqual("failed", crash.status)
        self.assertIn("parser_crash", crash.warnings)
        self.assertIn("parser_output_limit_exceeded", flood.warnings)

    def test_fork_bomb_style_unbounded_pids_and_root_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            scratch, copied = scratch_input(Path(tmp))
            with self.assertRaises(parser_sandbox.ParserSandboxError):
                parser_sandbox.build_parser_sandbox(
                    profile_name="metadata-json",
                    copied_input=copied,
                    job_scratch=scratch,
                    resource_profile={**resources(), "pids_limit": 0},
                )
            spec = parser_sandbox.build_parser_sandbox(
                profile_name="metadata-json",
                copied_input=copied,
                job_scratch=scratch,
                resource_profile=resources(),
            )
            modified = dict(spec)
            modified["user"] = "0:0"
            with self.assertRaises(parser_sandbox.ParserSandboxError):
                parser_sandbox.validate_parser_spec(modified)


def scratch_input(root: Path) -> tuple[Path, Path]:
    scratch = root / "job-scratch"
    scratch.mkdir(parents=True, exist_ok=True)
    copied = scratch / "input"
    copied.write_bytes(b"fixture")
    return scratch, copied


def resources() -> dict[str, int]:
    return {
        "memory_limit_mib": 256,
        "pids_limit": 32,
        "tmpfs_limit_mib": 64,
        "output_limit_mib": 64,
        "cpu_quota_percent": 50,
    }


if __name__ == "__main__":
    unittest.main()
