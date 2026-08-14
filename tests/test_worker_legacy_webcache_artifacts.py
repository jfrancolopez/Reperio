from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from shared.browser_artifact_schemas import validate_browser_artifact
from worker import legacy_webcache_artifacts, parser_sandbox
from worker.browser_profiles import BrowserProfile


class FakeParserRuntime:
    def __init__(self, result: parser_sandbox.ParserProcessResult) -> None:
        self.result = result
        self.calls: list[tuple[tuple[str, ...], int]] = []

    def run(
        self, command: tuple[str, ...], timeout_seconds: int
    ) -> parser_sandbox.ParserProcessResult:
        self.calls.append((command, timeout_seconds))
        return self.result


class WorkerLegacyWebCacheArtifactsTests(unittest.TestCase):
    def test_safe_webcache_fixture_is_normalized_with_parser_provenance(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            scratch, webcache = copied_webcache(Path(tmp))
            runtime = FakeParserRuntime(
                parser_sandbox.ParserProcessResult(
                    0,
                    lines(
                        {
                            "artifact_kind": "visit",
                            "row_reference": "Containers:1",
                            "url": "https://example.test/",
                            "title": "Example",
                            "timestamp": "2026-01-02T03:04:05Z",
                        },
                        {
                            "artifact_kind": "download",
                            "row_reference": "Containers:2",
                            "source_url": "https://example.test/file.zip",
                            "target_path": "C:/Users/Alice/Downloads/file.zip",
                            "start_time": "2026-01-02T03:04:06Z",
                            "end_time": "2026-01-02T03:04:07Z",
                            "received_bytes": 42,
                            "total_bytes": 42,
                        },
                        {
                            "artifact_kind": "favorite",
                            "row_reference": "Favorites:3",
                            "url": "https://example.test/bookmark",
                            "title": "Bookmark",
                            "created_time": "2026-01-02T03:04:08Z",
                        },
                        {
                            "artifact_kind": "cache_entry",
                            "row_reference": "Cache:4",
                            "url": "https://example.test/app.js",
                            "cache_key": "cache-key-1",
                            "stored_time": "2026-01-02T03:04:09Z",
                        },
                    ),
                )
            )

            result = legacy_webcache_artifacts.parse_legacy_webcache(
                profile(),
                copied_webcache_path=webcache,
                job_scratch=scratch,
                resource_profile=resources(),
                runtime=runtime,
                entry_id="entry-WebCacheV01.dat",
            )

            kinds = {record["artifact_kind"] for record in result.records}
            self.assertEqual({"visit", "download", "bookmark", "cache_entry"}, kinds)
            self.assertIn("--profile", runtime.calls[0][0])
            self.assertIn("legacy-webcache", runtime.calls[0][0])
            for record in result.records:
                self.assertTrue(validate_browser_artifact(record).valid, record)
                self.assertEqual("legacy_ie_edge", record["browser_family"])
                self.assertEqual("legacy-webcache-adapter-v1", record["raw_provenance"]["parser"])

    def test_missing_webcache_produces_status_record_and_warning(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            scratch = Path(tmp) / "scratch"
            scratch.mkdir()

            result = legacy_webcache_artifacts.parse_legacy_webcache(
                profile(),
                copied_webcache_path=scratch / "WebCacheV01.dat",
                job_scratch=scratch,
                resource_profile=resources(),
                runtime=FakeParserRuntime(parser_sandbox.ParserProcessResult(0, b"")),
            )

            self.assertEqual(("missing_artifact:WebCacheV01.dat",), result.warnings)
            self.assertEqual("profile", result.records[0]["artifact_kind"])
            self.assertTrue(validate_browser_artifact(result.records[0]).valid)

    def test_corrupt_tool_failure_timeout_and_no_artifact_cases_are_labeled(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            scratch, webcache = copied_webcache(Path(tmp))
            failed = legacy_webcache_artifacts.parse_legacy_webcache(
                profile(),
                copied_webcache_path=webcache,
                job_scratch=scratch,
                resource_profile=resources(),
                runtime=FakeParserRuntime(parser_sandbox.ParserProcessResult(1, b"corrupt page")),
            )
            timeout = legacy_webcache_artifacts.parse_legacy_webcache(
                profile(),
                copied_webcache_path=webcache,
                job_scratch=scratch,
                resource_profile=resources(),
                runtime=FakeParserRuntime(
                    parser_sandbox.ParserProcessResult(124, b"", timed_out=True)
                ),
            )
            empty = legacy_webcache_artifacts.parse_legacy_webcache(
                profile(),
                copied_webcache_path=webcache,
                job_scratch=scratch,
                resource_profile=resources(),
                runtime=FakeParserRuntime(parser_sandbox.ParserProcessResult(0, b"")),
            )

            self.assertIn("webcache_parser_crash", failed.warnings)
            self.assertIn("webcache_parser_timeout", timeout.warnings)
            self.assertIn("no_artifacts", empty.warnings)
            self.assertEqual("profile", failed.records[0]["artifact_kind"])

    def test_missing_logs_and_unsupported_records_do_not_block_supported_records(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            scratch, webcache = copied_webcache(Path(tmp))
            runtime = FakeParserRuntime(
                parser_sandbox.ParserProcessResult(
                    0,
                    lines(
                        {"artifact_kind": "missing_logs", "row_reference": "logs"},
                        {
                            "artifact_kind": "visit",
                            "row_reference": "Containers:5",
                            "url": "https://example.test/recovered",
                            "title": "Recovered",
                            "timestamp": "2026-01-02T03:04:10Z",
                        },
                    ),
                )
            )

            result = legacy_webcache_artifacts.parse_legacy_webcache(
                profile(),
                copied_webcache_path=webcache,
                job_scratch=scratch,
                resource_profile=resources(),
                runtime=runtime,
            )

            self.assertIn("unsupported_record:missing_logs", result.warnings)
            self.assertEqual(
                ("visit",), tuple(record["artifact_kind"] for record in result.records)
            )

    def test_rejects_source_path_outside_job_scratch(self) -> None:
        with (
            tempfile.TemporaryDirectory() as scratch_tmp,
            tempfile.TemporaryDirectory() as source_tmp,
        ):
            outside = Path(source_tmp) / "WebCacheV01.dat"
            outside.write_bytes(b"source")
            with self.assertRaises(legacy_webcache_artifacts.LegacyWebCacheError) as captured:
                legacy_webcache_artifacts.parse_legacy_webcache(
                    profile(),
                    copied_webcache_path=outside,
                    job_scratch=Path(scratch_tmp),
                    resource_profile=resources(),
                    runtime=FakeParserRuntime(parser_sandbox.ParserProcessResult(0, b"")),
                )

        self.assertEqual("input_not_copied", captured.exception.code)


def copied_webcache(root: Path) -> tuple[Path, Path]:
    scratch = root / "scratch"
    scratch.mkdir()
    webcache = scratch / "WebCacheV01.dat"
    webcache.write_bytes(b"synthetic safe ESE fixture placeholder")
    return scratch, webcache


def profile() -> BrowserProfile:
    return BrowserProfile(
        browser_profile_id="legacy-profile-1",
        browser_family="legacy_ie_edge",
        browser_name="Legacy Edge",
        profile_path="Users/Alice/AppData/Local/Microsoft/Windows/WebCache",
        profile_name="WebCache",
        volume_id="vol1",
        owner_profile_id="windows-profile-1",
        owner_sid="S-1-5-21-100",
        evidence=("WebCacheV01.dat",),
        companion_entry_ids=("entry-WebCacheV01.dat",),
        portable=False,
        partial=False,
    )


def resources() -> dict[str, int]:
    return {
        "memory_limit_mib": 256,
        "pids_limit": 32,
        "tmpfs_limit_mib": 64,
        "output_limit_mib": 64,
        "cpu_quota_percent": 50,
    }


def lines(*records: dict[str, object]) -> bytes:
    return b"".join(json.dumps(record).encode("utf-8") + b"\n" for record in records)


if __name__ == "__main__":
    unittest.main()
