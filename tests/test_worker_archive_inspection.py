from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from worker import archive_inspection, parser_sandbox


class FakeParserRuntime:
    def __init__(self, result: parser_sandbox.ParserProcessResult) -> None:
        self.result = result
        self.calls: list[tuple[tuple[str, ...], int]] = []

    def run(
        self, command: tuple[str, ...], timeout_seconds: int
    ) -> parser_sandbox.ParserProcessResult:
        self.calls.append((command, timeout_seconds))
        return self.result


class WorkerArchiveInspectionTests(unittest.TestCase):
    def test_zip_7z_rar_tar_and_gzip_route_to_sandbox_listing(self) -> None:
        cases = (
            ("file.zip", b"PK\x03\x04data", "zip"),
            ("file.7z", b"7z\xbc\xaf\x27\x1cdata", "7z"),
            ("file.rar", b"Rar!\x1a\x07\x00data", "rar"),
            ("file.tar", b"\0" * 257 + b"ustar" + b"\0" * 16, "tar"),
            ("file.gz", b"\x1f\x8bdata", "gzip"),
        )
        for name, payload, archive_format in cases:
            with self.subTest(name=name):
                result, runtime = parse_payload(
                    name,
                    payload,
                    line({"archive_format": archive_format, "members": [member("safe.txt")]}),
                )

            self.assertEqual("complete", result.status)
            self.assertEqual(archive_format, result.archive_format)
            self.assertEqual("safe.txt", result.members[0].path)
            self.assertIn("archive-inspect-json", runtime.calls[0][0])
            self.assertIn("--network=none", runtime.calls[0][0])

    def test_encrypted_nested_traversal_symlink_device_duplicate_and_bomb_are_labeled(self) -> None:
        result, _runtime = parse_payload(
            "file.zip",
            b"PK\x03\x04data",
            line(
                {
                    "archive_format": "zip",
                    "encrypted": True,
                    "nested_depth": 9,
                    "members": [
                        member("../escape.txt"),
                        member("link", kind="symlink"),
                        member("dev", kind="device"),
                        member("safe.txt", warnings=["duplicate_member_path"]),
                        member("bomb.bin", size_bytes=1_000_000, compressed_size_bytes=1),
                    ],
                }
            ),
            allow_extraction=True,
        )

        all_warnings = result.warnings + tuple(
            warning for item in result.members for warning in item.warnings
        )
        self.assertTrue(result.password_required)
        self.assertIn("nested_depth_limit_exceeded", all_warnings)
        self.assertIn("unsafe_member_path", all_warnings)
        self.assertIn("unsafe_member_kind:symlink", all_warnings)
        self.assertIn("unsafe_member_kind:device", all_warnings)
        self.assertIn("duplicate_member_path", all_warnings)
        self.assertIn("compression_ratio_limit", all_warnings)
        self.assertFalse(result.extraction_plan["allowed"])
        self.assertEqual("password_required", result.extraction_plan["reason"])

    def test_optional_extraction_plan_allows_only_safe_bounded_members(self) -> None:
        safe, _runtime = parse_payload(
            "file.zip",
            b"PK\x03\x04data",
            line({"members": [member("safe.txt")]}),
            allow_extraction=True,
        )
        listing_only, _runtime = parse_payload(
            "file.zip", b"PK\x03\x04data", line({"members": [member("safe.txt")]})
        )

        self.assertTrue(safe.extraction_plan["allowed"])
        self.assertEqual("bounded_scratch_extraction", safe.extraction_plan["reason"])
        self.assertFalse(listing_only.extraction_plan["allowed"])
        self.assertIn("extraction_not_requested", listing_only.warnings)

    def test_malformed_timeout_misleading_source_path_and_unsupported_are_labeled(self) -> None:
        malformed, _runtime = parse_payload(
            "file.zip",
            b"PK\x03\x04data",
            line({"status": "failed", "warnings": ["malformed_archive"]}),
        )
        timeout, _runtime = parse_process(
            "file.zip",
            b"PK\x03\x04data",
            parser_sandbox.ParserProcessResult(124, b"", timed_out=True),
        )
        misleading, _runtime = parse_payload("file.zip", b"MZpayload", b"")
        unsupported, _runtime = parse_payload("file.txt", b"plain text", b"")

        self.assertEqual("failed", malformed.status)
        self.assertIn("malformed_archive", malformed.warnings)
        self.assertEqual("timeout", timeout.status)
        self.assertIn("archive-inspect-json_parser_timeout", timeout.warnings)
        self.assertEqual("skipped", misleading.status)
        self.assertIn("parser_unsafe_signature:pe-executable", misleading.warnings)
        self.assertEqual("skipped", unsupported.status)
        self.assertIn("unsupported_mime:text/plain", unsupported.warnings)

        with (
            tempfile.TemporaryDirectory() as scratch_tmp,
            tempfile.TemporaryDirectory() as source_tmp,
        ):
            outside = Path(source_tmp) / "file.zip"
            outside.write_bytes(b"PK\x03\x04data")
            with self.assertRaises(archive_inspection.ArchiveInspectionError) as captured:
                archive_inspection.inspect_archive(
                    copied_archive_path=outside,
                    job_scratch=Path(scratch_tmp),
                    resource_profile=resources(),
                    runtime=FakeParserRuntime(parser_sandbox.ParserProcessResult(0, b"")),
                )
        self.assertEqual("input_not_copied", captured.exception.code)


def parse_payload(
    name: str, payload: bytes, stdout: bytes, *, allow_extraction: bool = False
) -> tuple[archive_inspection.ArchiveInspectionResult, FakeParserRuntime]:
    return parse_process(
        name,
        payload,
        parser_sandbox.ParserProcessResult(0, stdout),
        allow_extraction=allow_extraction,
    )


def parse_process(
    name: str,
    payload: bytes,
    process: parser_sandbox.ParserProcessResult,
    *,
    allow_extraction: bool = False,
) -> tuple[archive_inspection.ArchiveInspectionResult, FakeParserRuntime]:
    with tempfile.TemporaryDirectory() as tmp:
        scratch = Path(tmp) / "scratch"
        scratch.mkdir()
        copied = scratch / name
        copied.write_bytes(payload)
        runtime = FakeParserRuntime(process)
        result = archive_inspection.inspect_archive(
            copied_archive_path=copied,
            job_scratch=scratch,
            resource_profile=resources(),
            runtime=runtime,
            original_name=name,
            allow_extraction=allow_extraction,
            max_nested_depth=3,
        )
        return result, runtime


def resources() -> dict[str, int]:
    return {
        "memory_limit_mib": 256,
        "pids_limit": 32,
        "tmpfs_limit_mib": 64,
        "output_limit_mib": 64,
        "cpu_quota_percent": 50,
    }


def member(
    path: str,
    *,
    kind: str = "file",
    size_bytes: int = 10,
    compressed_size_bytes: int = 10,
    warnings: list[str] | None = None,
) -> dict[str, object]:
    return {
        "path": path,
        "kind": kind,
        "size_bytes": size_bytes,
        "compressed_size_bytes": compressed_size_bytes,
        "warnings": warnings or [],
    }


def line(record: dict[str, object]) -> bytes:
    return json.dumps(record).encode("utf-8") + b"\n"


if __name__ == "__main__":
    unittest.main()
