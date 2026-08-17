from __future__ import annotations

import hashlib
import json
import tempfile
import unittest
from pathlib import Path

from worker import parser_sandbox, repair


class FakeParserRuntime:
    def __init__(self, result: parser_sandbox.ParserProcessResult) -> None:
        self.result = result
        self.calls: list[tuple[tuple[str, ...], int]] = []

    def run(
        self, command: tuple[str, ...], timeout_seconds: int
    ) -> parser_sandbox.ParserProcessResult:
        self.calls.append((command, timeout_seconds))
        return self.result


class WorkerCopyRepairTests(unittest.TestCase):
    def test_each_repair_kind_routes_to_sandbox_with_derived_linked_artifact(self) -> None:
        cases = (
            ("clip.mp4", b"\0\0\0\x18ftypisom", "media-remux", "video/mp4"),
            ("file.zip", b"PK\x03\x04data", "archive-recovery", "application/zip"),
            ("doc.pdf", b"%PDF-1.4data", "pdf-rebuild", "application/pdf"),
            ("photo.jpg", b"\xff\xd8\xff\xe0data", "image-reencode", "image/jpeg"),
        )
        for name, payload, kind, output_mime in cases:
            with self.subTest(kind=kind):
                result, runtime = parse(
                    name,
                    payload,
                    lines(repaired(kind, output_mime, payload)),
                )

                self.assertEqual("complete", result.status)
                assert result.repaired is not None
                self.assertEqual(kind, result.repair_kind)
                self.assertEqual(kind, result.repaired.repair_kind)
                self.assertTrue(result.repaired.derived)
                self.assertIn("possibly_lossy", result.repaired.quality_status)
                self.assertEqual(
                    f"sha256:{hashlib.sha256(payload).hexdigest()}",
                    result.repaired.original_linkage,
                )
                self.assertEqual(
                    hashlib.sha256(payload).hexdigest(), result.original_content_sha256
                )
                self.assertIn("copy-repair-json", runtime.calls[0][0])
                self.assertIn("--network=none", runtime.calls[0][0])

    def test_failed_safe_fixture_reports_quality_and_warning_without_output(self) -> None:
        result, _runtime = parse(
            "doc.pdf",
            b"%PDF-1.4data",
            lines(
                repaired(
                    "pdf-rebuild",
                    "application/pdf",
                    b"%PDF-1.4data",
                    status="failed",
                    warnings=["unrecoverable"],
                )
            ),
        )

        self.assertEqual("failed", result.status)
        self.assertIsNone(result.repaired)
        self.assertIn("unrecoverable", result.warnings)

    def test_output_explosion_is_rejected(self) -> None:
        result, _runtime = parse(
            "clip.mp4",
            b"\0\0\0\x18ftypisom",
            lines(repaired("media-remux", "video/mp4", b"\0" * 8, size_bytes=1_500_000)),
            output_limit_mib=1,
        )

        self.assertEqual("failed", result.status)
        self.assertIsNone(result.repaired)
        self.assertIn("repair_output_limit", result.warnings)

    def test_source_path_denial_and_non_regular_input(self) -> None:
        with (
            tempfile.TemporaryDirectory() as scratch_tmp,
            tempfile.TemporaryDirectory() as source_tmp,
        ):
            outside = Path(source_tmp) / "doc.pdf"
            outside.write_bytes(b"%PDF-1.4data")
            with self.assertRaises(repair.CopyRepairError) as captured:
                repair.attempt_bounded_repair(
                    copied_artifact_path=outside,
                    job_scratch=Path(scratch_tmp),
                    resource_profile=resources(),
                    runtime=FakeParserRuntime(parser_sandbox.ParserProcessResult(0, b"")),
                )
        self.assertEqual("input_not_copied", captured.exception.code)

        with tempfile.TemporaryDirectory() as tmp:
            scratch = Path(tmp) / "scratch"
            scratch.mkdir()
            with self.assertRaises(repair.CopyRepairError) as captured:
                repair.attempt_bounded_repair(
                    copied_artifact_path=scratch,
                    job_scratch=scratch,
                    resource_profile=resources(),
                    runtime=FakeParserRuntime(parser_sandbox.ParserProcessResult(0, b"")),
                )
        self.assertEqual("invalid_repair_path", captured.exception.code)

    def test_provenance_linkage_mismatch_is_rejected(self) -> None:
        result, _runtime = parse(
            "photo.jpg",
            b"\xff\xd8\xff\xe0data",
            lines(repaired("image-reencode", "image/jpeg", b"stolen")),
        )

        self.assertEqual("failed", result.status)
        self.assertIsNone(result.repaired)
        self.assertIn("original_linkage_mismatch", result.warnings)

    def test_derived_flag_is_required_for_repaired_output(self) -> None:
        record = repaired("image-reencode", "image/jpeg", b"\xff\xd8\xff\xe0data")
        record["derived"] = False
        result, _runtime = parse("photo.jpg", b"\xff\xd8\xff\xe0data", lines(record))

        self.assertEqual("failed", result.status)
        self.assertIsNone(result.repaired)
        self.assertIn("repair_derived_required", result.warnings)

    def test_misleading_extension_unknown_mime_timeout_and_bad_storage_are_labeled(self) -> None:
        misleading, _runtime = parse("photo.jpg", b"MZpayload", b"")
        unknown, _runtime = parse("random.bin", b"?", b"")
        timeout, _runtime = parse_process(
            "doc.pdf",
            b"%PDF-1.4data",
            parser_sandbox.ParserProcessResult(124, b"", timed_out=True),
        )
        bad_storage, _runtime = parse(
            "doc.pdf",
            b"%PDF-1.4data",
            lines(
                {
                    **repaired("pdf-rebuild", "application/pdf", b"%PDF-1.4data"),
                    "storage_uri": "/tmp/source.pdf",
                }
            ),
        )

        self.assertEqual("skipped", misleading.status)
        self.assertIn("parser_unsafe_signature:pe-executable", misleading.warnings)
        self.assertEqual("skipped", unknown.status)
        self.assertIn("unsupported_mime:application/octet-stream", unknown.warnings)
        self.assertEqual("timeout", timeout.status)
        self.assertIn("copy-repair-json_parser_timeout", timeout.warnings)
        self.assertEqual("failed", bad_storage.status)
        self.assertIn("invalid_repaired_storage", bad_storage.warnings)


def repaired(
    kind: str,
    mime_type: str,
    payload: bytes,
    *,
    status: str = "complete",
    warnings: list[str] | None = None,
    size_bytes: int | None = None,
) -> dict[str, object]:
    record: dict[str, object] = {
        "status": status,
        "repair_kind": kind,
        "storage_uri": "scratch://sha256/" + (kind.encode().hex() * 64)[:64],
        "mime_type": mime_type,
        "size_bytes": size_bytes if size_bytes is not None else max(len(payload), 1),
        "quality_status": "possibly_lossy",
        "original_sha256": hashlib.sha256(payload).hexdigest(),
        "derived": True,
        "warnings": warnings or [],
    }
    return record


def parse(
    name: str,
    payload: bytes,
    stdout: bytes,
    *,
    output_limit_mib: int = 64,
) -> tuple[repair.CopyRepairResult, FakeParserRuntime]:
    return parse_process(
        name,
        payload,
        parser_sandbox.ParserProcessResult(0, stdout),
        output_limit_mib=output_limit_mib,
    )


def parse_process(
    name: str,
    payload: bytes,
    process: parser_sandbox.ParserProcessResult,
    *,
    output_limit_mib: int = 64,
) -> tuple[repair.CopyRepairResult, FakeParserRuntime]:
    with tempfile.TemporaryDirectory() as tmp:
        scratch = Path(tmp) / "scratch"
        scratch.mkdir()
        copied = scratch / name
        copied.write_bytes(payload)
        runtime = FakeParserRuntime(process)
        result = repair.attempt_bounded_repair(
            copied_artifact_path=copied,
            job_scratch=scratch,
            resource_profile=resources(output_limit_mib=output_limit_mib),
            runtime=runtime,
            original_name=name,
        )
        return result, runtime


def resources(*, output_limit_mib: int = 64) -> dict[str, int]:
    return {
        "memory_limit_mib": 256,
        "pids_limit": 32,
        "tmpfs_limit_mib": 64,
        "output_limit_mib": output_limit_mib,
        "cpu_quota_percent": 50,
    }


def lines(*records: dict[str, object]) -> bytes:
    return b"".join(json.dumps(record).encode("utf-8") + b"\n" for record in records)


if __name__ == "__main__":
    unittest.main()
