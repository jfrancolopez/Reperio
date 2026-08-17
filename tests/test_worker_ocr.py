from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from worker import ocr, parser_sandbox


class FakeParserRuntime:
    def __init__(self, result: parser_sandbox.ParserProcessResult) -> None:
        self.result = result
        self.calls: list[tuple[tuple[str, ...], int]] = []

    def run(
        self, command: tuple[str, ...], timeout_seconds: int
    ) -> parser_sandbox.ParserProcessResult:
        self.calls.append((command, timeout_seconds))
        return self.result


class WorkerOcrTests(unittest.TestCase):
    def test_ocr_extracts_english_and_spanish_regions_from_copied_image(self) -> None:
        result, runtime = parse_payload(
            b"\xff\xd8\xff\xe0data",
            "photo.jpg",
            parser_sandbox.ParserProcessResult(
                0,
                line(
                    {
                        "text": "hello mundo",
                        "mean_confidence": 0.91,
                        "derivative_uri": "scratch://sha256/" + "a" * 64,
                        "regions": [
                            {
                                "page_number": 1,
                                "text": "hello",
                                "confidence": 0.95,
                                "bbox": {"x": 1, "y": 2, "width": 3, "height": 4},
                            }
                        ],
                    }
                ),
            ),
        )

        self.assertEqual("complete", result.status)
        self.assertTrue(result.needs_ocr)
        self.assertEqual("hello mundo", result.ocr_text)
        self.assertEqual(("eng", "spa"), result.language_packs)
        self.assertEqual(0.91, result.mean_confidence)
        self.assertEqual("hello", result.regions[0].text)
        self.assertIn("ocr-json", runtime.calls[0][0])
        self.assertIn("--network=none", runtime.calls[0][0])

    def test_scanned_pdf_runs_ocr_but_existing_text_is_preserved_and_skipped(self) -> None:
        scanned, _runtime = parse_payload(
            b"%PDF-1.7\nscan",
            "scan.pdf",
            parser_sandbox.ParserProcessResult(0, line({"text": "scanned"})),
        )
        existing, runtime = parse_payload(
            b"%PDF-1.7\ntext",
            "text.pdf",
            parser_sandbox.ParserProcessResult(0, line({"text": "should not run"})),
            existing_text="already extracted",
        )

        self.assertEqual("complete", scanned.status)
        self.assertEqual("scanned", scanned.ocr_text)
        self.assertEqual("skipped-existing-text", existing.status)
        self.assertFalse(existing.needs_ocr)
        self.assertEqual("already extracted", existing.existing_text)
        self.assertEqual([], runtime.calls)

    def test_low_confidence_truncation_invalid_derivative_and_region_limit_are_labeled(
        self,
    ) -> None:
        result, _runtime = parse_payload(
            b"\x89PNG\r\n\x1a\ndata",
            "image.png",
            parser_sandbox.ParserProcessResult(
                0,
                line(
                    {
                        "text": "abcdef",
                        "mean_confidence": 0.3,
                        "derivative_uri": "/tmp/leak",
                        "regions": [
                            {
                                "page_number": 1,
                                "text": "x",
                                "confidence": 0.5,
                                "bbox": {"x": 1, "y": 1, "width": 1, "height": 1},
                            }
                        ]
                        * 600,
                    }
                ),
            ),
            max_text_chars=3,
        )

        self.assertEqual("abc", result.ocr_text)
        self.assertTrue(result.truncated)
        self.assertEqual(512, len(result.regions))
        self.assertIn("low_confidence_ocr", result.warnings)
        self.assertIn("ocr_text_truncated", result.warnings)
        self.assertIn("invalid_ocr_derivative_storage", result.warnings)
        self.assertIn("ocr_region_limit_applied", result.warnings)

    def test_corrupt_timeout_unsupported_misleading_source_path_and_language_are_labeled(
        self,
    ) -> None:
        corrupt, _runtime = parse_payload(
            b"RAW\x00data",
            "image.raw",
            parser_sandbox.ParserProcessResult(
                0, line({"status": "failed", "warnings": ["corrupt_image"]})
            ),
        )
        timeout, _runtime = parse_payload(
            b"%PDF-1.7", "scan.pdf", parser_sandbox.ParserProcessResult(124, b"", timed_out=True)
        )
        misleading, _runtime = parse_payload(
            b"MZpayload", "photo.jpg", parser_sandbox.ParserProcessResult(0, b"")
        )
        unsupported, _runtime = parse_payload(
            b"plain text", "file.txt", parser_sandbox.ParserProcessResult(0, b"")
        )

        self.assertEqual("failed", corrupt.status)
        self.assertIn("corrupt_image", corrupt.warnings)
        self.assertEqual("timeout", timeout.status)
        self.assertIn("ocr-json_parser_timeout", timeout.warnings)
        self.assertEqual("skipped", misleading.status)
        self.assertIn("parser_unsafe_signature:pe-executable", misleading.warnings)
        self.assertEqual("skipped", unsupported.status)
        self.assertIn("unsupported_mime:text/plain", unsupported.warnings)

        with (
            tempfile.TemporaryDirectory() as scratch_tmp,
            tempfile.TemporaryDirectory() as source_tmp,
        ):
            outside = Path(source_tmp) / "photo.jpg"
            outside.write_bytes(b"\xff\xd8\xff\xe0data")
            with self.assertRaises(ocr.OcrError) as captured:
                ocr.extract_ocr_text(
                    copied_input_path=outside,
                    job_scratch=Path(scratch_tmp),
                    resource_profile=resources(),
                    runtime=FakeParserRuntime(parser_sandbox.ParserProcessResult(0, b"")),
                )
        self.assertEqual("input_not_copied", captured.exception.code)

        with tempfile.TemporaryDirectory() as tmp:
            scratch, copied = copied_input(Path(tmp), "photo.jpg", b"\xff\xd8\xff\xe0data")
            with self.assertRaises(ocr.OcrError) as captured_language:
                ocr.extract_ocr_text(
                    copied_input_path=copied,
                    job_scratch=scratch,
                    resource_profile=resources(),
                    runtime=FakeParserRuntime(parser_sandbox.ParserProcessResult(0, b"")),
                    language_packs=("fra",),
                )
        self.assertEqual("unsupported_language_pack", captured_language.exception.code)


def parse_payload(
    payload: bytes,
    name: str,
    process: parser_sandbox.ParserProcessResult,
    *,
    existing_text: str = "",
    max_text_chars: int = 100_000,
) -> tuple[ocr.OcrResult, FakeParserRuntime]:
    with tempfile.TemporaryDirectory() as tmp:
        scratch, copied = copied_input(Path(tmp), name, payload)
        runtime = FakeParserRuntime(process)
        result = ocr.extract_ocr_text(
            copied_input_path=copied,
            job_scratch=scratch,
            resource_profile=resources(),
            runtime=runtime,
            original_name=name,
            existing_text=existing_text,
            max_text_chars=max_text_chars,
        )
        return result, runtime


def copied_input(root: Path, name: str, payload: bytes) -> tuple[Path, Path]:
    scratch = root / "scratch"
    scratch.mkdir()
    copied = scratch / name
    copied.write_bytes(payload)
    return scratch, copied


def resources() -> dict[str, int]:
    return {
        "memory_limit_mib": 256,
        "pids_limit": 32,
        "tmpfs_limit_mib": 64,
        "output_limit_mib": 64,
        "cpu_quota_percent": 50,
    }


def line(record: dict[str, object]) -> bytes:
    return json.dumps(record).encode("utf-8") + b"\n"


if __name__ == "__main__":
    unittest.main()
