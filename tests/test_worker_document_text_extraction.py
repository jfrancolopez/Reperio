from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from worker import document_text_extraction, parser_sandbox


class FakeParserRuntime:
    def __init__(self, result: parser_sandbox.ParserProcessResult) -> None:
        self.result = result
        self.calls: list[tuple[tuple[str, ...], int]] = []

    def run(
        self, command: tuple[str, ...], timeout_seconds: int
    ) -> parser_sandbox.ParserProcessResult:
        self.calls.append((command, timeout_seconds))
        return self.result


class WorkerDocumentTextExtractionTests(unittest.TestCase):
    def test_extracts_supported_copied_document_text_and_metadata(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            scratch, copied = copied_document(Path(tmp), b"%PDF-1.7\nsynthetic")
            runtime = FakeParserRuntime(
                parser_sandbox.ParserProcessResult(
                    0,
                    line(
                        {
                            "status": "complete",
                            "text": "hello from tika",
                            "metadata": {"Content-Type": "application/pdf", "title": "Fixture"},
                            "parser_chain": ["DefaultParser", "PDFParser"],
                        }
                    ),
                )
            )

            result = document_text_extraction.extract_document_text(
                copied_document_path=copied,
                job_scratch=scratch,
                resource_profile=resources(),
                runtime=runtime,
                original_name="fixture.pdf",
            )

        self.assertEqual("complete", result.status)
        self.assertEqual("application/pdf", result.mime_type)
        self.assertEqual("hello from tika", result.text)
        self.assertEqual("Fixture", result.metadata["title"])
        self.assertEqual(("DefaultParser", "PDFParser"), result.parser_chain)
        self.assertIn("tika-json", runtime.calls[0][0])
        self.assertIn("--network=none", runtime.calls[0][0])

    def test_docx_xlsx_pptx_rtf_text_and_email_signatures_are_supported(self) -> None:
        cases = (
            (b"PK\x03\x04word/document.xml", "file.docx"),
            (b"PK\x03\x04xl/workbook.xml", "file.xlsx"),
            (b"PK\x03\x04ppt/presentation.xml", "file.pptx"),
            (b"{\\rtf1 text}", "file.rtf"),
            (b"plain text", "file.txt"),
            (b"From: a@example.test\nSubject: Hi\n\nBody", "file.eml"),
        )
        for payload, name in cases:
            with self.subTest(name=name), tempfile.TemporaryDirectory() as tmp:
                scratch, copied = copied_document(Path(tmp), payload)
                result = document_text_extraction.extract_document_text(
                    copied_document_path=copied,
                    job_scratch=scratch,
                    resource_profile=resources(),
                    runtime=FakeParserRuntime(
                        parser_sandbox.ParserProcessResult(0, line({"text": "ok"}))
                    ),
                    original_name=name,
                )

            self.assertEqual("complete", result.status)

    def test_parser_timeout_crash_encrypted_malformed_and_empty_output_are_labeled(self) -> None:
        timeout = parse_with(parser_sandbox.ParserProcessResult(124, b"", timed_out=True))
        crash = parse_with(parser_sandbox.ParserProcessResult(1, b"boom"))
        encrypted = parse_with(
            parser_sandbox.ParserProcessResult(
                0, line({"status": "encrypted", "warnings": ["encrypted_document"]})
            )
        )
        malformed = parse_with(
            parser_sandbox.ParserProcessResult(
                0, line({"status": "failed", "warnings": ["malformed_document"]})
            )
        )
        empty = parse_with(parser_sandbox.ParserProcessResult(0, b""))

        self.assertEqual("timeout", timeout.status)
        self.assertIn("parser_timeout", timeout.warnings)
        self.assertEqual("failed", crash.status)
        self.assertIn("parser_crash", crash.warnings)
        self.assertEqual("encrypted", encrypted.status)
        self.assertIn("encrypted_document", encrypted.warnings)
        self.assertEqual("failed", malformed.status)
        self.assertIn("malformed_document", malformed.warnings)
        self.assertIn("tika_no_output", empty.warnings)

    def test_unsafe_unsupported_source_path_zip_bomb_and_text_truncation_are_bounded(self) -> None:
        executable = parse_payload(b"MZnot a document", "evil.pdf")
        zip_bomb = parse_payload(b"PK\x03\x04not-office" + b"A" * 4096, "bomb.zip")
        truncated = parse_with(
            parser_sandbox.ParserProcessResult(0, line({"text": "abcdef"})), max_text_chars=3
        )

        self.assertEqual("skipped", executable.status)
        self.assertIn("parser_unsafe_content", executable.warnings)
        self.assertEqual("skipped", zip_bomb.status)
        self.assertIn("unsupported_mime:application/zip", zip_bomb.warnings)
        self.assertEqual("abc", truncated.text)
        self.assertTrue(truncated.truncated)
        self.assertIn("text_truncated", truncated.warnings)

        with (
            tempfile.TemporaryDirectory() as scratch_tmp,
            tempfile.TemporaryDirectory() as source_tmp,
        ):
            outside = Path(source_tmp) / "file.pdf"
            outside.write_bytes(b"%PDF-1.7")
            with self.assertRaises(document_text_extraction.DocumentExtractionError) as captured:
                document_text_extraction.extract_document_text(
                    copied_document_path=outside,
                    job_scratch=Path(scratch_tmp),
                    resource_profile=resources(),
                    runtime=FakeParserRuntime(parser_sandbox.ParserProcessResult(0, b"")),
                )

        self.assertEqual("input_not_copied", captured.exception.code)


def copied_document(root: Path, payload: bytes) -> tuple[Path, Path]:
    scratch = root / "scratch"
    scratch.mkdir()
    copied = scratch / "input"
    copied.write_bytes(payload)
    return scratch, copied


def parse_with(
    process: parser_sandbox.ParserProcessResult, *, max_text_chars: int = 100_000
) -> document_text_extraction.DocumentExtractionResult:
    with tempfile.TemporaryDirectory() as tmp:
        scratch, copied = copied_document(Path(tmp), b"%PDF-1.7\nsynthetic")
        return document_text_extraction.extract_document_text(
            copied_document_path=copied,
            job_scratch=scratch,
            resource_profile=resources(),
            runtime=FakeParserRuntime(process),
            original_name="file.pdf",
            max_text_chars=max_text_chars,
        )


def parse_payload(
    payload: bytes, original_name: str
) -> document_text_extraction.DocumentExtractionResult:
    with tempfile.TemporaryDirectory() as tmp:
        scratch, copied = copied_document(Path(tmp), payload)
        return document_text_extraction.extract_document_text(
            copied_document_path=copied,
            job_scratch=scratch,
            resource_profile=resources(),
            runtime=FakeParserRuntime(parser_sandbox.ParserProcessResult(0, line({"text": "ok"}))),
            original_name=original_name,
        )


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
