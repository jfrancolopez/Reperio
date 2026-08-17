from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from worker import document_rendering, parser_sandbox


class FakeParserRuntime:
    def __init__(self, result: parser_sandbox.ParserProcessResult) -> None:
        self.result = result
        self.calls: list[tuple[tuple[str, ...], int]] = []

    def run(
        self, command: tuple[str, ...], timeout_seconds: int
    ) -> parser_sandbox.ParserProcessResult:
        self.calls.append((command, timeout_seconds))
        return self.result


class WorkerDocumentRenderingTests(unittest.TestCase):
    def test_renders_pdf_pages_and_first_page_thumbnail_without_source_delivery(self) -> None:
        result, runtime = parse_payload(
            b"%PDF-1.7\nfixture",
            "file.pdf",
            parser_sandbox.ParserProcessResult(
                0,
                line(
                    {
                        "status": "complete",
                        "total_pages": 2,
                        "pages": [
                            page(2, "scratch://sha256/" + "b" * 64),
                            page(
                                1,
                                "scratch://sha256/" + "a" * 64,
                                text_alignment_uri="scratch://sha256/" + "c" * 64,
                            ),
                        ],
                    }
                ),
            ),
        )

        self.assertEqual("complete", result.status)
        self.assertEqual("application/pdf", result.mime_type)
        self.assertEqual((1, 2), tuple(item.page_number for item in result.pages))
        self.assertEqual("scratch://sha256/" + "a" * 64, result.first_page_thumbnail_uri)
        self.assertEqual("scratch://sha256/" + "c" * 64, result.pages[0].text_alignment_uri)
        self.assertIn("document-render-json", runtime.calls[0][0])
        self.assertIn("--network=none", runtime.calls[0][0])

    def test_office_preview_fallback_uses_same_safe_page_contract(self) -> None:
        cases = (
            (b"PK\x03\x04word/document.xml", "file.docx"),
            (b"PK\x03\x04ppt/presentation.xml", "file.pptx"),
            (b"{\\rtf1 text}", "file.rtf"),
        )
        for payload, name in cases:
            with self.subTest(name=name):
                result, _runtime = parse_payload(
                    payload,
                    name,
                    parser_sandbox.ParserProcessResult(
                        0, line({"pages": [page(1, "scratch://sha256/" + "d" * 64)]})
                    ),
                )
            self.assertEqual("complete", result.status)
            self.assertEqual(1, result.pages[0].page_number)

    def test_encrypted_signed_malformed_javascript_and_timeout_are_labeled(self) -> None:
        encrypted, _runtime = parse_process(
            parser_sandbox.ParserProcessResult(
                0, line({"status": "encrypted", "warnings": ["encrypted_pdf"]})
            )
        )
        signed_js, _runtime = parse_process(
            parser_sandbox.ParserProcessResult(
                0,
                line(
                    {
                        "status": "complete",
                        "warnings": ["signed_pdf", "javascript_action_removed"],
                        "pages": [page(1, "scratch://sha256/" + "e" * 64)],
                    }
                ),
            )
        )
        malformed, _runtime = parse_process(
            parser_sandbox.ParserProcessResult(
                0, line({"status": "failed", "warnings": ["malformed_pdf"]})
            )
        )
        timeout, _runtime = parse_process(
            parser_sandbox.ParserProcessResult(124, b"", timed_out=True)
        )

        self.assertEqual("encrypted", encrypted.status)
        self.assertIn("encrypted_pdf", encrypted.warnings)
        self.assertEqual("complete", signed_js.status)
        self.assertIn("signed_pdf", signed_js.warnings)
        self.assertIn("javascript_action_removed", signed_js.warnings)
        self.assertEqual("failed", malformed.status)
        self.assertIn("malformed_pdf", malformed.warnings)
        self.assertEqual("timeout", timeout.status)
        self.assertIn("document-render-json_parser_timeout", timeout.warnings)

    def test_large_page_limits_active_output_and_source_path_are_blocked(self) -> None:
        unsafe, _runtime = parse_process(
            parser_sandbox.ParserProcessResult(
                0,
                line(
                    {
                        "total_pages": 10,
                        "pages": [
                            page(1, "scratch://sha256/" + "f" * 64, width=9999),
                            {**page(2, "scratch://sha256/" + "0" * 64), "mime_type": "text/html"},
                            page(3, "/tmp/source-leak"),
                        ],
                    }
                ),
            ),
            max_pages=2,
        )
        executable, _runtime = parse_payload(
            b"MZpayload", "file.pdf", parser_sandbox.ParserProcessResult(0, b"")
        )

        self.assertEqual("failed", unsafe.status)
        self.assertIn("page_limit_applied", unsafe.warnings)
        self.assertIn("page_dimension_limit:1", unsafe.warnings)
        self.assertIn("unsafe_page_mime:2", unsafe.warnings)
        self.assertEqual("skipped", executable.status)
        self.assertIn("parser_unsafe_signature:pe-executable", executable.warnings)

        with (
            tempfile.TemporaryDirectory() as scratch_tmp,
            tempfile.TemporaryDirectory() as source_tmp,
        ):
            outside = Path(source_tmp) / "file.pdf"
            outside.write_bytes(b"%PDF-1.7")
            with self.assertRaises(document_rendering.DocumentRenderError) as captured:
                document_rendering.render_document_pages(
                    copied_document_path=outside,
                    job_scratch=Path(scratch_tmp),
                    resource_profile=resources(),
                    runtime=FakeParserRuntime(parser_sandbox.ParserProcessResult(0, b"")),
                )
        self.assertEqual("input_not_copied", captured.exception.code)


def parse_process(
    process: parser_sandbox.ParserProcessResult, *, max_pages: int = 3
) -> tuple[document_rendering.DocumentRenderResult, FakeParserRuntime]:
    return parse_payload(b"%PDF-1.7\nfixture", "file.pdf", process, max_pages=max_pages)


def parse_payload(
    payload: bytes,
    name: str,
    process: parser_sandbox.ParserProcessResult,
    *,
    max_pages: int = 3,
) -> tuple[document_rendering.DocumentRenderResult, FakeParserRuntime]:
    with tempfile.TemporaryDirectory() as tmp:
        scratch = Path(tmp) / "scratch"
        scratch.mkdir()
        copied = scratch / name
        copied.write_bytes(payload)
        runtime = FakeParserRuntime(process)
        result = document_rendering.render_document_pages(
            copied_document_path=copied,
            job_scratch=scratch,
            resource_profile=resources(),
            runtime=runtime,
            original_name=name,
            max_pages=max_pages,
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


def page(
    number: int,
    storage_uri: str,
    *,
    width: int = 800,
    height: int = 1000,
    text_alignment_uri: str | None = None,
) -> dict[str, object]:
    record: dict[str, object] = {
        "page_number": number,
        "storage_uri": storage_uri,
        "mime_type": "image/webp",
        "width": width,
        "height": height,
        "size_bytes": 2048,
    }
    if text_alignment_uri is not None:
        record["text_alignment_uri"] = text_alignment_uri
    return record


def line(record: dict[str, object]) -> bytes:
    return json.dumps(record).encode("utf-8") + b"\n"


if __name__ == "__main__":
    unittest.main()
