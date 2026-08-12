from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from worker import content_signature


class WorkerContentSignatureTests(unittest.TestCase):
    def test_renamed_executable_is_not_parser_safe_by_extension(self) -> None:
        result = content_signature.detect_content_signature_bytes(
            b"MZ" + b"\0" * 64, extension_mime="image/jpeg"
        )

        self.assertEqual("pe-executable", result.signature)
        self.assertEqual("application/x-msdownload", result.mime_type)
        self.assertIn("extension_mismatch", result.evidence)
        self.assertFalse(result.parser_safe)

    def test_image_document_and_archive_signatures(self) -> None:
        jpeg = content_signature.detect_content_signature_bytes(b"\xff\xd8\xff\xe0data")
        pdf = content_signature.detect_content_signature_bytes(b"%PDF-1.7\n")
        zip_file = content_signature.detect_content_signature_bytes(b"PK\x03\x04data")

        self.assertEqual("image/jpeg", jpeg.mime_type)
        self.assertEqual("application/pdf", pdf.mime_type)
        self.assertEqual("application/zip", zip_file.mime_type)
        self.assertTrue(jpeg.parser_safe)
        self.assertTrue(pdf.parser_safe)

    def test_docx_zip_container_is_detected_from_bounded_sample(self) -> None:
        result = content_signature.detect_content_signature_bytes(b"PK\x03\x04word/document.xml")

        self.assertEqual("docx", result.signature)
        self.assertEqual(
            "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
            result.mime_type,
        )

    def test_polyglot_fixture_keeps_conflict_explicit(self) -> None:
        result = content_signature.detect_content_signature_bytes(b"%PDF-1.7\nbody PK\x03\x04")

        self.assertEqual("pdf", result.signature)
        self.assertIn("polyglot_signature", result.evidence)
        self.assertFalse(result.parser_safe)
        self.assertLess(result.confidence, 0.9)

    def test_empty_truncated_random_and_huge_sparse_files_are_bounded(self) -> None:
        empty = content_signature.detect_content_signature_bytes(b"")
        truncated = content_signature.detect_content_signature_bytes(b"%P")
        randomish = content_signature.detect_content_signature_bytes(bytes(range(256)) * 4)

        self.assertEqual("empty", empty.signature)
        self.assertEqual("unknown", truncated.signature)
        self.assertEqual("random", randomish.signature)

        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "huge.bin"
            with path.open("wb") as handle:
                handle.seek(1024 * 1024)
                handle.write(b"Z")

            sample = content_signature.sparse_sample(path, sample_limit=128)

        self.assertEqual(128, len(sample))

    def test_path_detection_uses_original_name_only_as_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "renamed.txt"
            path.write_bytes(b"\x89PNG\r\n\x1a\nrest")

            result = content_signature.detect_content_signature(
                path, original_name="photo.exe", sample_limit=16
            )

        self.assertEqual("image/png", result.mime_type)
        self.assertEqual("application/x-msdownload", result.extension_mime)
        self.assertIn("extension_mismatch", result.evidence)
        self.assertFalse(result.parser_safe)
        self.assertEqual(12, result.sample_size)


if __name__ == "__main__":
    unittest.main()
