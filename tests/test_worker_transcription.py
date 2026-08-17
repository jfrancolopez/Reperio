from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from worker import parser_sandbox, transcription


class FakeParserRuntime:
    def __init__(self, result: parser_sandbox.ParserProcessResult) -> None:
        self.result = result
        self.calls: list[tuple[tuple[str, ...], int]] = []

    def run(
        self, command: tuple[str, ...], timeout_seconds: int
    ) -> parser_sandbox.ParserProcessResult:
        self.calls.append((command, timeout_seconds))
        return self.result


class WorkerTranscriptionTests(unittest.TestCase):
    def test_audio_transcription_records_language_segments_and_cpu_mode(self) -> None:
        result, runtime = parse(
            "audio.mp3",
            b"ID3data",
            line(
                {
                    "text": "hello world",
                    "language": "en",
                    "confidence": 0.88,
                    "extracted_audio_uri": "scratch://sha256/" + "a" * 64,
                    "segments": [segment(0, 1.5, "hello", "en")],
                    "checkpoint": {
                        "chunk_index": 1,
                        "next_offset_seconds": 30.0,
                        "complete": False,
                    },
                }
            ),
        )

        self.assertEqual("complete", result.status)
        self.assertEqual("audio", result.media_kind)
        self.assertEqual("en", result.language)
        self.assertEqual("hello", result.segments[0].text)
        self.assertEqual(30.0, result.checkpoint["next_offset_seconds"])
        self.assertIn("cpu_only_transcription", result.warnings)
        self.assertIn("local-transcription-json", runtime.calls[0][0])
        self.assertIn("--network=none", runtime.calls[0][0])

    def test_video_spanish_unknown_language_and_long_chunk_resume_are_labeled(self) -> None:
        spanish, _runtime = parse(
            "clip.mp4",
            b"\0\0\0\x18ftypisom",
            line(
                {"text": "hola mundo", "language": "es", "segments": [segment(0, 2, "hola", "es")]}
            ),
        )
        other, _runtime = parse(
            "clip.mp4",
            b"\0\0\0\x18ftypisom",
            line({"text": "bonjour", "language": "fr", "checkpoint": {"chunk_index": 9}}),
        )
        truncated, _runtime = parse(
            "clip.mp4",
            b"\0\0\0\x18ftypisom",
            line({"text": "abcdef", "language": "unknown"}),
            max_text_chars=3,
        )

        self.assertEqual("es", spanish.language)
        self.assertEqual("unknown", other.language)
        self.assertIn("unsupported_detected_language:fr", other.warnings)
        self.assertEqual(9, other.checkpoint["chunk_index"])
        self.assertEqual("abc", truncated.text)
        self.assertTrue(truncated.truncated)
        self.assertIn("transcript_truncated", truncated.warnings)

    def test_silence_corrupt_timeout_disabled_and_bad_audio_uri_are_labeled(self) -> None:
        silence, _runtime = parse(
            "audio.wav", b"RIFF\0\0\0\0WAVEfmt ", line({"text": "", "language": "unknown"})
        )
        corrupt, _runtime = parse(
            "audio.wav",
            b"RIFF\0\0\0\0WAVEfmt ",
            line({"status": "failed", "warnings": ["corrupt_audio"]}),
        )
        timeout, _runtime = parse_process(
            "audio.wav",
            b"RIFF\0\0\0\0WAVEfmt ",
            parser_sandbox.ParserProcessResult(124, b"", timed_out=True),
        )
        bad_uri, _runtime = parse(
            "audio.mp3", b"ID3data", line({"text": "hello", "extracted_audio_uri": "/tmp/leak"})
        )
        disabled, _runtime = parse_process(
            "audio.mp3",
            b"ID3data",
            parser_sandbox.ParserProcessResult(0, b""),
            capability={"enabled": False},
        )

        self.assertIn("silence_or_no_speech", silence.warnings)
        self.assertEqual("failed", corrupt.status)
        self.assertIn("corrupt_audio", corrupt.warnings)
        self.assertEqual("timeout", timeout.status)
        self.assertIn("local-transcription-json_parser_timeout", timeout.warnings)
        self.assertIn("invalid_extracted_audio_storage", bad_uri.warnings)
        self.assertEqual("disabled", disabled.status)
        self.assertIn("transcription_capability_disabled", disabled.warnings)

    def test_source_path_misleading_extension_and_unsupported_media_are_blocked(self) -> None:
        misleading, _runtime = parse("audio.mp3", b"MZpayload", b"")
        unsupported, _runtime = parse("photo.jpg", b"\xff\xd8\xff\xe0data", b"")

        self.assertEqual("skipped", misleading.status)
        self.assertIn("parser_unsafe_signature:pe-executable", misleading.warnings)
        self.assertEqual("skipped", unsupported.status)
        self.assertIn("unsupported_mime:image/jpeg", unsupported.warnings)

        with (
            tempfile.TemporaryDirectory() as scratch_tmp,
            tempfile.TemporaryDirectory() as source_tmp,
        ):
            outside = Path(source_tmp) / "audio.mp3"
            outside.write_bytes(b"ID3data")
            with self.assertRaises(transcription.TranscriptionError) as captured:
                transcription.transcribe_media(
                    copied_media_path=outside,
                    job_scratch=Path(scratch_tmp),
                    resource_profile=resources(),
                    runtime=FakeParserRuntime(parser_sandbox.ParserProcessResult(0, b"")),
                )
        self.assertEqual("input_not_copied", captured.exception.code)


def parse(
    name: str, payload: bytes, stdout: bytes, *, max_text_chars: int = 100_000
) -> tuple[transcription.TranscriptionResult, FakeParserRuntime]:
    return parse_process(
        name, payload, parser_sandbox.ParserProcessResult(0, stdout), max_text_chars=max_text_chars
    )


def parse_process(
    name: str,
    payload: bytes,
    process: parser_sandbox.ParserProcessResult,
    *,
    capability: dict[str, object] | None = None,
    max_text_chars: int = 100_000,
) -> tuple[transcription.TranscriptionResult, FakeParserRuntime]:
    with tempfile.TemporaryDirectory() as tmp:
        scratch = Path(tmp) / "scratch"
        scratch.mkdir()
        copied = scratch / name
        copied.write_bytes(payload)
        runtime = FakeParserRuntime(process)
        result = transcription.transcribe_media(
            copied_media_path=copied,
            job_scratch=scratch,
            resource_profile=resources(),
            runtime=runtime,
            original_name=name,
            capability=capability,
            max_text_chars=max_text_chars,
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


def segment(start: float, end: float, text: str, language: str) -> dict[str, object]:
    return {
        "start_seconds": start,
        "end_seconds": end,
        "text": text,
        "language": language,
        "confidence": 0.8,
    }


def line(record: dict[str, object]) -> bytes:
    return json.dumps(record).encode("utf-8") + b"\n"


if __name__ == "__main__":
    unittest.main()
