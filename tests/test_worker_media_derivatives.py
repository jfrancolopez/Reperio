from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from worker import media_derivatives, parser_sandbox


class FakeParserRuntime:
    def __init__(self, result: parser_sandbox.ParserProcessResult) -> None:
        self.result = result
        self.calls: list[tuple[tuple[str, ...], int]] = []

    def run(
        self, command: tuple[str, ...], timeout_seconds: int
    ) -> parser_sandbox.ParserProcessResult:
        self.calls.append((command, timeout_seconds))
        return self.result


class WorkerMediaDerivativesTests(unittest.TestCase):
    def test_image_preview_uses_sandbox_and_rejects_active_output(self) -> None:
        good = parse(
            "photo.jpg",
            b"\xff\xd8\xff\xe0data",
            lines(derivative("image-preview", "image/webp", width=1200, height=800)),
        )
        active = parse(
            "photo.jpg",
            b"\xff\xd8\xff\xe0data",
            lines(derivative("image-preview", "text/html", width=1200, height=800)),
        )

        self.assertEqual("complete", good.status)
        self.assertEqual("image", good.media_kind)
        self.assertEqual("image-preview", good.derivatives[0].derivative_kind)
        self.assertEqual("failed", active.status)
        self.assertIn("unsafe_derivative_mime:image-preview", active.warnings)

    def test_video_preview_keyframe_and_audio_derivatives_support_ranges_only_on_derivatives(
        self,
    ) -> None:
        video = parse(
            "clip.mp4",
            b"\0\0\0\x18ftypisom",
            lines(
                derivative("video-preview", "video/mp4", duration_seconds=10, range_supported=True),
                derivative(
                    "video-keyframe", "image/webp", width=320, height=180, range_supported=True
                ),
            ),
        )
        audio = parse(
            "sound.mp3",
            b"ID3data",
            lines(
                derivative("audio-waveform", "image/webp", width=640, height=120),
                derivative("audio-preview", "audio/mpeg", duration_seconds=8, range_supported=True),
            ),
        )

        self.assertEqual(
            ("video-preview", "video-keyframe"),
            tuple(item.derivative_kind for item in video.derivatives),
        )
        self.assertTrue(video.derivatives[0].range_supported)
        self.assertFalse(video.derivatives[1].range_supported)
        self.assertEqual(
            ("audio-waveform", "audio-preview"),
            tuple(item.derivative_kind for item in audio.derivatives),
        )
        self.assertTrue(audio.derivatives[1].range_supported)

    def test_malformed_huge_duration_bad_storage_and_timeout_are_labeled(self) -> None:
        huge = parse(
            "clip.mp4",
            b"\0\0\0\x18ftypisom",
            lines(derivative("video-preview", "video/mp4", duration_seconds=999)),
        )
        bad_storage = parse(
            "clip.mp4",
            b"\0\0\0\x18ftypisom",
            lines({**derivative("video-preview", "video/mp4"), "storage_uri": "/tmp/source"}),
        )
        timeout = parse_process(
            "sound.wav",
            b"RIFF\0\0\0\0WAVEfmt ",
            parser_sandbox.ParserProcessResult(124, b"", timed_out=True),
        )

        self.assertEqual("failed", huge.status)
        self.assertIn("derivative_duration_limit:video-preview", huge.warnings)
        self.assertEqual("failed", bad_storage.status)
        self.assertIn("invalid_derivative_storage:video-preview", bad_storage.warnings)
        self.assertEqual("timeout", timeout.status)
        self.assertIn("media-derivative-json_parser_timeout", timeout.warnings)

    def test_misleading_extension_unknown_and_source_path_are_blocked(self) -> None:
        misleading = parse("photo.jpg", b"MZpayload", b"")
        unknown = parse("unknown.bin", b"???", b"")

        self.assertEqual("skipped", misleading.status)
        self.assertIn("parser_unsafe_signature:pe-executable", misleading.warnings)
        self.assertEqual("skipped", unknown.status)
        self.assertIn("unsupported_mime:application/octet-stream", unknown.warnings)

        with (
            tempfile.TemporaryDirectory() as scratch_tmp,
            tempfile.TemporaryDirectory() as source_tmp,
        ):
            outside = Path(source_tmp) / "clip.mp4"
            outside.write_bytes(b"\0\0\0\x18ftypisom")
            with self.assertRaises(media_derivatives.MediaDerivativeError) as captured:
                media_derivatives.generate_media_derivatives(
                    copied_media_path=outside,
                    job_scratch=Path(scratch_tmp),
                    resource_profile=resources(),
                    runtime=FakeParserRuntime(parser_sandbox.ParserProcessResult(0, b"")),
                )
        self.assertEqual("input_not_copied", captured.exception.code)


def parse(name: str, payload: bytes, stdout: bytes) -> media_derivatives.MediaDerivativeResult:
    return parse_process(name, payload, parser_sandbox.ParserProcessResult(0, stdout))


def parse_process(
    name: str, payload: bytes, process: parser_sandbox.ParserProcessResult
) -> media_derivatives.MediaDerivativeResult:
    with tempfile.TemporaryDirectory() as tmp:
        scratch = Path(tmp) / "scratch"
        scratch.mkdir()
        copied = scratch / name
        copied.write_bytes(payload)
        return media_derivatives.generate_media_derivatives(
            copied_media_path=copied,
            job_scratch=scratch,
            resource_profile=resources(),
            runtime=FakeParserRuntime(process),
            original_name=name,
            max_duration_seconds=30,
        )


def resources() -> dict[str, int]:
    return {
        "memory_limit_mib": 256,
        "pids_limit": 32,
        "tmpfs_limit_mib": 64,
        "output_limit_mib": 64,
        "cpu_quota_percent": 50,
    }


def derivative(
    kind: str,
    mime_type: str,
    *,
    width: int | None = None,
    height: int | None = None,
    duration_seconds: float | None = None,
    range_supported: bool = False,
) -> dict[str, object]:
    record: dict[str, object] = {
        "derivative_kind": kind,
        "storage_uri": "scratch://sha256/" + (kind.encode().hex() * 64)[:64],
        "mime_type": mime_type,
        "size_bytes": 1024,
        "range_supported": range_supported,
    }
    if width is not None:
        record["width"] = width
    if height is not None:
        record["height"] = height
    if duration_seconds is not None:
        record["duration_seconds"] = duration_seconds
    return record


def lines(*records: dict[str, object]) -> bytes:
    return b"".join(json.dumps(record).encode("utf-8") + b"\n" for record in records)


if __name__ == "__main__":
    unittest.main()
