from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from worker import media_metadata, parser_sandbox


class FakeParserRuntime:
    def __init__(self, result: parser_sandbox.ParserProcessResult) -> None:
        self.result = result
        self.calls: list[tuple[tuple[str, ...], int]] = []

    def run(
        self, command: tuple[str, ...], timeout_seconds: int
    ) -> parser_sandbox.ParserProcessResult:
        self.calls.append((command, timeout_seconds))
        return self.result


class WorkerMediaMetadataTests(unittest.TestCase):
    def test_image_metadata_uses_exiftool_profile_and_normalizes_gps(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            scratch, copied = copied_media(Path(tmp), "photo.jpg", b"\xff\xd8\xff\xe0data")
            runtime = FakeParserRuntime(
                parser_sandbox.ParserProcessResult(
                    0,
                    line(
                        {
                            "dimensions": {"width": 4000, "height": 3000},
                            "creation_time": "2026-01-02T03:04:05Z",
                            "device": {"make": "ExampleCam", "model": "One"},
                            "location": {"latitude": 12.5, "longitude": -45.25},
                            "editor": "safe metadata value",
                            "raw_metadata": {"GPSLatitude": "12.5"},
                        }
                    ),
                )
            )

            result = media_metadata.extract_media_metadata(
                copied_media_path=copied,
                job_scratch=scratch,
                resource_profile=resources(),
                runtime=runtime,
            )

        self.assertEqual("complete", result.status)
        self.assertEqual("image", result.media_kind)
        self.assertEqual({"width": 4000, "height": 3000}, result.dimensions)
        self.assertEqual({"latitude": 12.5, "longitude": -45.25}, result.location)
        self.assertIn("exiftool-json", runtime.calls[0][0])
        self.assertIn("--network=none", runtime.calls[0][0])

    def test_heic_tiff_raw_mp4_mov_and_audio_signatures_route_to_profiles(self) -> None:
        cases = (
            ("image.heic", b"\0\0\0\x18ftypheic", "image", "exiftool-json"),
            ("image.tif", b"II*\x00data", "image", "exiftool-json"),
            ("image.raw", b"RAW\x00data", "image", "exiftool-json"),
            ("movie.mp4", b"\0\0\0\x18ftypisom", "video", "ffprobe-json"),
            ("movie.mov", b"\0\0\0\x18ftypqt  ", "video", "ffprobe-json"),
            ("audio.mp3", b"ID3data", "audio", "ffprobe-json"),
            ("audio.wav", b"RIFF\0\0\0\0WAVEfmt ", "audio", "ffprobe-json"),
        )
        for name, payload, media_kind, profile in cases:
            with self.subTest(name=name), tempfile.TemporaryDirectory() as tmp:
                scratch, copied = copied_media(Path(tmp), name, payload)
                runtime = FakeParserRuntime(
                    parser_sandbox.ParserProcessResult(0, line({"status": "complete"}))
                )

                result = media_metadata.extract_media_metadata(
                    copied_media_path=copied,
                    job_scratch=scratch,
                    resource_profile=resources(),
                    runtime=runtime,
                    original_name=name,
                )

            self.assertEqual("complete", result.status)
            self.assertEqual(media_kind, result.media_kind)
            self.assertIn(profile, runtime.calls[0][0])

    def test_video_audio_fields_and_raw_metadata_are_bounded(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            scratch, copied = copied_media(Path(tmp), "movie.mp4", b"\0\0\0\x18ftypisom")
            runtime = FakeParserRuntime(
                parser_sandbox.ParserProcessResult(
                    0,
                    line(
                        {
                            "duration_seconds": 12.5,
                            "codecs": ["h264", "aac"],
                            "raw_metadata": {
                                **{f"key-{index}": "value" for index in range(300)},
                                "long-value": "x" * 5000,
                            },
                        }
                    ),
                )
            )

            result = media_metadata.extract_media_metadata(
                copied_media_path=copied,
                job_scratch=scratch,
                resource_profile=resources(),
                runtime=runtime,
            )

        self.assertEqual("video", result.media_kind)
        self.assertEqual(12.5, result.duration_seconds)
        self.assertEqual(("h264", "aac"), result.codecs)
        self.assertEqual(256, len(result.raw_metadata))
        self.assertLessEqual(max(len(value) for value in result.raw_metadata.values()), 4096)

    def test_timeout_malformed_misleading_extension_source_path_and_unknown_are_labeled(
        self,
    ) -> None:
        timeout = parse_payload(
            b"\xff\xd8\xff\xe0data", parser_sandbox.ParserProcessResult(124, b"", timed_out=True)
        )
        malformed = parse_payload(
            b"\0\0\0\x18ftypisom",
            parser_sandbox.ParserProcessResult(
                0, line({"malformed": True, "warnings": ["bad_atom"]})
            ),
        )
        misleading = parse_named(b"MZpayload", "photo.jpg")
        unknown = parse_named(b"???", "unknown.bin")

        self.assertEqual("timeout", timeout.status)
        self.assertIn("exiftool-json_parser_timeout", timeout.warnings)
        self.assertEqual("complete", malformed.status)
        self.assertIn("malformed_media", malformed.warnings)
        self.assertEqual("skipped", misleading.status)
        self.assertIn("parser_unsafe_signature:pe-executable", misleading.warnings)
        self.assertEqual("skipped", unknown.status)
        self.assertIn("unsupported_mime:application/octet-stream", unknown.warnings)

        with (
            tempfile.TemporaryDirectory() as scratch_tmp,
            tempfile.TemporaryDirectory() as source_tmp,
        ):
            outside = Path(source_tmp) / "photo.jpg"
            outside.write_bytes(b"\xff\xd8\xff\xe0data")
            with self.assertRaises(media_metadata.MediaMetadataError) as captured:
                media_metadata.extract_media_metadata(
                    copied_media_path=outside,
                    job_scratch=Path(scratch_tmp),
                    resource_profile=resources(),
                    runtime=FakeParserRuntime(parser_sandbox.ParserProcessResult(0, b"")),
                )

        self.assertEqual("input_not_copied", captured.exception.code)


def parse_payload(
    payload: bytes, process: parser_sandbox.ParserProcessResult
) -> media_metadata.MediaMetadataResult:
    with tempfile.TemporaryDirectory() as tmp:
        scratch, copied = copied_media(Path(tmp), "input", payload)
        return media_metadata.extract_media_metadata(
            copied_media_path=copied,
            job_scratch=scratch,
            resource_profile=resources(),
            runtime=FakeParserRuntime(process),
        )


def parse_named(payload: bytes, name: str) -> media_metadata.MediaMetadataResult:
    with tempfile.TemporaryDirectory() as tmp:
        scratch, copied = copied_media(Path(tmp), name, payload)
        return media_metadata.extract_media_metadata(
            copied_media_path=copied,
            job_scratch=scratch,
            resource_profile=resources(),
            runtime=FakeParserRuntime(parser_sandbox.ParserProcessResult(0, line({}))),
            original_name=name,
        )


def copied_media(root: Path, name: str, payload: bytes) -> tuple[Path, Path]:
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
