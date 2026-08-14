from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from worker import image_thumbnails, parser_sandbox


class FakeParserRuntime:
    def __init__(self, result: parser_sandbox.ParserProcessResult) -> None:
        self.result = result
        self.calls: list[tuple[tuple[str, ...], int]] = []

    def run(
        self, command: tuple[str, ...], timeout_seconds: int
    ) -> parser_sandbox.ParserProcessResult:
        self.calls.append((command, timeout_seconds))
        return self.result


class WorkerImageThumbnailTests(unittest.TestCase):
    def test_common_raw_heic_and_animated_images_route_to_libvips_profile(self) -> None:
        cases = (
            ("photo.jpg", b"\xff\xd8\xff\xe0data"),
            ("raw.raw", b"RAW\x00data"),
            ("phone.heic", b"\0\0\0\x18ftypheic"),
            ("animated.gif", b"GIF89adata"),
        )
        for name, payload in cases:
            with self.subTest(name=name), tempfile.TemporaryDirectory() as tmp:
                scratch, copied = copied_image(Path(tmp), name, payload)
                runtime = FakeParserRuntime(
                    parser_sandbox.ParserProcessResult(0, lines(thumb("embedded", 128, 96)))
                )

                result = image_thumbnails.generate_image_thumbnails(
                    copied_image_path=copied,
                    job_scratch=scratch,
                    content_sha256="a" * 64,
                    resource_profile=resources(),
                    runtime=runtime,
                    original_name=name,
                    requested_tiers=("embedded",),
                )

            self.assertEqual("complete", result.status)
            self.assertEqual("embedded", result.derivatives[0].tier)
            self.assertIn("libvips-thumbnail-json", runtime.calls[0][0])
            self.assertIn("--network=none", runtime.calls[0][0])

    def test_rotated_cmyk_and_cache_hit_keep_safe_derivative_metadata(self) -> None:
        cached = image_thumbnails.ThumbnailDerivative(
            tier="small",
            storage_uri="scratch://sha256/" + "b" * 64,
            mime_type="image/webp",
            width=320,
            height=240,
            size_bytes=1000,
            cache_key=image_thumbnails._cache_key("a" * 64, "small"),
            warnings=("orientation_applied", "cmyk_converted"),
        )
        with tempfile.TemporaryDirectory() as tmp:
            scratch, copied = copied_image(Path(tmp), "photo.jpg", b"\xff\xd8\xff\xe0data")
            runtime = FakeParserRuntime(parser_sandbox.ParserProcessResult(0, b""))

            result = image_thumbnails.generate_image_thumbnails(
                copied_image_path=copied,
                job_scratch=scratch,
                content_sha256="a" * 64,
                resource_profile=resources(),
                runtime=runtime,
                requested_tiers=("small",),
                cached_derivatives={cached.cache_key: cached},
            )

        self.assertEqual("cache-hit", result.status)
        self.assertEqual((cached,), result.derivatives)
        self.assertEqual([], runtime.calls)

    def test_huge_corrupt_unsafe_output_and_resource_limit_are_labeled(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            scratch, copied = copied_image(Path(tmp), "huge.jpg", b"\xff\xd8\xff\xe0data")
            runtime = FakeParserRuntime(
                parser_sandbox.ParserProcessResult(
                    0,
                    lines(
                        thumb("embedded", 9999, 100),
                        {**thumb("small", 100, 100), "mime_type": "image/svg+xml"},
                        {**thumb("large", 100, 100), "size_bytes": 2 * 1024 * 1024},
                    ),
                )
            )

            result = image_thumbnails.generate_image_thumbnails(
                copied_image_path=copied,
                job_scratch=scratch,
                content_sha256="a" * 64,
                resource_profile={**resources(), "output_limit_mib": 1},
                runtime=runtime,
            )

        self.assertEqual("failed", result.status)
        self.assertIn("thumbnail_dimension_limit:embedded", result.warnings)
        self.assertIn("unsafe_thumbnail_mime:small", result.warnings)
        self.assertIn("thumbnail_output_limit:large", result.warnings)

    def test_source_path_timeout_and_misleading_extension_do_not_generate_derivatives(self) -> None:
        timeout = parse_payload(
            b"\xff\xd8\xff\xe0data", parser_sandbox.ParserProcessResult(124, b"", timed_out=True)
        )
        misleading = parse_named(b"MZpayload", "photo.jpg")

        self.assertEqual("timeout", timeout.status)
        self.assertIn("libvips-thumbnail-json_parser_timeout", timeout.warnings)
        self.assertEqual("skipped", misleading.status)
        self.assertIn("parser_unsafe_signature:pe-executable", misleading.warnings)

        with (
            tempfile.TemporaryDirectory() as scratch_tmp,
            tempfile.TemporaryDirectory() as source_tmp,
        ):
            outside = Path(source_tmp) / "photo.jpg"
            outside.write_bytes(b"\xff\xd8\xff\xe0data")
            with self.assertRaises(image_thumbnails.ThumbnailError) as captured:
                image_thumbnails.generate_image_thumbnails(
                    copied_image_path=outside,
                    job_scratch=Path(scratch_tmp),
                    content_sha256="a" * 64,
                    resource_profile=resources(),
                    runtime=FakeParserRuntime(parser_sandbox.ParserProcessResult(0, b"")),
                )
        self.assertEqual("input_not_copied", captured.exception.code)


def parse_payload(
    payload: bytes, process: parser_sandbox.ParserProcessResult
) -> image_thumbnails.ThumbnailResult:
    with tempfile.TemporaryDirectory() as tmp:
        scratch, copied = copied_image(Path(tmp), "input.jpg", payload)
        return image_thumbnails.generate_image_thumbnails(
            copied_image_path=copied,
            job_scratch=scratch,
            content_sha256="a" * 64,
            resource_profile=resources(),
            runtime=FakeParserRuntime(process),
        )


def parse_named(payload: bytes, name: str) -> image_thumbnails.ThumbnailResult:
    with tempfile.TemporaryDirectory() as tmp:
        scratch, copied = copied_image(Path(tmp), name, payload)
        return image_thumbnails.generate_image_thumbnails(
            copied_image_path=copied,
            job_scratch=scratch,
            content_sha256="a" * 64,
            resource_profile=resources(),
            runtime=FakeParserRuntime(
                parser_sandbox.ParserProcessResult(0, lines(thumb("embedded", 10, 10)))
            ),
            original_name=name,
        )


def copied_image(root: Path, name: str, payload: bytes) -> tuple[Path, Path]:
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


def thumb(tier: str, width: int, height: int) -> dict[str, object]:
    return {
        "tier": tier,
        "storage_uri": "scratch://sha256/" + hashlib_like(tier),
        "mime_type": "image/webp",
        "width": width,
        "height": height,
        "size_bytes": 1000,
    }


def hashlib_like(value: str) -> str:
    return (value.encode("utf-8").hex() * 64)[:64]


def lines(*records: dict[str, object]) -> bytes:
    return b"".join(json.dumps(record).encode("utf-8") + b"\n" for record in records)


if __name__ == "__main__":
    unittest.main()
