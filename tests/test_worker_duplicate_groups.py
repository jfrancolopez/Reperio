from __future__ import annotations

import unittest

from worker import duplicate_groups


class WorkerDuplicateGroupsTests(unittest.TestCase):
    def test_exact_duplicates_preserve_all_members_and_select_canonical_preview(self) -> None:
        digest = "a" * 64
        result = duplicate_groups.build_duplicate_groups(
            (
                candidate("finding_2", digest, 20, ("/b/photo.jpg",), "image"),
                candidate("finding_1", digest, 20, ("/a/photo.jpg",), "image"),
                candidate("finding_3", "b" * 64, 20, ("/c/photo.jpg",), "image"),
            )
        )

        groups = [group for group in result.groups if group.group_kind == "exact-sha256"]
        self.assertEqual(1, len(groups))
        self.assertEqual(
            ("finding_1", "finding_2"), tuple(member.finding_id for member in groups[0].members)
        )
        self.assertEqual("finding_1", groups[0].canonical_finding_id)
        self.assertEqual("/a/photo.jpg", groups[0].canonical_preview_uri)

    def test_perceptual_image_groups_near_resized_cropped_or_rotated_hashes(self) -> None:
        result = duplicate_groups.build_duplicate_groups(
            (
                candidate("base", "1" * 64, 10, ("/base.jpg",), "image", perceptual_hash="f0f0"),
                candidate(
                    "resized", "2" * 64, 9, ("/resized.jpg",), "image", perceptual_hash="f0f1"
                ),
                candidate(
                    "cropped", "3" * 64, 8, ("/cropped.jpg",), "photo", perceptual_hash="f1f1"
                ),
                candidate("far", "4" * 64, 10, ("/far.jpg",), "image", perceptual_hash="0000"),
            ),
            config=duplicate_groups.DuplicateGroupingConfig(image_hamming_threshold=4),
        )

        groups = [group for group in result.groups if group.group_kind == "image-perceptual"]
        self.assertEqual(1, len(groups))
        self.assertEqual(
            ("base", "cropped", "resized"), tuple(member.finding_id for member in groups[0].members)
        )
        self.assertTrue(all(member.distance is not None for member in groups[0].members))
        self.assertEqual(4, groups[0].threshold)

    def test_video_keyframe_similarity_uses_visible_configurable_thresholds(self) -> None:
        result = duplicate_groups.build_duplicate_groups(
            (
                candidate(
                    "clip_a",
                    "a" * 64,
                    30,
                    ("/a.mp4",),
                    "video",
                    video_hashes=("ffff", "0000", "aaaa"),
                ),
                candidate(
                    "clip_b",
                    "b" * 64,
                    31,
                    ("/b.mp4",),
                    "video",
                    video_hashes=("fffe", "0001", "1234"),
                ),
                candidate(
                    "clip_far",
                    "c" * 64,
                    32,
                    ("/far.mp4",),
                    "video",
                    video_hashes=("1111", "2222", "3333"),
                ),
            ),
            config=duplicate_groups.DuplicateGroupingConfig(
                video_frame_hamming_threshold=2, video_min_matching_frames=2
            ),
        )

        groups = [group for group in result.groups if group.group_kind == "video-keyframe"]
        self.assertEqual(1, len(groups))
        self.assertEqual(
            ("clip_a", "clip_b"), tuple(member.finding_id for member in groups[0].members)
        )
        self.assertEqual(2, groups[0].threshold)
        self.assertIn("video_min_matching_frames:2", groups[0].warnings)

    def test_corrupt_media_hashes_are_labeled_without_blocking_valid_groups(self) -> None:
        result = duplicate_groups.build_duplicate_groups(
            (
                candidate(
                    "bad_image", "a" * 64, 10, ("/bad.jpg",), "image", perceptual_hash="not-hex"
                ),
                candidate(
                    "bad_video", "b" * 64, 10, ("/bad.mp4",), "video", video_hashes=("0000", "bad")
                ),
                candidate("one", "c" * 64, 10, ("/one.jpg",), "image", perceptual_hash="ffff"),
                candidate("two", "d" * 64, 11, ("/two.jpg",), "image", perceptual_hash="fffe"),
            ),
            config=duplicate_groups.DuplicateGroupingConfig(image_hamming_threshold=1),
        )

        self.assertIn("invalid_perceptual_hash:bad_image", result.warnings)
        self.assertIn("invalid_video_keyframe_hash:bad_video", result.warnings)
        self.assertEqual(
            1, len([group for group in result.groups if group.group_kind == "image-perceptual"])
        )

    def test_hash_collision_size_mismatch_seam_does_not_group_exact_duplicates(self) -> None:
        digest = "e" * 64
        result = duplicate_groups.build_duplicate_groups(
            (
                candidate("left", digest, 10, ("/left.bin",), "other"),
                candidate("right", digest, 11, ("/right.bin",), "other"),
            )
        )

        self.assertEqual((), result.groups)
        self.assertIn(f"sha256_size_mismatch:{digest}", result.warnings)


def candidate(
    finding_id: str,
    digest: str,
    size: int,
    paths: tuple[str, ...],
    media_kind: str,
    *,
    perceptual_hash: str | None = None,
    video_hashes: tuple[str, ...] = (),
) -> duplicate_groups.DuplicateCandidate:
    return duplicate_groups.DuplicateCandidate(
        finding_id=finding_id,
        content_sha256=digest,
        size_bytes=size,
        source_paths=paths,
        media_kind=media_kind,
        preview_uri=paths[0] if paths else None,
        perceptual_hash=perceptual_hash,
        video_keyframe_hashes=video_hashes,
        content_id=f"content_{finding_id}",
    )


if __name__ == "__main__":
    unittest.main()
