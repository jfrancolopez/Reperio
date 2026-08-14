"""Deterministic duplicate grouping for recovered findings."""

from __future__ import annotations

import hashlib
from collections import defaultdict
from collections.abc import Iterable
from dataclasses import dataclass

PARSER_VERSION = "duplicate-groups-v1"


@dataclass(frozen=True)
class DuplicateGroupingConfig:
    image_hamming_threshold: int = 8
    video_frame_hamming_threshold: int = 10
    video_min_matching_frames: int = 2
    max_video_keyframes: int = 32


@dataclass(frozen=True)
class DuplicateCandidate:
    finding_id: str
    content_sha256: str | None
    size_bytes: int | None
    source_paths: tuple[str, ...]
    media_kind: str
    preview_uri: str | None = None
    perceptual_hash: str | None = None
    video_keyframe_hashes: tuple[str, ...] = ()
    content_id: str | None = None


@dataclass(frozen=True)
class DuplicateMember:
    finding_id: str
    content_id: str | None
    source_paths: tuple[str, ...]
    content_sha256: str | None
    size_bytes: int | None
    distance: int | None = None
    matching_frames: int | None = None


@dataclass(frozen=True)
class DuplicateGroup:
    group_id: str
    group_kind: str
    algorithm: str
    threshold: int | None
    canonical_finding_id: str
    canonical_preview_uri: str | None
    members: tuple[DuplicateMember, ...]
    warnings: tuple[str, ...] = ()
    parser_version: str = PARSER_VERSION


@dataclass(frozen=True)
class DuplicateGroupingResult:
    groups: tuple[DuplicateGroup, ...]
    warnings: tuple[str, ...] = ()
    parser_version: str = PARSER_VERSION


def build_duplicate_groups(
    candidates: Iterable[DuplicateCandidate],
    *,
    config: DuplicateGroupingConfig | None = None,
) -> DuplicateGroupingResult:
    """Group exact and near-duplicate media findings without dropping any member."""

    config = config or DuplicateGroupingConfig()
    items = tuple(sorted(candidates, key=lambda item: item.finding_id))
    warnings: list[str] = []
    groups: list[DuplicateGroup] = []
    groups.extend(_exact_groups(items, warnings))
    groups.extend(_image_groups(items, config, warnings))
    groups.extend(_video_groups(items, config, warnings))
    return DuplicateGroupingResult(
        groups=tuple(sorted(groups, key=lambda group: (group.group_kind, group.group_id))),
        warnings=tuple(dict.fromkeys(warnings)),
    )


def _exact_groups(
    items: tuple[DuplicateCandidate, ...], warnings: list[str]
) -> tuple[DuplicateGroup, ...]:
    by_hash: dict[str, list[DuplicateCandidate]] = defaultdict(list)
    for item in items:
        if item.content_sha256 is None:
            continue
        if not _valid_sha256(item.content_sha256):
            warnings.append(f"invalid_content_sha256:{item.finding_id}")
            continue
        by_hash[item.content_sha256].append(item)

    groups: list[DuplicateGroup] = []
    for digest, members in sorted(by_hash.items()):
        if len(members) < 2:
            continue
        sizes = {member.size_bytes for member in members}
        if len(sizes) != 1:
            warnings.append(f"sha256_size_mismatch:{digest}")
            continue
        groups.append(
            _group(
                "exact-sha256",
                "sha256-size-v1",
                None,
                tuple(_member(member) for member in members),
                (),
            )
        )
    return tuple(groups)


def _image_groups(
    items: tuple[DuplicateCandidate, ...],
    config: DuplicateGroupingConfig,
    warnings: list[str],
) -> tuple[DuplicateGroup, ...]:
    image_items: list[tuple[DuplicateCandidate, int]] = []
    for item in items:
        if item.media_kind not in {"image", "photo"} or item.perceptual_hash is None:
            continue
        value = _hex_hash(item.perceptual_hash)
        if value is None:
            warnings.append(f"invalid_perceptual_hash:{item.finding_id}")
            continue
        image_items.append((item, value))
    clusters = _clusters(
        tuple(candidate for candidate, _value in image_items),
        lambda left, right: _hamming(_lookup(left, image_items), _lookup(right, image_items))
        <= config.image_hamming_threshold,
    )
    return tuple(
        _group(
            "image-perceptual",
            "hex-hamming-v1",
            config.image_hamming_threshold,
            tuple(
                _member(item, distance=_distance_to_canonical(item, cluster, image_items))
                for item in cluster
            ),
            (),
        )
        for cluster in clusters
    )


def _video_groups(
    items: tuple[DuplicateCandidate, ...],
    config: DuplicateGroupingConfig,
    warnings: list[str],
) -> tuple[DuplicateGroup, ...]:
    video_items: list[tuple[DuplicateCandidate, tuple[int, ...]]] = []
    for item in items:
        if item.media_kind != "video" or not item.video_keyframe_hashes:
            continue
        frame_hashes = tuple(
            _hex_hash(value) for value in item.video_keyframe_hashes[: config.max_video_keyframes]
        )
        if any(value is None for value in frame_hashes):
            warnings.append(f"invalid_video_keyframe_hash:{item.finding_id}")
            continue
        video_items.append((item, tuple(value for value in frame_hashes if value is not None)))
    clusters = _clusters(
        tuple(candidate for candidate, _value in video_items),
        lambda left, right: _matching_frames(
            _video_lookup(left, video_items),
            _video_lookup(right, video_items),
            config.video_frame_hamming_threshold,
        )
        >= config.video_min_matching_frames,
    )
    return tuple(
        _group(
            "video-keyframe",
            "bounded-keyframe-hamming-v1",
            config.video_frame_hamming_threshold,
            tuple(
                _member(
                    item,
                    matching_frames=_matching_frames(
                        _video_lookup(item, video_items),
                        _video_lookup(_canonical(cluster), video_items),
                        config.video_frame_hamming_threshold,
                    ),
                )
                for item in cluster
            ),
            (f"video_min_matching_frames:{config.video_min_matching_frames}",),
        )
        for cluster in clusters
    )


def _group(
    group_kind: str,
    algorithm: str,
    threshold: int | None,
    members: tuple[DuplicateMember, ...],
    warnings: tuple[str, ...],
) -> DuplicateGroup:
    canonical = _canonical_member(members)
    raw_id = "\0".join((group_kind, algorithm, *sorted(member.finding_id for member in members)))
    return DuplicateGroup(
        group_id=f"dup-{hashlib.sha256(raw_id.encode('utf-8')).hexdigest()[:24]}",
        group_kind=group_kind,
        algorithm=algorithm,
        threshold=threshold,
        canonical_finding_id=canonical.finding_id,
        canonical_preview_uri=_preview_uri(canonical.finding_id, members),
        members=tuple(sorted(members, key=lambda member: member.finding_id)),
        warnings=warnings,
    )


def _clusters(
    items: tuple[DuplicateCandidate, ...], predicate: object
) -> tuple[tuple[DuplicateCandidate, ...], ...]:
    if len(items) < 2:
        return ()
    parent = {item.finding_id: item.finding_id for item in items}

    def find(value: str) -> str:
        while parent[value] != value:
            parent[value] = parent[parent[value]]
            value = parent[value]
        return value

    def union(left: str, right: str) -> None:
        left_root = find(left)
        right_root = find(right)
        if left_root != right_root:
            parent[max(left_root, right_root)] = min(left_root, right_root)

    for index, left in enumerate(items):
        for right in items[index + 1 :]:
            if predicate(left, right):  # type: ignore[operator]
                union(left.finding_id, right.finding_id)

    grouped: dict[str, list[DuplicateCandidate]] = defaultdict(list)
    for item in items:
        grouped[find(item.finding_id)].append(item)
    return tuple(
        tuple(sorted(group, key=lambda item: item.finding_id))
        for group in grouped.values()
        if len(group) > 1
    )


def _member(
    item: DuplicateCandidate,
    *,
    distance: int | None = None,
    matching_frames: int | None = None,
) -> DuplicateMember:
    return DuplicateMember(
        finding_id=item.finding_id,
        content_id=item.content_id,
        source_paths=tuple(item.source_paths),
        content_sha256=item.content_sha256,
        size_bytes=item.size_bytes,
        distance=distance,
        matching_frames=matching_frames,
    )


def _canonical_member(members: tuple[DuplicateMember, ...]) -> DuplicateMember:
    return sorted(
        members,
        key=lambda member: (
            _preview_uri(member.finding_id, members) is None,
            -(member.size_bytes or 0),
            min(member.source_paths) if member.source_paths else "",
            member.finding_id,
        ),
    )[0]


def _canonical(items: tuple[DuplicateCandidate, ...]) -> DuplicateCandidate:
    return sorted(
        items,
        key=lambda item: (
            item.preview_uri is None,
            -(item.size_bytes or 0),
            min(item.source_paths) if item.source_paths else "",
            item.finding_id,
        ),
    )[0]


def _preview_uri(finding_id: str, members: tuple[DuplicateMember, ...]) -> str | None:
    for member in members:
        if member.finding_id == finding_id and member.source_paths:
            return member.source_paths[0]
    return None


def _lookup(item: DuplicateCandidate, values: list[tuple[DuplicateCandidate, int]]) -> int:
    for candidate, value in values:
        if candidate.finding_id == item.finding_id:
            return value
    raise KeyError(item.finding_id)


def _video_lookup(
    item: DuplicateCandidate, values: list[tuple[DuplicateCandidate, tuple[int, ...]]]
) -> tuple[int, ...]:
    for candidate, value in values:
        if candidate.finding_id == item.finding_id:
            return value
    raise KeyError(item.finding_id)


def _distance_to_canonical(
    item: DuplicateCandidate,
    cluster: tuple[DuplicateCandidate, ...],
    values: list[tuple[DuplicateCandidate, int]],
) -> int:
    return _hamming(_lookup(item, values), _lookup(_canonical(cluster), values))


def _matching_frames(left: tuple[int, ...], right: tuple[int, ...], threshold: int) -> int:
    matches = 0
    used: set[int] = set()
    for left_value in left:
        for index, right_value in enumerate(right):
            if index in used:
                continue
            if _hamming(left_value, right_value) <= threshold:
                used.add(index)
                matches += 1
                break
    return matches


def _hex_hash(value: str) -> int | None:
    stripped = value.strip().lower()
    if (
        not stripped
        or len(stripped) % 2 != 0
        or any(char not in "0123456789abcdef" for char in stripped)
    ):
        return None
    return int(stripped, 16)


def _hamming(left: int, right: int) -> int:
    return (left ^ right).bit_count()


def _valid_sha256(value: str) -> bool:
    return len(value) == 64 and all(char in "0123456789abcdef" for char in value.lower())
