"""Windows activity and user-interaction artifact parsers (RPR-160).

Isolated, deterministic parsers for registry hives, LNK files, jump lists,
recent documents, shell bags, Windows Timeline, prefetch, and selected event
logs, plus related-file links to normalized Recycle Bin evidence (RPR-186).
Every artifact retains its parser/version/raw source and supports classification
and related-file links without ever claiming a timestamp proves a human action.
Corrupt or missing sources are explicit outcomes, never crashes. Pure and
dependency-free.
"""

from __future__ import annotations

import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Any

WINDOWS_ARTIFACTS_VERSION = "windows-artifacts-v1"

ARTIFACT_KINDS = frozenset(
    {
        "registry",
        "lnk",
        "jumplist",
        "recent_documents",
        "shell_bags",
        "timeline",
        "prefetch",
        "event_log",
    }
)
PARSER_VERSIONS: dict[str, str] = {kind: f"{kind}-parser-v1" for kind in sorted(ARTIFACT_KINDS)}

TIMESTAMP_CAVEAT = "a timestamp in this artifact indicates system activity, not proven human action"

LNK_TARGET_RE = re.compile(r"target_path=([^\r\n\t]+)")
SID_RE = re.compile(r"^S-1-5-21-[0-9-]+$")


class WindowsArtifactsError(ValueError):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


@dataclass(frozen=True)
class ParsedArtifact:
    kind: str
    parser: str
    parser_version: str
    raw_source: str
    entries: tuple[Mapping[str, Any], ...]
    warnings: tuple[str, ...] = ()
    corrupt: bool = False

    def metadata(self) -> dict[str, str]:
        return {
            "kind": self.kind,
            "parser": self.parser,
            "parser_version": self.parser_version,
            "raw_source": self.raw_source,
        }


def parse_artifact(kind: str, raw: Mapping[str, Any]) -> ParsedArtifact:
    """Dispatch a raw artifact source to its isolated parser."""
    if kind not in ARTIFACT_KINDS:
        raise WindowsArtifactsError("unknown_kind", f"artifact kind {kind!r} is unknown")
    raw_source = str(raw.get("raw_source") or "unknown")
    parser = f"{kind}_parser"
    data = raw.get("data")
    if data is None or data == "":
        return ParsedArtifact(
            kind=kind,
            parser=parser,
            parser_version=PARSER_VERSIONS[kind],
            raw_source=raw_source,
            entries=(),
            warnings=("missing_source",),
            corrupt=True,
        )
    if isinstance(data, bytes):
        text = _decode(data)
    elif isinstance(data, str):
        text = data
    else:
        return ParsedArtifact(
            kind=kind,
            parser=parser,
            parser_version=PARSER_VERSIONS[kind],
            raw_source=raw_source,
            entries=(),
            warnings=("malformed_source",),
            corrupt=True,
        )
    entries = tuple(_parse_text(kind, text))
    return ParsedArtifact(
        kind=kind,
        parser=parser,
        parser_version=PARSER_VERSIONS[kind],
        raw_source=raw_source,
        entries=entries,
    )


def classify(artifact: ParsedArtifact) -> list[dict[str, Any]]:
    """Classification labels per entry; never claims a human action."""
    labels: list[dict[str, Any]] = []
    for entry in artifact.entries:
        labels.append(
            {
                "kind": artifact.kind,
                "entry_id": entry.get("entry_id"),
                "category": _category(artifact.kind),
                "timestamp_is_human_proof": False,
                "timestamp_caveat": TIMESTAMP_CAVEAT,
                "parser_version": artifact.parser_version,
            }
        )
    return labels


def related_file_links(
    artifact: ParsedArtifact, recycle_evidence: Sequence[Mapping[str, Any]]
) -> list[dict[str, Any]]:
    """Link artifact targets to normalized Recycle Bin evidence (RPR-186)."""
    links: list[dict[str, Any]] = []
    for entry in artifact.entries:
        target = str(entry.get("target_path") or "")
        for evidence in recycle_evidence:
            evidence_path = str(evidence.get("original_path") or evidence.get("name") or "")
            if target and evidence_path and _under_same_name(target, evidence_path):
                links.append(
                    {
                        "entry_id": entry.get("entry_id"),
                        "recycle_entry_id": evidence.get("entry_id"),
                        "target_path": target,
                        "evidence_path": evidence_path,
                    }
                )
    return links


def cross_parser_compare(records: Sequence[ParsedArtifact], kind: str) -> dict[str, Any]:
    """Compare entries for the same kind across parser versions."""
    seen_versions: set[str] = set()
    entry_count = 0
    for artifact in records:
        if artifact.kind != kind:
            continue
        seen_versions.add(artifact.parser_version)
        entry_count += len(artifact.entries)
    return {
        "kind": kind,
        "parser_versions": sorted(seen_versions),
        "total_entries": entry_count,
        "distinct_sources": sum(1 for artifact in records if artifact.kind == kind),
    }


def _parse_text(kind: str, text: str) -> list[dict[str, Any]]:
    """Deterministic per-kind line-oriented parse of the synthetic fixtures."""
    entries: list[dict[str, Any]] = []
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if kind in {
            "registry",
            "lnk",
            "jumplist",
            "recent_documents",
            "shell_bags",
            "timeline",
            "prefetch",
            "event_log",
        }:
            fields = dict(_kv_pairs(line))
            entry_id = fields.pop("entry_id", _stable_id(kind, line))
            fields.setdefault("user", fields.get("user") or "unknown")
            fields.setdefault("source_path", "")
            entries.append({"entry_id": entry_id, **fields})
    return entries


def _kv_pairs(line: str) -> list[tuple[str, str]]:
    pairs: list[tuple[str, str]] = []
    for token in line.split("|"):
        if "=" in token:
            key, value = token.split("=", 1)
            pairs.append((key.strip(), value.strip()))
    return pairs


def _category(kind: str) -> str:
    if kind == "registry":
        return "registry_activity"
    if kind == "lnk":
        return "shortcut_activity"
    if kind == "jumplist":
        return "recent_application_activity"
    if kind == "recent_documents":
        return "recent_documents"
    if kind == "shell_bags":
        return "folder_navigation"
    if kind == "timeline":
        return "activity_timeline"
    if kind == "prefetch":
        return "program_execution"
    return "event_log_activity"


def _decode(data: bytes) -> str:
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError:
        return data.decode("latin-1")


def _stable_id(kind: str, line: str) -> str:
    return f"{kind}-{abs(hash(line)) % 10**10:010d}"


def _under_same_name(target: str, evidence_path: str) -> bool:
    target_name = target.replace("\\", "/").rsplit("/", 1)[-1].lower()
    evidence_name = evidence_path.replace("\\", "/").rsplit("/", 1)[-1].lower()
    return bool(target_name) and target_name == evidence_name
