#!/usr/bin/env python3

from __future__ import annotations

import unittest
from typing import Any

from worker.windows_artifacts import (
    ARTIFACT_KINDS,
    WINDOWS_ARTIFACTS_VERSION,
    WindowsArtifactsError,
    classify,
    cross_parser_compare,
    parse_artifact,
    related_file_links,
)


def fixture(kind: str, *, user: str = "alice", lines: list[str] | None = None) -> dict[str, Any]:
    default_lines = [
        f"entry_id=e-{kind}-1|user={user}|target_path=C:\\\\Users\\\\{user}\\\\Documents\\\\report.pdf|timestamp=2026-08-19T10:00:00Z",
        f"entry_id=e-{kind}-2|user={user}|target_path=C:\\\\Users\\\\{user}\\\\Downloads\\\\setup.exe|timestamp=2026-08-19T09:00:00Z",
    ]
    body = "\n".join(lines if lines is not None else default_lines)
    return {"raw_source": f"sample/{kind}.bin", "data": body}


class ParseTests(unittest.TestCase):
    def test_every_advertised_artifact(self) -> None:
        for kind in ARTIFACT_KINDS:
            artifact = parse_artifact(kind, fixture(kind))
            self.assertFalse(artifact.corrupt, kind)
            self.assertEqual(2, len(artifact.entries), kind)
            self.assertEqual(f"{kind}-parser-v1", artifact.parser_version)
            self.assertEqual(f"{kind}_parser", artifact.parser)

    def test_multi_user_fixtures(self) -> None:
        artifact = parse_artifact("lnk", fixture("lnk", user="bob"))
        self.assertEqual("bob", artifact.entries[0]["user"])

    def test_raw_source_retained(self) -> None:
        artifact = parse_artifact("registry", fixture("registry"))
        self.assertEqual("sample/registry.bin", artifact.raw_source)

    def test_missing_source_is_corrupt(self) -> None:
        artifact = parse_artifact("lnk", {"raw_source": "x", "data": None})
        self.assertTrue(artifact.corrupt)
        self.assertIn("missing_source", artifact.warnings)
        self.assertEqual((), artifact.entries)

    def test_malformed_source_is_corrupt(self) -> None:
        artifact = parse_artifact("lnk", {"raw_source": "x", "data": 42})
        self.assertTrue(artifact.corrupt)

    def test_unknown_kind_rejected(self) -> None:
        with self.assertRaisesRegex(WindowsArtifactsError, "unknown"):
            parse_artifact("mystery", {"data": "x"})


class ClassificationTests(unittest.TestCase):
    def test_never_claims_human_action(self) -> None:
        artifact = parse_artifact("timeline", fixture("timeline"))
        labels = classify(artifact)
        self.assertFalse(labels[0]["timestamp_is_human_proof"])
        self.assertIn("not proven human action", labels[0]["timestamp_caveat"])

    def test_classification_categories(self) -> None:
        self.assertEqual(
            "recent_documents",
            classify(parse_artifact("recent_documents", fixture("recent_documents")))[0][
                "category"
            ],
        )
        self.assertEqual(
            "program_execution",
            classify(parse_artifact("prefetch", fixture("prefetch")))[0]["category"],
        )


class LinkTests(unittest.TestCase):
    def test_related_recycle_evidence_linked(self) -> None:
        artifact = parse_artifact("lnk", fixture("lnk"))
        evidence = [
            {"entry_id": "recycle-9", "original_path": "C:/Users/alice/Documents/report.pdf"}
        ]
        links = related_file_links(artifact, evidence)
        self.assertEqual(1, len(links))
        self.assertEqual("recycle-9", links[0]["recycle_entry_id"])

    def test_no_match_when_names_differ(self) -> None:
        artifact = parse_artifact("lnk", fixture("lnk"))
        evidence = [{"entry_id": "recycle-9", "original_path": "C:/other/thing.bin"}]
        self.assertEqual([], related_file_links(artifact, evidence))


class CompareTests(unittest.TestCase):
    def test_cross_parser_versions(self) -> None:
        first = parse_artifact("lnk", fixture("lnk"))
        second = parse_artifact("lnk", fixture("lnk", lines=["entry_id=other|target_path=X"]))
        summary = cross_parser_compare([first, second], "lnk")
        self.assertEqual(3, summary["total_entries"])
        self.assertEqual(2, summary["distinct_sources"])

    def test_version_constant(self) -> None:
        self.assertEqual("windows-artifacts-v1", WINDOWS_ARTIFACTS_VERSION)


if __name__ == "__main__":
    unittest.main()
