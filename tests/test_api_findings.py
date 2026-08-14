from __future__ import annotations

import asyncio
import json
import tempfile
import unittest
from pathlib import Path
from typing import Any

from migrations import runner
from shared import catalog_schema
from tests.test_api_service import asgi_request

try:
    from api.app import create_app
except ModuleNotFoundError as error:
    raise unittest.SkipTest("FastAPI runtime dependencies are not installed") from error

NOW = "2026-08-11T14:40:00Z"
HASH = "c" * 64


class ApiFindingQueryTests(unittest.TestCase):
    def test_empty_query_returns_no_findings_and_facets(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            app = self._app(Path(tmp))

            findings = asyncio.run(asgi_request(app, "GET", "/api/v1/findings"))
            facets = asyncio.run(asgi_request(app, "GET", "/api/v1/findings/facets"))

        self.assertEqual(200, findings.status_code)
        self.assertEqual([], findings.json["findings"])
        self.assertIsNone(findings.json["next_cursor"])
        self.assertEqual([], facets.json["facets"]["finding_type"])

    def test_cursor_pagination_does_not_skip_or_duplicate_with_concurrent_insert(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            app = self._app(root)
            connection = catalog_schema.connect_catalog(root / "catalog.sqlite3")
            try:
                self._seed_case(connection)
                for index in range(1200):
                    self._insert_finding(connection, f"finding_{index:04d}", created_at=NOW)
            finally:
                connection.close()

            first = asyncio.run(asgi_request(app, "GET", "/api/v1/findings?limit=500"))
            connection = catalog_schema.connect_catalog(root / "catalog.sqlite3")
            try:
                self._insert_finding(connection, "finding_0500a", created_at=NOW)
            finally:
                connection.close()
            second = asyncio.run(
                asgi_request(
                    app, "GET", f"/api/v1/findings?limit=500&cursor={first.json['next_cursor']}"
                )
            )

        first_ids = [finding["finding_id"] for finding in first.json["findings"]]
        second_ids = [finding["finding_id"] for finding in second.json["findings"]]
        self.assertEqual(500, len(first_ids))
        self.assertEqual(500, len(second_ids))
        self.assertFalse(set(first_ids) & set(second_ids))
        self.assertIn("finding_0500a", second_ids)

    def test_filters_facets_unicode_search_detail_and_system_noise_toggle(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            app = self._app(root)
            connection = catalog_schema.connect_catalog(root / "catalog.sqlite3")
            try:
                self._seed_case(connection)
                self._insert_finding(
                    connection,
                    "finding_doc",
                    finding_type="document",
                    severity="high",
                    title="Résumé été",
                )
                self._insert_finding(
                    connection,
                    "finding_noise",
                    finding_type="other",
                    severity="info",
                    title="system cache",
                    system_noise=True,
                )
            finally:
                connection.close()

            filtered = asyncio.run(
                asgi_request(app, "GET", "/api/v1/findings?finding_type=document&q=%C3%A9t%C3%A9")
            )
            hidden_noise = asyncio.run(asgi_request(app, "GET", "/api/v1/findings"))
            visible_noise = asyncio.run(
                asgi_request(app, "GET", "/api/v1/findings?include_system_noise=true")
            )
            detail = asyncio.run(asgi_request(app, "GET", "/api/v1/findings/finding_doc"))
            facets = asyncio.run(asgi_request(app, "GET", "/api/v1/findings/facets?case_id=case_1"))

        self.assertEqual(
            ["finding_doc"], [item["finding_id"] for item in filtered.json["findings"]]
        )
        self.assertEqual(
            ["finding_doc"], [item["finding_id"] for item in hidden_noise.json["findings"]]
        )
        self.assertEqual(
            ["finding_doc", "finding_noise"],
            [item["finding_id"] for item in visible_noise.json["findings"]],
        )
        self.assertEqual("finding_doc", detail.json["finding"]["finding_id"])
        self.assertEqual("metadata", detail.json["evidence"][0]["evidence_kind"])
        self.assertEqual(
            {"document": 1, "other": 1},
            {row["value"]: row["count"] for row in facets.json["facets"]["finding_type"]},
        )

    def test_invalid_cursor_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            app = self._app(Path(tmp))

            response = asyncio.run(asgi_request(app, "GET", "/api/v1/findings?cursor=not-valid"))

        self.assertEqual(400, response.status_code)

    def _app(self, root: Path) -> Any:
        db_path = root / "catalog.sqlite3"
        runner.migrate_catalog(db_path)
        return create_app(catalog_path=db_path)

    def _seed_case(self, connection: Any) -> None:
        connection.execute(
            """
            INSERT OR IGNORE INTO sources
            (source_id, stable_identity, media_kind, size_bytes, sector_size,
             fingerprint_sha256, status, created_at, updated_at)
            VALUES ('source_1', 'stable-source-1', 'block', 1024, 512, ?, 'approved', ?, ?)
            """,
            (HASH, NOW, NOW),
        )
        connection.execute(
            """
            INSERT OR IGNORE INTO scan_cases
            (case_id, source_id, state, policy_json, created_at, updated_at)
            VALUES ('case_1', 'source_1', 'running', '{}', ?, ?)
            """,
            (NOW, NOW),
        )

    def _insert_finding(
        self,
        connection: Any,
        finding_id: str,
        *,
        finding_type: str = "document",
        severity: str = "medium",
        title: str = "title",
        created_at: str = NOW,
        system_noise: bool = False,
    ) -> None:
        connection.execute(
            """
            INSERT INTO findings
            (finding_id, case_id, finding_type, severity, title, summary, status, confidence, created_at)
            VALUES (?, 'case_1', ?, ?, ?, 'summary', 'new', 0.9, ?)
            """,
            (finding_id, finding_type, severity, title, created_at),
        )
        connection.execute(
            """
            INSERT INTO evidence
            (evidence_id, finding_id, evidence_kind, data_json, created_at)
            VALUES (?, ?, 'metadata', ?, ?)
            """,
            (
                f"evidence_{finding_id}",
                finding_id,
                json.dumps({"system_noise": system_noise}),
                created_at,
            ),
        )


if __name__ == "__main__":
    unittest.main()
