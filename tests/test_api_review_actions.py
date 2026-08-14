from __future__ import annotations

import asyncio
import json
import tempfile
import unittest
from pathlib import Path
from typing import Any

from migrations import runner
from shared import catalog_schema
from tests.test_api_findings import HASH, NOW
from tests.test_api_service import asgi_request

try:
    from api.app import create_app
except ModuleNotFoundError as error:
    raise unittest.SkipTest("FastAPI runtime dependencies are not installed") from error


class ApiReviewActionTests(unittest.TestCase):
    def test_bulk_dismiss_restore_and_undo_preserve_rows(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            app = self._app(root)
            self._seed(root, ["finding_a", "finding_b"])

            dismissed = self._post(
                app,
                "/api/v1/findings/review/dismiss",
                {"finding_ids": ["finding_a", "finding_b"], "actor": "tester"},
            )
            action_id = dismissed.json["review_action_id"]
            undo = self._post(app, f"/api/v1/review-actions/{action_id}/undo", {"actor": "tester"})

            statuses = self._statuses(root)
            count = self._count(root, "findings")

        self.assertEqual(2, count)
        self.assertEqual(["finding_a", "finding_b"], dismissed.json["changed_ids"])
        self.assertEqual(["finding_a", "finding_b"], undo.json["restored_ids"])
        self.assertEqual({"finding_a": "new", "finding_b": "new"}, statuses)

    def test_saved_query_snapshot_does_not_affect_later_findings(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            app = self._app(root)
            self._seed(root, ["finding_doc"])

            dismissed = self._post(
                app,
                "/api/v1/findings/review/dismiss",
                {"saved_query": {"finding_type": "document", "include_system_noise": True}},
            )
            self._insert_finding(root, "finding_later", finding_type="document")
            undo = self._post(
                app, f"/api/v1/review-actions/{dismissed.json['review_action_id']}/undo", {}
            )

            statuses = self._statuses(root)

        self.assertEqual(["finding_doc"], dismissed.json["changed_ids"])
        self.assertEqual(["finding_doc"], undo.json["restored_ids"])
        self.assertEqual("new", statuses["finding_doc"])
        self.assertEqual("new", statuses["finding_later"])

    def test_partial_overlap_and_repeated_undo_are_idempotent(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            app = self._app(root)
            self._seed(root, ["finding_a", "finding_b"])
            first = self._post(
                app, "/api/v1/findings/review/dismiss", {"finding_ids": ["finding_a"]}
            )
            second = self._post(
                app,
                "/api/v1/findings/review/dismiss",
                {"finding_ids": ["finding_a", "finding_b"]},
            )
            undo_second = self._post(
                app, f"/api/v1/review-actions/{second.json['review_action_id']}/undo", {}
            )
            undo_second_again = self._post(
                app, f"/api/v1/review-actions/{second.json['review_action_id']}/undo", {}
            )
            undo_first = self._post(
                app, f"/api/v1/review-actions/{first.json['review_action_id']}/undo", {}
            )

            statuses = self._statuses(root)

        self.assertEqual(["finding_b"], second.json["changed_ids"])
        self.assertEqual(["finding_a", "finding_b"], undo_second.json["restored_ids"])
        self.assertTrue(undo_second_again.json["already_undone"])
        self.assertEqual(["finding_a"], undo_first.json["restored_ids"])
        self.assertEqual({"finding_a": "new", "finding_b": "new"}, statuses)

    def test_permission_disabled_api_rejects_review_changes(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            app = self._app(root)
            app.state.review_actions_enabled = False
            self._seed(root, ["finding_a"])

            response = self._post(
                app, "/api/v1/findings/review/dismiss", {"finding_ids": ["finding_a"]}
            )

        self.assertEqual(403, response.status_code)

    def _app(self, root: Path) -> Any:
        db_path = root / "catalog.sqlite3"
        runner.migrate_catalog(db_path)
        return create_app(catalog_path=db_path)

    def _seed(self, root: Path, finding_ids: list[str]) -> None:
        connection = catalog_schema.connect_catalog(root / "catalog.sqlite3")
        try:
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
            for finding_id in finding_ids:
                self._insert_finding(root, finding_id, connection=connection)
        finally:
            connection.close()

    def _insert_finding(
        self,
        root: Path,
        finding_id: str,
        *,
        finding_type: str = "document",
        connection: Any | None = None,
    ) -> None:
        owned = connection is None
        db = connection or catalog_schema.connect_catalog(root / "catalog.sqlite3")
        try:
            db.execute(
                """
                INSERT INTO findings
                (finding_id, case_id, finding_type, severity, title, summary, status, confidence, created_at)
                VALUES (?, 'case_1', ?, 'medium', ?, 'summary', 'new', 0.9, ?)
                """,
                (finding_id, finding_type, finding_id, NOW),
            )
        finally:
            if owned:
                db.close()

    def _post(self, app: Any, path: str, payload: dict[str, Any]) -> Any:
        return asyncio.run(
            asgi_request(
                app,
                "POST",
                path,
                body=json.dumps(payload).encode(),
                headers={"content-type": "application/json"},
            )
        )

    def _statuses(self, root: Path) -> dict[str, str]:
        connection = catalog_schema.connect_catalog(root / "catalog.sqlite3")
        try:
            return dict(connection.execute("SELECT finding_id, status FROM findings"))
        finally:
            connection.close()

    def _count(self, root: Path, table: str) -> int:
        connection = catalog_schema.connect_catalog(root / "catalog.sqlite3")
        try:
            return int(connection.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0])
        finally:
            connection.close()


if __name__ == "__main__":
    unittest.main()
