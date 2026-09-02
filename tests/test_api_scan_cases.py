from __future__ import annotations

import asyncio
import json
import tempfile
import time
import unittest
from pathlib import Path
from typing import Any

from migrations import runner
from tests.test_api_service import asgi_request

try:
    from api.app import CONFIRMATION_TOKEN_TTL_SECONDS, HostdUnavailable, create_app
except ModuleNotFoundError as error:
    raise unittest.SkipTest("FastAPI runtime dependencies are not installed") from error


class FakeHostd:
    def __init__(self) -> None:
        self.calls: list[tuple[str, dict[str, Any]]] = []
        self.generation = 7
        self.safe = True
        self.fail = False

    def request(self, method: str, params: dict[str, Any]) -> dict[str, Any]:
        self.calls.append((method, dict(params)))
        if self.fail:
            raise HostdUnavailable("offline")
        if method == "list_devices":
            return {
                "devices": [
                    {
                        "source_id": "source_current",
                        "observed_generation": self.generation,
                        "model": "Synthetic USB",
                    }
                ]
            }
        if method == "inspect_safety":
            if params["observed_generation"] != self.generation:
                raise HostdUnavailable("stale")
            return {
                "safety_inspection_id": "safe_current",
                "safe_for_scan": self.safe,
                "warnings": [] if self.safe else ["unsupported_device"],
            }
        if method == "prepare_read_only":
            return {"readonly_preparation_id": "roprep_current", "prepared": True}
        if method == "launch_scanner":
            return {"scanner_session_id": "scanner_current", "state": "running"}
        if method == "scanner_status":
            return {"scanner_session_id": params["scanner_session_id"], "state": "running"}
        if method == "stop_scanner":
            return {"scanner_session_id": params["scanner_session_id"], "state": "paused"}
        if method == "reconnect":
            if params["observed_generation"] != self.generation:
                raise HostdUnavailable("stale")
            return {"scanner_session_id": "scanner_current", "state": "running"}
        raise AssertionError(method)


class ApiScanCaseTests(unittest.TestCase):
    def test_valid_lifecycle_lists_previews_starts_status_pauses_and_reconnects(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            hostd = FakeHostd()
            app = self._app(Path(tmp), hostd)

            listed = asyncio.run(asgi_request(app, "GET", "/api/v1/sources"))
            preview = asyncio.run(
                asgi_request(
                    app,
                    "POST",
                    "/api/v1/sources/source_current/scan-preview",
                    body=json.dumps(
                        {"observed_generation": 7, "scan_policy": {"mode": "deep"}}
                    ).encode(),
                    headers={"content-type": "application/json"},
                )
            )
            start = asyncio.run(
                asgi_request(
                    app,
                    "POST",
                    "/api/v1/scan-cases",
                    body=json.dumps(
                        {
                            "source_id": "source_current",
                            "observed_generation": 7,
                            "safety_inspection_id": "safe_current",
                            "operator_confirmation_token": preview.json[
                                "operator_confirmation_token"
                            ],
                            "scratch_separation_id": "scratch_current",
                            "resource_profile": "default",
                            "scan_policy": {"mode": "deep"},
                        }
                    ).encode(),
                    headers={"content-type": "application/json"},
                )
            )
            case_id = start.json["case_id"]
            status = asyncio.run(asgi_request(app, "GET", f"/api/v1/scan-cases/{case_id}"))
            paused = asyncio.run(
                asgi_request(
                    app,
                    "POST",
                    f"/api/v1/scan-cases/{case_id}/pause",
                    body=b'{"reason":"operator pause"}',
                    headers={"content-type": "application/json"},
                )
            )
            resumed = asyncio.run(
                asgi_request(
                    app,
                    "POST",
                    f"/api/v1/scan-cases/{case_id}/resume",
                    body=b'{"observed_generation":7}',
                    headers={"content-type": "application/json"},
                )
            )
            reconnected = asyncio.run(
                asgi_request(
                    app,
                    "POST",
                    f"/api/v1/scan-cases/{case_id}/reconnect",
                    body=b'{"observed_generation":7}',
                    headers={"content-type": "application/json"},
                )
            )

        self.assertEqual(200, listed.status_code)
        self.assertEqual("source_current", listed.json["sources"][0]["source_id"])
        self.assertEqual(200, preview.status_code)
        self.assertEqual(200, start.status_code)
        self.assertEqual("running", status.json["case"]["state"])
        self.assertEqual("scanner_current", status.json["scanner"]["scanner_session_id"])
        self.assertEqual("paused", paused.json["state"])
        self.assertEqual("running", resumed.json["reconnect"]["state"])
        self.assertEqual("running", reconnected.json["reconnect"]["state"])
        self.assertNotIn("container_args", json.dumps([call[1] for call in hostd.calls]))

    def test_start_rejects_stale_or_missing_confirmation_token(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            hostd = FakeHostd()
            app = self._app(Path(tmp), hostd)

            response = asyncio.run(
                asgi_request(
                    app,
                    "POST",
                    "/api/v1/scan-cases",
                    body=json.dumps(
                        {
                            "source_id": "source_current",
                            "observed_generation": 8,
                            "safety_inspection_id": "safe_current",
                            "operator_confirmation_token": "confirm_wrong",
                            "scratch_separation_id": "scratch_current",
                        }
                    ).encode(),
                    headers={"content-type": "application/json"},
                )
            )

        self.assertEqual(409, response.status_code)

    def test_start_rejects_expired_confirmation_token(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            hostd = FakeHostd()
            app = self._app(Path(tmp), hostd)
            token = self._preview_token(app)
            app.state.source_confirmations["source_current"]["issued_at"] = (
                time.monotonic() - CONFIRMATION_TOKEN_TTL_SECONDS - 1
            )

            response = self._start(app, token)

        self.assertEqual(409, response.status_code)

    def test_swapped_device_generation_blocks_preview(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            hostd = FakeHostd()
            app = self._app(Path(tmp), hostd)

            response = asyncio.run(
                asgi_request(
                    app,
                    "POST",
                    "/api/v1/sources/source_current/scan-preview",
                    body=b'{"observed_generation":6}',
                    headers={"content-type": "application/json"},
                )
            )

        self.assertEqual(503, response.status_code)

    def test_already_active_case_blocks_second_start(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            hostd = FakeHostd()
            app = self._app(Path(tmp), hostd)
            token = self._preview_token(app)
            self._start(app, token)

            second = self._start(app, token)

        self.assertEqual(409, second.status_code)

    def test_hostd_unavailable_and_unsupported_device_are_reported(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            hostd = FakeHostd()
            hostd.fail = True
            unavailable = asyncio.run(
                asgi_request(self._app(Path(tmp), hostd), "GET", "/api/v1/sources")
            )

        with tempfile.TemporaryDirectory() as tmp:
            hostd = FakeHostd()
            hostd.safe = False
            unsupported = asyncio.run(
                asgi_request(
                    self._app(Path(tmp), hostd),
                    "POST",
                    "/api/v1/sources/source_current/scan-preview",
                    body=b'{"observed_generation":7}',
                    headers={"content-type": "application/json"},
                )
            )

        self.assertEqual(503, unavailable.status_code)
        self.assertEqual(409, unsupported.status_code)

    def _app(self, root: Path, hostd: FakeHostd) -> Any:
        db_path = root / "catalog.sqlite3"
        runner.migrate_catalog(db_path)
        return create_app(catalog_path=db_path, hostd_client=hostd)

    def _preview_token(self, app: Any) -> str:
        response = asyncio.run(
            asgi_request(
                app,
                "POST",
                "/api/v1/sources/source_current/scan-preview",
                body=b'{"observed_generation":7}',
                headers={"content-type": "application/json"},
            )
        )
        return str(response.json["operator_confirmation_token"])

    def _start(self, app: Any, token: str) -> Any:
        return asyncio.run(
            asgi_request(
                app,
                "POST",
                "/api/v1/scan-cases",
                body=json.dumps(
                    {
                        "source_id": "source_current",
                        "observed_generation": 7,
                        "safety_inspection_id": "safe_current",
                        "operator_confirmation_token": token,
                        "scratch_separation_id": "scratch_current",
                    }
                ).encode(),
                headers={"content-type": "application/json"},
            )
        )


if __name__ == "__main__":
    unittest.main()
