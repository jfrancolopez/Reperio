from __future__ import annotations

import asyncio
import json
import tempfile
import unittest
from pathlib import Path
from typing import Any

from migrations import runner

try:
    from pydantic import BaseModel

    from api.app import create_app, public_openapi_schema
    from api.openapi import OPENAPI_PATH
except ModuleNotFoundError as error:
    raise unittest.SkipTest("FastAPI runtime dependencies are not installed") from error


class EchoBody(BaseModel):
    value: str


class ApiServiceTests(unittest.TestCase):
    def test_malformed_json_returns_structured_error_without_trace(self) -> None:
        app = create_app()

        @app.post("/api/v1/test/echo", include_in_schema=False)
        async def echo(body: EchoBody) -> dict[str, str]:
            return {"value": body.value}

        response = asyncio.run(
            asgi_request(
                app,
                "POST",
                "/api/v1/test/echo",
                body=b'{"value":',
                headers={"content-type": "application/json"},
            )
        )

        self.assertEqual(400, response.status_code)
        self.assertEqual("invalid_request", response.json["error"]["code"])
        self.assertNotIn("traceback", json.dumps(response.json).lower())

    def test_oversized_request_is_rejected_before_handler(self) -> None:
        app = create_app(max_request_bytes=4)

        response = asyncio.run(
            asgi_request(
                app,
                "POST",
                "/api/v1/health",
                body=b"12345",
                headers={"content-length": "5"},
            )
        )

        self.assertEqual(413, response.status_code)
        self.assertEqual("request_too_large", response.json["error"]["code"])

    def test_timeout_returns_structured_error(self) -> None:
        app = create_app(request_timeout_seconds=0.001)

        @app.get("/api/v1/test/slow", include_in_schema=False)
        async def slow() -> dict[str, str]:
            await asyncio.sleep(0.05)
            return {"status": "late"}

        response = asyncio.run(asgi_request(app, "GET", "/api/v1/test/slow"))

        self.assertEqual(504, response.status_code)
        self.assertEqual("request_timeout", response.json["error"]["code"])

    def test_unknown_route_returns_structured_error_and_request_id(self) -> None:
        app = create_app()

        response = asyncio.run(
            asgi_request(app, "GET", "/api/v1/missing", headers={"x-request-id": "req-test"})
        )

        self.assertEqual(404, response.status_code)
        self.assertEqual("not_found", response.json["error"]["code"])
        self.assertEqual("req-test", response.headers["x-request-id"])
        self.assertEqual("req-test", response.json["error"]["request_id"])

    def test_readiness_is_unavailable_during_migration(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            db_path = Path(tmp) / "catalog.sqlite3"
            runner.migrate_catalog(db_path)
            app = create_app(catalog_path=db_path, migration_in_progress=True)

            response = asyncio.run(asgi_request(app, "GET", "/api/v1/ready"))

            self.assertEqual(503, response.status_code)
            self.assertEqual("migration_in_progress", response.json["error"]["code"])

    def test_readiness_requires_current_schema(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            app = create_app(catalog_path=Path(tmp) / "missing.sqlite3")

            response = asyncio.run(asgi_request(app, "GET", "/api/v1/ready"))

            self.assertEqual(503, response.status_code)
            self.assertEqual("catalog_not_ready", response.json["error"]["code"])

    def test_openapi_file_matches_generated_schema(self) -> None:
        committed = json.loads(OPENAPI_PATH.read_text(encoding="utf-8"))

        self.assertEqual(public_openapi_schema(), committed)


class AsgiResponse:
    def __init__(self, status_code: int, headers: dict[str, str], body: bytes) -> None:
        self.status_code = status_code
        self.headers = headers
        self.body = body
        self.json: dict[str, Any] = json.loads(body.decode())


async def asgi_request(
    app: Any,
    method: str,
    path: str,
    *,
    body: bytes = b"",
    headers: dict[str, str] | None = None,
) -> AsgiResponse:
    raw_headers = [
        (name.lower().encode("latin-1"), value.encode("latin-1"))
        for name, value in (headers or {}).items()
    ]
    scope = {
        "type": "http",
        "asgi": {"version": "3.0"},
        "http_version": "1.1",
        "method": method,
        "scheme": "http",
        "path": path,
        "raw_path": path.encode("ascii"),
        "query_string": b"",
        "headers": raw_headers,
        "client": ("127.0.0.1", 12345),
        "server": ("testserver", 80),
    }
    messages: list[dict[str, Any]] = []
    received = False

    async def receive() -> dict[str, Any]:
        nonlocal received
        if received:
            return {"type": "http.disconnect"}
        received = True
        return {"type": "http.request", "body": body, "more_body": False}

    async def send(message: dict[str, Any]) -> None:
        messages.append(message)

    await app(scope, receive, send)
    start = next(message for message in messages if message["type"] == "http.response.start")
    chunks = [
        message.get("body", b"") for message in messages if message["type"] == "http.response.body"
    ]
    response_headers = {
        key.decode("latin-1"): value.decode("latin-1") for key, value in start["headers"]
    }
    return AsgiResponse(start["status"], response_headers, b"".join(chunks))


if __name__ == "__main__":
    unittest.main()
