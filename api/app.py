"""Versioned FastAPI service scaffold for the Reperio control plane."""

from __future__ import annotations

import asyncio
import sqlite3
import uuid
from pathlib import Path
from typing import Any

from fastapi import FastAPI, Query, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from starlette.exceptions import HTTPException as StarletteHTTPException
from starlette.middleware.base import RequestResponseEndpoint
from starlette.responses import Response

from api import __version__
from migrations import runner
from shared import catalog_schema, event_outbox

DEFAULT_MAX_REQUEST_BYTES = 1_048_576
DEFAULT_TIMEOUT_SECONDS = 30.0
REQUEST_ID_HEADER = "x-request-id"


def create_app(
    *,
    catalog_path: Path | None = None,
    static_dir: Path | None = None,
    max_request_bytes: int = DEFAULT_MAX_REQUEST_BYTES,
    request_timeout_seconds: float = DEFAULT_TIMEOUT_SECONDS,
    migration_in_progress: bool = False,
) -> FastAPI:
    """Build the API app without opening source media or destination paths."""

    app = FastAPI(
        title="Reperio API",
        version=__version__,
        openapi_url="/api/v1/openapi.json",
        docs_url=None,
        redoc_url=None,
    )
    app.state.catalog_path = catalog_path
    app.state.migration_in_progress = migration_in_progress

    @app.middleware("http")
    async def safety_middleware(request: Request, call_next: RequestResponseEndpoint) -> Response:
        request_id = _request_id(request)
        request.state.request_id = request_id
        content_length = request.headers.get("content-length")
        if content_length is not None and int(content_length) > max_request_bytes:
            return _error_response(
                status_code=413,
                code="request_too_large",
                message="request body exceeds configured size limit",
                request_id=request_id,
            )
        try:
            response = await asyncio.wait_for(call_next(request), timeout=request_timeout_seconds)
        except TimeoutError:
            response = _error_response(
                status_code=504,
                code="request_timeout",
                message="request exceeded configured time limit",
                request_id=request_id,
            )
        response.headers["x-request-id"] = request_id
        return response

    @app.exception_handler(StarletteHTTPException)
    async def http_exception_handler(request: Request, exc: StarletteHTTPException) -> JSONResponse:
        return _error_response(
            status_code=exc.status_code,
            code="not_found" if exc.status_code == 404 else "http_error",
            message="route not found" if exc.status_code == 404 else "request failed",
            request_id=_request_id(request),
        )

    @app.exception_handler(RequestValidationError)
    async def validation_exception_handler(
        request: Request, _exc: RequestValidationError
    ) -> JSONResponse:
        return _error_response(
            status_code=400,
            code="invalid_request",
            message="request body or parameters are invalid",
            request_id=_request_id(request),
        )

    @app.exception_handler(Exception)
    async def unhandled_exception_handler(request: Request, _exc: Exception) -> JSONResponse:
        return _error_response(
            status_code=500,
            code="internal_error",
            message="internal server error",
            request_id=_request_id(request),
        )

    @app.get("/health", include_in_schema=False)
    async def root_health() -> dict[str, str]:
        return {"status": "ok", "version": __version__}

    @app.get("/api/v1/health", tags=["system"])
    async def health() -> dict[str, str]:
        return {"status": "ok", "version": __version__}

    @app.get("/api/v1/ready", tags=["system"], response_model=None)
    async def readiness() -> Response | dict[str, str]:
        if app.state.migration_in_progress:
            return _error_response(
                status_code=503,
                code="migration_in_progress",
                message="database migration is in progress",
                request_id="readiness",
            )
        if app.state.catalog_path is None or not runner.ready_for_workers(app.state.catalog_path):
            return _error_response(
                status_code=503,
                code="catalog_not_ready",
                message="catalog schema is not ready for workers",
                request_id="readiness",
            )
        return {"status": "ready", "schema_version": str(runner.CURRENT_SCHEMA_VERSION)}

    @app.get("/api/v1/cases/{case_id}/events", tags=["events"])
    async def poll_case_events(
        case_id: str, after: int = Query(default=0, ge=0), limit: int = Query(default=100, ge=1)
    ) -> dict[str, Any]:
        connection = _open_ready_catalog(app.state.catalog_path)
        try:
            events = event_outbox.list_events(
                connection, case_id=case_id, after_sequence=after, limit=limit
            )
        finally:
            connection.close()
        return {"case_id": case_id, "events": events, "next_after": _next_after(events, after)}

    @app.get("/api/v1/cases/{case_id}/events/stream", tags=["events"])
    async def stream_case_events(
        request: Request,
        case_id: str,
        after: int = Query(default=0, ge=0),
        limit: int = Query(default=100, ge=1),
    ) -> StreamingResponse:
        last_event_id = request.headers.get("last-event-id")
        resume_after = _resume_sequence(last_event_id, after)

        async def body() -> Any:
            connection = _open_ready_catalog(app.state.catalog_path)
            try:
                events = event_outbox.list_events(
                    connection, case_id=case_id, after_sequence=resume_after, limit=limit
                )
                for event in events:
                    if await request.is_disconnected():
                        break
                    yield event_outbox.format_sse(event)
                    await asyncio.sleep(0)
            finally:
                connection.close()

        return StreamingResponse(body(), media_type="text/event-stream")

    if static_dir is not None and static_dir.exists():
        app.mount("/", StaticFiles(directory=static_dir, html=True), name="static-ui")

    return app


def _request_id(request: Request) -> str:
    existing = request.headers.get(REQUEST_ID_HEADER)
    if existing and 1 <= len(existing) <= 128 and all(char.isprintable() for char in existing):
        return existing
    state_id = getattr(request.state, "request_id", None)
    if isinstance(state_id, str):
        return state_id
    return f"req_{uuid.uuid4().hex}"


def _error_response(status_code: int, code: str, message: str, request_id: str) -> JSONResponse:
    return JSONResponse(
        status_code=status_code,
        content={"error": {"code": code, "message": message, "request_id": request_id}},
    )


def _open_ready_catalog(catalog_path: Path | None) -> sqlite3.Connection:
    if catalog_path is None or not runner.ready_for_workers(catalog_path):
        raise StarletteHTTPException(status_code=503)
    return catalog_schema.connect_catalog(catalog_path)


def _resume_sequence(last_event_id: str | None, after: int) -> int:
    if last_event_id is None:
        return after
    try:
        return max(after, int(last_event_id))
    except ValueError:
        return after


def _next_after(events: list[dict[str, Any]], fallback: int) -> int:
    if not events:
        return fallback
    return int(events[-1]["sequence"])


def public_openapi_schema() -> dict[str, Any]:
    """Return the committed public OpenAPI document."""

    return create_app().openapi()
