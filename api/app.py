"""Versioned FastAPI service scaffold for the Reperio control plane."""

from __future__ import annotations

import asyncio
import uuid
from pathlib import Path
from typing import Any

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles
from starlette.exceptions import HTTPException as StarletteHTTPException
from starlette.middleware.base import RequestResponseEndpoint
from starlette.responses import Response

from api import __version__
from migrations import runner

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


def public_openapi_schema() -> dict[str, Any]:
    """Return the committed public OpenAPI document."""

    return create_app().openapi()
