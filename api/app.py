"""Versioned FastAPI service scaffold for the Reperio control plane."""

from __future__ import annotations

import asyncio
import hashlib
import json
import sqlite3
import uuid
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any

from fastapi import FastAPI, Query, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field
from starlette.exceptions import HTTPException as StarletteHTTPException
from starlette.middleware.base import RequestResponseEndpoint
from starlette.responses import Response

from api import __version__
from migrations import runner
from shared import catalog_schema, event_outbox

DEFAULT_MAX_REQUEST_BYTES = 1_048_576
DEFAULT_TIMEOUT_SECONDS = 30.0
REQUEST_ID_HEADER = "x-request-id"
NOW_SQL = "strftime('%Y-%m-%dT%H:%M:%SZ', 'now')"


class HostdUnavailable(RuntimeError):
    """Raised when the host controller cannot service an API request."""


class UnavailableHostdClient:
    """Default hostd boundary used until the Unix-socket client is wired."""

    def request(self, method: str, params: Mapping[str, Any]) -> dict[str, Any]:
        raise HostdUnavailable("hostd is not configured")


class SourcePreviewRequest(BaseModel):
    observed_generation: int = Field(ge=0)
    scan_policy: dict[str, Any] = Field(default_factory=dict)


class StartScanRequest(BaseModel):
    source_id: str
    observed_generation: int = Field(ge=0)
    safety_inspection_id: str
    operator_confirmation_token: str
    scratch_separation_id: str
    resource_profile: str = "default"
    scan_policy: dict[str, Any] = Field(default_factory=dict)


class CaseActionRequest(BaseModel):
    reason: str = "operator request"


def create_app(
    *,
    catalog_path: Path | None = None,
    static_dir: Path | None = None,
    hostd_client: Any | None = None,
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
    app.state.hostd_client = hostd_client or UnavailableHostdClient()
    app.state.source_confirmations = {}
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

    @app.get("/api/v1/sources", tags=["sources"])
    async def list_sources() -> dict[str, Any]:
        return {"sources": _hostd(app, "list_devices", {}).get("devices", [])}

    @app.get("/api/v1/sources/{source_id}", tags=["sources"])
    async def source_detail(source_id: str) -> dict[str, Any]:
        devices = _hostd(app, "list_devices", {}).get("devices", [])
        for source in devices:
            if isinstance(source, Mapping) and source.get("source_id") == source_id:
                return {"source": dict(source)}
        raise StarletteHTTPException(status_code=404)

    @app.post("/api/v1/sources/{source_id}/scan-preview", tags=["sources"])
    async def scan_preview(source_id: str, body: SourcePreviewRequest) -> dict[str, Any]:
        inspection = _hostd(
            app,
            "inspect_safety",
            {"source_id": source_id, "observed_generation": body.observed_generation},
        )
        safety_id = str(inspection.get("safety_inspection_id", ""))
        if not safety_id or not inspection.get("safe_for_scan", False):
            raise StarletteHTTPException(status_code=409)
        token = _confirmation_token(source_id, body.observed_generation, safety_id)
        app.state.source_confirmations[source_id] = {
            "generation": body.observed_generation,
            "safety_inspection_id": safety_id,
            "token": token,
        }
        return {
            "source_id": source_id,
            "observed_generation": body.observed_generation,
            "safety_inspection": inspection,
            "operator_confirmation_token": token,
            "scan_policy": body.scan_policy,
        }

    @post_json(app, "/api/v1/scan-cases", tags=["scan-cases"])
    async def start_scan(body: StartScanRequest) -> dict[str, Any]:
        _require_confirmation(app, body)
        connection = _open_ready_catalog(app.state.catalog_path)
        try:
            _ensure_no_active_case(connection, body.source_id)
            readonly = _hostd(
                app,
                "prepare_read_only",
                {
                    "source_id": body.source_id,
                    "observed_generation": body.observed_generation,
                    "safety_inspection_id": body.safety_inspection_id,
                    "operator_confirmation_token": body.operator_confirmation_token,
                },
            )
            case_id = f"case_{uuid.uuid4().hex[:24]}"
            scanner = _hostd(
                app,
                "launch_scanner",
                {
                    "source_id": body.source_id,
                    "observed_generation": body.observed_generation,
                    "safety_inspection_id": body.safety_inspection_id,
                    "readonly_preparation_id": readonly["readonly_preparation_id"],
                    "scan_case_id": case_id,
                    "scratch_separation_id": body.scratch_separation_id,
                    "resource_profile": body.resource_profile,
                },
            )
            _create_scan_case(connection, case_id, body, scanner)
        finally:
            connection.close()
        return {"case_id": case_id, "state": "running", "scanner": scanner}

    @app.get("/api/v1/scan-cases/{case_id}", tags=["scan-cases"])
    async def scan_status(case_id: str) -> dict[str, Any]:
        connection = _open_ready_catalog(app.state.catalog_path)
        try:
            case = _get_case(connection, case_id)
        finally:
            connection.close()
        scanner_session_id = case["policy"].get("scanner_session_id")
        scanner = (
            _hostd(app, "scanner_status", {"scanner_session_id": scanner_session_id})
            if isinstance(scanner_session_id, str)
            else None
        )
        return {"case": case, "scanner": scanner}

    @post_json(app, "/api/v1/scan-cases/{case_id}/pause", tags=["scan-cases"])
    async def pause_scan(case_id: str, body: CaseActionRequest) -> dict[str, str]:
        return _stop_or_reconnect_case(app, case_id, body.reason, "paused")

    @post_json(app, "/api/v1/scan-cases/{case_id}/safe-stop", tags=["scan-cases"])
    async def safe_stop_scan(case_id: str, body: CaseActionRequest) -> dict[str, str]:
        return _stop_or_reconnect_case(app, case_id, body.reason, "paused")

    @post_json(app, "/api/v1/scan-cases/{case_id}/resume", tags=["scan-cases"])
    async def resume_scan(case_id: str, body: SourcePreviewRequest) -> dict[str, Any]:
        return _reconnect_case(app, case_id, body.observed_generation, mark_running=True)

    @post_json(app, "/api/v1/scan-cases/{case_id}/reconnect", tags=["scan-cases"])
    async def reconnect_scan(case_id: str, body: SourcePreviewRequest) -> dict[str, Any]:
        return _reconnect_case(app, case_id, body.observed_generation, mark_running=False)

    def _reconnect_case(
        app: FastAPI, case_id: str, observed_generation: int, *, mark_running: bool
    ) -> dict[str, Any]:
        connection = _open_ready_catalog(app.state.catalog_path)
        try:
            case = _get_case(connection, case_id)
            result = _hostd(
                app,
                "reconnect",
                {
                    "scan_case_id": case_id,
                    "source_id": case["source_id"],
                    "observed_generation": observed_generation,
                },
            )
            if mark_running:
                with connection:
                    connection.execute(
                        f"UPDATE scan_cases SET state = 'running', updated_at = {NOW_SQL} WHERE case_id = ?",
                        (case_id,),
                    )
        finally:
            connection.close()
        return {"case_id": case_id, "reconnect": result}

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


def post_json(app: FastAPI, path: str, *, tags: Sequence[str]) -> Any:
    return app.post(path, tags=list(tags))


def _hostd(app: FastAPI, method: str, params: Mapping[str, Any]) -> dict[str, Any]:
    try:
        result = app.state.hostd_client.request(method, params)
    except HostdUnavailable:
        raise StarletteHTTPException(status_code=503) from None
    if not isinstance(result, dict):
        raise StarletteHTTPException(status_code=502)
    return result


def _confirmation_token(source_id: str, generation: int, safety_inspection_id: str) -> str:
    digest = hashlib.sha256(f"{source_id}:{generation}:{safety_inspection_id}".encode()).hexdigest()
    return f"confirm_{digest[:32]}"


def _require_confirmation(app: FastAPI, body: StartScanRequest) -> None:
    confirmation = app.state.source_confirmations.get(body.source_id)
    if confirmation != {
        "generation": body.observed_generation,
        "safety_inspection_id": body.safety_inspection_id,
        "token": body.operator_confirmation_token,
    }:
        raise StarletteHTTPException(status_code=409)


def _ensure_no_active_case(connection: sqlite3.Connection, source_id: str) -> None:
    active = connection.execute(
        """
        SELECT 1 FROM scan_cases
        WHERE source_id = ? AND state IN ('created', 'running', 'paused')
        LIMIT 1
        """,
        (source_id,),
    ).fetchone()
    if active is not None:
        raise StarletteHTTPException(status_code=409)


def _create_scan_case(
    connection: sqlite3.Connection,
    case_id: str,
    body: StartScanRequest,
    scanner: Mapping[str, Any],
) -> None:
    policy = dict(body.scan_policy)
    if isinstance(scanner.get("scanner_session_id"), str):
        policy["scanner_session_id"] = scanner["scanner_session_id"]
    with connection:
        connection.execute(
            f"""
            INSERT OR IGNORE INTO sources
            (source_id, stable_identity, media_kind, size_bytes, sector_size,
             fingerprint_sha256, status, created_at, updated_at)
            VALUES (?, ?, 'block', 0, 512, ?, 'approved', {NOW_SQL}, {NOW_SQL})
            """,
            (body.source_id, body.source_id, _synthetic_fingerprint(body.source_id)),
        )
        connection.execute(
            f"""
            INSERT INTO scan_cases
            (case_id, source_id, state, policy_json, created_at, updated_at)
            VALUES (?, ?, 'running', ?, {NOW_SQL}, {NOW_SQL})
            """,
            (case_id, body.source_id, json.dumps(policy, sort_keys=True)),
        )


def _get_case(connection: sqlite3.Connection, case_id: str) -> dict[str, Any]:
    row = connection.execute(
        """
        SELECT case_id, source_id, state, policy_json, created_at, updated_at
        FROM scan_cases
        WHERE case_id = ?
        """,
        (case_id,),
    ).fetchone()
    if row is None:
        raise StarletteHTTPException(status_code=404)
    return {
        "case_id": row[0],
        "source_id": row[1],
        "state": row[2],
        "policy": json.loads(row[3]),
        "created_at": row[4],
        "updated_at": row[5],
    }


def _stop_or_reconnect_case(app: FastAPI, case_id: str, reason: str, state: str) -> dict[str, str]:
    connection = _open_ready_catalog(app.state.catalog_path)
    try:
        case = _get_case(connection, case_id)
        scanner_session_id = case["policy"].get("scanner_session_id")
        if not isinstance(scanner_session_id, str):
            raise StarletteHTTPException(status_code=409)
        _hostd(app, "stop_scanner", {"scanner_session_id": scanner_session_id, "reason": reason})
        with connection:
            connection.execute(
                f"UPDATE scan_cases SET state = ?, updated_at = {NOW_SQL} WHERE case_id = ?",
                (state, case_id),
            )
    finally:
        connection.close()
    return {"case_id": case_id, "state": state}


def _synthetic_fingerprint(source_id: str) -> str:
    return hashlib.sha256(source_id.encode()).hexdigest()


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
