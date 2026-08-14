"""Versioned FastAPI service scaffold for the Reperio control plane."""

from __future__ import annotations

import asyncio
import base64
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


class FindingQueryParams(BaseModel):
    case_id: str | None = None
    finding_type: str | None = None
    severity: str | None = None
    status: str | None = None
    q: str | None = None
    cursor: str | None = None
    limit: int = Field(default=100, ge=1, le=500)
    include_system_noise: bool = False


class ReviewActionRequest(BaseModel):
    finding_ids: list[str] = Field(default_factory=list)
    saved_query: FindingQueryParams | None = None
    actor: str = "operator"
    note: str | None = None


class ReviewUndoRequest(BaseModel):
    actor: str = "operator"


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
    app.state.review_actions_enabled = True
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

    @app.get("/api/v1/findings", tags=["findings"])
    async def list_findings(
        case_id: str | None = None,
        finding_type: str | None = None,
        severity: str | None = None,
        status: str | None = None,
        q: str | None = None,
        cursor: str | None = None,
        limit: int = Query(default=100, ge=1, le=500),
        include_system_noise: bool = False,
    ) -> dict[str, Any]:
        params = FindingQueryParams(
            case_id=case_id,
            finding_type=finding_type,
            severity=severity,
            status=status,
            q=q,
            cursor=cursor,
            limit=limit,
            include_system_noise=include_system_noise,
        )
        connection = _open_ready_catalog(app.state.catalog_path)
        try:
            return _query_findings(connection, params)
        finally:
            connection.close()

    @app.get("/api/v1/findings/facets", tags=["findings"])
    async def finding_facets(case_id: str | None = None) -> dict[str, Any]:
        connection = _open_ready_catalog(app.state.catalog_path)
        try:
            return {"case_id": case_id, "facets": _finding_facets(connection, case_id)}
        finally:
            connection.close()

    @app.get("/api/v1/findings/{finding_id}", tags=["findings"])
    async def finding_detail(finding_id: str) -> dict[str, Any]:
        connection = _open_ready_catalog(app.state.catalog_path)
        try:
            finding = _get_finding(connection, finding_id)
            evidence = _finding_evidence(connection, finding_id)
        finally:
            connection.close()
        return {"finding": finding, "evidence": evidence, "provenance": evidence}

    @post_json(app, "/api/v1/findings/review/dismiss", tags=["findings"])
    async def dismiss_findings(body: ReviewActionRequest) -> dict[str, Any]:
        return _apply_review_action(app, body, action="dismiss", target_status="dismissed")

    @post_json(app, "/api/v1/findings/review/restore", tags=["findings"])
    async def restore_findings(body: ReviewActionRequest) -> dict[str, Any]:
        return _apply_review_action(app, body, action="restore", target_status="new")

    @post_json(app, "/api/v1/review-actions/{review_action_id}/undo", tags=["findings"])
    async def undo_review_action(review_action_id: str, body: ReviewUndoRequest) -> dict[str, Any]:
        if not app.state.review_actions_enabled:
            raise StarletteHTTPException(status_code=403)
        connection = _open_ready_catalog(app.state.catalog_path)
        try:
            return _undo_review_action(connection, review_action_id, actor=body.actor)
        finally:
            connection.close()

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


def _query_findings(connection: sqlite3.Connection, params: FindingQueryParams) -> dict[str, Any]:
    where, values = _finding_where(params)
    cursor_created, cursor_id = _decode_finding_cursor(params.cursor)
    if cursor_created is not None and cursor_id is not None:
        where.append("(created_at > ? OR (created_at = ? AND finding_id > ?))")
        values.extend([cursor_created, cursor_created, cursor_id])
    sql = f"""
        SELECT finding_id, case_id, entry_id, content_id, finding_type, severity,
               title, summary, status, confidence, created_at
        FROM findings
        WHERE {" AND ".join(where)}
        ORDER BY created_at, finding_id
        LIMIT ?
    """
    rows = connection.execute(sql, (*values, params.limit + 1)).fetchall()
    findings = [_finding_from_row(row) for row in rows[: params.limit]]
    next_cursor = None
    if len(rows) > params.limit and findings:
        next_cursor = _encode_finding_cursor(findings[-1]["created_at"], findings[-1]["finding_id"])
    return {
        "findings": findings,
        "next_cursor": next_cursor,
        "fts": {"enabled": False, "q": params.q},
    }


def _finding_where(params: FindingQueryParams) -> tuple[list[str], list[Any]]:
    where = ["1 = 1"]
    values: list[Any] = []
    for column in ("case_id", "finding_type", "severity", "status"):
        value = getattr(params, column)
        if value is not None:
            where.append(f"{column} = ?")
            values.append(value)
    if params.q:
        where.append("(title LIKE ? ESCAPE '\\' OR summary LIKE ? ESCAPE '\\')")
        like = f"%{_escape_like(params.q)}%"
        values.extend([like, like])
    if not params.include_system_noise:
        where.append(
            """
            NOT EXISTS (
                SELECT 1 FROM evidence
                WHERE evidence.finding_id = findings.finding_id
                  AND evidence.evidence_kind = 'metadata'
                  AND json_extract(evidence.data_json, '$.system_noise') = 1
            )
            """
        )
    return where, values


def _apply_review_action(
    app: FastAPI, body: ReviewActionRequest, *, action: str, target_status: str
) -> dict[str, Any]:
    if not app.state.review_actions_enabled:
        raise StarletteHTTPException(status_code=403)
    connection = _open_ready_catalog(app.state.catalog_path)
    try:
        finding_ids = _review_target_ids(connection, body)
        group_id = f"review_{uuid.uuid4().hex[:24]}"
        changed: list[str] = []
        with connection:
            for index, finding in enumerate(_findings_for_update(connection, finding_ids)):
                finding_id = finding["finding_id"]
                previous_status = finding["status"]
                if previous_status != target_status:
                    connection.execute(
                        "UPDATE findings SET status = ? WHERE finding_id = ?",
                        (target_status, finding_id),
                    )
                    changed.append(finding_id)
                note = {
                    "group_id": group_id,
                    "operator_note": body.note,
                    "previous_status": previous_status,
                    "target_status": target_status,
                    "undone": False,
                }
                connection.execute(
                    f"""
                    INSERT INTO review_actions
                    (review_action_id, finding_id, action, actor, note, created_at)
                    VALUES (?, ?, ?, ?, ?, {NOW_SQL})
                    """,
                    (
                        group_id if index == 0 else f"{group_id}_{index}",
                        finding_id,
                        action,
                        body.actor,
                        json.dumps(note, sort_keys=True),
                    ),
                )
    finally:
        connection.close()
    return {"review_action_id": group_id, "matched_count": len(finding_ids), "changed_ids": changed}


def _review_target_ids(connection: sqlite3.Connection, body: ReviewActionRequest) -> list[str]:
    explicit = list(dict.fromkeys(body.finding_ids))
    if explicit and body.saved_query is not None:
        raise StarletteHTTPException(status_code=400)
    if explicit:
        return explicit
    if body.saved_query is None:
        raise StarletteHTTPException(status_code=400)
    where, values = _finding_where(body.saved_query)
    rows = connection.execute(
        f"SELECT finding_id FROM findings WHERE {' AND '.join(where)} ORDER BY created_at, finding_id",
        values,
    ).fetchall()
    return [str(row[0]) for row in rows]


def _findings_for_update(
    connection: sqlite3.Connection, finding_ids: list[str]
) -> list[dict[str, Any]]:
    if not finding_ids:
        return []
    placeholders = ",".join("?" for _ in finding_ids)
    rows = connection.execute(
        f"SELECT finding_id, status FROM findings WHERE finding_id IN ({placeholders}) ORDER BY finding_id",
        finding_ids,
    ).fetchall()
    found = {str(row[0]) for row in rows}
    if found != set(finding_ids):
        raise StarletteHTTPException(status_code=404)
    return [{"finding_id": row[0], "status": row[1]} for row in rows]


def _undo_review_action(
    connection: sqlite3.Connection, review_action_id: str, *, actor: str
) -> dict[str, Any]:
    rows = connection.execute(
        """
        SELECT review_action_id, finding_id, note
        FROM review_actions
        WHERE review_action_id = ? OR note LIKE ?
        ORDER BY review_action_id
        """,
        (review_action_id, f'%"group_id": "{review_action_id}"%'),
    ).fetchall()
    if not rows:
        raise StarletteHTTPException(status_code=404)
    notes = [(row[0], row[1], json.loads(row[2] or "{}")) for row in rows]
    if all(note.get("undone") is True for _, _, note in notes):
        return {"review_action_id": review_action_id, "undone": False, "already_undone": True}
    restored: list[str] = []
    with connection:
        for row_id, finding_id, note in notes:
            previous_status = note.get("previous_status")
            if isinstance(previous_status, str):
                connection.execute(
                    "UPDATE findings SET status = ? WHERE finding_id = ?",
                    (previous_status, finding_id),
                )
                restored.append(str(finding_id))
            note["undone"] = True
            note["undo_actor"] = actor
            connection.execute(
                "UPDATE review_actions SET note = ? WHERE review_action_id = ?",
                (json.dumps(note, sort_keys=True), row_id),
            )
    return {"review_action_id": review_action_id, "undone": True, "restored_ids": restored}


def _get_finding(connection: sqlite3.Connection, finding_id: str) -> dict[str, Any]:
    row = connection.execute(
        """
        SELECT finding_id, case_id, entry_id, content_id, finding_type, severity,
               title, summary, status, confidence, created_at
        FROM findings
        WHERE finding_id = ?
        """,
        (finding_id,),
    ).fetchone()
    if row is None:
        raise StarletteHTTPException(status_code=404)
    return _finding_from_row(row)


def _finding_evidence(connection: sqlite3.Connection, finding_id: str) -> list[dict[str, Any]]:
    rows = connection.execute(
        """
        SELECT evidence_id, evidence_kind, content_id, data_json, created_at
        FROM evidence
        WHERE finding_id = ?
        ORDER BY created_at, evidence_id
        """,
        (finding_id,),
    ).fetchall()
    return [
        {
            "evidence_id": row[0],
            "evidence_kind": row[1],
            "content_id": row[2],
            "data": json.loads(row[3]),
            "created_at": row[4],
        }
        for row in rows
    ]


def _finding_facets(
    connection: sqlite3.Connection, case_id: str | None
) -> dict[str, list[dict[str, Any]]]:
    facets: dict[str, list[dict[str, Any]]] = {}
    where = "WHERE case_id = ?" if case_id is not None else ""
    values: tuple[str, ...] = (case_id,) if case_id is not None else ()
    for column in ("finding_type", "severity", "status"):
        rows = connection.execute(
            f"SELECT {column}, COUNT(*) FROM findings {where} GROUP BY {column} ORDER BY {column}",
            values,
        ).fetchall()
        facets[column] = [{"value": row[0], "count": row[1]} for row in rows]
    return facets


def _finding_from_row(row: sqlite3.Row | tuple[Any, ...]) -> dict[str, Any]:
    return {
        "finding_id": row[0],
        "case_id": row[1],
        "entry_id": row[2],
        "content_id": row[3],
        "finding_type": row[4],
        "severity": row[5],
        "title": row[6],
        "summary": row[7],
        "status": row[8],
        "confidence": row[9],
        "created_at": row[10],
    }


def _encode_finding_cursor(created_at: str, finding_id: str) -> str:
    raw = json.dumps({"created_at": created_at, "finding_id": finding_id}, separators=(",", ":"))
    return base64.urlsafe_b64encode(raw.encode()).decode().rstrip("=")


def _decode_finding_cursor(cursor: str | None) -> tuple[str | None, str | None]:
    if cursor is None:
        return None, None
    try:
        padded = cursor + "=" * (-len(cursor) % 4)
        payload = json.loads(base64.urlsafe_b64decode(padded.encode()).decode())
    except (ValueError, json.JSONDecodeError):
        raise StarletteHTTPException(status_code=400) from None
    created_at = payload.get("created_at")
    finding_id = payload.get("finding_id")
    if not isinstance(created_at, str) or not isinstance(finding_id, str):
        raise StarletteHTTPException(status_code=400)
    return created_at, finding_id


def _escape_like(value: str) -> str:
    return value.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")


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
