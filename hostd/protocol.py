"""Versioned host-controller protocol contract for RPR-009.

This module validates the narrow Unix-socket message envelopes shared by the
control plane and hostd. It intentionally exposes no device operations; later
tasks attach implementations behind this fixed allowlist.
"""

from __future__ import annotations

import re
from collections.abc import Mapping
from typing import Any

PROTOCOL_SCHEMA_VERSION = 1
AUTH_KIND = "unix_peer_credentials"

METHODS = (
    "list_devices",
    "inspect_safety",
    "prepare_read_only",
    "launch_scanner",
    "scanner_status",
    "stop_scanner",
    "reconnect",
)

REQUEST_KEYS = frozenset({"schema_version", "request_id", "auth", "method", "params"})
RESPONSE_KEYS = frozenset({"schema_version", "request_id", "ok", "result", "error"})
ERROR_KEYS = frozenset({"code", "message"})
ERROR_CODES = frozenset(
    {
        "bad_request",
        "unauthorized",
        "not_found",
        "stale_source",
        "safety_blocked",
        "read_only_failed",
        "scanner_unavailable",
        "internal_error",
    }
)

OPAQUE_ID_RE = re.compile(r"^[a-z][a-z0-9_]*_[A-Za-z0-9_-]{16,128}$")
REQUEST_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")

METHOD_PARAM_KEYS = {
    "list_devices": frozenset(),
    "inspect_safety": frozenset({"source_id", "observed_generation"}),
    "prepare_read_only": frozenset(
        {
            "source_id",
            "observed_generation",
            "safety_inspection_id",
            "operator_confirmation_token",
        }
    ),
    "launch_scanner": frozenset(
        {
            "source_id",
            "observed_generation",
            "safety_inspection_id",
            "readonly_preparation_id",
            "scan_case_id",
            "scratch_separation_id",
            "resource_profile",
        }
    ),
    "scanner_status": frozenset({"scanner_session_id"}),
    "stop_scanner": frozenset({"scanner_session_id", "reason"}),
    "reconnect": frozenset({"scan_case_id", "source_id", "observed_generation"}),
}

METHOD_REQUIRED_KEYS = {
    "list_devices": frozenset(),
    "inspect_safety": frozenset({"source_id", "observed_generation"}),
    "prepare_read_only": frozenset(
        {
            "source_id",
            "observed_generation",
            "safety_inspection_id",
            "operator_confirmation_token",
        }
    ),
    "launch_scanner": frozenset(
        {
            "source_id",
            "observed_generation",
            "safety_inspection_id",
            "readonly_preparation_id",
            "scan_case_id",
            "scratch_separation_id",
            "resource_profile",
        }
    ),
    "scanner_status": frozenset({"scanner_session_id"}),
    "stop_scanner": frozenset({"scanner_session_id", "reason"}),
    "reconnect": frozenset({"scan_case_id", "source_id", "observed_generation"}),
}

OPAQUE_ID_FIELDS = frozenset(
    {
        "source_id",
        "safety_inspection_id",
        "operator_confirmation_token",
        "readonly_preparation_id",
        "scan_case_id",
        "scratch_separation_id",
        "scanner_session_id",
    }
)

RESOURCE_PROFILE_RE = re.compile(r"^[a-z][a-z0-9_-]{0,63}$")
REASON_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9 ._:-]{0,127}$")
PATHLIKE_MARKERS = ("/", "\\", "..", "\x00")


class ProtocolError(ValueError):
    """Raised when a hostd protocol message violates the RPR-009 contract."""


def validate_request(
    message: Mapping[str, Any], *, source_generations: Mapping[str, int] | None = None
) -> dict[str, Any]:
    """Validate and return a normalized hostd request message.

    ``source_generations`` is supplied by the future device registry. When a
    request names a known source, its observed generation must match exactly so
    stale selections fail before any source-touching operation can run.
    """
    _require_keys(message, REQUEST_KEYS, REQUEST_KEYS, "request")
    _validate_schema_version(message.get("schema_version"), "request.schema_version")
    _validate_request_id(message.get("request_id"))
    _validate_auth(message.get("auth"))

    method = message.get("method")
    if method not in METHODS:
        raise ProtocolError(f"request.method {method!r} is not allowlisted")

    params = message.get("params")
    if not isinstance(params, Mapping):
        raise ProtocolError("request.params must be an object")
    _validate_params(method, params, source_generations or {})

    return {
        "schema_version": PROTOCOL_SCHEMA_VERSION,
        "request_id": message["request_id"],
        "auth": dict(message["auth"]),
        "method": method,
        "params": dict(params),
    }


def validate_response(message: Mapping[str, Any]) -> dict[str, Any]:
    """Validate and return a normalized hostd response envelope."""
    _require_keys(message, {"schema_version", "request_id", "ok"}, RESPONSE_KEYS, "response")
    _validate_schema_version(message.get("schema_version"), "response.schema_version")
    _validate_request_id(message.get("request_id"))
    if not isinstance(message.get("ok"), bool):
        raise ProtocolError("response.ok must be boolean")
    if message["ok"]:
        if "result" not in message or "error" in message:
            raise ProtocolError("successful response requires result and forbids error")
        if not isinstance(message["result"], Mapping):
            raise ProtocolError("successful response.result must be an object")
    elif "error" not in message or "result" in message:
        raise ProtocolError("failed response requires error and forbids result")
    else:
        _validate_error(message["error"])
    _reject_pathlike_strings(message, "response")
    return dict(message)


def _require_keys(
    message: Mapping[str, Any],
    required: frozenset[str] | set[str],
    allowed: frozenset[str],
    path: str,
) -> None:
    missing = sorted(required - set(message))
    if missing:
        raise ProtocolError(f"{path} missing required key(s): {', '.join(missing)}")
    extra = sorted(set(message) - allowed)
    if extra:
        raise ProtocolError(f"{path} has unsupported key(s): {', '.join(extra)}")


def _validate_schema_version(value: object, path: str) -> None:
    if value != PROTOCOL_SCHEMA_VERSION:
        raise ProtocolError(f"{path} must be {PROTOCOL_SCHEMA_VERSION}")


def _validate_request_id(value: object) -> None:
    if not isinstance(value, str) or REQUEST_ID_RE.fullmatch(value) is None:
        raise ProtocolError("request_id must be a bounded protocol correlation id")


def _validate_auth(value: object) -> None:
    if not isinstance(value, Mapping):
        raise ProtocolError("request.auth must be an object")
    _require_keys(value, {"kind", "principal"}, frozenset({"kind", "principal"}), "request.auth")
    if value.get("kind") != AUTH_KIND:
        raise ProtocolError(f"request.auth.kind must be {AUTH_KIND!r}")
    if value.get("principal") != "reperio-api":
        raise ProtocolError("request.auth.principal must be 'reperio-api'")


def _validate_params(
    method: str, params: Mapping[str, Any], source_generations: Mapping[str, int]
) -> None:
    _require_keys(
        params, METHOD_REQUIRED_KEYS[method], METHOD_PARAM_KEYS[method], f"{method}.params"
    )
    _reject_pathlike_strings(params, f"{method}.params")

    for field, value in params.items():
        if field in OPAQUE_ID_FIELDS:
            _validate_opaque_id(field, value)
        elif field == "observed_generation":
            if not isinstance(value, int) or isinstance(value, bool) or value < 0:
                raise ProtocolError("observed_generation must be a non-negative integer")
        elif field == "resource_profile":
            if not isinstance(value, str) or RESOURCE_PROFILE_RE.fullmatch(value) is None:
                raise ProtocolError("resource_profile must name a configured resource profile")
        elif field == "reason":
            if not isinstance(value, str) or REASON_RE.fullmatch(value) is None:
                raise ProtocolError("reason must be bounded operator-visible text")

    source_id = params.get("source_id")
    observed_generation = params.get("observed_generation")
    if isinstance(source_id, str) and isinstance(observed_generation, int):
        current_generation = source_generations.get(source_id)
        if current_generation is None:
            raise ProtocolError(f"source_id {source_id!r} is not current")
        if observed_generation != current_generation:
            raise ProtocolError(
                f"source_id {source_id!r} generation is stale: "
                f"observed {observed_generation}, current {current_generation}"
            )


def _validate_opaque_id(field: str, value: object) -> None:
    if not isinstance(value, str) or OPAQUE_ID_RE.fullmatch(value) is None:
        raise ProtocolError(f"{field} must be an opaque Reperio identifier")


def _validate_error(value: object) -> None:
    if not isinstance(value, Mapping):
        raise ProtocolError("failed response.error must be an object")
    _require_keys(value, ERROR_KEYS, ERROR_KEYS, "response.error")
    if value.get("code") not in ERROR_CODES:
        raise ProtocolError("response.error.code is not supported")
    message = value.get("message")
    if not isinstance(message, str) or not 1 <= len(message) <= 512:
        raise ProtocolError("response.error.message must contain 1 to 512 characters")


def _reject_pathlike_strings(value: object, path: str) -> None:
    if isinstance(value, str):
        if any(marker in value for marker in PATHLIKE_MARKERS):
            raise ProtocolError(f"{path} must not contain path-like text")
        return
    if isinstance(value, Mapping):
        for key, child in value.items():
            _reject_pathlike_strings(child, f"{path}.{key}")
        return
    if isinstance(value, list):
        for index, child in enumerate(value):
            _reject_pathlike_strings(child, f"{path}[{index}]")
