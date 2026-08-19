"""Native Ollama adapter (RPR-086).

Discovers local models via ``/api/tags``, selects a model, and drives the native
``/api/generate`` and ``/api/embed`` endpoints with JSON schema prompting,
declared image support, and bounded cancellation. A missing model surfaces setup
guidance; Reperio never auto-pulls a large model without an explicit admin
action. Pure and dependency-free: network I/O is injected as a transport.
"""

from __future__ import annotations

import base64
import json
import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Any

from worker.openai_compatible import Transport, validate_endpoint
from worker.provider_contract import (
    REDACTED,
    SECRET_PATTERNS,
    ProviderCapabilities,
)

OLLAMA_ADAPTER_VERSION = "ollama-adapter-v1"

DEFAULT_OLLAMA_ENDPOINT = "http://localhost:11434"
MAX_AUTO_PULL_BYTES = 0
VISION_CAPABILITY = "vision"

TAGS_PATH = "/api/tags"
GENERATE_PATH = "/api/generate"
EMBED_PATH = "/api/embed"
SHOW_PATH = "/api/show"

NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:\-]{0,127}$")


class OllamaAdapterError(ValueError):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


@dataclass(frozen=True)
class OllamaModel:
    name: str
    size_bytes: int
    capabilities: tuple[str, ...] = ()

    @property
    def supports_vision(self) -> bool:
        return VISION_CAPABILITY in self.capabilities


@dataclass
class CancellationToken:
    _cancelled: bool = False

    def cancel(self) -> None:
        self._cancelled = True

    def check(self) -> None:
        if self._cancelled:
            raise OllamaAdapterError("cancelled", "request was cancelled")


def parse_tags(body_bytes: bytes) -> tuple[OllamaModel, ...]:
    """Parse a ``/api/tags`` response into ordered model records."""
    try:
        body = json.loads(body_bytes.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        raise OllamaAdapterError("malformed_tags", "tags response is not valid JSON")
    models: list[OllamaModel] = []
    for entry in body.get("models") or []:
        if not isinstance(entry, dict):
            continue
        name = entry.get("name") or entry.get("model")
        if not isinstance(name, str) or not name:
            continue
        details_value = entry.get("details")
        details: dict[str, Any] = details_value if isinstance(details_value, dict) else {}
        raw_capabilities = details.get("capabilities") or ()
        capabilities = tuple(item for item in raw_capabilities if isinstance(item, str))
        models.append(
            OllamaModel(
                name=name,
                size_bytes=_nonnegative_int(entry.get("size")),
                capabilities=capabilities,
            )
        )
    return tuple(sorted(models, key=lambda model: model.name))


def model_available(models: Sequence[OllamaModel], name: str) -> bool:
    return any(model.name == name for model in models)


def select_model(models: Sequence[OllamaModel], preferred: str | None = None) -> OllamaModel | None:
    """Select a model: exact preferred match first, else the smallest model."""
    if not models:
        return None
    if preferred is not None:
        exact = next((model for model in models if model.name == preferred), None)
        if exact is not None:
            return exact
    return min(models, key=lambda model: model.size_bytes)


def missing_model_guidance(model_name: str) -> str:
    """Setup guidance for a missing model; never an automatic pull."""
    return (
        f"model {model_name!r} is not installed locally; pull it explicitly with "
        f"'ollama pull {model_name}' after an admin decision"
    )


def pull_allowed(*, size_bytes: int, explicit_admin_action: bool) -> tuple[bool, str | None]:
    """Large-model pull policy: only an explicit admin action can allow a pull."""
    if not explicit_admin_action:
        return False, "a model pull requires an explicit admin action"
    if size_bytes > MAX_AUTO_PULL_BYTES:
        return (
            explicit_admin_action,
            "large model pull allowed only after explicit admin action",
        )
    return True, None


def build_generate_request(
    base_url: str,
    *,
    model: str,
    prompt: str,
    format_json: bool = False,
    images: Sequence[str] = (),
    stream: bool = False,
    options: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Build a native ``/api/generate`` request; streaming off unless needed."""
    if not NAME_RE.match(model):
        raise OllamaAdapterError("invalid_model", f"model name {model!r} is not safe")
    payload: dict[str, Any] = {"model": model, "prompt": prompt, "stream": stream}
    if format_json:
        payload["format"] = "json"
    if images:
        payload["images"] = [
            base64.b64encode(image.encode("utf-8")).decode("ascii") for image in images
        ]
    if options:
        payload["options"] = dict(options)
    return {
        "version": OLLAMA_ADAPTER_VERSION,
        "url": endpoint_for(base_url, GENERATE_PATH),
        "method": "POST",
        "headers": {"Content-Type": "application/json"},
        "json": payload,
        "task": "text",
        "model": model,
        "timeout_seconds": 120,
    }


def build_embed_request(base_url: str, *, model: str, inputs: Sequence[str]) -> dict[str, Any]:
    """Build a native ``/api/embed`` request for the declared model."""
    if not NAME_RE.match(model):
        raise OllamaAdapterError("invalid_model", f"model name {model!r} is not safe")
    return {
        "version": OLLAMA_ADAPTER_VERSION,
        "url": endpoint_for(base_url, EMBED_PATH),
        "method": "POST",
        "headers": {"Content-Type": "application/json"},
        "json": {"model": model, "input": list(inputs)},
        "task": "embeddings",
        "model": model,
        "timeout_seconds": 60,
    }


def parse_generate(body_bytes: bytes, *, expect_json: bool = False) -> dict[str, Any]:
    """Parse a ``/api/generate`` response with JSON validation when requested."""
    try:
        body = json.loads(body_bytes.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        raise OllamaAdapterError("malformed_json", "generate response is not valid JSON")
    response = body.get("response")
    if not isinstance(response, str) or not response:
        raise OllamaAdapterError("empty_response", "generate returned no usable response")
    if expect_json:
        try:
            structured = json.loads(response)
        except json.JSONDecodeError:
            raise OllamaAdapterError(
                "invalid_json_output", "model output is not valid JSON for the requested format"
            )
        return {"response": response, "structured": structured, "done": bool(body.get("done"))}
    return {"response": response, "done": bool(body.get("done"))}


def parse_embed(body_bytes: bytes) -> list[list[float]]:
    """Parse a ``/api/embed`` response into a list of embedding vectors."""
    try:
        body = json.loads(body_bytes.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        raise OllamaAdapterError("malformed_json", "embed response is not valid JSON")
    embeddings = body.get("embeddings")
    if not isinstance(embeddings, list) or not embeddings:
        raise OllamaAdapterError("empty_embeddings", "embed returned no embeddings")
    vectors: list[list[float]] = []
    for vector in embeddings:
        if not isinstance(vector, list):
            continue
        if all(isinstance(value, int | float) for value in vector):
            vectors.append([float(value) for value in vector])
    if not vectors:
        raise OllamaAdapterError("empty_embeddings", "embed returned no usable vectors")
    return vectors


def negotiate_capabilities(model_details: Mapping[str, Any]) -> ProviderCapabilities:
    """Negotiate provider capabilities from ``/api/show`` model details."""
    capabilities = set(model_details.get("capabilities") or ())
    modalities = {"text"}
    if VISION_CAPABILITY in capabilities:
        modalities.add("image")
    tasks = {"text", "embeddings"}
    if VISION_CAPABILITY in capabilities:
        tasks.add("vision")
    return ProviderCapabilities(
        provider="ollama",
        model=str(model_details.get("model") or "unknown"),
        mode="local",
        supported_tasks=frozenset(tasks),
        modalities=frozenset(modalities),
        max_input_bytes=int(model_details.get("max_input_bytes") or 4_194_304),
        max_input_images=4 if VISION_CAPABILITY in capabilities else 0,
        max_timeout_seconds=int(model_details.get("max_timeout_seconds") or 120),
        streaming=False,
    )


def call_with_cancel(
    request: Mapping[str, Any], transport: Transport, token: CancellationToken
) -> Mapping[str, Any]:
    """Route a request through the transport, honouring cancellation."""
    token.check()
    validate_endpoint(str(request.get("url") or ""))
    try:
        response = transport(request)
    except Exception as exc:
        raise OllamaAdapterError("unavailable", f"endpoint unavailable: {exc}") from exc
    token.check()
    if not isinstance(response, Mapping):
        raise OllamaAdapterError("bad_transport", "transport must return a mapping")
    return response


def redact_message(message: str) -> str:
    """Redact known secret patterns from messages before logging or surfacing."""
    redacted = message
    for pattern in SECRET_PATTERNS:
        redacted = pattern.sub(REDACTED, redacted)
    return redacted


def endpoint_for(base_url: str, path: str) -> str:
    """Join a base URL with a native Ollama API path."""
    try:
        validate_endpoint(base_url)
    except Exception as exc:
        raise OllamaAdapterError("unsafe_endpoint", f"endpoint violates policy: {exc}") from exc
    return f"{base_url.rstrip('/')}{path}"


def _nonnegative_int(value: Any) -> int:
    if isinstance(value, bool):
        return 0
    if isinstance(value, int) and value >= 0:
        return value
    return 0
