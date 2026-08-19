"""OpenAI-compatible LAN endpoint adapter (RPR-085).

Configures a base URL/model adapter for compatible local services (llama.cpp,
vLLM, LM Studio, Ollama's OpenAI shim, ...) with structured output, vision/
embedding capability negotiation, streaming disabled unless explicitly needed,
and bounded retries. Private/LAN endpoints may use no API key; TLS/auth options
use opaque ``vault:`` secret references. Arbitrary URL redirects are rejected
unless they stay on the configured endpoint host (SSRF policy). Pure and
dependency-free: network I/O is injected as a transport callable.
"""

from __future__ import annotations

import ipaddress
import json
import urllib.parse
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from typing import Any

from worker.provider_contract import (
    REDACTED,
    SECRET_PATTERNS,
    TASK_LIMITS,
    ProviderCapabilities,
    ProviderError,
    provider_capabilities,
)

OPENAI_COMPATIBLE_VERSION = "openai-compatible-v1"

DEFAULT_STREAMING = False
MAX_REDIRECTS = 0
RETRYABLE_HTTP_CODES = frozenset({429, 500, 502, 503, 504})
RETRY_BUDGET = 3
RETRYABLE_CODES = frozenset({"timeout", "rate_limited", "unavailable", "too_large"})

_PRIVATE_NETWORKS = (
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("fc00::/7"),
    ipaddress.ip_network("fe80::/10"),
)

Transport = Callable[[Mapping[str, Any]], Mapping[str, Any]]


class OpenAiCompatibleError(ValueError):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


@dataclass(frozen=True)
class EndpointPolicy:
    scheme: str
    host: str
    port: int | None
    private_or_loopback: bool
    path_prefix: str = ""


def validate_endpoint(base_url: str) -> EndpointPolicy:
    """Validate a LAN endpoint; public hosts are rejected for remote-safe routing."""
    parsed = urllib.parse.urlparse(base_url)
    if parsed.scheme not in {"http", "https"}:
        raise OpenAiCompatibleError("invalid_endpoint", "endpoint scheme must be http or https")
    if not parsed.hostname:
        raise OpenAiCompatibleError("invalid_endpoint", "endpoint requires a host")
    hostname = parsed.hostname
    private = _is_private_or_loopback(hostname)
    if not private:
        raise OpenAiCompatibleError(
            "unsafe_endpoint", "endpoint host must be loopback, private, or link-local"
        )
    return EndpointPolicy(
        scheme=parsed.scheme,
        host=hostname,
        port=parsed.port,
        private_or_loopback=private,
        path_prefix=parsed.path.rstrip("/"),
    )


def no_key_allowed(base_url: str) -> bool:
    """Private/LAN endpoints may be used without an API key."""
    try:
        policy = validate_endpoint(base_url)
    except OpenAiCompatibleError:
        return False
    return policy.private_or_loopback


def validate_redirect(redirect_url: str, base_url: str) -> bool:
    """Redirects are allowed only to the same configured endpoint host."""
    try:
        policy = validate_endpoint(base_url)
        parsed = urllib.parse.urlparse(redirect_url)
        if parsed.scheme not in {"http", "https"}:
            return False
        if not parsed.hostname:
            return False
        return parsed.hostname == policy.host and parsed.port == policy.port
    except OpenAiCompatibleError:
        return False


def endpoint_uri(base_url: str, path: str) -> str:
    """Build an endpoint URL joined to the configured base URL path prefix."""
    policy = validate_endpoint(base_url)
    base_path = policy.path_prefix
    if base_path:
        if not base_path.endswith("/"):
            base_path += "/"
    else:
        base_path = "/"
    target = path.lstrip("/")
    host = policy.host
    if ":" in host and not host.startswith("["):
        host = f"[{host}]"
    authority = host if policy.port is None else f"{host}:{policy.port}"
    return f"{policy.scheme}://{authority}{base_path}{target}"


def resolve_auth(api_key_ref: str | None, secrets: Mapping[str, str] | None) -> str | None:
    """Resolve an opaque secret reference; raw inline keys are rejected."""
    if api_key_ref is None:
        return None
    if not api_key_ref.startswith("vault:"):
        raise OpenAiCompatibleError(
            "inline_secret", "API keys must be referenced as opaque vault secrets"
        )
    if secrets is None or api_key_ref not in secrets:
        raise OpenAiCompatibleError("missing_secret", f"secret {api_key_ref!r} is not available")
    return secrets[api_key_ref]


def build_request(
    *,
    base_url: str,
    model: str,
    task: str,
    api_key_ref: str | None = None,
    secrets: Mapping[str, str] | None = None,
    messages: list[Mapping[str, Any] | str] | None = None,
    json_schema: Mapping[str, Any] | None = None,
    stream: bool = DEFAULT_STREAMING,
) -> dict[str, Any]:
    """Build a request payload; streaming is off unless explicitly requested."""
    limits = TASK_LIMITS.get(task)
    if limits is None:
        raise OpenAiCompatibleError("unsupported_task", f"task {task!r} is not supported")
    payload: dict[str, Any] = {"model": model, "stream": stream}
    if json_schema is not None:
        payload["response_format"] = {"type": "json_schema", "json_schema": json_schema}
    payload["messages" if task != "embeddings" else "input"] = messages or []
    headers: dict[str, str] = {"Content-Type": "application/json"}
    auth = resolve_auth(api_key_ref, secrets)
    if auth is not None:
        headers["Authorization"] = f"Bearer {auth}"
    return {
        "version": OPENAI_COMPATIBLE_VERSION,
        "url": endpoint_uri(
            base_url, "/v1/chat/completions" if task != "embeddings" else "/v1/embeddings"
        ),
        "method": "POST",
        "headers": headers,
        "json": payload,
        "task": task,
        "model": model,
        "timeout_seconds": limits.max_timeout_seconds,
        "retry_budget": RETRY_BUDGET,
    }


def should_retry(code: str, http_status: int | None, attempt: int) -> bool:
    """Bounded retry for retryable codes or transient HTTP statuses."""
    if attempt >= RETRY_BUDGET:
        return False
    if code in RETRYABLE_CODES:
        return True
    return http_status in RETRYABLE_HTTP_CODES


def retry_delay_seconds(attempt: int, *, base: float = 0.5, cap: float = 4.0) -> float:
    """Exponential backoff with a hard cap; deterministic and bounded."""
    delay: float = float(base * (2 ** max(attempt, 0)))
    return min(delay, cap)


def parse_completion(
    body_bytes: bytes,
    *,
    model: str,
    task: str,
    json_schema: Mapping[str, Any] | None = None,
) -> ProviderError | dict[str, Any]:
    """Parse a completion/embedding response; malformed JSON is a typed error."""
    try:
        body = json.loads(body_bytes.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        return ProviderError(
            schema_version="provider-contract/v1",
            task=task,
            provider="openai-compatible",
            model=model,
            code="malformed_json",
            message="provider returned malformed JSON",
            retryable=False,
            redacted=True,
        )
    if task == "embeddings":
        data = body.get("data")
        if isinstance(data, list) and data and isinstance(data[0], dict):
            embedding = data[0].get("embedding")
            if isinstance(embedding, list):
                return {
                    "content": "",
                    "embedding": embedding,
                    "evidence": (),
                    "redacted": False,
                }
    choices = body.get("choices")
    if isinstance(choices, list) and choices:
        message = choices[0].get("message") or choices[0]
        content = message.get("content")
        if isinstance(content, str):
            if json_schema is not None:
                try:
                    parsed = json.loads(content)
                except json.JSONDecodeError:
                    return ProviderError(
                        schema_version="provider-contract/v1",
                        task=task,
                        provider="openai-compatible",
                        model=model,
                        code="invalid_structured_output",
                        message="structured output did not match the requested JSON schema",
                        retryable=True,
                        redacted=True,
                    )
                return {
                    "content": content,
                    "structured": parsed,
                    "evidence": (),
                    "redacted": False,
                }
            return {"content": content, "evidence": (), "redacted": False}
    return ProviderError(
        schema_version="provider-contract/v1",
        task=task,
        provider="openai-compatible",
        model=model,
        code="empty_response",
        message="provider returned no usable completion",
        retryable=False,
        redacted=True,
    )


def negotiate_capabilities(profile: Mapping[str, Any]) -> ProviderCapabilities:
    """Negotiate capabilities from a provider profile record."""
    return provider_capabilities(profile)


def redact_message(message: str) -> str:
    """Redact known secret patterns from messages before logging or surfacing."""
    redacted = message
    for pattern in SECRET_PATTERNS:
        redacted = pattern.sub(REDACTED, redacted)
    return redacted


def call_adapter(request: Mapping[str, Any], transport: Transport) -> Mapping[str, Any]:
    """Route a built request through an injected transport with redirect policy."""
    if not isinstance(request.get("url"), str) or not request["url"]:
        raise OpenAiCompatibleError("invalid_request", "request has no url")
    try:
        validate_endpoint(request["url"])
    except OpenAiCompatibleError as exc:
        raise OpenAiCompatibleError(
            "ssrf_blocked", f"request url violates endpoint policy: {exc}"
        ) from exc
    response = transport(request)
    if not isinstance(response, Mapping):
        raise OpenAiCompatibleError("bad_transport", "transport must return a mapping")
    return response


def _is_private_or_loopback(hostname: str) -> bool:
    if hostname in {"localhost"} or hostname.endswith(".localhost"):
        return True
    if hostname.endswith(".local") or hostname.endswith(".lan"):
        return True
    try:
        address = ipaddress.ip_address(hostname)
    except ValueError:
        return False
    return any(address in network for network in _PRIVATE_NETWORKS)
