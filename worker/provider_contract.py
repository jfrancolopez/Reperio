"""Versioned provider and task contract schemas with bounded limits.

RPR-083: capability discovery plus structured request/result/error schemas for
text, vision, embeddings, translation, classification, and summarization tasks.
Providers can never request tools or paths; every normalized result names its
provider/model/task/prompt version/schema version and evidence references.
"""

from __future__ import annotations

import re
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

CONTRACT_VERSION = "provider-contract-v1"
SCHEMA_VERSION = "reperio/provider-contract/v1"
TASKS = frozenset(
    {"text", "vision", "embeddings", "translation", "classification", "summarization"}
)
MODALITIES = frozenset({"text", "image", "audio"})
MODES = frozenset({"local", "remote"})
CONTENT_URI_RE = re.compile(r"^(?:content|scratch)://sha256/[0-9a-f]{64}$")
EVIDENCE_REF_RE = re.compile(r"^[a-z_]+:[0-9a-z_-]{6,}$")
IDENTIFIER_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:\-]{0,127}$")
RESPONSE_REQUESTING_ACCESS = frozenset(
    {
        "tool",
        "tool_call",
        "tool_calls",
        "tool_use",
        "function_call",
        "file_path",
        "source_path",
        "device",
        "read_file",
        "write_file",
        "command",
        "executable",
        "mount",
        "shell",
    }
)
RETRYABLE_CODES = frozenset({"timeout", "rate_limited", "unavailable", "too_large"})
SECRET_PATTERNS = (
    re.compile(r"sk-[A-Za-z0-9_\-]{16,}"),
    re.compile(r"vault:[0-9a-f]{32}"),
    re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
    re.compile(r"(?i)api[_-]?key\s*[=:]\s*\S{8,}"),
    re.compile(r"(?i)bearer\s+[a-z0-9._~+/\-]{16,}"),
    re.compile(r"(?i)password\s*[=:]\s*\S{8,}"),
)
REDACTED = "[redacted]"


class ProviderContractError(ValueError):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


@dataclass(frozen=True)
class TaskLimits:
    task: str
    modalities: frozenset[str]
    max_input_bytes: int
    max_input_characters: int
    max_input_images: int
    max_timeout_seconds: int
    max_output_characters: int


TASK_LIMITS: dict[str, TaskLimits] = {
    "text": TaskLimits("text", frozenset({"text"}), 262_144, 200_000, 0, 60, 40_000),
    "vision": TaskLimits("vision", frozenset({"image", "text"}), 4_194_304, 50_000, 4, 120, 40_000),
    "embeddings": TaskLimits("embeddings", frozenset({"text"}), 524_288, 400_000, 0, 60, 16_384),
    "translation": TaskLimits("translation", frozenset({"text"}), 262_144, 200_000, 0, 60, 80_000),
    "classification": TaskLimits(
        "classification", frozenset({"text"}), 262_144, 200_000, 0, 60, 4_000
    ),
    "summarization": TaskLimits(
        "summarization", frozenset({"text"}), 262_144, 200_000, 0, 60, 20_000
    ),
}


@dataclass(frozen=True)
class ProviderCapabilities:
    provider: str
    model: str
    mode: str
    supported_tasks: frozenset[str]
    modalities: frozenset[str]
    max_input_bytes: int
    max_input_images: int
    max_timeout_seconds: int
    streaming: bool
    parser_version: str = CONTRACT_VERSION

    def supports(self, task: str, *, modality: str | None = None) -> bool:
        limits = TASK_LIMITS.get(task)
        if limits is None or task not in self.supported_tasks:
            return False
        if not limits.modalities.issubset(self.modalities):
            return False
        return modality is None or modality in self.modalities

    def supports_modality(self, modality: str) -> bool:
        return modality in self.modalities


@dataclass(frozen=True)
class ProviderRequest:
    schema_version: str
    task: str
    provider: str
    model: str
    prompt_version: str
    mode: str
    input_refs: tuple[str, ...]
    evidence_refs: tuple[str, ...]
    limits: TaskLimits
    input_bytes: int
    input_images: int
    parser_version: str = CONTRACT_VERSION


@dataclass(frozen=True)
class ProviderResult:
    schema_version: str
    task: str
    provider: str
    model: str
    prompt_version: str
    content: str
    evidence: tuple[str, ...]
    confidence: float | None
    usage: Mapping[str, int]
    redacted: bool
    warnings: tuple[str, ...]
    parser_version: str = CONTRACT_VERSION


@dataclass(frozen=True)
class ProviderError:
    schema_version: str
    task: str
    provider: str
    model: str
    code: str
    message: str
    retryable: bool
    redacted: bool
    parser_version: str = CONTRACT_VERSION


def provider_capabilities(record: Mapping[str, Any]) -> ProviderCapabilities:
    """Normalize and validate a provider's declared capability record."""
    provider = _required_str(record, "provider")
    model = _required_str(record, "model")
    mode = str(record.get("mode") or "local")
    if mode not in MODES:
        raise ProviderContractError("invalid_mode", "provider mode must be local or remote")
    tasks = _keyword_set(record.get("tasks"), TASKS, "unsupported_task")
    modalities = _keyword_set(record.get("modalities"), MODALITIES, "unsupported_modality")
    if not tasks:
        raise ProviderContractError("malformed_capability", "provider declares no tasks")
    if not modalities:
        raise ProviderContractError("malformed_capability", "provider declares no modalities")
    max_input_bytes = _positive_int(record.get("max_input_bytes"), "limit_input_bytes")
    max_input_images = _nonnegative_int(record.get("max_input_images"), "limit_input_images")
    max_timeout_seconds = _positive_int(record.get("max_timeout_seconds"), "limit_timeout_seconds")
    return ProviderCapabilities(
        provider=provider,
        model=model,
        mode=mode,
        supported_tasks=frozenset(tasks),
        modalities=frozenset(modalities),
        max_input_bytes=max_input_bytes,
        max_input_images=max_input_images,
        max_timeout_seconds=max_timeout_seconds,
        streaming=bool(record.get("streaming")),
    )


def require_supported(capabilities: ProviderCapabilities, task: str) -> None:
    if not capabilities.supports(task):
        raise ProviderContractError(
            "unsupported_task", f"provider {capabilities.provider} does not support task {task!r}"
        )


def require_modality(capabilities: ProviderCapabilities, modality: str) -> None:
    if not capabilities.supports_modality(modality):
        raise ProviderContractError(
            "unsupported_modality",
            f"provider {capabilities.provider} does not support modality {modality!r}",
        )


def build_request(
    *,
    task: str,
    provider: str,
    model: str,
    prompt_version: str,
    mode: str,
    input_refs: tuple[str, ...] = (),
    evidence_refs: tuple[str, ...] = (),
    input_bytes: int = 0,
    input_images: int = 0,
) -> ProviderRequest:
    """Build a versioned, bounded request that contains no tools or paths."""
    limits = TASK_LIMITS.get(task)
    if limits is None:
        raise ProviderContractError("unsupported_task", "task is not defined in the contract")
    if mode not in MODES:
        raise ProviderContractError("invalid_mode", "request mode must be local or remote")
    if not _safe_identifier(provider):
        raise ProviderContractError("invalid_provider", "provider name is not a safe identifier")
    if not _safe_identifier(model):
        raise ProviderContractError("invalid_model", "model name is not a safe identifier")
    if not _safe_identifier(prompt_version):
        raise ProviderContractError("invalid_prompt", "prompt version is not a safe identifier")
    for ref in input_refs:
        if not CONTENT_URI_RE.fullmatch(ref):
            raise ProviderContractError(
                "request_path_rejected", "provider inputs must be content URIs, never paths"
            )
    for ref in evidence_refs:
        if not EVIDENCE_REF_RE.fullmatch(ref):
            raise ProviderContractError(
                "invalid_evidence_ref", "evidence references must be finding/evidence refs"
            )
    if input_bytes > limits.max_input_bytes:
        raise ProviderContractError(
            "request_size_limit", "input package exceeds the task byte budget"
        )
    if input_images > limits.max_input_images:
        raise ProviderContractError(
            "request_image_limit", "input package exceeds the task image budget"
        )
    return ProviderRequest(
        schema_version=SCHEMA_VERSION,
        task=task,
        provider=provider,
        model=model,
        prompt_version=prompt_version,
        mode=mode,
        input_refs=tuple(input_refs),
        evidence_refs=tuple(evidence_refs),
        limits=limits,
        input_bytes=input_bytes,
        input_images=input_images,
    )


def normalize_result(
    record: Mapping[str, Any],
    *,
    expected: ProviderRequest,
    max_output_characters: int | None = None,
) -> ProviderResult:
    """Validate and normalize a provider result, rejecting tool/path requests."""
    _reject_access_requests(record)
    schema_version = str(record.get("schema_version") or "")
    if schema_version != SCHEMA_VERSION:
        raise ProviderContractError(
            "malformed_output", "provider result is missing the contract schema version"
        )
    task = str(record.get("task") or "")
    provider = str(record.get("provider") or "")
    model = str(record.get("model") or "")
    prompt_version = str(record.get("prompt_version") or "")
    if (task, provider, model, prompt_version) != (
        expected.task,
        expected.provider,
        expected.model,
        expected.prompt_version,
    ):
        raise ProviderContractError(
            "identity_mismatch", "provider result does not name its request identity"
        )
    content = record.get("content")
    if not isinstance(content, str) or not content:
        raise ProviderContractError("malformed_output", "provider result has no text content")
    limit = max_output_characters or expected.limits.max_output_characters
    if len(content) > limit:
        raise ProviderContractError(
            "output_limit", "provider result exceeds the task output budget"
        )
    raw_evidence = record.get("evidence")
    evidence = _evidence_list(raw_evidence)
    if not evidence:
        raise ProviderContractError("missing_evidence", "provider result has no evidence refs")
    warnings: list[str] = []
    confidence = record.get("confidence")
    norm_confidence: float | None = None
    if confidence is not None:
        if isinstance(confidence, int | float) and 0.0 <= float(confidence) <= 1.0:
            norm_confidence = round(float(confidence), 4)
        else:
            warnings.append("invalid_confidence")
    usage = _usage_map(record.get("usage"))
    redacted_content, redacted = _redact(content)
    if redacted:
        warnings.append("secret_redacted")
    return ProviderResult(
        schema_version=schema_version,
        task=task,
        provider=provider,
        model=model,
        prompt_version=prompt_version,
        content=redacted_content,
        evidence=evidence,
        confidence=norm_confidence,
        usage=usage,
        redacted=redacted,
        warnings=tuple(dict.fromkeys(warnings)),
    )


def normalize_error(
    record: Mapping[str, Any],
    *,
    task: str,
    provider: str,
    model: str,
) -> ProviderError:
    """Normalize a provider error record, redacting secrets and bounding message."""
    schema_version = str(record.get("schema_version") or "")
    if schema_version != SCHEMA_VERSION:
        raise ProviderContractError(
            "malformed_error", "provider error is missing the contract schema version"
        )
    code = str(record.get("code") or "provider_error")
    raw_message = str(record.get("message") or "")[:2_000]
    message, redacted = _redact(raw_message)
    retryable = bool(record.get("retryable")) or code in RETRYABLE_CODES
    return ProviderError(
        schema_version=schema_version,
        task=task,
        provider=provider,
        model=model,
        code=code,
        message=message,
        retryable=retryable,
        redacted=redacted,
    )


def timeout_error(*, task: str, provider: str, model: str) -> ProviderError:
    return ProviderError(
        schema_version=SCHEMA_VERSION,
        task=task,
        provider=provider,
        model=model,
        code="timeout",
        message="provider call exceeded the task timeout budget",
        retryable=True,
        redacted=False,
    )


def _reject_access_requests(record: Mapping[str, Any]) -> None:
    declared = next((key for key in RESPONSE_REQUESTING_ACCESS if key in record), None)
    if declared is not None:
        raise ProviderContractError(
            "provider_requested_access",
            f"provider result requested forbidden access via {declared!r}",
        )
    nested = _nested_access_keys(record.get("choices")) or _nested_access_keys(
        record.get("message")
    )
    if nested is not None:
        raise ProviderContractError(
            "provider_requested_access",
            f"provider result requested forbidden access via {nested!r}",
        )


def _nested_access_keys(value: object) -> str | None:
    if not isinstance(value, Mapping):
        return None
    for key in RESPONSE_REQUESTING_ACCESS:
        if key in value:
            return key
    return None


def _required_str(record: Mapping[str, Any], name: str) -> str:
    value = str(record.get(name) or "")
    if not value:
        raise ProviderContractError("malformed_capability", f"{name} is required")
    return value


def _keyword_set(value: object, allowed: frozenset[str], error_code: str) -> set[str]:
    if not isinstance(value, list | tuple):
        raise ProviderContractError("malformed_capability", "keyword field must be a list")
    result: set[str] = set()
    for item in value:
        keyword = str(item)
        if keyword not in allowed:
            raise ProviderContractError(error_code, f"unknown keyword {keyword!r}")
        result.add(keyword)
    return result


def _evidence_list(value: object) -> tuple[str, ...]:
    if not isinstance(value, list | tuple):
        return ()
    evidence: list[str] = []
    for item in value:
        ref = str(item)
        if EVIDENCE_REF_RE.fullmatch(ref):
            evidence.append(ref)
    return tuple(dict.fromkeys(evidence))


def _usage_map(value: object) -> dict[str, int]:
    if not isinstance(value, Mapping):
        return {}
    usage: dict[str, int] = {}
    for key, item in value.items():
        try:
            usage[str(key)[:64]] = int(item)
        except (TypeError, ValueError):
            continue
    return usage


def _redact(text: str) -> tuple[str, bool]:
    redacted = False
    for pattern in SECRET_PATTERNS:
        if pattern.search(text):
            text = pattern.sub(REDACTED, text)
            redacted = True
    return text, redacted


def _positive_int(value: object, label: str) -> int:
    if not isinstance(value, int) or value <= 0:
        raise ProviderContractError(label, f"{label} must be a positive integer")
    return value


def _nonnegative_int(value: object, label: str) -> int:
    if not isinstance(value, int) or value < 0:
        raise ProviderContractError(label, f"{label} must be a non-negative integer")
    return value


def _safe_identifier(value: str) -> bool:
    return bool(IDENTIFIER_RE.fullmatch(value)) and ".." not in value
