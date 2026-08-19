"""Ordered provider profile settings and non-content health checks (RPR-084).

Profiles are named, ordered, and independently enableable. Each profile carries
a local/remote mode, endpoint, model, eligible AI tasks and finding categories,
a routing weight, timeout, and an opaque secret reference. Remote profiles are
disabled until the operator acknowledges the remote gate. Health checks are
strictly non-content: they probe endpoint/model capability and never send user
or recovered content.
"""

from __future__ import annotations

import re
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, replace
from typing import Any

from worker.provider_contract import (
    MODES,
    TASKS,
    ProviderCapabilities,
    provider_capabilities,
)

PROFILE_SETTINGS_VERSION = "provider-settings-v1"
SECRET_REF_PREFIX = "vault:"
PROFILE_NAME_RE = re.compile(r"^[a-z][a-z0-9_-]{0,63}$")
LOCAL_ENDPOINTS = frozenset({"local", "ollama://local", "openai-compatible://local"})

FINDING_CATEGORIES = frozenset(
    {
        "media",
        "documents",
        "archives",
        "messages/email",
        "browser",
        "backups/mobile",
        "wallets/vaults/keys",
        "software/code/databases",
        "deleted/carved",
        "corrupted",
        "unknown",
        "system/noise",
    }
)

HealthChecker = Callable[[str, str], Mapping[str, Any]]


class ProviderSettingsError(ValueError):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


@dataclass(frozen=True)
class ProviderProfile:
    name: str
    enabled: bool
    mode: str
    endpoint: str
    model: str
    tasks: frozenset[str]
    categories: frozenset[str]
    weight: int
    timeout_seconds: int
    api_key_ref: str | None
    capabilities: ProviderCapabilities | None = None

    @property
    def is_remote(self) -> bool:
        return self.mode == "remote"


@dataclass(frozen=True)
class ProviderSettings:
    version: str
    profiles: tuple[ProviderProfile, ...]
    remote_acknowledged: bool

    def profile_by_name(self, name: str) -> ProviderProfile | None:
        for profile in self.profiles:
            if profile.name == name:
                return profile
        return None

    def enabled_profiles(self) -> tuple[ProviderProfile, ...]:
        return tuple(profile for profile in self.profiles if profile.enabled)


@dataclass(frozen=True)
class HealthResult:
    profile: str
    reachable: bool
    model_status: str
    mode: str
    warnings: tuple[str, ...] = ()
    parser_version: str = PROFILE_SETTINGS_VERSION


def normalize_provider_settings(
    records: Sequence[Mapping[str, Any]],
    *,
    remote_acknowledged: bool = False,
) -> ProviderSettings:
    """Build ordered provider settings, rejecting duplicate names and invalid fields.

    A remote profile that is enabled while ``remote_acknowledged`` is false does
    not raise here; callers must route through :func:`ensure_remote_gate` before
    any remote call. ``remote_acknowledged`` is treated as an explicit operator
    acknowledgment of every current remote profile.
    """
    profiles: list[ProviderProfile] = []
    seen: set[str] = set()
    for index, record in enumerate(records):
        name = _required_str(record, "name")
        if name in seen:
            raise ProviderSettingsError(
                "duplicate_profile", f"provider profile {name!r} is defined more than once"
            )
        seen.add(name)
        profiles.append(_normalize_profile(name, record, index))

    return ProviderSettings(
        version=PROFILE_SETTINGS_VERSION,
        profiles=tuple(profiles),
        remote_acknowledged=bool(remote_acknowledged),
    )


def validate_provider_settings(settings: ProviderSettings) -> tuple[str, ...]:
    """Return structural warnings that do not block loading (e.g. weak config)."""
    warnings: list[str] = []
    for profile in settings.profiles:
        if (
            profile.is_remote
            and profile.api_key_ref is None
            and profile.endpoint not in LOCAL_ENDPOINTS
        ):
            warnings.append(f"{profile.name}:remote_profile_without_secret_reference")
        if not profile.enabled:
            warnings.append(f"{profile.name}:profile_disabled")
        if (
            profile.capabilities is not None
            and profile.timeout_seconds > profile.capabilities.max_timeout_seconds
        ):
            warnings.append(f"{profile.name}:timeout_exceeds_capability")
    return tuple(warnings)


def ensure_remote_gate(settings: ProviderSettings) -> None:
    """Raise when any enabled remote profile lacks the operator acknowledgment."""
    if settings.remote_acknowledged:
        return
    remote = [profile.name for profile in settings.enabled_profiles() if profile.is_remote]
    if remote:
        raise ProviderSettingsError(
            "remote_gate_not_acknowledged",
            "remote provider profiles require explicit acknowledgment: "
            + ", ".join(sorted(remote)),
        )


def remote_enabled_profiles(settings: ProviderSettings) -> tuple[ProviderProfile, ...]:
    return tuple(profile for profile in settings.profiles if profile.enabled and profile.is_remote)


def route_profiles(settings: ProviderSettings, task: str) -> tuple[ProviderProfile, ...]:
    """Return enabled profiles eligible for ``task``, ordered by descending weight."""
    eligible = [
        profile
        for profile in settings.enabled_profiles()
        if task in profile.tasks
        and (profile.capabilities is None or profile.capabilities.supports(task))
    ]
    return tuple(sorted(eligible, key=lambda profile: profile.weight, reverse=True))


def select_primary_secondary_tertiary(
    settings: ProviderSettings, task: str
) -> tuple[ProviderProfile | None, ProviderProfile | None, ProviderProfile | None]:
    """Select primary/secondary/tertiary opinions for one task from the ordered set."""
    routed = route_profiles(settings, task)
    return (
        routed[0] if len(routed) > 0 else None,
        routed[1] if len(routed) > 1 else None,
        routed[2] if len(routed) > 2 else None,
    )


def reorder_profiles(settings: ProviderSettings, order: list[str]) -> ProviderSettings:
    """Return settings with profiles reordered; unknown names are rejected."""
    known = {profile.name for profile in settings.profiles}
    if len(order) != len(known) or set(order) != known:
        raise ProviderSettingsError(
            "invalid_profile_order", "order must name every profile exactly once"
        )
    by_name = {profile.name: profile for profile in settings.profiles}
    return replace(settings, profiles=tuple(by_name[name] for name in order))


def health_check(profile: ProviderProfile, checker: HealthChecker) -> HealthResult:
    """Run a non-content health test for one profile.

    ``checker`` probes the endpoint/model and must never receive user content,
    recovered bytes, prompts, or document text. A missing model or unreachable
    endpoint is reported as status, not silently fixed.
    """
    warnings: list[str] = []
    try:
        report = dict(checker(profile.endpoint, profile.model))
    except Exception as error:  # pragma: no cover - checker boundary
        return HealthResult(
            profile.name,
            False,
            "unknown",
            profile.mode,
            (f"health_check_error:{type(error).__name__}",),
        )
    reachable = bool(report.get("reachable"))
    model_status = str(report.get("model_status") or "unknown")
    if not reachable:
        warnings.append("endpoint_unreachable")
    if model_status not in {"present", "missing", "unknown"}:
        warnings.append(f"invalid_model_status:{model_status}")
    if (
        profile.capabilities is not None
        and profile.timeout_seconds > profile.capabilities.max_timeout_seconds
    ):
        warnings.append("timeout_exceeds_capability")
    return HealthResult(profile.name, reachable, model_status, profile.mode, tuple(warnings))


def _normalize_profile(name: str, record: Mapping[str, Any], index: int) -> ProviderProfile:
    if not PROFILE_NAME_RE.fullmatch(name):
        raise ProviderSettingsError(
            "invalid_profile_name", f"profile name {name!r} is not a safe identifier"
        )
    mode = str(record.get("mode") or "local")
    if mode not in MODES:
        raise ProviderSettingsError("invalid_mode", f"{name}: mode must be local or remote")
    if "endpoint" in record and not str(record.get("endpoint") or "").strip():
        raise ProviderSettingsError("missing_endpoint", f"{name}: endpoint is required")
    endpoint = str(record.get("endpoint") or ("local" if mode == "local" else ""))
    if not endpoint:
        raise ProviderSettingsError("missing_endpoint", f"{name}: endpoint is required")
    if mode == "remote" and endpoint in LOCAL_ENDPOINTS:
        raise ProviderSettingsError(
            "remote_endpoint_conflict", f"{name}: local endpoint cannot be used for remote mode"
        )
    model = str(record.get("model") or "")
    if not model or ".." in model:
        raise ProviderSettingsError("missing_model", f"{name}: model is required")
    tasks = _keyword_set(record.get("tasks"), TASKS, "unsupported_task", name)
    categories = _keyword_set(
        record.get("categories"), FINDING_CATEGORIES, "unsupported_category", name
    )
    if not tasks:
        raise ProviderSettingsError("no_eligible_tasks", f"{name}: profile lists no eligible tasks")
    weight = _nonnegative_int(record.get("weight"), f"{name}:weight")
    timeout_seconds = _positive_int(record.get("timeout_seconds"), f"{name}:timeout_seconds")
    api_key_ref = record.get("api_key_ref")
    if api_key_ref is not None:
        if not isinstance(api_key_ref, str) or not api_key_ref.startswith(SECRET_REF_PREFIX):
            raise ProviderSettingsError(
                "inline_secret_rejected",
                f"{name}: api key must be an opaque vault reference, never inline",
            )

    capabilities: ProviderCapabilities | None = None
    raw_capabilities = record.get("capabilities")
    if raw_capabilities is not None:
        if not isinstance(raw_capabilities, Mapping):
            raise ProviderSettingsError(
                "malformed_capability", f"{name}: capabilities must be an object"
            )
        capabilities = provider_capabilities(raw_capabilities)

    return ProviderProfile(
        name=name,
        enabled=bool(record.get("enabled", True)),
        mode=mode,
        endpoint=endpoint,
        model=model,
        tasks=frozenset(tasks),
        categories=frozenset(categories),
        weight=weight,
        timeout_seconds=timeout_seconds,
        api_key_ref=api_key_ref,
        capabilities=capabilities,
    )


def _required_str(record: Mapping[str, Any], name: str) -> str:
    value = str(record.get(name) or "")
    if not value:
        raise ProviderSettingsError("missing_name", f"{name} is required")
    return value


def _keyword_set(value: object, allowed: frozenset[str], error_code: str, name: str) -> set[str]:
    if not isinstance(value, list | tuple):
        raise ProviderSettingsError("malformed_keywords", f"{name}: keyword field must be a list")
    result: set[str] = set()
    for item in value:
        keyword = str(item)
        if keyword not in allowed:
            raise ProviderSettingsError(error_code, f"{name}: unknown keyword {keyword!r}")
        result.add(keyword)
    return result


def _positive_int(value: object, label: str) -> int:
    if not isinstance(value, int) or value <= 0:
        raise ProviderSettingsError("invalid_integer", f"{label} must be a positive integer")
    return value


def _nonnegative_int(value: object, label: str) -> int:
    if not isinstance(value, int) or value < 0:
        raise ProviderSettingsError("invalid_integer", f"{label} must be a non-negative integer")
    return value
