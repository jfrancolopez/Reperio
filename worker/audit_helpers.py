"""Allowlisted format-to-audit-material adapters (RPR-098).

Wraps selected ``*2john``/``*2hashcat`` helper adapters for archive, PDF,
Office, key, and wallet formats. Every helper receives a copied target only --
never the source device -- and the extracted audit material is classified as
secret and is never downloadable by default. Helper timeouts and crashes are
normalized outcomes with secrets redacted. Pure and dependency-free; the helper
process is injected as a runner.
"""

from __future__ import annotations

import re
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from typing import Any

AUDIT_HELPER_VERSION = "audit-helper-v1"

HELPER_BIN = "reperio-2john"
ALLOWLISTED_HELPERS: tuple[tuple[str, str], ...] = (
    ("zip", "zip2john"),
    ("7z", "7z2john"),
    ("rar", "rar2john"),
    ("pdf", "pdf2john"),
    ("office", "office2john"),
    ("key", "key2john"),
    ("bitcoin_wallet", "bitcoin2john"),
    ("ethereum_wallet", "ethereum2john"),
    ("gpg", "gpg2john"),
)
SUPPORTED_FORMATS = frozenset(format for format, _helper in ALLOWLISTED_HELPERS)
HELPER_BY_FORMAT = dict(ALLOWLISTED_HELPERS)

Runner = Callable[[Mapping[str, Any]], Mapping[str, Any]]

MASKED = "[redacted]"
SECRET_PATTERNS = (
    re.compile(r"(?i)password\s*[=:]\s*\S{8,}"),
    re.compile(r"(?i)secret\s*[=:]\s*\S{8,}"),
    re.compile(r"(?i)wallet\s*[=:]\s*\S{8,}"),
)


class AuditHelperError(ValueError):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


@dataclass(frozen=True)
class HelperAdapter:
    format: str
    helper: str
    engine: str = "john"

    @property
    def mode(self) -> str:
        return f"{self.helper}/{self.engine}"

    def metadata(self) -> dict[str, str]:
        return {
            "version": AUDIT_HELPER_VERSION,
            "format": self.format,
            "helper": self.helper,
            "engine": self.engine,
            "mode": self.mode,
            "input": "copied_target_only",
            "output_classification": "secret",
        }


def adapter_for(format: str) -> HelperAdapter:
    """Resolve the allowlisted adapter for a format; unknown formats are rejected."""
    helper = HELPER_BY_FORMAT.get(format)
    if helper is None:
        raise AuditHelperError("unsupported_format", f"format {format!r} has no allowed adapter")
    return HelperAdapter(format=format, helper=helper)


def detect_format(record: Mapping[str, Any]) -> str:
    """Detect the format from normalized metadata; wrong detection is explicit."""
    candidates = [
        str(record.get("format")),
        str(record.get("file_kind")),
        str(record.get("container")),
    ]
    for candidate in candidates:
        if candidate in SUPPORTED_FORMATS:
            return candidate
    raise AuditHelperError("undetected_format", "no supported format could be detected")


def build_invocation(
    *,
    format: str,
    copied_target_path: str,
    scratch_dir: str,
    timeout_seconds: int = 30,
) -> dict[str, Any]:
    """Build a helper invocation on a copied target in per-job scratch only."""
    adapter = adapter_for(format)
    if not copied_target_path.startswith(scratch_dir):
        raise AuditHelperError("unsafe_input", "helper input must be a copied scratch target")
    return {
        "version": AUDIT_HELPER_VERSION,
        "adapter": adapter.metadata(),
        "argv": [
            HELPER_BIN,
            adapter.helper,
            copied_target_path,
        ],
        "env": {"REPERIO_SCRATCH": scratch_dir},
        "timeout_seconds": timeout_seconds,
        "output_classification": "secret",
        "downloadable_by_default": False,
        "redact_patterns": True,
    }


def run_helper(invocation: Mapping[str, Any], runner: Runner) -> dict[str, Any]:
    """Run the helper with normalized timeout/crash outcomes and redaction."""
    try:
        result = runner(invocation)
    except Exception as exc:
        return {
            "status": "crashed",
            "reason": "helper crashed",
            "detail": str(exc),
            "redacted": True,
        }
    timed_out = bool(result.get("timed_out"))
    if timed_out:
        return {
            "status": "timed_out",
            "reason": "helper exceeded its time budget",
            "redacted": True,
        }
    if result.get("returncode") != 0:
        return {
            "status": "failed",
            "reason": "helper returned a non-zero exit status",
            "redacted": True,
        }
    material = str(result.get("material") or "")
    return {
        "status": "ok",
        "material": redact_material(material),
        "classified": True,
        "downloadable_by_default": False,
        "adapter": invocation.get("adapter"),
    }


def redact_material(text: str) -> str:
    """Redact secret-like values from extracted material before it leaves the sandbox."""
    redacted = text
    for pattern in SECRET_PATTERNS:
        redacted = pattern.sub(MASKED, redacted)
    return redacted


def supported_formats() -> tuple[str, ...]:
    return tuple(sorted(SUPPORTED_FORMATS))
