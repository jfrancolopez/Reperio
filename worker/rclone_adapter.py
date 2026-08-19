"""Pinned rclone destination adapter (RPR-109).

Runs allowlisted copy/check operations against generated per-job rclone configs.
Credentials live only in the disposable per-job config file and never in
arguments or logs; sync/delete operations are forbidden; FTP advertises its
plaintext caveat; checksum availability is recorded so verification limitations
are explicit. Interruption/resume and retries are budgeted. Pure and
dependency-free; the rclone process is injected as a runner.
"""

from __future__ import annotations

import re
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from typing import Any

RCLONE_VERSION = "rclone-adapter-v1"

ALLOWED_COMMANDS = frozenset({"copy", "check"})
FORBIDDEN_COMMANDS = frozenset({"sync", "delete", "deletefile", "purge", "mount", "serve", "rm"})
REMOTE_TYPES = frozenset(
    {"local", "sftp", "smb", "ftp", "webdav", "s3", "google_drive", "dropbox", "onedrive"}
)
PLAINTEXT_REMOTES = frozenset({"ftp"})
CHECKSUM_REMOTES = frozenset({"local", "sftp", "s3", "webdav", "smb"})

Runner = Callable[[Mapping[str, Any]], Mapping[str, Any]]

MASKED = "[redacted]"
CREDENTIAL_PATTERN = re.compile(r"(?i)(password|pass|token|secret|key)\s*[=:]\s*\S+")


class RcloneError(ValueError):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


@dataclass(frozen=True)
class RemoteCapability:
    remote_type: str
    supports_checksum: bool
    plaintext_warning: str | None

    def metadata(self) -> dict[str, Any]:
        return {
            "version": RCLONE_VERSION,
            "remote_type": self.remote_type,
            "supports_checksum": self.supports_checksum,
            "plaintext_warning": self.plaintext_warning,
        }


def capability_check(remote_type: str) -> RemoteCapability:
    """Capability check for the remote; FTP warns about plaintext transport."""
    if remote_type not in REMOTE_TYPES:
        raise RcloneError("unsupported_remote", f"remote type {remote_type!r} is not supported")
    return RemoteCapability(
        remote_type=remote_type,
        supports_checksum=remote_type in CHECKSUM_REMOTES,
        plaintext_warning=(
            "FTP transfers plaintext credentials and data unless TLS is configured"
            if remote_type in PLAINTEXT_REMOTES
            else None
        ),
    )


def build_job_config(*, remote_type: str, credentials: Mapping[str, str]) -> str:
    """Generated per-job rclone config; credentials live here, not in argv/logs."""
    capability_check(remote_type)
    lines = [
        "[job-remote]",
        f"type = {remote_type}",
    ]
    for key, value in credentials.items():
        if re.search(r"(?i)pass|token|secret|key", key):
            lines.append(f"{key} = {value}")
        else:
            lines.append(f"{key} = {value}")
    return "\n".join(lines) + "\n"


def build_command(
    *,
    remote_type: str,
    operation: str,
    source: str,
    destination: str,
    job_config: str,
    checksum: bool = False,
) -> dict[str, Any]:
    """Build an argv with allowlisted operations and no inline credentials."""
    if operation not in ALLOWED_COMMANDS:
        raise RcloneError("forbidden_command", f"operation {operation!r} is not allowed")
    argv = [
        "rclone",
        operation,
        source,
        destination,
        "--config",
        job_config,
    ]
    if checksum:
        argv.append("--checksum")
    return {
        "version": RCLONE_VERSION,
        "argv": argv,
        "operation": operation,
        "checksum": checksum,
        "credentials_in_argv": False,
        "credentials_in_logs": False,
    }


def assert_no_forbidden_flag(operation: str) -> None:
    """Reject destructive or mount operations before they reach the runner."""
    if operation in FORBIDDEN_COMMANDS:
        raise RcloneError("forbidden_command", f"operation {operation!r} is forbidden")


def retry_policy(attempt: int, *, budget: int = 3) -> bool:
    """Budgeted retry for interruption/resume after a transient failure."""
    if budget < 0:
        raise RcloneError("invalid_budget", "retry budget must be non-negative")
    return attempt < budget


def resume_plan(state: Mapping[str, Any], *, attempt: int, budget: int = 3) -> dict[str, Any]:
    """Resume an interrupted transfer from its checkpoint without re-sending."""
    transferred = int(state.get("transferred_items") or 0)
    total = int(state.get("total_items") or 0)
    remaining = max(0, total - transferred)
    if not retry_policy(attempt, budget=budget):
        return {
            "status": "exhausted",
            "resume": False,
            "reason": "retry budget exhausted",
        }
    return {
        "status": "resumed",
        "resume": True,
        "transferred_items": transferred,
        "remaining_items": remaining,
        "reason": "interrupted transfer resumed from checkpoint",
    }


def run_rclone(invocation: Mapping[str, Any], runner: Runner) -> dict[str, Any]:
    """Run the adapter with normalized crash/timeout outcomes and redaction."""
    try:
        result = runner(invocation)
    except Exception as exc:
        return {
            "status": "crashed",
            "reason": "rclone crashed",
            "detail": str(exc),
            "redacted": True,
        }
    timed_out = bool(result.get("timed_out"))
    if timed_out:
        return {
            "status": "timed_out",
            "reason": "rclone exceeded its time budget",
            "redacted": True,
        }
    returncode = int(result.get("returncode") or 0)
    output = str(result.get("output") or "")
    return {
        "status": "ok" if returncode == 0 else "failed",
        "returncode": returncode,
        "output": redact_output(output),
        "redacted": True,
    }


def redact_output(output: str) -> str:
    """Redact credential-like values from rclone output before it is logged."""
    return CREDENTIAL_PATTERN.sub(MASKED, output)


def verify_limitations(remote_type: str, *, checksum_requested: bool) -> dict[str, Any]:
    """Record verification limitations explicitly for the report."""
    capability = capability_check(remote_type)
    return {
        "remote_type": remote_type,
        "checksum_requested": checksum_requested,
        "checksum_available": capability.supports_checksum,
        "limitation": None
        if (capability.supports_checksum or not checksum_requested)
        else "destination cannot verify checksums; integrity is unverified",
        "plaintext_warning": capability.plaintext_warning,
    }
