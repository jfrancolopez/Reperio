"""Read-only disk health inspection through a fixed smartctl JSON adapter."""

from __future__ import annotations

import json
import math
import os
import re
import stat
import subprocess
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from typing import Any

SMARTCTL_VERSION = "7.4"
SMARTCTL_COMMAND = "smartctl"
SMARTCTL_TIMEOUT_SECONDS = 10.0
MAX_TIMEOUT_SECONDS = 30.0
MAX_SMARTCTL_OUTPUT_BYTES = 1024 * 1024
MAX_HEALTH_COUNTER = (1 << 63) - 1
KERNEL_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._+-]{0,127}$")
MAJOR_MINOR_RE = re.compile(r"^(0|[1-9][0-9]*):(0|[1-9][0-9]*)$")

HEALTH_FAILURE_ATTRIBUTES = {
    "Reallocated_Sector_Ct": "reallocated_sectors",
    "Current_Pending_Sector": "pending_sectors",
    "Offline_Uncorrectable": "uncorrectable_sectors",
}


class DiskHealthError(ValueError):
    """Raised when disk-health inspection input would widen the safe command."""


@dataclass(frozen=True)
class SmartctlRun:
    """Completed smartctl invocation facts used by the parser and tests."""

    returncode: int
    stdout: str
    stderr: str = ""


SmartctlRunner = Callable[[Sequence[str], float], object]
DeviceIdentityVerifier = Callable[[str, str], bool]


def inspect_disk_health(
    device: Mapping[str, Any],
    *,
    runner: SmartctlRunner | None = None,
    timeout_seconds: float = SMARTCTL_TIMEOUT_SECONDS,
    identity_verifier: DeviceIdentityVerifier | None = None,
) -> dict[str, Any]:
    """Run the fixed read-only smartctl inspection and return normalized facts."""
    kernel_name = str(device.get("kernel_name", ""))
    if not _valid_kernel_name(kernel_name):
        raise DiskHealthError("kernel_name is invalid")
    major_minor = str(device.get("major_minor", ""))
    if not _valid_major_minor(major_minor):
        raise DiskHealthError("major_minor is invalid")
    if (
        isinstance(timeout_seconds, bool)
        or not isinstance(timeout_seconds, int | float)
        or not math.isfinite(timeout_seconds)
        or timeout_seconds <= 0
        or timeout_seconds > MAX_TIMEOUT_SECONDS
    ):
        raise DiskHealthError("timeout_seconds is outside the supported bound")

    command = build_smartctl_command(kernel_name)
    verifier = identity_verifier or _verify_device_identity
    if not verifier(kernel_name, major_minor):
        return _unavailable(device, "device_identity_changed", command)
    try:
        completed = (runner or _run_smartctl)(command, timeout_seconds)
    except FileNotFoundError:
        return _unavailable(device, "missing_tool", command)
    except subprocess.TimeoutExpired:
        return _unavailable(device, "timeout", command)
    except OSError:
        return _unavailable(device, "tool_execution_failed", command)

    if not isinstance(completed, SmartctlRun):
        return _unavailable(device, "invalid_tool_result", command)
    if not verifier(kernel_name, major_minor):
        return _unavailable(device, "device_identity_changed_during_inspection", command)
    if len(completed.stdout.encode("utf-8")) > MAX_SMARTCTL_OUTPUT_BYTES:
        return _unavailable(device, "tool_output_too_large", command)

    try:
        payload = json.loads(completed.stdout)
    except (ValueError, RecursionError):
        result = _unavailable(device, "malformed_json", command)
        result["tool_exit_code"] = completed.returncode
        return result
    if not isinstance(payload, Mapping):
        result = _unavailable(device, "malformed_json", command)
        result["tool_exit_code"] = completed.returncode
        return result

    return _normalize_health(device, payload, completed.returncode, command)


def build_smartctl_command(kernel_name: str) -> list[str]:
    """Return the only smartctl command shape allowed by RPR-017."""
    if not _valid_kernel_name(kernel_name):
        raise DiskHealthError("kernel_name is invalid")
    return [
        SMARTCTL_COMMAND,
        "--json=c",
        "--health",
        "--attributes",
        "--info",
        "--nocheck=standby",
        f"/dev/{kernel_name}",
    ]


def _run_smartctl(command: Sequence[str], timeout_seconds: float) -> SmartctlRun:
    completed = subprocess.run(
        list(command),
        check=False,
        capture_output=True,
        close_fds=True,
        cwd="/",
        env={"LANG": "C", "LC_ALL": "C", "PATH": "/usr/sbin:/usr/bin:/sbin:/bin"},
        stdin=subprocess.DEVNULL,
        text=True,
        timeout=timeout_seconds,
    )
    return SmartctlRun(completed.returncode, completed.stdout, completed.stderr)


def _normalize_health(
    device: Mapping[str, Any], payload: Mapping[str, Any], returncode: int, command: Sequence[str]
) -> dict[str, Any]:
    smart_status = _mapping(payload.get("smart_status"))
    passed = smart_status.get("passed")
    attributes = _ata_failure_attributes(payload)
    nvme_warnings = _nvme_warnings(payload)
    limitations = _bridge_limitations(payload)
    exit_reasons = _exit_status_reasons(returncode)

    status = "unknown"
    reasons: list[str] = []
    if passed is True:
        status = "passed"
    elif passed is False:
        status = "failed"
        reasons.append("smart_health_failed")
    if any(value > 0 for value in attributes.values()) and status != "failed":
        status = "warning"
        reasons.append("ata_attribute_warning")
    if nvme_warnings and status != "failed":
        status = "warning"
        reasons.append("nvme_critical_warning")
    if status == "unknown" and limitations:
        status = "unavailable"
        reasons.append("bridge_or_device_limitation")
    if "smartctl_health_failed" in exit_reasons:
        status = "failed"
    elif any(reason.startswith("smartctl_health_warning") for reason in exit_reasons):
        if status != "failed":
            status = "warning"
    elif "smartctl_command_failed" in exit_reasons:
        status = "unavailable"
    reasons.extend(reason for reason in exit_reasons if reason not in reasons)

    return {
        "source_id": device.get("source_id"),
        "kernel_name": device.get("kernel_name"),
        "tool": "smartctl",
        "tool_version": SMARTCTL_VERSION,
        "tool_exit_code": returncode,
        "command_profile": _command_profile(command),
        "status": status,
        "acknowledgment_required": status in {"failed", "warning"},
        "reasons": reasons,
        "temperature_celsius": _temperature(payload),
        "ata_attributes": attributes,
        "nvme_warnings": nvme_warnings,
        "limitations": limitations,
    }


def _unavailable(device: Mapping[str, Any], reason: str, command: Sequence[str]) -> dict[str, Any]:
    return {
        "source_id": device.get("source_id"),
        "kernel_name": device.get("kernel_name"),
        "tool": "smartctl",
        "tool_version": SMARTCTL_VERSION,
        "command_profile": _command_profile(command),
        "status": "unavailable",
        "acknowledgment_required": False,
        "reasons": [reason],
        "temperature_celsius": None,
        "ata_attributes": {},
        "nvme_warnings": [],
        "limitations": [],
    }


def _ata_failure_attributes(payload: Mapping[str, Any]) -> dict[str, int]:
    table = _mapping(payload.get("ata_smart_attributes")).get("table")
    result = {value: 0 for value in HEALTH_FAILURE_ATTRIBUTES.values()}
    if not isinstance(table, list):
        return result
    for row in table:
        if not isinstance(row, Mapping):
            continue
        name = row.get("name")
        normalized = HEALTH_FAILURE_ATTRIBUTES.get(str(name))
        if normalized is None:
            continue
        result[normalized] = _raw_int(row)
    return result


def _raw_int(row: Mapping[str, Any]) -> int:
    raw = _mapping(row.get("raw"))
    value = raw.get("value")
    if isinstance(value, int) and not isinstance(value, bool):
        return min(max(value, 0), MAX_HEALTH_COUNTER)
    if isinstance(value, str):
        match = re.match(r"^\s*(\d+)", value)
        if match:
            return min(int(match.group(1)[:19]), MAX_HEALTH_COUNTER)
    return 0


def _nvme_warnings(payload: Mapping[str, Any]) -> list[str]:
    log = _mapping(payload.get("nvme_smart_health_information_log"))
    warning = log.get("critical_warning")
    if isinstance(warning, int) and not isinstance(warning, bool) and 0 < warning <= 255:
        return [f"critical_warning_{warning}"]
    return []


def _temperature(payload: Mapping[str, Any]) -> int | None:
    temperature = _mapping(payload.get("temperature"))
    current = temperature.get("current")
    if isinstance(current, int) and not isinstance(current, bool) and -100 <= current <= 1000:
        return current
    log = _mapping(payload.get("nvme_smart_health_information_log"))
    current = log.get("temperature")
    if isinstance(current, int) and not isinstance(current, bool) and -100 <= current <= 1000:
        return current
    return None


def _bridge_limitations(payload: Mapping[str, Any]) -> list[str]:
    limitations: list[str] = []
    messages = _mapping(payload.get("smartctl")).get("messages")
    if isinstance(messages, list):
        for message in messages:
            if not isinstance(message, Mapping):
                continue
            text = str(message.get("string", "")).lower()
            if any(token in text for token in ("unsupported", "unknown usb bridge", "unavailable")):
                limitations.append(_safe_reason(text))
    return limitations


def _command_profile(command: Sequence[str]) -> dict[str, Any]:
    return {
        "executable": SMARTCTL_COMMAND,
        "version": SMARTCTL_VERSION,
        "read_only_flags": [flag for flag in command[1:-1]],
        "prohibited_flags_absent": not any(
            flag.startswith(("--test", "-t", "--smart=", "-s")) for flag in command
        ),
    }


def _mapping(value: object) -> Mapping[str, Any]:
    return value if isinstance(value, Mapping) else {}


def _safe_reason(value: str) -> str:
    cleaned = "_".join(value.replace("\x00", "").split())
    return cleaned[:128] if cleaned else "unsupported"


def _valid_kernel_name(value: str) -> bool:
    return KERNEL_NAME_RE.fullmatch(value) is not None and ".." not in value


def _valid_major_minor(value: str) -> bool:
    return MAJOR_MINOR_RE.fullmatch(value) is not None


def _verify_device_identity(kernel_name: str, major_minor: str) -> bool:
    try:
        opened = os.stat(f"/dev/{kernel_name}", follow_symlinks=False)
    except OSError:
        return False
    expected_major, expected_minor = (int(value) for value in major_minor.split(":", 1))
    return stat.S_ISBLK(opened.st_mode) and (
        os.major(opened.st_rdev),
        os.minor(opened.st_rdev),
    ) == (expected_major, expected_minor)


def _exit_status_reasons(returncode: int) -> list[str]:
    if isinstance(returncode, bool) or not isinstance(returncode, int) or returncode < 0:
        return ["smartctl_command_failed"]
    reasons: list[str] = []
    if returncode & 0b00000111:
        reasons.append("smartctl_command_failed")
    if returncode & 0b00001000:
        reasons.append("smartctl_health_failed")
    if returncode & 0b11110000:
        reasons.append("smartctl_health_warning_log")
    return reasons
