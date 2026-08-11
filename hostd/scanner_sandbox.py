"""Fixed scanner sandbox launch specification for RPR-019."""

from __future__ import annotations

import re
from collections.abc import Mapping
from typing import Any

SCANNER_IMAGE = (
    "reperio/scanner@sha256:1111111111111111111111111111111111111111111111111111111111111111"
)
SCANNER_ENTRYPOINT = "/usr/local/bin/python"
SCANNER_ARGS = ("-m", "scanner")
CONTAINER_SOURCE_PATH = "/dev/reperio-source"
SCRATCH_TMPFS_PATH = "/run/reperio-scratch"
NON_ROOT_USER = "65532:6"
ALLOWED_RUNTIMES = frozenset({"docker", "podman"})
IMAGE_DIGEST_RE = re.compile(r"^[a-z0-9./_-]+@sha256:[0-9a-f]{64}$")


class ScannerSandboxError(ValueError):
    """Raised when a scanner sandbox cannot be built safely."""


def build_scanner_launch(
    source: Mapping[str, Any],
    read_only_preparation: Mapping[str, Any],
    resource_profile: Mapping[str, int],
    *,
    runtime: str = "docker",
) -> dict[str, Any]:
    """Build the immutable Docker/Podman launch command for one prepared source."""
    if runtime not in ALLOWED_RUNTIMES:
        raise ScannerSandboxError("runtime must be docker or podman")
    if read_only_preparation.get("prepared") is not True:
        raise ScannerSandboxError("source must be read-only prepared before scanner launch")

    kernel_name = str(source.get("kernel_name", ""))
    if not _valid_kernel_name(kernel_name):
        raise ScannerSandboxError("source kernel name is invalid")

    resources = _resources(resource_profile)
    device = f"/dev/{kernel_name}:{CONTAINER_SOURCE_PATH}:r"
    tmpfs = f"{SCRATCH_TMPFS_PATH}:rw,noexec,nosuid,nodev,size={resources['scratch_limit_mib']}m"
    command = [
        runtime,
        "run",
        "--rm",
        "--network=none",
        "--cap-drop=ALL",
        "--security-opt=no-new-privileges:true",
        "--read-only",
        f"--user={NON_ROOT_USER}",
        f"--device={device}",
        f"--tmpfs={tmpfs}",
        f"--pids-limit={resources['pids_limit']}",
        f"--memory={resources['memory_limit_mib']}m",
        f"--cpus={resources['cpus']}",
        "--entrypoint",
        SCANNER_ENTRYPOINT,
        SCANNER_IMAGE,
        *SCANNER_ARGS,
    ]
    spec = {
        "runtime": runtime,
        "image": SCANNER_IMAGE,
        "entrypoint": SCANNER_ENTRYPOINT,
        "args": list(SCANNER_ARGS),
        "network": "none",
        "capabilities": {"drop": ["ALL"], "add": []},
        "security_options": ["no-new-privileges:true"],
        "read_only_rootfs": True,
        "user": NON_ROOT_USER,
        "devices": [
            {"host": f"/dev/{kernel_name}", "container": CONTAINER_SOURCE_PATH, "mode": "r"}
        ],
        "mounts": [],
        "tmpfs": [{"path": SCRATCH_TMPFS_PATH, "options": tmpfs.split(":", 1)[1]}],
        "resources": resources,
        "command": command,
    }
    validate_scanner_spec(spec)
    return spec


def validate_scanner_spec(spec: Mapping[str, Any]) -> None:
    """Validate the immutable scanner sandbox profile."""
    if spec.get("image") != SCANNER_IMAGE or not IMAGE_DIGEST_RE.fullmatch(str(spec.get("image"))):
        raise ScannerSandboxError("scanner image must be the fixed immutable digest")
    if spec.get("entrypoint") != SCANNER_ENTRYPOINT or tuple(spec.get("args", [])) != SCANNER_ARGS:
        raise ScannerSandboxError("scanner entrypoint and arguments are fixed")
    if spec.get("network") != "none":
        raise ScannerSandboxError("scanner network must be disabled")
    capabilities = spec.get("capabilities")
    if not isinstance(capabilities, Mapping):
        raise ScannerSandboxError("capabilities profile is missing")
    if capabilities.get("drop") != ["ALL"] or capabilities.get("add") != []:
        raise ScannerSandboxError("all capabilities must be dropped and none added")
    if spec.get("read_only_rootfs") is not True:
        raise ScannerSandboxError("root filesystem must be read-only")
    if spec.get("user") == "0" or str(spec.get("user", "")).startswith("0:"):
        raise ScannerSandboxError("scanner must not run as root")
    devices = spec.get("devices")
    if not isinstance(devices, list) or len(devices) != 1:
        raise ScannerSandboxError("scanner must receive exactly one source device")
    device = devices[0]
    if not isinstance(device, Mapping) or device.get("mode") != "r":
        raise ScannerSandboxError("source device must be read-only")
    if device.get("container") != CONTAINER_SOURCE_PATH:
        raise ScannerSandboxError("source device container path is fixed")
    if spec.get("mounts") != []:
        raise ScannerSandboxError("scanner receives no host mounts")
    tmpfs = spec.get("tmpfs")
    if not isinstance(tmpfs, list) or len(tmpfs) != 1:
        raise ScannerSandboxError("scanner scratch must be one bounded tmpfs")
    if spec.get("resources") is None:
        raise ScannerSandboxError("scanner resources must be bounded")


def _resources(resource_profile: Mapping[str, int]) -> dict[str, int | str]:
    memory = _positive_int(resource_profile.get("memory_limit_mib"), "memory_limit_mib")
    pids = _positive_int(resource_profile.get("pids_limit"), "pids_limit")
    scratch = _positive_int(resource_profile.get("scratch_limit_mib"), "scratch_limit_mib")
    cpu_quota = _positive_int(resource_profile.get("cpu_quota_percent"), "cpu_quota_percent")
    return {
        "memory_limit_mib": memory,
        "pids_limit": pids,
        "scratch_limit_mib": scratch,
        "cpu_quota_percent": cpu_quota,
        "cpus": _format_cpus(cpu_quota),
    }


def _format_cpus(cpu_quota_percent: int) -> str:
    cpus = max(cpu_quota_percent / 100, 0.01)
    return f"{cpus:.2f}".rstrip("0").rstrip(".")


def _positive_int(value: object, label: str) -> int:
    if not isinstance(value, int) or value <= 0:
        raise ScannerSandboxError(f"{label} must be a positive integer")
    return value


def _valid_kernel_name(value: str) -> bool:
    return bool(value) and "/" not in value and "\x00" not in value and ".." not in value
