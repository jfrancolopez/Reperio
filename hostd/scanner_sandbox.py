"""Fixed scanner sandbox launch specification for RPR-019."""

from __future__ import annotations

import os
import re
import stat
import subprocess
from collections.abc import Callable, Mapping, Sequence
from types import MappingProxyType
from typing import Any

from hostd.safety_audit import SafetyAuditLog

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
KERNEL_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._+-]{0,127}$")
MAJOR_MINOR_RE = re.compile(r"^(0|[1-9][0-9]*):(0|[1-9][0-9]*)$")
SPEC_KEYS = frozenset(
    {
        "runtime",
        "image",
        "entrypoint",
        "args",
        "network",
        "capabilities",
        "security_options",
        "read_only_rootfs",
        "user",
        "source_identity",
        "devices",
        "mounts",
        "tmpfs",
        "resources",
        "command",
    }
)
RESOURCE_KEYS = frozenset(
    {
        "memory_limit_mib",
        "pids_limit",
        "scratch_limit_mib",
        "cpu_quota_percent",
        "cpus",
    }
)
RESOURCE_MAXIMUMS = {
    "memory_limit_mib": 1024 * 1024,
    "pids_limit": 4096,
    "scratch_limit_mib": 1024 * 1024,
    "cpu_quota_percent": 100 * 1024,
}
RUNTIME_ENVIRONMENT = MappingProxyType(
    {
        "LANG": "C",
        "LC_ALL": "C",
        "PATH": "/usr/sbin:/usr/bin:/sbin:/bin",
    }
)

ScannerRunner = Callable[[Sequence[str]], object]
DeviceIdentityVerifier = Callable[[str, str], bool]


class ScannerSandboxError(ValueError):
    """Raised when a scanner sandbox cannot be built or launched safely."""


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
    kernel_name, major_minor = _source_identity(source)
    _validate_read_only_preparation(source, read_only_preparation)

    resources = _resources(resource_profile)
    tmpfs_options = _tmpfs_options(resources)
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
        "source_identity": {"kernel_name": kernel_name, "major_minor": major_minor},
        "devices": [
            {"host": f"/dev/{kernel_name}", "container": CONTAINER_SOURCE_PATH, "mode": "r"}
        ],
        "mounts": [],
        "tmpfs": [{"path": SCRATCH_TMPFS_PATH, "options": tmpfs_options}],
        "resources": resources,
        "command": _command(runtime, kernel_name, resources),
    }
    validate_scanner_spec(spec)
    return spec


def launch_scanner(
    source: Mapping[str, Any],
    read_only_preparation: Mapping[str, Any],
    resource_profile: Mapping[str, int],
    *,
    audit_log: SafetyAuditLog,
    runtime: str = "docker",
    runner: ScannerRunner | None = None,
    identity_verifier: DeviceIdentityVerifier | None = None,
) -> object:
    """Audit and launch the fixed scanner profile without a caller-supplied command."""
    spec = build_scanner_launch(source, read_only_preparation, resource_profile, runtime=runtime)
    identity = _mapping(spec["source_identity"], "source identity")
    kernel_name = str(identity["kernel_name"])
    major_minor = str(identity["major_minor"])
    verifier = identity_verifier or _verify_device_identity
    if not verifier(kernel_name, major_minor):
        raise ScannerSandboxError("source identity changed before scanner launch")

    audit_log.append("scanner_sandbox_profile", _audit_profile(spec))
    try:
        return (runner or _run_scanner)(tuple(spec["command"]))
    except (OSError, subprocess.SubprocessError) as error:
        raise ScannerSandboxError("scanner runtime launch failed") from error


def validate_scanner_spec(spec: Mapping[str, Any]) -> None:
    """Validate every field of the fixed scanner sandbox profile."""
    if frozenset(spec) != SPEC_KEYS:
        raise ScannerSandboxError("scanner specification keys do not match the fixed profile")
    runtime = spec.get("runtime")
    if runtime not in ALLOWED_RUNTIMES:
        raise ScannerSandboxError("runtime must be docker or podman")
    image = spec.get("image")
    if image != SCANNER_IMAGE or not IMAGE_DIGEST_RE.fullmatch(str(image)):
        raise ScannerSandboxError("scanner image must be the fixed immutable digest")
    if spec.get("entrypoint") != SCANNER_ENTRYPOINT or tuple(spec.get("args", [])) != SCANNER_ARGS:
        raise ScannerSandboxError("scanner entrypoint and arguments are fixed")
    if spec.get("network") != "none":
        raise ScannerSandboxError("scanner network must be disabled")
    if spec.get("capabilities") != {"drop": ["ALL"], "add": []}:
        raise ScannerSandboxError("all capabilities must be dropped and none added")
    if spec.get("security_options") != ["no-new-privileges:true"]:
        raise ScannerSandboxError("scanner security options are fixed")
    if spec.get("read_only_rootfs") is not True:
        raise ScannerSandboxError("root filesystem must be read-only")
    if spec.get("user") != NON_ROOT_USER:
        raise ScannerSandboxError("scanner must use the fixed non-root read identity")

    identity = _mapping(spec.get("source_identity"), "source identity")
    if frozenset(identity) != {"kernel_name", "major_minor"}:
        raise ScannerSandboxError("source identity keys are invalid")
    kernel_name = str(identity.get("kernel_name", ""))
    major_minor = str(identity.get("major_minor", ""))
    if not _valid_kernel_name(kernel_name) or not _valid_major_minor(major_minor):
        raise ScannerSandboxError("source identity is invalid")

    expected_device = {
        "host": f"/dev/{kernel_name}",
        "container": CONTAINER_SOURCE_PATH,
        "mode": "r",
    }
    if spec.get("devices") != [expected_device]:
        raise ScannerSandboxError("scanner must receive exactly the prepared read-only source")
    if spec.get("mounts") != []:
        raise ScannerSandboxError("scanner receives no host mounts")

    resources = _validated_resources(spec.get("resources"))
    expected_tmpfs = [{"path": SCRATCH_TMPFS_PATH, "options": _tmpfs_options(resources)}]
    if spec.get("tmpfs") != expected_tmpfs:
        raise ScannerSandboxError("scanner scratch must be one fixed bounded tmpfs")
    if spec.get("command") != _command(str(runtime), kernel_name, resources):
        raise ScannerSandboxError("scanner command does not match the fixed profile")


def _validate_read_only_preparation(
    source: Mapping[str, Any], preparation: Mapping[str, Any]
) -> None:
    if preparation.get("prepared") is not True:
        raise ScannerSandboxError("source must be read-only prepared before scanner launch")
    source_id = source.get("source_id")
    if not isinstance(source_id, str) or not source_id or preparation.get("source_id") != source_id:
        raise ScannerSandboxError("read-only preparation does not match the selected source")
    if preparation.get("blockers") != []:
        raise ScannerSandboxError("read-only preparation contains blockers")

    expected = _source_targets(source)
    targets = preparation.get("targets")
    if not isinstance(targets, list) or len(targets) != len(expected):
        raise ScannerSandboxError("read-only preparation target set is incomplete")
    observed: set[tuple[str, str]] = set()
    for target in targets:
        if not isinstance(target, Mapping):
            raise ScannerSandboxError("read-only preparation target is invalid")
        identity = (str(target.get("kernel_name", "")), str(target.get("major_minor", "")))
        if target.get("set_read_only") is not True or target.get("verified_read_only") is not True:
            raise ScannerSandboxError("read-only preparation target is not verified")
        observed.add(identity)
    if observed != expected or len(observed) != len(targets):
        raise ScannerSandboxError("read-only preparation does not match current source targets")


def _source_targets(source: Mapping[str, Any]) -> set[tuple[str, str]]:
    root = _source_identity(source)
    children = source.get("children", [])
    if not isinstance(children, list):
        raise ScannerSandboxError("source children must be a list")
    targets = {root}
    for child in children:
        if not isinstance(child, Mapping):
            raise ScannerSandboxError("source child identity is invalid")
        identity = _source_identity(child)
        if identity in targets:
            raise ScannerSandboxError("source target identities must be unique")
        targets.add(identity)
    return targets


def _source_identity(source: Mapping[str, Any]) -> tuple[str, str]:
    kernel_name = str(source.get("kernel_name", ""))
    major_minor = str(source.get("major_minor", ""))
    if not _valid_kernel_name(kernel_name):
        raise ScannerSandboxError("source kernel name is invalid")
    if not _valid_major_minor(major_minor):
        raise ScannerSandboxError("source major:minor is invalid")
    return kernel_name, major_minor


def _resources(resource_profile: Mapping[str, object]) -> dict[str, int | str]:
    values = {
        key: _bounded_positive_int(resource_profile.get(key), key, maximum)
        for key, maximum in RESOURCE_MAXIMUMS.items()
    }
    return {**values, "cpus": _format_cpus(values["cpu_quota_percent"])}


def _validated_resources(value: object) -> dict[str, int | str]:
    resources = _mapping(value, "resources")
    if frozenset(resources) != RESOURCE_KEYS:
        raise ScannerSandboxError("scanner resource keys do not match the fixed profile")
    normalized = _resources({key: resources.get(key) for key in RESOURCE_MAXIMUMS})
    if resources.get("cpus") != normalized["cpus"]:
        raise ScannerSandboxError("scanner CPU quota is inconsistent")
    return normalized


def _command(runtime: str, kernel_name: str, resources: Mapping[str, int | str]) -> list[str]:
    device = f"/dev/{kernel_name}:{CONTAINER_SOURCE_PATH}:r"
    tmpfs = f"{SCRATCH_TMPFS_PATH}:{_tmpfs_options(resources)}"
    return [
        runtime,
        "run",
        "--rm",
        "--pull=never",
        "--network=none",
        "--cap-drop=ALL",
        "--security-opt=no-new-privileges:true",
        "--read-only",
        "--log-driver=none",
        f"--user={NON_ROOT_USER}",
        f"--device={device}",
        f"--tmpfs={tmpfs}",
        f"--workdir={SCRATCH_TMPFS_PATH}",
        f"--pids-limit={resources['pids_limit']}",
        f"--memory={resources['memory_limit_mib']}m",
        f"--cpus={resources['cpus']}",
        "--entrypoint",
        SCANNER_ENTRYPOINT,
        SCANNER_IMAGE,
        *SCANNER_ARGS,
    ]


def _tmpfs_options(resources: Mapping[str, int | str]) -> str:
    return f"rw,noexec,nosuid,nodev,size={resources['scratch_limit_mib']}m"


def _format_cpus(cpu_quota_percent: int) -> str:
    cpus = max(cpu_quota_percent / 100, 0.01)
    return f"{cpus:.2f}".rstrip("0").rstrip(".")


def _bounded_positive_int(value: object, label: str, maximum: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0 or value > maximum:
        raise ScannerSandboxError(f"{label} must be a bounded positive integer")
    return value


def _mapping(value: object, label: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise ScannerSandboxError(f"scanner {label} is missing")
    return value


def _audit_profile(spec: Mapping[str, Any]) -> dict[str, Any]:
    identity = _mapping(spec["source_identity"], "source identity")
    return {
        "runtime": spec["runtime"],
        "image": spec["image"],
        "entrypoint": spec["entrypoint"],
        "args": spec["args"],
        "network": spec["network"],
        "capabilities": spec["capabilities"],
        "security_options": spec["security_options"],
        "read_only_rootfs": spec["read_only_rootfs"],
        "user": spec["user"],
        "source_major_minor": identity["major_minor"],
        "source_permissions": "read_only",
        "host_mount_count": 0,
        "tmpfs": spec["tmpfs"],
        "resources": spec["resources"],
    }


def _run_scanner(command: Sequence[str]) -> object:
    return subprocess.Popen(
        list(command),
        close_fds=True,
        cwd="/",
        env=RUNTIME_ENVIRONMENT,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        start_new_session=True,
    )


def _verify_device_identity(kernel_name: str, major_minor: str) -> bool:
    expected_major, expected_minor = (int(part) for part in major_minor.split(":", 1))
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        fd = os.open(f"/dev/{kernel_name}", flags)
    except OSError:
        return False
    try:
        opened = os.fstat(fd)
        return stat.S_ISBLK(opened.st_mode) and (
            os.major(opened.st_rdev),
            os.minor(opened.st_rdev),
        ) == (expected_major, expected_minor)
    finally:
        os.close(fd)


def _valid_kernel_name(value: str) -> bool:
    return KERNEL_NAME_RE.fullmatch(value) is not None and ".." not in value


def _valid_major_minor(value: str) -> bool:
    return MAJOR_MINOR_RE.fullmatch(value) is not None
