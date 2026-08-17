"""Generic parser sandbox profile and structured runner."""

from __future__ import annotations

import json
import re
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Protocol

PARSER_IMAGE = (
    "reperio/parser-tools@sha256:2222222222222222222222222222222222222222222222222222222222222222"
)
ENTRYPOINT = "/usr/local/bin/reperio-parser"
NON_ROOT_USER = "65532:65532"
IMAGE_DIGEST_RE = re.compile(r"^[a-z0-9./_-]+@sha256:[0-9a-f]{64}$")
ALLOWED_RUNTIMES = frozenset({"docker", "podman"})
DENIED_ARG_FRAGMENTS = frozenset(
    {"/dev/", "docker.sock", "catalog.sqlite", "master.key", "secrets", "--privileged"}
)


class ParserSandboxError(ValueError):
    """Raised when a parser sandbox cannot be run safely."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


@dataclass(frozen=True)
class ParserProfile:
    name: str
    tool: str
    args: tuple[str, ...]
    max_stdout_bytes: int
    timeout_seconds: int


@dataclass(frozen=True)
class ParserRunResult:
    status: str
    records: tuple[dict[str, Any], ...]
    warnings: tuple[str, ...] = ()
    exit_code: int | None = None


@dataclass(frozen=True)
class ParserProcessResult:
    exit_code: int
    stdout: bytes
    stderr: bytes = b""
    timed_out: bool = False


class ParserRuntime(Protocol):
    def run(self, command: tuple[str, ...], timeout_seconds: int) -> ParserProcessResult: ...


PROFILES = {
    "metadata-json": ParserProfile(
        name="metadata-json",
        tool="metadata-json",
        args=("--input", "/work/input", "--output", "/work/output", "--json-lines"),
        max_stdout_bytes=64 * 1024,
        timeout_seconds=30,
    ),
    "text-json": ParserProfile(
        name="text-json",
        tool="text-json",
        args=("--input", "/work/input", "--output", "/work/output", "--json-lines"),
        max_stdout_bytes=256 * 1024,
        timeout_seconds=60,
    ),
    "tika-json": ParserProfile(
        name="tika-json",
        tool="apache-tika",
        args=("--input", "/work/input", "--output", "/work/output", "--json-lines"),
        max_stdout_bytes=512 * 1024,
        timeout_seconds=90,
    ),
    "exiftool-json": ParserProfile(
        name="exiftool-json",
        tool="exiftool",
        args=("--input", "/work/input", "--output", "/work/output", "--json-lines"),
        max_stdout_bytes=512 * 1024,
        timeout_seconds=60,
    ),
    "ffprobe-json": ParserProfile(
        name="ffprobe-json",
        tool="ffprobe",
        args=("--input", "/work/input", "--output", "/work/output", "--json-lines"),
        max_stdout_bytes=512 * 1024,
        timeout_seconds=60,
    ),
    "libvips-thumbnail-json": ParserProfile(
        name="libvips-thumbnail-json",
        tool="libvips-thumbnail",
        args=("--input", "/work/input", "--output", "/work/output", "--json-lines"),
        max_stdout_bytes=512 * 1024,
        timeout_seconds=60,
    ),
    "media-derivative-json": ParserProfile(
        name="media-derivative-json",
        tool="ffmpeg-media-derivative",
        args=("--input", "/work/input", "--output", "/work/output", "--json-lines"),
        max_stdout_bytes=512 * 1024,
        timeout_seconds=120,
    ),
    "document-render-json": ParserProfile(
        name="document-render-json",
        tool="pdf-office-render",
        args=("--input", "/work/input", "--output", "/work/output", "--json-lines"),
        max_stdout_bytes=512 * 1024,
        timeout_seconds=120,
    ),
    "ocr-json": ParserProfile(
        name="ocr-json",
        tool="tesseract-ocrmypdf",
        args=("--input", "/work/input", "--output", "/work/output", "--json-lines"),
        max_stdout_bytes=512 * 1024,
        timeout_seconds=120,
    ),
    "legacy-webcache": ParserProfile(
        name="legacy-webcache",
        tool="legacy-webcache",
        args=("--input", "/work/input", "--output", "/work/output", "--json-lines"),
        max_stdout_bytes=256 * 1024,
        timeout_seconds=60,
    ),
}


def build_parser_sandbox(
    *,
    profile_name: str,
    copied_input: Path,
    job_scratch: Path,
    resource_profile: Mapping[str, int],
    runtime: str = "docker",
) -> dict[str, Any]:
    """Build an immutable parser sandbox command for copied input only."""

    if runtime not in ALLOWED_RUNTIMES:
        raise ParserSandboxError("invalid_runtime", "runtime must be docker or podman")
    profile = PROFILES.get(profile_name)
    if profile is None:
        raise ParserSandboxError("unknown_profile", "parser profile is not allowlisted")
    copied_input = copied_input.resolve()
    job_scratch = job_scratch.resolve()
    if not _under(copied_input, job_scratch):
        raise ParserSandboxError("input_not_copied", "parser input must be a scratch copy")
    resources = _resources(resource_profile)
    _validate_args(profile.args)
    tmpfs = f"/tmp:rw,noexec,nosuid,nodev,size={resources['tmpfs_limit_mib']}m"
    output_tmpfs = f"/work-output:rw,noexec,nosuid,nodev,size={resources['output_limit_mib']}m"
    command = (
        runtime,
        "run",
        "--rm",
        "--network=none",
        "--cap-drop=ALL",
        "--security-opt=no-new-privileges:true",
        "--read-only",
        f"--user={NON_ROOT_USER}",
        f"--mount=type=bind,source={job_scratch},target=/work,readonly",
        f"--tmpfs={tmpfs}",
        f"--tmpfs={output_tmpfs}",
        f"--pids-limit={resources['pids_limit']}",
        f"--memory={resources['memory_limit_mib']}m",
        f"--cpus={resources['cpus']}",
        "--entrypoint",
        ENTRYPOINT,
        PARSER_IMAGE,
        "--profile",
        profile.name,
        *profile.args,
    )
    spec = {
        "runtime": runtime,
        "image": PARSER_IMAGE,
        "entrypoint": ENTRYPOINT,
        "profile": profile.name,
        "network": "none",
        "capabilities": {"drop": ["ALL"], "add": []},
        "read_only_rootfs": True,
        "user": NON_ROOT_USER,
        "devices": [],
        "mounts": [{"source": str(job_scratch), "target": "/work", "mode": "ro"}],
        "tmpfs": [tmpfs, output_tmpfs],
        "resources": resources,
        "command": command,
        "max_stdout_bytes": profile.max_stdout_bytes,
        "timeout_seconds": profile.timeout_seconds,
        "input_path": str(copied_input),
    }
    validate_parser_spec(spec)
    return spec


def run_parser_sandbox(spec: Mapping[str, Any], runtime: ParserRuntime) -> ParserRunResult:
    """Run a validated parser sandbox and decode bounded JSON-lines stdout."""

    validate_parser_spec(spec)
    result = runtime.run(tuple(str(item) for item in spec["command"]), int(spec["timeout_seconds"]))
    if result.timed_out:
        return ParserRunResult("timeout", (), ("parser_timeout",), result.exit_code)
    max_stdout = int(spec["max_stdout_bytes"])
    if len(result.stdout) > max_stdout:
        return ParserRunResult("failed", (), ("parser_output_limit_exceeded",), result.exit_code)
    if result.exit_code != 0:
        return ParserRunResult("failed", (), ("parser_crash",), result.exit_code)
    records = _parse_json_lines(result.stdout)
    return ParserRunResult("complete", records, (), result.exit_code)


def validate_parser_spec(spec: Mapping[str, Any]) -> None:
    if spec.get("image") != PARSER_IMAGE or not IMAGE_DIGEST_RE.fullmatch(str(spec.get("image"))):
        raise ParserSandboxError("invalid_image", "parser image must be the fixed digest")
    if spec.get("entrypoint") != ENTRYPOINT:
        raise ParserSandboxError("invalid_entrypoint", "parser entrypoint is fixed")
    if spec.get("profile") not in PROFILES:
        raise ParserSandboxError("unknown_profile", "parser profile is not allowlisted")
    if spec.get("network") != "none":
        raise ParserSandboxError("network_enabled", "parser network must be disabled")
    if spec.get("devices") != []:
        raise ParserSandboxError("device_access", "parser receives no devices")
    if spec.get("read_only_rootfs") is not True:
        raise ParserSandboxError("writable_rootfs", "parser root filesystem must be read-only")
    if str(spec.get("user", "")).startswith("0"):
        raise ParserSandboxError("root_user", "parser must not run as root")
    capabilities = spec.get("capabilities")
    if (
        not isinstance(capabilities, Mapping)
        or capabilities.get("drop") != ["ALL"]
        or capabilities.get("add") != []
    ):
        raise ParserSandboxError("capabilities", "parser capabilities must all be dropped")
    mounts = spec.get("mounts")
    if not isinstance(mounts, list) or len(mounts) != 1:
        raise ParserSandboxError("mounts", "parser must receive exactly one copied input mount")
    mount = mounts[0]
    if (
        not isinstance(mount, Mapping)
        or mount.get("target") != "/work"
        or mount.get("mode") != "ro"
    ):
        raise ParserSandboxError("mounts", "parser input mount must be read-only /work")
    _validate_args(tuple(str(arg) for arg in spec.get("command", ())))
    if spec.get("resources") is None:
        raise ParserSandboxError("resources", "parser resources must be bounded")


def _parse_json_lines(stdout: bytes) -> tuple[dict[str, Any], ...]:
    records: list[dict[str, Any]] = []
    try:
        lines = stdout.decode("utf-8").splitlines()
    except UnicodeDecodeError as error:
        raise ParserSandboxError("invalid_stdout", "parser stdout must be UTF-8") from error
    for line in lines:
        if not line.strip():
            continue
        try:
            record = json.loads(line)
        except json.JSONDecodeError as error:
            raise ParserSandboxError(
                "invalid_stdout", "parser stdout must be JSON lines"
            ) from error
        if not isinstance(record, dict):
            raise ParserSandboxError("invalid_stdout", "parser stdout record must be an object")
        records.append(record)
    return tuple(records)


def _resources(resource_profile: Mapping[str, int]) -> dict[str, int | str]:
    memory = _positive_int(resource_profile.get("memory_limit_mib"), "memory_limit_mib")
    pids = _positive_int(resource_profile.get("pids_limit"), "pids_limit")
    tmpfs = _positive_int(resource_profile.get("tmpfs_limit_mib"), "tmpfs_limit_mib")
    output = _positive_int(resource_profile.get("output_limit_mib"), "output_limit_mib")
    cpu_quota = _positive_int(resource_profile.get("cpu_quota_percent"), "cpu_quota_percent")
    return {
        "memory_limit_mib": memory,
        "pids_limit": pids,
        "tmpfs_limit_mib": tmpfs,
        "output_limit_mib": output,
        "cpu_quota_percent": cpu_quota,
        "cpus": _format_cpus(cpu_quota),
    }


def _validate_args(args: tuple[str, ...]) -> None:
    joined = " ".join(args).lower()
    if any(fragment in joined for fragment in DENIED_ARG_FRAGMENTS) or "--network=host" in joined:
        raise ParserSandboxError("forbidden_access", "parser arguments request forbidden access")


def _under(path: Path, root: Path) -> bool:
    try:
        path.relative_to(root)
    except ValueError:
        return False
    return True


def _positive_int(value: object, label: str) -> int:
    if not isinstance(value, int) or value <= 0:
        raise ParserSandboxError("invalid_resource", f"{label} must be a positive integer")
    return value


def _format_cpus(cpu_quota_percent: int) -> str:
    cpus = max(cpu_quota_percent / 100, 0.01)
    return f"{cpus:.2f}".rstrip("0").rstrip(".")
