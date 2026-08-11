#!/usr/bin/env python3
"""Dependency-free placeholder-skeleton gate (RPR-004).

Verifies every scaffolded package exposes a version and a healthy placeholder
entry point, that health processes refuse a device argument, that no component
currently touches privileged I/O, and that the single versions command reports
all packages. Run from the repository root.
"""

from __future__ import annotations

import importlib
import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PYTHON_PACKAGES = ("hostd", "api", "scanner", "worker", "shared", "migrations")


def module_checks() -> list[str]:
    sys.path.insert(0, str(ROOT))
    failures: list[str] = []
    for name in PYTHON_PACKAGES:
        module = importlib.import_module(name)
        version = getattr(module, "__version__", None)
        if not isinstance(version, str) or not version:
            failures.append(f"{name}: missing non-empty __version__")
            continue
        health = getattr(module, "health", None)
        if not callable(health):
            failures.append(f"{name}: missing callable health()")
            continue
        record = health()
        if record.get("component") != name:
            failures.append(f"{name}: health component mismatch")
        if record.get("status") != "placeholder":
            failures.append(f"{name}: health status must be placeholder")
        if record.get("privileged_io"):
            failures.append(f"{name}: placeholder must not enable privileged I/O")
        if record.get("device") is not None:
            failures.append(f"{name}: placeholder must not reference a device")
        try:
            health("--device")
        except ValueError:
            pass
        else:
            failures.append(f"{name}: health() must refuse a device argument")
    return failures


def entry_point_checks() -> list[str]:
    failures: list[str] = []
    for name in PYTHON_PACKAGES:
        ok, stdout = _run_module(name)
        if ok != 0:
            failures.append(f"python -m {name}: non-zero exit {ok}: {stdout.strip()}")
            continue
        try:
            record = json.loads(stdout)
        except json.JSONDecodeError:
            failures.append(f"python -m {name}: invalid JSON output")
            continue
        if record.get("component") != name or record.get("status") != "placeholder":
            failures.append(f"python -m {name}: unexpected health record")

        ok, stdout = _run_module(name, "--device", "/dev/not-a-source")
        if ok == 0:
            failures.append(f"python -m {name}: accepted a device argument")
        else:
            try:
                decoded = json.loads(stdout)
            except json.JSONDecodeError:
                failures.append(f"python -m {name}: refusal output is not JSON")
            else:
                if "error" not in decoded:
                    failures.append(f"python -m {name}: refusal output lacks an error")
    return failures


def versions_checks() -> list[str]:
    failures: list[str] = []
    result = subprocess.run(
        [sys.executable, str(ROOT / "scripts" / "report-versions.py")],
        cwd=ROOT,
        check=False,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
    )
    if result.returncode:
        return [f"report-versions: non-zero exit: {result.stdout.strip()}"]
    expected = {"project", "web"} | set(PYTHON_PACKAGES)
    printed = {line.split()[0] for line in result.stdout.splitlines() if line.strip()}
    missing = sorted(expected - printed)
    if missing:
        failures.append(f"report-versions: missing packages: {', '.join(missing)}")
    versions = {
        line.split()[0]: line.split(None, 1)[1]
        for line in result.stdout.splitlines()
        if len(line.split(None, 1)) == 2
    }
    for name in PYTHON_PACKAGES:
        if name in versions and versions[name] != "0.1.0.dev0":
            failures.append(f"report-versions: unexpected version for {name}")
    return failures


def check_skeleton() -> list[str]:
    failures = []
    failures.extend(module_checks())
    failures.extend(entry_point_checks())
    failures.extend(versions_checks())
    return failures


def _run_module(name: str, *arguments: str) -> tuple[int, str]:
    result = subprocess.run(
        [sys.executable, "-m", name, *arguments],
        cwd=ROOT,
        check=False,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
    )
    return result.returncode, result.stdout


def main() -> int:
    failures = check_skeleton()
    if failures:
        print("FAIL: monorepo skeleton")
        for failure in failures:
            print(f"  - {failure}")
        return 1
    print("PASS: monorepo skeleton")
    return 0


if __name__ == "__main__":
    sys.exit(main())
