#!/usr/bin/env python3
"""Report every package version in one command (RPR-004).

Dependency-free: Python 3.11+ stdlib only. Used by ``make versions``.
"""

from __future__ import annotations

import importlib
import json
import sys
import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PYTHON_PACKAGES = ("hostd", "api", "scanner", "worker", "shared", "migrations")


def main() -> int:
    sys.path.insert(0, str(ROOT))
    with (ROOT / "pyproject.toml").open("rb") as handle:
        project = tomllib.load(handle)["project"]
    print(f"project {project['version']}")
    for name in PYTHON_PACKAGES:
        module = importlib.import_module(name)
        print(f"{name} {module.__version__}")
    with (ROOT / "web" / "package.json").open(encoding="utf-8") as handle:
        web_version = json.load(handle)["version"]
    print(f"web {web_version}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
