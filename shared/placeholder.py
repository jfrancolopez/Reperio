"""Shared placeholder helpers for the RPR-004 monorepo skeleton.

These helpers keep the per-package health entry points identical and free of
feature logic. A placeholder must never accept, open, or inspect a device.
"""

from __future__ import annotations

import argparse
import json
import sys


def placeholder_health(
    component: str, version: str, device: str | None = None
) -> dict[str, str | bool | None]:
    """Return a placeholder health record, refusing any device argument."""
    if device is not None:
        raise ValueError(f"{component} placeholder refuses any device handle: {device!r}")
    return {
        "component": component,
        "version": version,
        "status": "placeholder",
        "privileged_io": False,
        "device": None,
    }


def placeholder_main(component: str, version: str, argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog=f"python -m {component}")
    parser.add_argument("--device", default=None, help="rejected placeholder argument")
    args = parser.parse_args(argv)
    try:
        record = placeholder_health(component, version, args.device)
    except ValueError as error:
        print(json.dumps({"component": component, "error": str(error)}))
        return 1
    print(json.dumps(record))
    return 0


if __name__ == "__main__":
    sys.exit(placeholder_main("shared", "0.0.0"))
