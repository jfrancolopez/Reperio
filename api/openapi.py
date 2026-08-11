"""OpenAPI generation entry point for compatibility review."""

from __future__ import annotations

import json
from pathlib import Path

from api.app import public_openapi_schema

OPENAPI_PATH = Path(__file__).with_name("openapi.v1.json")


def write_openapi(path: Path = OPENAPI_PATH) -> None:
    path.write_text(json.dumps(public_openapi_schema(), indent=2, sort_keys=True) + "\n")


if __name__ == "__main__":
    write_openapi()
