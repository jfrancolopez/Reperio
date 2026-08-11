"""Shared schemas, versioning, and placeholder helpers.

Package ownership: control-plane/backend shared code. Holds shared versioned
schemas and cross-package helpers; no feature implementation in this skeleton
task.
"""

from __future__ import annotations

from shared.placeholder import placeholder_health

COMPONENT = "shared"
__version__ = "0.1.0.dev0"


def health(device: str | None = None) -> dict[str, str | bool | None]:
    return placeholder_health(COMPONENT, __version__, device)
