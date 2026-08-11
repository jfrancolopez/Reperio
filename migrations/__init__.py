"""Numbered schema migrations.

Package ownership: forward migration runner, schema-version table, and
compatibility policy.
"""

from __future__ import annotations

from shared.placeholder import placeholder_health

COMPONENT = "migrations"
__version__ = "0.1.0.dev0"


def health(device: str | None = None) -> dict[str, str | bool | None]:
    return placeholder_health(COMPONENT, __version__, device)
