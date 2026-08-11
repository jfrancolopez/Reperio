"""Scanner worker placeholder package.

Package ownership: the ephemeral, network-isolated scanner that receives the
selected source device read-only and emits normalized findings to the catalog.
Opens the device O_RDONLY only; no HTTP, no provider/destination credentials.
See docs/MASTER_PLAN.md sections 3.1 and 6.3. No feature implementation in this
skeleton task.
"""

from __future__ import annotations

from shared.placeholder import placeholder_health

COMPONENT = "scanner"
__version__ = "0.1.0.dev0"


def health(device: str | None = None) -> dict[str, str | bool | None]:
    return placeholder_health(COMPONENT, __version__, device)
