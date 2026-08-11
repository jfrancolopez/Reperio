"""Linux host controller placeholder package.

Package ownership: the smallest privileged component. Only hostd may touch
kernel device state (identity resolution, mount/holder inspection, kernel
read-only verification, and fixed scanner launch). See
docs/adr/0002-linux-host-control.md. No feature implementation in this
skeleton task.
"""

from __future__ import annotations

from shared.placeholder import placeholder_health

COMPONENT = "hostd"
__version__ = "0.1.0.dev0"


def health(device: str | None = None) -> dict[str, str | bool | None]:
    return placeholder_health(COMPONENT, __version__, device)
