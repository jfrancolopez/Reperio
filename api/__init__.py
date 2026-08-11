"""Control-plane API placeholder package.

Package ownership: versioned REST API, SQLite catalog/jobs, and UI serving
(FastAPI later). Never receives a source-device handle. See
docs/MASTER_PLAN.md section 6.2 and docs/THREAT_MODEL.md. No feature
implementation in this skeleton task.
"""

from __future__ import annotations

from shared.placeholder import placeholder_health

COMPONENT = "api"
__version__ = "0.1.0.dev0"


def health(device: str | None = None) -> dict[str, str | bool | None]:
    return placeholder_health(COMPONENT, __version__, device)
