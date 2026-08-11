"""Sandboxed enrichment worker placeholder package.

Package ownership: preview, OCR, parse, AI-adapter, and export workers that
operate only on copies/derivatives in scratch storage and never receive a
source-device handle. See docs/MASTER_PLAN.md section 6.4 and
docs/THREAT_MODEL.md. No feature implementation in this skeleton task.
"""

from __future__ import annotations

from shared.placeholder import placeholder_health

COMPONENT = "worker"
__version__ = "0.1.0.dev0"


def health(device: str | None = None) -> dict[str, str | bool | None]:
    return placeholder_health(COMPONENT, __version__, device)
