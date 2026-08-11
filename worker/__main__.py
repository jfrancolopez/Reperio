"""Entry point for the worker placeholder health process."""

from __future__ import annotations

import sys

from shared.placeholder import placeholder_main
from worker import COMPONENT, __version__

if __name__ == "__main__":
    sys.exit(placeholder_main(COMPONENT, __version__))
