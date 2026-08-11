"""Entry point for the migrations placeholder health process."""

from __future__ import annotations

import sys

from migrations import COMPONENT, __version__
from shared.placeholder import placeholder_main

if __name__ == "__main__":
    sys.exit(placeholder_main(COMPONENT, __version__))
