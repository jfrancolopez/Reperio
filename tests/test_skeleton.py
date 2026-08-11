#!/usr/bin/env python3

from __future__ import annotations

import sys
import unittest
from pathlib import Path

REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPOSITORY_ROOT))
sys.path.insert(0, str(REPOSITORY_ROOT / "scripts"))

import check_skeleton as skeleton  # noqa: E402

import shared.placeholder  # noqa: E402


class SkeletonChecksTests(unittest.TestCase):
    def test_all_skeleton_checks_pass_in_this_checkout(self) -> None:
        self.assertEqual([], skeleton.check_skeleton())

    def test_placeholder_health_refuses_device(self) -> None:
        with self.assertRaises(ValueError):
            shared.placeholder.placeholder_health("hostd", "0.1.0.dev0", "/dev/sda")

    def test_every_expected_package_is_defined(self) -> None:
        self.assertEqual(
            ("hostd", "api", "scanner", "worker", "shared", "migrations"),
            skeleton.PYTHON_PACKAGES,
        )
        for name in skeleton.PYTHON_PACKAGES:
            module = __import__(name)
            self.assertIsInstance(module.__version__, str)
            self.assertEqual("placeholder", module.health()["status"])


if __name__ == "__main__":
    unittest.main()
