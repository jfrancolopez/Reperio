#!/usr/bin/env python3

from __future__ import annotations

import json
import subprocess
import unittest
from collections.abc import Sequence

from hostd import disk_health


def run_with(payload: dict, returncode: int = 0) -> disk_health.SmartctlRunner:
    def runner(command: Sequence[str], timeout_seconds: float) -> disk_health.SmartctlRun:
        return disk_health.SmartctlRun(returncode, json.dumps(payload), "")

    return runner


class HostdDiskHealthTests(unittest.TestCase):
    def test_ata_json_normalizes_health_temperature_and_sector_counters(self) -> None:
        payload = {
            "smart_status": {"passed": True},
            "temperature": {"current": 31},
            "ata_smart_attributes": {
                "table": [
                    {"name": "Reallocated_Sector_Ct", "raw": {"value": 0}},
                    {"name": "Current_Pending_Sector", "raw": {"value": 2}},
                    {"name": "Offline_Uncorrectable", "raw": {"value": 0}},
                ]
            },
        }

        result = disk_health.inspect_disk_health(
            {"source_id": "source_abc", "kernel_name": "sda"}, runner=run_with(payload)
        )

        self.assertEqual("warning", result["status"])
        self.assertTrue(result["acknowledgment_required"])
        self.assertEqual(31, result["temperature_celsius"])
        self.assertEqual(2, result["ata_attributes"]["pending_sectors"])
        self.assertIn("ata_attribute_warning", result["reasons"])

    def test_smart_health_failure_requires_acknowledgment(self) -> None:
        result = disk_health.inspect_disk_health(
            {"kernel_name": "sdb"}, runner=run_with({"smart_status": {"passed": False}})
        )

        self.assertEqual("failed", result["status"])
        self.assertTrue(result["acknowledgment_required"])
        self.assertIn("smart_health_failed", result["reasons"])

    def test_nvme_warning_is_reported_without_device_setting_changes(self) -> None:
        payload = {
            "smart_status": {"passed": True},
            "nvme_smart_health_information_log": {"critical_warning": 4, "temperature": 42},
        }
        seen_command: list[str] = []

        def runner(command: Sequence[str], timeout_seconds: float) -> disk_health.SmartctlRun:
            seen_command.extend(command)
            return disk_health.SmartctlRun(0, json.dumps(payload), "")

        result = disk_health.inspect_disk_health({"kernel_name": "nvme0n1"}, runner=runner)

        self.assertEqual("warning", result["status"])
        self.assertEqual(["critical_warning_4"], result["nvme_warnings"])
        self.assertEqual(42, result["temperature_celsius"])
        self.assertIn("/dev/nvme0n1", seen_command)
        self.assertNotIn("--test", " ".join(seen_command))
        self.assertNotIn("--smart=", " ".join(seen_command))
        self.assertTrue(result["command_profile"]["prohibited_flags_absent"])

    def test_bridge_limitation_becomes_unavailable(self) -> None:
        payload = {
            "smartctl": {"messages": [{"string": "Unknown USB bridge, SMART data unavailable"}]}
        }

        result = disk_health.inspect_disk_health(
            {"kernel_name": "sdc"}, runner=run_with(payload, 2)
        )

        self.assertEqual("unavailable", result["status"])
        self.assertIn("bridge_or_device_limitation", result["reasons"])
        self.assertTrue(result["limitations"])

    def test_malformed_timeout_and_missing_tool_are_normalized(self) -> None:
        def malformed(command: Sequence[str], timeout_seconds: float) -> disk_health.SmartctlRun:
            return disk_health.SmartctlRun(1, "not-json", "")

        def timeout(command: Sequence[str], timeout_seconds: float) -> disk_health.SmartctlRun:
            raise subprocess.TimeoutExpired(command, timeout_seconds)

        def missing(command: Sequence[str], timeout_seconds: float) -> disk_health.SmartctlRun:
            raise FileNotFoundError

        self.assertEqual(
            ["malformed_json"],
            disk_health.inspect_disk_health({"kernel_name": "sdd"}, runner=malformed)["reasons"],
        )
        self.assertEqual(
            ["timeout"],
            disk_health.inspect_disk_health({"kernel_name": "sdd"}, runner=timeout)["reasons"],
        )
        self.assertEqual(
            ["missing_tool"],
            disk_health.inspect_disk_health({"kernel_name": "sdd"}, runner=missing)["reasons"],
        )

    def test_rejects_pathlike_kernel_names(self) -> None:
        with self.assertRaises(disk_health.DiskHealthError):
            disk_health.inspect_disk_health({"kernel_name": "../sda"}, runner=run_with({}))


if __name__ == "__main__":
    unittest.main()
