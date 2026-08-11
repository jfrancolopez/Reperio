#!/usr/bin/env python3

from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path

REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPOSITORY_ROOT / "scripts"))

import validate_repository as policy  # noqa: E402


class RepositoryPolicyTests(unittest.TestCase):
    def setUp(self) -> None:
        temporary_root = REPOSITORY_ROOT / "tmp"
        temporary_root.mkdir(exist_ok=True)
        self.temporary_directory = tempfile.TemporaryDirectory(dir=temporary_root)
        self.work = Path(self.temporary_directory.name)

    def tearDown(self) -> None:
        self.temporary_directory.cleanup()

    def test_detects_high_confidence_secret_signature(self) -> None:
        secret_file = self.work / "candidate.txt"
        inert_token = "github" + "_pat_" + ("A" * 24)
        secret_file.write_text(f"token={inert_token}\n", encoding="utf-8")

        failures = policy.check_secret_signatures([secret_file])

        self.assertTrue(any("GitHub token" in failure for failure in failures))

    def test_rejects_environment_database_and_disk_image_files(self) -> None:
        environment_file = self.work / ".env.production"
        database_file = self.work / "catalog.sqlite3"
        disk_image = self.work / "source.img"
        for path in (environment_file, database_file, disk_image):
            path.write_bytes(b"synthetic\n")

        failures = policy.check_repository_paths([environment_file, database_file, disk_image])

        self.assertTrue(any("environment/secret" in failure for failure in failures))
        self.assertTrue(any("runtime database" in failure for failure in failures))
        self.assertTrue(any("disk images/source media" in failure for failure in failures))

    def test_accepts_immutable_least_privilege_workflow(self) -> None:
        workflow = """name: safe
on:
  pull_request:
permissions:
  contents: read
jobs:
  test:
    runs-on: ubuntu-latest
    timeout-minutes: 5
    steps:
      - uses: actions/checkout@1111111111111111111111111111111111111111
        with:
          persist-credentials: false
      - run: ./scripts/validate-repository.sh
"""

        failures = self.check_workflow(workflow)

        self.assertEqual([], failures)

    def test_rejects_mutable_action_and_privileged_trigger(self) -> None:
        workflow = """name: unsafe
on:
  pull_request_target:
permissions:
  contents: read
jobs:
  test:
    runs-on: ubuntu-latest
    timeout-minutes: 5
    steps:
      - uses: actions/checkout@v7
"""

        failures = self.check_workflow(workflow)

        self.assertTrue(any("trigger is prohibited" in failure for failure in failures))
        self.assertTrue(any("full commit SHA" in failure for failure in failures))

    def test_rejects_context_interpolation_in_shell(self) -> None:
        expression_open = "$" + "{{"
        workflow = f"""name: unsafe-shell
on:
  pull_request:
permissions:
  contents: read
jobs:
  test:
    runs-on: ubuntu-latest
    timeout-minutes: 5
    steps:
      - run: echo {expression_open} github.event.pull_request.title }}}}
"""

        failures = self.check_workflow(workflow)

        self.assertTrue(any("through env" in failure for failure in failures))

    def test_rejects_artifact_upload_without_retention_limit(self) -> None:
        workflow = """name: upload-no-retention
on:
  pull_request:
permissions:
  contents: read
jobs:
  test:
    runs-on: ubuntu-latest
    timeout-minutes: 5
    steps:
      - uses: actions/upload-artifact@1111111111111111111111111111111111111111
        with:
          name: report
          path: report.json
"""

        failures = self.check_workflow(workflow)

        self.assertTrue(any("retention-days" in failure for failure in failures))

    def test_accepts_artifact_upload_with_retention_limit(self) -> None:
        workflow = """name: upload-with-retention
on:
  pull_request:
permissions:
  contents: read
jobs:
  test:
    runs-on: ubuntu-latest
    timeout-minutes: 5
    steps:
      - uses: actions/upload-artifact@1111111111111111111111111111111111111111
        with:
          name: report
          path: report.json
          retention-days: 30
"""

        failures = self.check_workflow(workflow)

        self.assertEqual([], failures)

    def check_workflow(self, content: str) -> list[str]:
        workflow_directory = self.work / "workflows"
        workflow_directory.mkdir()
        (workflow_directory / "policy.yml").write_text(content, encoding="utf-8")
        original_directory = policy.WORKFLOW_DIRECTORY
        try:
            policy.WORKFLOW_DIRECTORY = workflow_directory
            return policy.check_workflows()
        finally:
            policy.WORKFLOW_DIRECTORY = original_directory


if __name__ == "__main__":
    unittest.main()
