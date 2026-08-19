#!/usr/bin/env python3

from __future__ import annotations

import hashlib
import os
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace

from worker.local_export import (
    ExportError,
    ExportItem,
    cleanup_partial,
    copy_stream,
    ensure_under_root,
    export_local_item,
    finalize_copy,
    list_partials,
    prepare_copy,
    prove_destination_separation,
    prune_partials,
    verify_copy,
)

NOW = "2026-08-19T10:00:00Z"


def make_item(content: bytes) -> ExportItem:
    source_path = tempfile.mkstemp(prefix="rpr106-src-")[1]
    Path(source_path).write_bytes(content)
    return ExportItem(
        export_item_id="export_item_test_001",
        source_path=source_path,
        expected_size=len(content),
        expected_sha256=hashlib.sha256(content).hexdigest(),
    )


def fake_evaluate(separate: bool = True) -> object:
    def evaluate_destination_separation(
        source: object, destination_path: object, mounts: object = None, holders: object = None
    ) -> dict:
        return {
            "resolved_path": str(destination_path),
            "separate": separate,
            "blockers": () if separate else ("same_disk",),
            "warnings": (),
            "destination_ancestry": (),
        }

    return SimpleNamespace(evaluate_destination_separation=evaluate_destination_separation)


class SeparationTests(unittest.TestCase):
    def test_same_disk_destination_is_blocked(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaisesRegex(ExportError, "child partition"):
                prove_destination_separation(
                    tmp, {"source_id": "s"}, evaluate=fake_evaluate(separate=False)
                )

    def test_separate_destination_is_allowed(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            resolved = prove_destination_separation(tmp, {}, evaluate=fake_evaluate(separate=True))
            self.assertEqual(Path(tmp), Path(resolved))

    def test_source_outside_scratch_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            outside = Path(tmp) / "elsewhere.txt"
            outside.write_bytes(b"x")
            with self.assertRaisesRegex(ExportError, "scratch"):
                ensure_under_root(str(outside), tmp + "/scratch")


class SuccessfulExportTests(unittest.TestCase):
    def test_success_streams_verifies_and_finalizes(self) -> None:
        content = b"hello recovered photo" * 1000
        with tempfile.TemporaryDirectory() as tmp:
            destination = Path(tmp) / "dest"
            destination.mkdir()
            source = Path(tempfile.mkstemp()[1])
            source.write_bytes(content)
            item = ExportItem(
                export_item_id="export_item_test_002",
                source_path=str(source),
                expected_size=len(content),
                expected_sha256=hashlib.sha256(content).hexdigest(),
            )
            progress: list[int] = []

            result = export_local_item(
                item,
                destination_dir=str(destination),
                now=NOW,
                on_progress=lambda p: progress.append(p.copied_bytes),
            )

            self.assertEqual("completed", result.state)
            self.assertTrue(result.verified)
            final = Path(result.destination_path or "")
            self.assertTrue(final.exists())
            self.assertEqual(content, final.read_bytes())
            self.assertEqual(0, len(list(destination.glob("*.partial"))))
            self.assertTrue(progress)

    def test_source_unchanged_after_export(self) -> None:
        content = b"source-bytes"
        with tempfile.TemporaryDirectory() as tmp:
            destination = Path(tmp) / "dest"
            destination.mkdir()
            source = Path(tempfile.mkstemp()[1])
            source.write_bytes(content)
            item = ExportItem(
                export_item_id="export_item_test_003",
                source_path=str(source),
                expected_size=len(content),
                expected_sha256=hashlib.sha256(content).hexdigest(),
            )
            before = source.read_bytes()
            export_local_item(item, destination_dir=str(destination), now=NOW)
            self.assertEqual(before, source.read_bytes())


class FailureTests(unittest.TestCase):
    def test_destination_disk_full_fails_and_cleans_partial(self) -> None:
        content = b"x" * 4096
        item = make_item(content)

        def enospc_writer(path: Path, chunk: bytes) -> None:
            raise OSError(28, "No space left on device")

        with tempfile.TemporaryDirectory() as tmp:
            destination = Path(tmp) / "dest"
            destination.mkdir()
            result = export_local_item(
                item, destination_dir=str(destination), now=NOW, writer=enospc_writer
            )
            self.assertEqual("failed", result.state)
            self.assertEqual("copy_io_failed", result.error)
            self.assertEqual(0, len(list(destination.glob("*.partial"))))
            self.assertEqual(0, len(list(destination.glob("*.final"))))

    def test_source_disconnect_fails_with_short_read(self) -> None:
        item = ExportItem(
            export_item_id="export_item_test_004",
            source_path=tempfile.mkstemp()[1],
            expected_size=1000,
            expected_sha256="f" * 64,
        )
        with tempfile.TemporaryDirectory() as tmp:
            destination = Path(tmp) / "dest"
            destination.mkdir()
            result = export_local_item(item, destination_dir=str(destination), now=NOW)
            self.assertEqual("failed", result.state)
            self.assertEqual("source_changed", result.error)
            self.assertEqual(0, len(list(destination.glob("*.partial"))))

    def test_existing_collision_is_refused(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            destination = Path(tmp) / "dest"
            destination.mkdir()
            final = destination / "export_item_test_005.final"
            final.write_bytes(b"previous")
            result = export_local_item(
                ExportItem(
                    export_item_id="export_item_test_005",
                    source_path=tempfile.mkstemp()[1],
                    expected_size=0,
                    expected_sha256=hashlib.sha256(b"").hexdigest(),
                ),
                destination_dir=str(destination),
                now=NOW,
            )
            self.assertEqual("failed", result.state)
            self.assertEqual("destination_exists", result.error)
            self.assertEqual(b"previous", final.read_bytes())

    def test_permission_error_fails(self) -> None:
        content = b"data"
        item = make_item(content)
        with tempfile.TemporaryDirectory() as tmp:
            destination = Path(tmp) / "dest"
            destination.mkdir()
            os.chmod(destination, 0o500)
            try:
                result = export_local_item(item, destination_dir=str(destination), now=NOW)
            finally:
                os.chmod(destination, 0o700)
            self.assertEqual("failed", result.state)
            self.assertEqual("copy_io_failed", result.error)

    def test_corrupted_copy_seam_fails_verification(self) -> None:
        content = b"clean-bytes"
        source_path = tempfile.mkstemp(prefix="rpr106-corr-")[1]
        Path(source_path).write_bytes(content)
        item = ExportItem(
            export_item_id="export_item_test_006",
            source_path=source_path,
            expected_size=len(content),
            expected_sha256=hashlib.sha256(b"different").hexdigest(),
        )
        with tempfile.TemporaryDirectory() as tmp:
            destination = Path(tmp) / "dest"
            destination.mkdir()
            result = export_local_item(item, destination_dir=str(destination), now=NOW)
            self.assertEqual("failed", result.state)
            self.assertEqual("verification_failed", result.error)
            self.assertEqual(0, len(list(destination.glob("*.partial"))))
            self.assertEqual(0, len(list(destination.glob("*.final"))))

    def test_verify_detects_size_mismatch(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            partial = Path(tmp) / "x.partial"
            partial.write_bytes(b"12345")
            with self.assertRaisesRegex(ExportError, "copied size does not match"):
                verify_copy(partial, expected_size=10, expected_sha256="0" * 64)


class PartialPolicyTests(unittest.TestCase):
    def test_prune_only_removes_partials(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            Path(tmp, ".a.partial").write_bytes(b"x")
            Path(tmp, "b.final").write_bytes(b"y")
            Path(tmp, ".hidden.final").write_bytes(b"z")
            self.assertEqual([".a.partial"], list_partials(tmp))
            self.assertEqual(1, prune_partials(tmp))
            self.assertTrue(Path(tmp, "b.final").exists())
            self.assertTrue(Path(tmp, ".hidden.final").exists())
            self.assertFalse(Path(tmp, ".a.partial").exists())

    def test_cleanup_partial_returns_true(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            partial = Path(tmp) / ".x.partial"
            partial.write_bytes(b"x")
            self.assertTrue(cleanup_partial(partial))
            self.assertFalse(partial.exists())
            self.assertFalse(cleanup_partial(partial))


class LowLevelTests(unittest.TestCase):
    def test_finalize_atomic_replace(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            destination = Path(tmp) / "dest"
            destination.mkdir()
            partial, final = prepare_copy(
                item_id="export_item_test_007",
                destination_dir=str(destination),
                expected_size=3,
            )
            partial.write_bytes(b"abc")
            finalize_copy(partial, final, fsync=False)
            self.assertTrue(final.exists())
            self.assertEqual(b"abc", final.read_bytes())
            self.assertFalse(partial.exists())

    def test_copy_stream_rejects_source_growth(self) -> None:
        content = b"short"
        source_path = tempfile.mkstemp()[1]
        Path(source_path).write_bytes(content)
        item = ExportItem(
            export_item_id="export_item_test_008",
            source_path=source_path,
            expected_size=2,
            expected_sha256="0" * 64,
        )
        with tempfile.TemporaryDirectory() as tmp:
            partial = Path(tmp) / ".x.partial"
            with self.assertRaisesRegex(ExportError, "grew beyond"):
                copy_stream(item, partial, now=NOW)
            self.assertFalse(partial.exists())


if __name__ == "__main__":
    unittest.main()
