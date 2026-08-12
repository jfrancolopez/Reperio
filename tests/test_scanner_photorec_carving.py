from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from scanner import photorec_carving


class FakeRunner:
    def __init__(self, result: photorec_carving.PhotoRecRunResult) -> None:
        self.result = result
        self.calls: list[tuple[tuple[str, ...], int]] = []

    def run(
        self, args: tuple[str, ...], timeout_seconds: int
    ) -> photorec_carving.PhotoRecRunResult:
        self.calls.append((args, timeout_seconds))
        return self.result


class ScannerPhotoRecCarvingTests(unittest.TestCase):
    def test_allowlisted_jpeg_pdf_zip_command_writes_under_quarantine(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            scratch = Path(tmp) / "scratch"
            command = photorec_carving.build_photorec_command(
                source_path=Path("/dev/reperio-source"),
                scratch_root=scratch,
                signatures=("jpg", "pdf", "zip"),
                ranges=(photorec_carving.CarveRange(1024, 4096),),
            )

        self.assertEqual(("jpg", "pdf", "zip"), command.signatures)
        self.assertIn("/cmd", command.args)
        self.assertIn("/d", command.args)
        self.assertIn("search", command.args)
        self.assertTrue(str(command.destination).endswith("scratch/photorec-quarantine"))

    def test_non_allowlisted_signature_is_refused(self) -> None:
        with self.assertRaises(photorec_carving.PhotoRecCarvingError) as captured:
            photorec_carving.build_photorec_command(
                source_path=Path("/dev/reperio-source"),
                scratch_root=Path("/scratch"),
                signatures=("exe",),
                ranges=(photorec_carving.CarveRange(0, 512),),
            )

        self.assertEqual("signature_not_allowed", captured.exception.code)

    def test_repair_or_write_command_surface_is_refused(self) -> None:
        with self.assertRaises(photorec_carving.PhotoRecCarvingError) as captured:
            photorec_carving.build_photorec_command(
                source_path=Path("/dev/reperio-source"),
                scratch_root=Path("/scratch"),
                signatures=("jpg",),
                ranges=(photorec_carving.CarveRange(0, 512),),
                photorec_binary="testdisk",
            )

        self.assertEqual("unsafe_photorec_command", captured.exception.code)

    def test_deleted_fixture_log_counts_recovered_files(self) -> None:
        recovered, warnings = photorec_carving.parse_photorec_log(
            "PhotoRec 7.2\n3 files saved\n", "", 0
        )

        self.assertEqual(3, recovered)
        self.assertEqual((), warnings)

    def test_unknown_raw_disk_is_warning_not_crash(self) -> None:
        recovered, warnings = photorec_carving.parse_photorec_log(
            "Unknown filesystem, not a disk image\n", "", 1
        )

        self.assertEqual(0, recovered)
        self.assertIn("photorec_input_unknown", warnings)

    def test_no_space_destination_is_normalized(self) -> None:
        recovered, warnings = photorec_carving.parse_photorec_log("", "No space left on device", 2)

        self.assertEqual(0, recovered)
        self.assertIn("photorec_no_space", warnings)
        self.assertIn("photorec_exit:2", warnings)

    def test_timeout_returns_partial_summary(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            runner = FakeRunner(
                photorec_carving.PhotoRecRunResult(124, "2 files saved\n", "", timed_out=True)
            )

            summary = photorec_carving.run_photorec_carve(
                source_path=Path("/dev/reperio-source"),
                scratch_root=Path(tmp) / "scratch",
                signatures=("jpg",),
                ranges=(photorec_carving.CarveRange(0, 4096),),
                runner=runner,
                timeout_seconds=5,
            )

        self.assertEqual("partial", summary.status)
        self.assertEqual(2, summary.recovered_count)
        self.assertIn("photorec_timeout", summary.warnings)
        self.assertEqual(5, runner.calls[0][1])

    def test_malformed_output_is_sanitized_and_bounded(self) -> None:
        recovered, warnings = photorec_carving.parse_photorec_log(
            "not parseable\n", "bad\x00stderr " + "x" * 300, 9
        )

        self.assertEqual(0, recovered)
        self.assertIn("photorec_exit:9", warnings)
        self.assertTrue(
            any(warning.startswith("photorec_stderr:bad stderr") for warning in warnings)
        )


if __name__ == "__main__":
    unittest.main()
