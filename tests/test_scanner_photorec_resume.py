from __future__ import annotations

import stat
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from scanner import photorec_carving, photorec_resume

SOURCE_HASH = "a" * 64
SESSION_DATA = (
    b"#1723555200\n"
    b"/dev/reperio-source partition_i386,1\n"
    b"fileopt,jpg,enable,wholespace,search,status=find_offset,inter\n"
    b"0-7\n"
)


class ScannerPhotoRecResumeTests(unittest.TestCase):
    def test_clean_pause_backs_up_session_and_normalizes_progress(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            session = root / "photorec.ses"
            session.write_bytes(SESSION_DATA)
            binding = sample_binding(root)

            backup = photorec_resume.backup_session(
                session,
                root / "backups",
                binding=binding,
                progress=photorec_resume.normalize_progress("sector 2048\n3 files saved\n"),
            )

            self.assertTrue(backup.backup_path.exists())
            self.assertEqual({"recovered_count": 3, "last_sector": 2048}, backup.progress)
            self.assertTrue(backup.backup_path.with_suffix(".json").exists())
            self.assertEqual(0o600, stat.S_IMODE(backup.backup_path.stat().st_mode))
            self.assertEqual(
                0o600, stat.S_IMODE(backup.backup_path.with_suffix(".json").stat().st_mode)
            )

    def test_process_kill_resume_invocation_uses_validated_session(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            binding = sample_binding(root)
            backup = write_backup(root, binding=binding, completed=False)
            loaded = photorec_resume.load_session_backup(
                backup.backup_path, expected_binding=binding
            )

            command = photorec_resume.build_resume_command(
                backup=loaded,
                source_path=Path("/dev/reperio-source"),
                scratch_root=root / "scratch",
            )

            self.assertEqual(("/cmd", "resume"), command.args[4:6])
            self.assertEqual("/dev/reperio-source", command.args[-1])

    def test_corrupt_session_is_refused(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            session = root / "photorec.ses"
            session.write_bytes(b"not photorec")

            with self.assertRaises(photorec_resume.PhotoRecResumeError) as captured:
                photorec_resume.backup_session(
                    session, root / "backups", binding=sample_binding(root), progress={}
                )

            self.assertEqual("corrupt_session", captured.exception.code)

    def test_upstream_reserved_session_padding_is_accepted(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            session = root / "photorec.ses"
            session.write_bytes(
                SESSION_DATA + b"\x00" * (photorec_resume.SESSION_MAX_BYTES - len(SESSION_DATA))
            )

            backup = photorec_resume.backup_session(
                session, root / "backups", binding=sample_binding(root), progress={}
            )

            self.assertEqual(photorec_resume.SESSION_MAX_BYTES, session.stat().st_size)
            self.assertTrue(backup.backup_path.exists())

    def test_session_without_free_space_ranges_is_refused(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            session = root / "photorec.ses"
            session.write_bytes(
                b"#1723555200\n"
                b"/dev/reperio-source partition_i386,1\n"
                b"fileopt,jpg,enable,wholespace,search,status=find_offset,inter\n"
            )

            with self.assertRaises(photorec_resume.PhotoRecResumeError) as captured:
                photorec_resume.backup_session(
                    session, root / "backups", binding=sample_binding(root), progress={}
                )

            self.assertEqual("corrupt_session", captured.exception.code)

    def test_wrong_source_cannot_reuse_session(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            binding = sample_binding(root)
            backup = write_backup(root, binding=binding)
            wrong = photorec_resume.SessionBinding(
                source_fingerprint="b" * 64,
                tool_version=binding.tool_version,
                signatures=binding.signatures,
                ranges=binding.ranges,
                command_hash=binding.command_hash,
            )

            with self.assertRaises(photorec_resume.PhotoRecResumeError) as captured:
                photorec_resume.load_session_backup(backup.backup_path, expected_binding=wrong)

            self.assertEqual("wrong_source", captured.exception.code)

    def test_wrong_config_cannot_reuse_session(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            binding = sample_binding(root)
            backup = write_backup(root, binding=binding)
            wrong = photorec_resume.SessionBinding(
                source_fingerprint=binding.source_fingerprint,
                tool_version=binding.tool_version,
                signatures=("pdf",),
                ranges=binding.ranges,
                command_hash=binding.command_hash,
            )

            with self.assertRaises(photorec_resume.PhotoRecResumeError) as captured:
                photorec_resume.load_session_backup(backup.backup_path, expected_binding=wrong)

            self.assertEqual("wrong_config", captured.exception.code)

    def test_upgraded_tool_cannot_reuse_session(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            binding = sample_binding(root)
            backup = write_backup(root, binding=binding)
            wrong = photorec_resume.SessionBinding(
                source_fingerprint=binding.source_fingerprint,
                tool_version="7.3",
                signatures=binding.signatures,
                ranges=binding.ranges,
                command_hash=binding.command_hash,
            )

            with self.assertRaises(photorec_resume.PhotoRecResumeError) as captured:
                photorec_resume.load_session_backup(backup.backup_path, expected_binding=wrong)

            self.assertEqual("wrong_tool_version", captured.exception.code)

    def test_completed_session_restart_does_not_resume(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            binding = sample_binding(root)
            backup = write_backup(root, binding=binding, completed=True)

            with self.assertRaises(photorec_resume.PhotoRecResumeError) as captured:
                photorec_resume.build_resume_command(
                    backup=backup,
                    source_path=Path("/dev/reperio-source"),
                    scratch_root=root / "scratch",
                )

            self.assertEqual("session_completed", captured.exception.code)

    def test_changed_source_path_cannot_build_resume_command(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            binding = sample_binding(root)
            backup = write_backup(root, binding=binding)

            with self.assertRaises(photorec_resume.PhotoRecResumeError) as captured:
                photorec_resume.build_resume_command(
                    backup=backup,
                    source_path=Path("/dev/other-source"),
                    scratch_root=root / "scratch",
                )

            self.assertEqual("wrong_source", captured.exception.code)

    def test_malformed_manifest_is_refused_as_corrupt_state(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            binding = sample_binding(root)
            backup = write_backup(root, binding=binding)
            backup.backup_path.with_suffix(".json").write_text("{", encoding="utf-8")

            with self.assertRaises(photorec_resume.PhotoRecResumeError) as captured:
                photorec_resume.load_session_backup(backup.backup_path, expected_binding=binding)

            self.assertEqual("corrupt_session", captured.exception.code)

    def test_session_symlink_and_source_storage_destination_are_refused(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            target_dir = root / "real-session"
            target_dir.mkdir()
            target = target_dir / "photorec.ses"
            target.write_bytes(SESSION_DATA)
            session = root / "photorec.ses"
            session.symlink_to(target)
            binding = sample_binding(root)

            with self.assertRaises(photorec_resume.PhotoRecResumeError) as captured:
                photorec_resume.backup_session(
                    session, root / "backups", binding=binding, progress={}
                )
            self.assertEqual("invalid_session_file", captured.exception.code)

            with self.assertRaises(photorec_resume.PhotoRecResumeError) as captured:
                photorec_resume.backup_session(
                    target, Path("/dev/reperio-state"), binding=binding, progress={}
                )
            self.assertEqual("invalid_storage_path", captured.exception.code)

    def test_progress_uses_current_sector_and_caps_large_values(self) -> None:
        progress = photorec_resume.normalize_progress(
            "Reading sector 2048/4096\nReading sector 12/4096\n"
        )
        self.assertEqual(2048, progress["last_sector"])

        capped = photorec_resume.normalize_progress(
            f"Reading sector {photorec_resume.MAX_PROGRESS_VALUE + 1}/4096\n"
        )
        self.assertEqual(photorec_resume.MAX_PROGRESS_VALUE, capped["last_sector"])

    def test_resume_invocation_stages_and_refreshes_durable_session(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            binding = sample_binding(root)
            backup = write_backup(root, binding=binding)
            updated_session = SESSION_DATA.replace(b"#1723555200", b"#1723555201")
            runner = FakeResumeRunner(
                photorec_carving.PhotoRecRunResult(
                    124, "Reading sector 2048/4096\n2 files saved\n", "", timed_out=True
                ),
                session_data=updated_session,
            )

            summary = photorec_resume.run_photorec_resume(
                backup=backup,
                source_path=Path("/dev/reperio-source"),
                scratch_root=root / "scratch",
                runner=runner,
                timeout_seconds=5,
            )
            refreshed = photorec_resume.load_session_backup(
                summary.backup.backup_path, expected_binding=binding
            )

        self.assertEqual("partial", summary.status)
        self.assertNotEqual(backup.backup_path, summary.backup.backup_path)
        self.assertEqual(5, runner.calls[0][1])
        self.assertEqual("resume", runner.calls[0][0][5])
        self.assertEqual(2, refreshed.progress["recovered_count"])
        self.assertEqual(2048, refreshed.progress["last_sector"])

    def test_completed_resume_marks_session_non_resumable(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            binding = sample_binding(root)
            backup = write_backup(root, binding=binding)
            runner = FakeResumeRunner(
                photorec_carving.PhotoRecRunResult(0, "2 files saved\n", ""), remove_session=True
            )

            summary = photorec_resume.run_photorec_resume(
                backup=backup,
                source_path=Path("/dev/reperio-source"),
                scratch_root=root / "scratch",
                runner=runner,
            )
            completed = photorec_resume.load_session_backup(
                summary.backup.backup_path, expected_binding=binding
            )

            with self.assertRaises(photorec_resume.PhotoRecResumeError) as captured:
                photorec_resume.build_resume_command(
                    backup=completed,
                    source_path=Path("/dev/reperio-source"),
                    scratch_root=root / "scratch",
                )

        self.assertEqual("complete", summary.status)
        self.assertTrue(completed.completed)
        self.assertTrue(summary.backup.completed)
        self.assertEqual("session_completed", captured.exception.code)

    def test_completion_without_durable_state_is_reported_as_warning(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            binding = sample_binding(root)
            backup = write_backup(root, binding=binding)
            runner = FakeResumeRunner(
                photorec_carving.PhotoRecRunResult(0, "2 files saved\n", ""), remove_session=True
            )
            with mock.patch.object(
                photorec_resume,
                "_mark_backup_completed",
                side_effect=photorec_resume.PhotoRecResumeError("write_failed", "injected"),
            ):
                summary = photorec_resume.run_photorec_resume(
                    backup=backup,
                    source_path=Path("/dev/reperio-source"),
                    scratch_root=root / "scratch",
                    runner=runner,
                )

        self.assertEqual("completed-warning", summary.status)
        self.assertFalse(summary.backup.completed)
        self.assertIn("photorec_session_backup:write_failed", summary.warnings)

    def test_resume_subprocess_runner_uses_private_working_directory(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            binding = sample_binding(root)
            backup = write_backup(root, binding=binding)
            working_directory = root / "scratch"
            working_directory.mkdir(mode=0o700)
            command = photorec_resume.build_resume_command(
                backup=backup,
                source_path=Path("/dev/reperio-source"),
                scratch_root=working_directory,
            )
            completed = mock.Mock(returncode=0, stdout="", stderr="")
            with mock.patch.object(
                photorec_resume.subprocess, "run", return_value=completed
            ) as run:
                result = photorec_resume.SubprocessPhotoRecResumeRunner().run(
                    command.args, 5, working_directory
                )

        self.assertEqual(0, result.returncode)
        self.assertEqual(str(working_directory), run.call_args.kwargs["cwd"])
        self.assertEqual(photorec_carving.SAFE_SUBPROCESS_ENV, run.call_args.kwargs["env"])
        self.assertTrue(run.call_args.kwargs["start_new_session"])


class FakeResumeRunner:
    def __init__(
        self,
        result: photorec_carving.PhotoRecRunResult,
        *,
        remove_session: bool = False,
        session_data: bytes | None = None,
    ) -> None:
        self.result = result
        self.remove_session = remove_session
        self.session_data = session_data
        self.calls: list[tuple[tuple[str, ...], int, Path]] = []

    def run(
        self, args: tuple[str, ...], timeout_seconds: int, working_directory: Path
    ) -> photorec_carving.PhotoRecRunResult:
        self.calls.append((args, timeout_seconds, working_directory))
        if self.remove_session:
            (working_directory / photorec_resume.SESSION_NAME).unlink()
        elif self.session_data is not None:
            (working_directory / photorec_resume.SESSION_NAME).write_bytes(self.session_data)
        return self.result


def write_backup(
    root: Path, *, binding: photorec_resume.SessionBinding, completed: bool = False
) -> photorec_resume.SessionBackup:
    session = root / "photorec.ses"
    session.write_bytes(SESSION_DATA)
    return photorec_resume.backup_session(
        session,
        root / "backups",
        binding=binding,
        progress={"last_sector": 10},
        completed=completed,
    )


def sample_binding(root: Path) -> photorec_resume.SessionBinding:
    ranges = (photorec_carving.CarveRange(0, 4096),)
    command = photorec_carving.build_photorec_command(
        source_path=Path("/dev/reperio-source"),
        scratch_root=root / "scratch",
        signatures=("jpg",),
        ranges=ranges,
    )
    return photorec_resume.binding_for_command(
        source_fingerprint=SOURCE_HASH, command=command, ranges=ranges
    )


if __name__ == "__main__":
    unittest.main()
