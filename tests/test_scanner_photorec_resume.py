from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from scanner import photorec_carving, photorec_resume

SOURCE_HASH = "a" * 64


class ScannerPhotoRecResumeTests(unittest.TestCase):
    def test_clean_pause_backs_up_session_and_normalizes_progress(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            session = root / "photorec.ses"
            session.write_bytes(b"PhotoRec session bytes")
            binding = sample_binding(root)

            backup = photorec_resume.backup_session(
                session,
                root / "backups",
                binding=binding,
                progress=photorec_resume.normalize_progress("sector 2048\n3 files saved\n"),
            )

            self.assertTrue(backup.backup_path.exists())
            self.assertEqual({"recovered_count": 3, "last_sector": 2048}, backup.progress)

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

            self.assertEqual("resume", command.args[-1])
            self.assertIn("/cmd", command.args)

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


def write_backup(
    root: Path, *, binding: photorec_resume.SessionBinding, completed: bool = False
) -> photorec_resume.SessionBackup:
    session = root / "photorec.ses"
    session.write_bytes(b"PhotoRec session bytes")
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
