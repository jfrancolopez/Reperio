from __future__ import annotations

import errno
import unittest
from pathlib import Path

from hostd import fingerprint
from scanner import messages, source_validation

DATA = bytes(index % 251 for index in range(4096))


def facts(size: int = 4096, sector_size: int = 512) -> dict[str, object]:
    return {
        "source_id": "source_abcdefghijklmnop",
        "identity_strength": "by-id",
        "by_id_name": "usb-Reperio_Disk_123",
        "size_bytes": size,
        "logical_block_size": sector_size,
        "physical_block_size": sector_size,
        "removable": True,
    }


class FakeSourceOps:
    def __init__(
        self,
        data: bytes = DATA,
        *,
        is_block: bool = True,
        is_symlink: bool = False,
        read_only: bool = True,
        open_error: OSError | None = None,
        swapped: bool = False,
    ) -> None:
        self.data = data
        self.is_block = is_block
        self.is_symlink = is_symlink
        self.read_only = read_only
        self.open_error = open_error
        self.swapped = swapped
        self.closed = False

    def lstat(self, path: Path) -> source_validation.SourceStat:
        return source_validation.SourceStat(self.is_block, self.is_symlink, 123)

    def open_readonly(self, path: Path) -> int:
        if self.open_error is not None:
            raise self.open_error
        return 7

    def fstat(self, fd: int) -> source_validation.SourceStat:
        return source_validation.SourceStat(self.is_block, False, 456 if self.swapped else 123)

    def pread(self, fd: int, length: int, offset: int) -> bytes:
        return self.data[offset : offset + length]

    def verify_read_only(self, fd: int) -> bool:
        return self.read_only

    def close(self, fd: int) -> None:
        self.closed = True


class ScannerSourceValidationTests(unittest.TestCase):
    def test_valid_fixture_reports_capabilities(self) -> None:
        expected = expected_source(DATA)
        ops = FakeSourceOps(DATA)

        result = source_validation.validate_source(expected, ops=ops)
        decoded = messages.decode_line(result.capabilities_message())

        self.assertTrue(ops.closed)
        self.assertEqual(expected.fingerprint_hash, result.fingerprint_hash)
        self.assertEqual("capabilities", decoded.message_type)
        self.assertIn("source-validation", decoded.payload["capabilities"])

    def test_symlink_swap_is_rejected_before_open(self) -> None:
        with self.assertRaises(source_validation.SourceValidationError) as captured:
            source_validation.validate_source(
                expected_source(DATA), ops=FakeSourceOps(is_symlink=True)
            )
        self.assertEqual("source_symlink", captured.exception.code)

    def test_source_replacement_after_open_is_rejected(self) -> None:
        with self.assertRaises(source_validation.SourceValidationError) as captured:
            source_validation.validate_source(
                expected_source(DATA), ops=FakeSourceOps(swapped=True)
            )
        self.assertEqual("source_replaced", captured.exception.code)

    def test_writable_loop_is_rejected(self) -> None:
        with self.assertRaises(source_validation.SourceValidationError) as captured:
            source_validation.validate_source(
                expected_source(DATA), ops=FakeSourceOps(read_only=False)
            )
        self.assertEqual("source_writable", captured.exception.code)

    def test_regular_file_is_rejected(self) -> None:
        with self.assertRaises(source_validation.SourceValidationError) as captured:
            source_validation.validate_source(
                expected_source(DATA), ops=FakeSourceOps(is_block=False)
            )
        self.assertEqual("source_not_block", captured.exception.code)

    def test_wrong_fingerprint_is_rejected(self) -> None:
        changed = bytearray(DATA)
        changed[2048] ^= 0xFF

        with self.assertRaises(source_validation.SourceValidationError) as captured:
            source_validation.validate_source(
                expected_source(DATA), ops=FakeSourceOps(bytes(changed))
            )
        self.assertEqual("source_fingerprint_mismatch", captured.exception.code)

    def test_wrong_sector_size_is_rejected(self) -> None:
        expected = expected_source(DATA)
        wrong = source_validation.ExpectedSource(
            path=expected.path,
            source_id=expected.source_id,
            size_bytes=expected.size_bytes,
            sector_size=1024,
            fingerprint_hash=expected.fingerprint_hash,
            identity_facts=facts(sector_size=1024),
        )

        with self.assertRaises(source_validation.SourceValidationError) as captured:
            source_validation.validate_source(wrong, ops=FakeSourceOps(DATA))
        self.assertEqual("source_fingerprint_mismatch", captured.exception.code)

    def test_permission_failure_is_reported_safely(self) -> None:
        with self.assertRaises(source_validation.SourceValidationError) as captured:
            source_validation.validate_source(
                expected_source(DATA),
                ops=FakeSourceOps(open_error=PermissionError(errno.EACCES, "fixture denied")),
            )
        self.assertEqual("source_open_failed", captured.exception.code)

    def test_invalid_expected_geometry_is_rejected_before_open(self) -> None:
        expected = expected_source(DATA)
        invalid = source_validation.ExpectedSource(
            path=expected.path,
            source_id=expected.source_id,
            size_bytes=-1,
            sector_size=expected.sector_size,
            fingerprint_hash=expected.fingerprint_hash,
            identity_facts=expected.identity_facts,
        )

        with self.assertRaisesRegex(source_validation.SourceValidationError, "geometry"):
            source_validation.validate_source(invalid, ops=FakeSourceOps())

    def test_unreadable_sample_is_reported_without_raw_exception(self) -> None:
        class FailingFingerprintOps(FakeSourceOps):
            def pread(self, fd: int, length: int, offset: int) -> bytes:
                raise OSError("fixture read failure")

        with self.assertRaisesRegex(source_validation.SourceValidationError, "fingerprint"):
            source_validation.validate_source(expected_source(DATA), ops=FailingFingerprintOps())


def expected_source(data: bytes) -> source_validation.ExpectedSource:
    identity_facts = facts(size=len(data))
    result = fingerprint.fingerprint_from_reader(
        lambda offset, length: data[offset : offset + length],
        size_bytes=len(data),
        sector_size=512,
        identity_facts=identity_facts,
    )
    return source_validation.ExpectedSource(
        path=Path("/dev/reperio-fixture"),
        source_id="source_abcdefghijklmnop",
        size_bytes=len(data),
        sector_size=512,
        fingerprint_hash=str(result["fingerprint_hash"]),
        identity_facts=identity_facts,
    )


if __name__ == "__main__":
    unittest.main()
