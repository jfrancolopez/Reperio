from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

try:
    from shared import secret_store
except ModuleNotFoundError as error:
    raise unittest.SkipTest("cryptography runtime dependency is not installed") from error


class SecretStoreTests(unittest.TestCase):
    def test_restart_decrypt_uses_existing_master_key(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            first = secret_store.SecretStore(Path(tmp))
            metadata = first.put(label="provider-token", value="fixture-value")

            restarted = secret_store.SecretStore(Path(tmp))

            self.assertTrue(metadata.ref.startswith("vault:"))
            self.assertEqual("fixture-value", restarted.get(metadata.ref))
            self.assertEqual("provider-token", restarted.metadata(metadata.ref).label)

    def test_wrong_key_fails_to_decrypt(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            store = secret_store.SecretStore(root)
            metadata = store.put(label="destination", value="fixture-value")
            (root / "master.key").write_bytes(b"x" * secret_store.KEY_BYTES)

            wrong = secret_store.SecretStore(root)

            with self.assertRaises(secret_store.SecretStoreError):
                wrong.get(metadata.ref)

    def test_rotation_preserves_values_and_changes_ciphertext(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            store = secret_store.SecretStore(Path(tmp))
            metadata = store.put(label="provider-token", value="fixture-value")
            path = Path(tmp) / "secrets" / f"{metadata.ref.removeprefix('vault:')}.json"
            before = path.read_bytes()

            store.rotate_master_key()

            self.assertEqual("fixture-value", store.get(metadata.ref))
            self.assertNotEqual(before, path.read_bytes())
            self.assertEqual(2, store.metadata(metadata.ref).key_version)

    def test_delete_removes_secret_record(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            store = secret_store.SecretStore(Path(tmp))
            metadata = store.put(label="provider-token", value="fixture-value")

            store.delete(metadata.ref)

            with self.assertRaises(secret_store.SecretStoreError):
                store.get(metadata.ref)

    def test_redacted_snapshot_never_contains_secret_value(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            store = secret_store.SecretStore(Path(tmp))
            store.put(label="provider-token", value="fixture-value")

            snapshot = store.redacted_snapshot()
            encoded = json.dumps(snapshot, sort_keys=True)

            self.assertIn(secret_store.MASKED_VALUE, encoded)
            self.assertNotIn("fixture-value", encoded)
            self.assertNotIn("ciphertext", encoded)

    def test_permissions_audit_requires_private_store_files(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            store = secret_store.SecretStore(Path(tmp))
            store.put(label="provider-token", value="fixture-value")

            audits = store.audit_permissions()

            self.assertTrue(all(item.ok for item in audits))
            self.assertEqual({0o600, 0o700}, {item.expected_mode for item in audits})

    def test_corrupt_record_fails_without_raw_parser_error(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            store = secret_store.SecretStore(root)
            metadata = store.put(label="provider-token", value="fixture-value")
            record_path = root / "secrets" / f"{metadata.ref.removeprefix('vault:')}.json"
            record_path.write_text('{"nonce":"not-base64"}', encoding="utf-8")

            with self.assertRaises(secret_store.SecretStoreError):
                store.get(metadata.ref)

    def test_corrupt_plaintext_fails_as_store_error(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            store = secret_store.SecretStore(root)
            metadata = store.put(label="provider-token", value="fixture-value")
            record_path = root / "secrets" / f"{metadata.ref.removeprefix('vault:')}.json"
            record = json.loads(record_path.read_text(encoding="utf-8"))
            record["ciphertext"] = record["ciphertext"][:-2] + "AA"
            record_path.write_text(json.dumps(record), encoding="utf-8")

            with self.assertRaises(secret_store.SecretStoreError):
                store.get(metadata.ref)


if __name__ == "__main__":
    unittest.main()
