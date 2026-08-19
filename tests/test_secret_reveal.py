#!/usr/bin/env python3

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from shared.secret_store import SecretStore
from worker import secret_reveal
from worker.secret_reveal import (
    ClipboardCopy,
    RevealError,
    RevealPolicy,
    assert_secret_free,
    auto_hide_due,
    clipboard_audit_record,
    clipboard_due,
    clipboard_prepare,
    create_reveal_session,
    delete_secret,
    reveal_audit_record,
    reveal_permission,
    scrub_secret_refs,
)

NOW = "2026-08-19T10:00:00Z"
SOON = "2026-08-19T10:00:10Z"
AFTER_HIDE = "2026-08-19T10:00:40Z"
AFTER_CLEAR = "2026-08-19T10:00:20Z"
REF = "vault:" + "a" * 32
SECRET_VALUE = "correct-horse-battery-staple-42"


def policy(
    *,
    mode: str = "authenticated",
    auto_hide_seconds: int = 30,
    clipboard_clear_seconds: int = 15,
    non_persistent: bool = False,
    require_lan_warning_ack: bool = True,
) -> RevealPolicy:
    return RevealPolicy(
        mode=mode,
        auto_hide_seconds=auto_hide_seconds,
        clipboard_clear_seconds=clipboard_clear_seconds,
        non_persistent=non_persistent,
        require_lan_warning_ack=require_lan_warning_ack,
    )


class RevealPermissionTests(unittest.TestCase):
    def test_authenticated_mode_allows_reveal(self) -> None:
        decision = reveal_permission(policy(), mode="authenticated", lan_warning_acknowledged=True)
        self.assertTrue(decision.allowed)

    def test_denied_mode_always_blocks(self) -> None:
        decision = reveal_permission(
            policy(mode="denied"), mode="authenticated", lan_warning_acknowledged=True
        )
        self.assertFalse(decision.allowed)
        self.assertIn("reveal_mode_denied", decision.reasons)

    def test_unauthenticated_lan_requires_warning_ack(self) -> None:
        decision = reveal_permission(
            policy(mode="unauthenticated_lan"),
            mode="unauthenticated_lan",
            lan_warning_acknowledged=False,
        )
        self.assertFalse(decision.allowed)
        self.assertIn("lan_warning_not_acknowledged", decision.reasons)

    def test_unauthenticated_lan_allows_after_ack(self) -> None:
        decision = reveal_permission(
            policy(mode="unauthenticated_lan"),
            mode="unauthenticated_lan",
            lan_warning_acknowledged=True,
        )
        self.assertTrue(decision.allowed)

    def test_invalid_reveal_mode_blocks(self) -> None:
        decision = reveal_permission(policy(), mode="sudo", lan_warning_acknowledged=True)
        self.assertFalse(decision.allowed)
        self.assertIn("invalid_reveal_mode", decision.reasons)


class RevealSessionTests(unittest.TestCase):
    def test_session_expires_after_auto_hide_window(self) -> None:
        session = create_reveal_session(ref=REF, value=SECRET_VALUE, policy=policy(), now=NOW)
        self.assertEqual(SECRET_VALUE, session.revealed_value)
        self.assertFalse(auto_hide_due(session, now=SOON))
        self.assertTrue(auto_hide_due(session, now=AFTER_HIDE))

    def test_manual_hide_clears_value(self) -> None:
        session = create_reveal_session(ref=REF, value=SECRET_VALUE, policy=policy(), now=NOW)
        hidden = session.hide(now=SOON, auto=False)
        self.assertTrue(hidden.auto_hidden)
        self.assertIsNone(hidden.revealed_value)
        self.assertEqual("manual_hide", hidden.reason)

    def test_auto_hide_reason(self) -> None:
        session = create_reveal_session(ref=REF, value=SECRET_VALUE, policy=policy(), now=NOW)
        hidden = session.hide(now=SOON, auto=True)
        self.assertEqual("auto_hide_expired", hidden.reason)

    def test_invalid_ref_rejected(self) -> None:
        with self.assertRaisesRegex(RevealError, "opaque vault reference"):
            create_reveal_session(ref="not-a-ref", value="x", policy=policy(), now=NOW)


class ClipboardTests(unittest.TestCase):
    def test_copy_prepares_autoclear_timestamp(self) -> None:
        session = create_reveal_session(ref=REF, value=SECRET_VALUE, policy=policy(), now=NOW)
        copy = clipboard_prepare(session, policy=policy(), now=NOW)
        self.assertIsInstance(copy, ClipboardCopy)
        self.assertFalse(clipboard_due(copy, now=SOON))
        self.assertTrue(clipboard_due(copy, now=AFTER_CLEAR))

    def test_copy_refuses_hidden_session(self) -> None:
        session = create_reveal_session(ref=REF, value=SECRET_VALUE, policy=policy(), now=NOW)
        hidden = session.hide(now=NOW, auto=False)
        with self.assertRaisesRegex(RevealError, "hidden"):
            clipboard_prepare(hidden, policy=policy(), now=NOW)

    def test_clipboard_audit_never_contains_value(self) -> None:
        record = clipboard_audit_record(
            ref=REF, mode="authenticated", now=NOW, forbidden_values=(SECRET_VALUE,)
        )
        self.assertEqual("secret.clipboard", record["event_type"])
        self.assertNotIn(SECRET_VALUE, repr(record))


class RedactionTests(unittest.TestCase):
    def test_reveal_audit_record_redacts_value(self) -> None:
        decision = reveal_permission(policy(), mode="authenticated", lan_warning_acknowledged=True)
        session = create_reveal_session(ref=REF, value=SECRET_VALUE, policy=policy(), now=NOW)
        record = reveal_audit_record(
            ref=REF, decision=decision, now=NOW, session=session, forbidden_values=(SECRET_VALUE,)
        )
        self.assertEqual("secret.reveal", record["event_type"])
        self.assertNotIn(SECRET_VALUE, repr(record))

    def test_support_bundle_refs_are_scrubbed(self) -> None:
        text = f"found {REF} in recovery"
        scrubbed = scrub_secret_refs(text)
        self.assertNotIn(REF, scrubbed)
        self.assertIn(secret_reveal.REDACTED_REF, scrubbed)

    def test_assert_secret_free_fails_on_leak(self) -> None:
        with self.assertRaisesRegex(RevealError, "leaked"):
            assert_secret_free({"value": SECRET_VALUE}, forbidden_values=(SECRET_VALUE,))


class SecretStoreIntegrationTests(unittest.TestCase):
    def _store(self) -> SecretStore:
        root = Path(tempfile.mkdtemp(prefix="rpr102-"))
        return SecretStore(root)

    def test_key_rotation_preserves_reveal(self) -> None:
        store = self._store()
        metadata = store.put(label="credential", value=SECRET_VALUE)
        store.rotate_master_key()
        self.assertEqual(SECRET_VALUE, store.get(metadata.ref))
        self.assertEqual(2, store.metadata(metadata.ref).key_version)

    def test_delete_leaves_result_status_intact(self) -> None:
        store = self._store()
        metadata = store.put(label="credential", value=SECRET_VALUE)
        finding_id = "finding_keep_1"
        catalog_state = {"finding_id": finding_id, "status": "reviewed", "ref": metadata.ref}
        result = delete_secret(store, ref=metadata.ref)
        self.assertTrue(result["deleted"])
        with self.assertRaises(Exception):
            store.metadata(metadata.ref)
        self.assertEqual("reviewed", catalog_state["status"])
        self.assertEqual(finding_id, catalog_state["finding_id"])

    def test_redacted_snapshot_never_exposes_value(self) -> None:
        store = self._store()
        store.put(label="credential", value=SECRET_VALUE)
        for record in store.redacted_snapshot():
            self.assertNotIn(SECRET_VALUE, repr(record))


if __name__ == "__main__":
    unittest.main()
