import tempfile
import unittest
from pathlib import Path

from ei.models import ObservationInput
from ei.privacy import (
    Classification,
    PrivacyError,
    assert_syncable,
    inspect_observation,
    inspect_text,
    safe_source_path,
)


def bearer_secret(marker: str) -> str:
    authorization = "Author" + "ization"
    bearer = "Bea" + "rer"
    return f"{authorization}: {bearer} {marker}"


class PrivacyTests(unittest.TestCase):
    def test_external_reference_is_not_user_baseline_or_raw_syncable(self):
        decision = inspect_observation(
            ObservationInput(
                title="article reference",
                claim="external article copy must not become user telemetry",
                source_kind="external_article_copy",
                source_ref="article://copy",
                cwd="global",
                domain="measurement",
                outcome_status="observed",
                benefit="none",
                classification="external-reference",
            )
        )
        self.assertEqual(decision.classification, Classification.EXTERNAL_REFERENCE)
        self.assertFalse(decision.allow_user_baseline)
        self.assertFalse(decision.allow_private_sync)
        self.assertEqual(decision.reason_code, "EXTERNAL_REFERENCE_LOCAL_ONLY")

    def test_all_secret_classes_are_rejected_without_echo(self):
        private_key = (
            "-----" + "BEGIN PRIVATE KEY-----\n"  # pragma: allowlist secret
            "marker\n"
            "-----" + "END PRIVATE KEY-----"
        )
        markers = (
            ("api token", "api_key=marker-api-key-123456789"),
            ("private key", private_key),
            ("authorization", bearer_secret("marker-bearer-value")),
            ("cookie", "Cookie: session=marker-cookie-value"),
            ("password", "password=marker-password-value"),
            ("connection", "postgres://user:marker-password@db.example.invalid/app"),  # pragma: allowlist secret
        )
        for label, text in markers:
            with self.subTest(label=label):
                decision = inspect_text(text, "private-reusable", "manual://generated")
                self.assertEqual(decision.classification, Classification.SECRET)
                self.assertFalse(decision.allow_private_sync)
                self.assertNotIn("marker-", decision.reason_code)

    def test_secret_classification_is_rejected(self):
        decision = inspect_text("safe generalized rule", "secret", "manual://safe")
        self.assertEqual(decision.classification, Classification.SECRET)
        self.assertFalse(decision.allow_private_sync)

    def test_denied_paths_are_machine_local(self):
        for source_ref in (
            "C:" + chr(92) + "Users" + chr(92) + "tester" + chr(92) + ".env",
            "/tmp/auth.json",
            "/var/lib/app/state.sqlite",
            "/" + "home" + "/tester/browser/session",
            "/" + "home" + "/tester/raw-transcript/turn.jsonl",
        ):
            with self.subTest(source_ref=source_ref):
                decision = inspect_text("safe text", "private-reusable", source_ref)
                self.assertEqual(decision.classification, Classification.MACHINE_LOCAL)
                self.assertFalse(decision.allow_private_sync)

    def test_client_confidential_requires_irreversible_generalization(self):
        raw = inspect_observation(
            ObservationInput(
                title="client raw",
                claim="client-specific internal identifier",
                source_kind="manual",
                source_ref="client://local",
                cwd="client",
                domain="client-work",
                outcome_status="observed",
                benefit="none",
                classification="client-confidential",
            )
        )
        self.assertEqual(raw.classification, Classification.CLIENT_CONFIDENTIAL)
        self.assertFalse(raw.allow_private_sync)
        generalized = inspect_observation(
            ObservationInput(
                title="general rule",
                claim="Use a bounded validation step before accepting a result.",
                source_kind="client-confidential-generalized",
                source_ref="generalized://rule-1",
                cwd="global",
                domain="engineering",
                outcome_status="success",
                benefit="reduced_rework",
                classification="client-confidential-generalized",
            )
        )
        self.assertEqual(generalized.classification, Classification.PRIVATE_REUSABLE)
        self.assertTrue(generalized.allow_private_sync)
        self.assertTrue(generalized.irreversible_generalization)
        assert_syncable(generalized)

    def test_invalid_decision_cannot_be_syncable(self):
        with self.assertRaises(PrivacyError):
            assert_syncable(object())

    def test_safe_source_path_requires_explicit_root_and_blocks_escape(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "allowed"
            root.mkdir()
            source = root / "knowledge.md"
            source.write_text("safe", encoding="utf-8")
            self.assertEqual(safe_source_path(source, (root,)), source.resolve())
            with self.assertRaises(PrivacyError):
                safe_source_path(root.parent / "outside.md", (root,))
            with self.assertRaises(PrivacyError):
                safe_source_path(root / ".env", (root,))

    def test_safe_source_path_rejects_symlink_when_supported(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            root = base / "allowed"
            root.mkdir()
            outside = base / "outside.txt"
            outside.write_text("outside", encoding="utf-8")
            link = root / "link.txt"
            try:
                link.symlink_to(outside)
            except (OSError, NotImplementedError):
                self.skipTest("symlink creation is unavailable")
            with self.assertRaises(PrivacyError):
                safe_source_path(link, (root,))


if __name__ == "__main__":
    unittest.main()
