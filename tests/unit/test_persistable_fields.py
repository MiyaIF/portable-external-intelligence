from __future__ import annotations

import unittest

from ei.persistable_fields import (
    inspect_changeset_payload,
    inspect_persistable,
    is_privacy_or_safety_violation,
)


def digest(letter: str = "a") -> str:
    return "sha256:" + letter * 64


class PersistableFieldsTests(unittest.TestCase):
    def _payload(self) -> dict[str, object]:
        return {
            "actor": "agent_direct",
            "provider_id": "openai",
            "classification": "private-reusable",
            "source_hash": digest("a"),
            "source_ref_hash": digest("b"),
            "source_hashes": [digest("a"), digest("b")],
            "evidence_refs": [digest("a")],
            "provenances": ["source:alpha", "source:beta"],
            "record_fingerprint": digest("c"),
            "session_id_hash": digest("d"),
            "turn_id_hash": digest("e"),
            "provenance_key": "source:alpha",
            "title": "再利用可能な観測",
            "claim": "検証済みの判断を次回の作業でも再利用できる",
            "rule": "証拠、適用範囲、失敗条件を確認してから判断ルールへ昇格する。",
            "precondition": "同じ構造が別案件でも観測されたとき",
            "failure_mode": "根拠を確認せずに一般化すること",
            "exception": "機密情報を含む場合は保存しない",
            "version_constraint": None,
            "domain": "cli-agent",
            "scopes": ["codex-cli", "claude-code"],
            "applicability": ["portable-workspace"],
            "benefit": "再調査コストを減らす",
            "benefit_count": 1,
            "source_kind": "agent_direct",
            "source_ref": "turn://source/1",
            "outcome_status": "success",
            "reason_code": "EVIDENCE_SUFFICIENT",
            "pattern_id": "pattern_1",
            "cluster_id": "cluster_1",
            "proposal_only": False,
            "contradiction_count": 0,
            "revision": 1,
            "approved_by": digest("f"),
            "approval_identity_hash": digest("f"),
            "cwd_fingerprint": digest("1"),
            "user_id_hash": digest("2"),
            "machine_id_hash": digest("3"),
            "host_id_hash": digest("4"),
            "reference_hash": digest("5"),
            "match_kind": "similar",
        }

    def test_valid_payload_reports_every_nested_string_pointer(self) -> None:
        inspection = inspect_changeset_payload(self._payload())
        self.assertTrue(inspection.valid, inspection.to_dict())
        self.assertIn("/provenances/0", inspection.inspected_paths)
        self.assertIn("/evidence_refs/0", inspection.inspected_paths)
        self.assertIn("/scopes/1", inspection.inspected_paths)
        self.assertEqual(dict(inspection.normalized_values)["/applicability/0"], "portable-workspace")

    def test_sensitive_values_fail_with_json_pointer_and_never_return_normalized_values(self) -> None:
        cases = (
            ("title", "api_key=do-not-store", "SECRET_PATTERN_MATCH"),
            ("claim", "原因は " + "C:" + chr(92) + "Users" + chr(92) + "someone" + chr(92) + "private" + chr(92) + "file.txt に残っている", "ABSOLUTE_PATH_FORBIDDEN"),
            ("domain", "安全\u202e逆順", "UNICODE_CONTROL_FORBIDDEN"),
            ("approved_by", "MiyaIF", "IDENTIFIER_HASH_REQUIRED"),
        )
        for field, value, reason in cases:
            with self.subTest(field=field):
                payload = self._payload()
                payload[field] = value
                inspection = inspect_changeset_payload(payload)
                self.assertFalse(inspection.valid)
                self.assertIn(reason, inspection.reason_codes)
                self.assertEqual(inspection.normalized_values, ())

    def test_unknown_and_nested_object_fields_fail_closed(self) -> None:
        unknown = self._payload()
        unknown["new_metadata"] = {"claim": "should not be accepted"}
        inspection = inspect_changeset_payload(unknown)
        self.assertIn("UNKNOWN_FIELD", inspection.reason_codes)
        self.assertEqual(inspection.issues[0].pointer, "/new_metadata")

        nested = self._payload()
        nested["scopes"] = [{"name": "cli-agent"}]
        inspection = inspect_changeset_payload(nested)
        self.assertIn("NESTED_OBJECT_FORBIDDEN", inspection.reason_codes)
        self.assertEqual(inspection.issues[0].pointer, "/scopes/0")

    def test_generic_event_walk_checks_deep_values(self) -> None:
        inspection = inspect_persistable(
            {"metadata": {"nested": {"path": "C:" + chr(92) + "Users" + chr(92) + "someone" + chr(92) + "work"}}}
        )
        self.assertFalse(inspection.valid)
        self.assertEqual(inspection.issues[0].pointer, "/metadata/nested/path")
        self.assertEqual(inspection.issues[0].reason_code, "ABSOLUTE_PATH_FORBIDDEN")

    def test_privacy_and_safety_reason_predicate_covers_persistable_boundary_codes(self) -> None:
        for reason in (
            "SECRET_PATTERN_MATCH",
            "ABSOLUTE_PATH_FORBIDDEN",
            "UNICODE_CONTROL_FORBIDDEN",
            "IDENTIFIER_HASH_REQUIRED",
            "PERSONAL_OR_CLIENT_IDENTIFIER_FORBIDDEN",
            "RAW_CONTENT_FORBIDDEN",
            "PRIVACY_REJECTED",
            "PATH_TRAVERSAL",
            "CLASSIFICATION_NOT_SYNCABLE",
            "HOST_APPLICABILITY_INVALID",
            "MACHINE_LOCAL_SOURCE",
            "MACHINE_LOCAL_PATH",
            "PAYLOAD_TOO_LARGE",
            "CHANGESET_TOO_LARGE",
        ):
            with self.subTest(reason=reason):
                self.assertTrue(is_privacy_or_safety_violation(reason))
        self.assertFalse(is_privacy_or_safety_violation("MALFORMED_RESPONSE"))


if __name__ == "__main__":
    unittest.main()
