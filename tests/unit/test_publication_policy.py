from __future__ import annotations

import copy
import json
import tempfile
import unittest
from contextlib import redirect_stdout
from io import StringIO
from pathlib import Path

from ei.cli import EXIT_INPUT, main
from ei.publication_policy import (
    PUBLIC_OWNER_DECISION_REQUIRED,
    PublicationPolicyError,
    load_publication_policy,
    policy_digest,
    validate_publication_policy,
)


class PublicationPolicyTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.fixture = Path(__file__).resolve().parents[1] / "fixtures" / "publication-policy.valid.json"
        cls.invalid_fixture = Path(__file__).resolve().parents[1] / "fixtures" / "publication-policy.invalid.json"
        cls.valid = json.loads(cls.fixture.read_text(encoding="utf-8"))

    def assert_policy_error(self, value: object, code: str) -> None:
        with self.assertRaises(PublicationPolicyError) as context:
            validate_publication_policy(value)
        self.assertEqual(context.exception.code, code)

    def test_valid_policy_is_closed_and_has_stable_digest(self) -> None:
        value = validate_publication_policy(copy.deepcopy(self.valid))
        self.assertEqual(value["github"]["owner"], "fixture-owner")
        first = policy_digest(value)
        reordered = json.loads(json.dumps(value, ensure_ascii=False))
        self.assertEqual(first, policy_digest(reordered))
        self.assertTrue(first.startswith("sha256:"))

    def test_missing_policy_requires_owner_decision(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaises(PublicationPolicyError) as context:
                load_publication_policy(Path(tmp) / "missing.json")
        self.assertEqual(context.exception.code, PUBLIC_OWNER_DECISION_REQUIRED)

    def test_unknown_field_is_rejected(self) -> None:
        value = copy.deepcopy(self.valid)
        value["unexpected"] = "not permitted"
        self.assert_policy_error(value, "PUBLIC_POLICY_UNKNOWN_FIELD")

    def test_invalid_spdx_expression_is_rejected(self) -> None:
        value = copy.deepcopy(self.valid)
        value["license_spdx"] = "Definitely-Not-SPDX"
        self.assert_policy_error(value, "PUBLIC_POLICY_INVALID_LICENSE")

    def test_non_public_author_email_is_rejected(self) -> None:
        value = copy.deepcopy(self.valid)
        value["public_author"]["email"] = "owner@example.com"
        self.assert_policy_error(value, "PUBLIC_POLICY_AUTHOR_EMAIL_NOT_PUBLIC")

    def test_malformed_github_slug_is_rejected(self) -> None:
        value = copy.deepcopy(self.valid)
        value["github"]["repository"] = "owner/repository"
        self.assert_policy_error(value, "PUBLIC_POLICY_GITHUB_SLUG_INVALID")

    def test_missing_security_route_is_rejected(self) -> None:
        value = copy.deepcopy(self.valid)
        del value["security_reporting"]
        self.assert_policy_error(value, "PUBLIC_POLICY_SECURITY_ROUTE_REQUIRED")

    def test_secret_like_value_is_rejected(self) -> None:
        value = copy.deepcopy(self.valid)
        value["copyright_holder"] = "ghp_" + "A" * 36
        self.assert_policy_error(value, "PUBLIC_POLICY_SECRET_LIKE_VALUE")

    def test_invalid_fixture_is_rejected(self) -> None:
        value = json.loads(self.invalid_fixture.read_text(encoding="utf-8"))
        with self.assertRaises(PublicationPolicyError):
            validate_publication_policy(value)

    def test_cli_verifies_policy_and_emits_digest(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            policy_path = Path(tmp) / "policy.json"
            policy_path.write_text(json.dumps(self.valid, ensure_ascii=False), encoding="utf-8")
            output = StringIO()
            with redirect_stdout(output):
                code = main(["public-release", "policy", "verify", "--policy", str(policy_path), "--json"])
        self.assertEqual(code, 0)
        result = json.loads(output.getvalue())
        self.assertTrue(result["valid"])
        self.assertEqual(result["policy_digest"], policy_digest(self.valid))
        self.assertNotIn("unknown", result)

    def test_cli_missing_policy_returns_owner_decision_code(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            output = StringIO()
            with redirect_stdout(output):
                code = main(
                    [
                        "public-release",
                        "policy",
                        "verify",
                        "--policy",
                        str(Path(tmp) / "missing.json"),
                        "--json",
                    ]
                )
        self.assertEqual(code, EXIT_INPUT)
        self.assertEqual(json.loads(output.getvalue())["error_code"], PUBLIC_OWNER_DECISION_REQUIRED)


if __name__ == "__main__":
    unittest.main()
