from __future__ import annotations

import json
import unittest
from pathlib import Path

from ei.publication_policy import load_publication_policy, policy_digest


ROOT = Path(__file__).resolve().parents[2]
POLICY_PATH = ROOT / "release" / "publication-policy.json"


class PublicGovernanceAcceptanceTests(unittest.TestCase):
    def test_owner_policy_and_package_metadata_are_aligned(self) -> None:
        policy = load_publication_policy(POLICY_PATH)
        self.assertEqual(policy["license_spdx"], "Apache-2.0")
        self.assertEqual(policy["copyright_holder"], "Fiso")
        self.assertEqual(policy["public_author"], {"name": "MiyaIF", "email": "103426917+MiyaIF@users.noreply.github.com"})
        self.assertEqual(policy["github"]["owner"], "MiyaIF")
        self.assertEqual(policy["github"]["repository"], "portable-external-intelligence")
        self.assertEqual(policy["contribution_policy"]["dco_required"], True)
        self.assertEqual(policy["contribution_policy"]["cla_required"], False)
        metadata = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
        self.assertIn('license = "Apache-2.0"', metadata)
        self.assertIn('email = "103426917+MiyaIF@users.noreply.github.com"', metadata)
        self.assertEqual(len(policy_digest(policy)), len("sha256:") + 64)

    def test_exact_license_and_governance_documents_are_present(self) -> None:
        license_text = (ROOT / "LICENSE").read_text(encoding="utf-8")
        self.assertIn("Apache License", license_text)
        self.assertIn("Version 2.0, January 2004", license_text)
        self.assertIn("TERMS AND CONDITIONS FOR USE, REPRODUCTION, AND DISTRIBUTION", license_text)
        for path in (
            "SECURITY.md",
            "CONTRIBUTING.md",
            "CODE_OF_CONDUCT.md",
            "CHANGELOG.md",
            "THIRD_PARTY_NOTICES.md",
            "docs/support.md",
            "docs/trademarks.md",
            ".github/CODEOWNERS",
            ".github/ISSUE_TEMPLATE/bug.yml",
            ".github/ISSUE_TEMPLATE/feature.yml",
            ".github/ISSUE_TEMPLATE/config.yml",
            ".github/pull_request_template.md",
        ):
            self.assertTrue((ROOT / path).is_file(), path)

    def test_security_and_contribution_boundaries_do_not_request_private_contact(self) -> None:
        security = (ROOT / "SECURITY.md").read_text(encoding="utf-8")
        contributing = (ROOT / "CONTRIBUTING.md").read_text(encoding="utf-8")
        self.assertIn("security/advisories/new", security)
        self.assertIn("7 days", security)
        self.assertIn("14 days", security)
        self.assertIn("DCO", contributing)
        self.assertIn("does not require a CLA", contributing)
        self.assertNotIn("gmail.com", security.casefold() + contributing.casefold())

    def test_issue_forms_and_trademark_boundary_are_explicit(self) -> None:
        for path in (ROOT / ".github" / "ISSUE_TEMPLATE").glob("*.yml"):
            value = json.loads(json.dumps(__import__("yaml").safe_load(path.read_text(encoding="utf-8"))))
            self.assertIsInstance(value, dict)
        bug = (ROOT / ".github" / "ISSUE_TEMPLATE" / "bug.yml").read_text(encoding="utf-8")
        self.assertIn("secrets", bug.casefold())
        self.assertIn("client data", bug.casefold())
        trademarks = (ROOT / "docs" / "trademarks.md").read_text(encoding="utf-8")
        self.assertIn("not produced, sponsored, endorsed", trademarks)
        for name in ("Codex", "Claude", "Gemini", "Qwen"):
            self.assertIn(name, trademarks)


if __name__ == "__main__":
    unittest.main()
