from __future__ import annotations

import json
import py_compile
import shutil
import tempfile
import unittest
from pathlib import Path


REQUIRED = (
    "SKILL.md",
    "workflows/recall.md",
    "workflows/closeout.md",
    "workflows/maintain.md",
    "workflows/sync.md",
    "workflows/repair.md",
    "prompts/inheritance-gate.md",
    "prompts/curator.md",
    "prompts/maintainer.md",
    "schemas/gate-decision.schema.json",
    "schemas/change-set.schema.json",
    "scripts/closeout.py",
    "scripts/_trusted_runtime.py",
    "scripts/launcher.py",
    "scripts/recall.py",
    "scripts/maintain.py",
    "scripts/sync.py",
    "scripts/repair.py",
    "scripts/status.py",
)


class SkillPackageTests(unittest.TestCase):
    def test_copied_package_resolves_every_declared_relative_file(self):
        source = Path(__file__).parents[2] / "skills" / "external-intelligence"
        with tempfile.TemporaryDirectory() as tmp:
            copied = Path(tmp) / "external-intelligence"
            shutil.copytree(source, copied)
            for relative in REQUIRED:
                target = copied / relative
                self.assertTrue(target.is_file(), relative)
            for schema in ("schemas/gate-decision.schema.json", "schemas/change-set.schema.json"):
                self.assertIsInstance(json.loads((copied / schema).read_text(encoding="utf-8")), dict)
            for script in (copied / "scripts").glob("*.py"):
                py_compile.compile(str(script), doraise=True)
            text = (copied / "SKILL.md").read_text(encoding="utf-8")
            for mode in ("recall", "closeout", "maintain", "sync", "repair", "status"):
                self.assertIn(mode, text)

    def test_package_is_single_skill_and_declares_gemini_consent(self):
        source = Path(__file__).parents[2] / "skills" / "external-intelligence"
        self.assertEqual([item.name for item in source.parent.iterdir() if item.is_dir()], ["external-intelligence"])
        text = (source / "SKILL.md").read_text(encoding="utf-8")
        self.assertIn("Gemini Skill activation is a consented enrichment step", text)
        self.assertIn("not required for primary capture", text)

    def test_scripts_do_not_write_knowledge_or_invoke_provider_recursively(self):
        source = Path(__file__).parents[2] / "skills" / "external-intelligence" / "scripts"
        for script in source.glob("*.py"):
            text = script.read_text(encoding="utf-8")
            self.assertNotIn("provider.generate", text)
            self.assertNotIn("write_text(", text)
            self.assertNotIn("knowledge/", text)
            self.assertNotIn("transcript", text.lower())
            self.assertNotIn("NotImplementedError", text)
            self.assertNotIn("pass", text.replace("password", ""))
        for name in ("closeout.py", "recall.py", "maintain.py", "sync.py", "repair.py", "status.py"):
            text = (source / name).read_text(encoding="utf-8")
            self.assertIn("_trusted_runtime", text)
            self.assertIn("require_trusted_child", text)


if __name__ == "__main__":
    unittest.main()
