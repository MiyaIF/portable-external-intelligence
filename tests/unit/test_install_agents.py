import json
import sys
import tempfile
import unittest
from pathlib import Path

from ei.installer import _skill_binding
from ei.install_agents import (
    BEGIN_MARKER,
    END_MARKER,
    merge_global_agents,
    merge_managed_context,
    remove_global_agents,
    render_global_agents,
    render_managed_context,
)
from ei.skill_installer import SkillInstallResult
from tests.helpers import make_hook_settings


class InstallAgentsTests(unittest.TestCase):
    def test_skill_binding_uses_schema_v2_personal_alias_and_null_team(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            settings = make_hook_settings(root)
            result = SkillInstallResult(
                "codex-cli",
                "copy",
                root / "source",
                root / "host" / "skills" / "external-intelligence",
                "sha256:" + "a" * 64,
                "sha256:" + "b" * 64,
                False,
            )
            _, raw = _skill_binding("codex-cli", result, settings, Path(sys.executable))
            binding = json.loads(raw.decode("utf-8"))
            self.assertEqual(binding["schema_version"], 2)
            self.assertEqual(binding["personal_knowledge_root"], str(settings.paths.personal_knowledge_root))
            self.assertEqual(binding["knowledge_root"], str(settings.paths.personal_knowledge_root))
            self.assertIsNone(binding["team_knowledge_root"])

    def test_absent_existing_second_install_and_uninstall_round_trip(self):
        block = render_global_agents(r"C:\Program Files\Python\python.exe")
        once = merge_global_agents("# Existing\n", block)
        self.assertEqual(once, merge_global_agents(once, block))
        self.assertIn("# Existing\n", once)
        self.assertNotIn("{{OBSERVE_COMMAND}}", once)
        self.assertEqual(remove_global_agents(once), "# Existing\n")

    def test_corrupt_markers_and_path_with_spaces(self):
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp) / "AGENTS.md"
            original = "before\n" + BEGIN_MARKER + "\n" + BEGIN_MARKER + "\n" + END_MARKER + "\nafter\n"
            target.write_text(original, encoding="utf-8")
            rendered = render_global_agents(r"C:\Path With Spaces\python.exe")
            with self.assertRaisesRegex(ValueError, "AGENTS_MARKER_CORRUPT"):
                merge_managed_context(target, rendered)
            self.assertEqual(target.read_text(encoding="utf-8"), original)
        rendered = render_global_agents(r"C:\Path With Spaces\python.exe")
        self.assertIn("C:\\Path With Spaces\\python.exe", rendered)
        self.assertEqual(rendered.count(BEGIN_MARKER), 1)
        self.assertEqual(rendered.count(END_MARKER), 1)

    def test_all_host_context_templates_render_without_placeholder_and_preserve_markers(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            for host_id, marker_name in (
                ("codex-cli", "AGENTS.md"),
                ("claude-code", "CLAUDE.md"),
                ("gemini-cli", "GEMINI.md"),
                ("qwen-code", "QWEN.md"),
            ):
                rendered = render_managed_context(
                    host_id,
                    root / "Python With Spaces" / "python.exe",
                    root / "repo with spaces",
                    root / "runtime with spaces",
                    root / "skills with spaces" / "external-intelligence",
                )
                self.assertEqual(rendered.count(BEGIN_MARKER), 1)
                self.assertEqual(rendered.count(END_MARKER), 1)
                self.assertNotIn("{{", rendered)
                self.assertIn("launcher.py", rendered)
                self.assertIn("-I", rendered)
                self.assertIn("-B", rendered)
                expected_label = marker_name.split(".")[0] if host_id == "codex-cli" else host_id.split("-")[0].upper()
                self.assertIn(expected_label, rendered)

    def test_context_command_uses_explicit_roots_and_survives_shell_characters(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            rendered = render_managed_context(
                "claude-code",
                root / "Python 日本語 & (safe)" / "python.exe",
                root / "engine 'root'",
                root / "runtime $root",
                root / "skills with spaces" / "external-intelligence",
                root / "knowledge \"root\"",
            )
            self.assertIn("--engine-root", rendered)
            self.assertIn("--knowledge-root", rendered)
            self.assertIn("--runtime-root", rendered)
            self.assertIn("launcher.py", rendered)
            self.assertIn("-I", rendered)
            self.assertIn("-B", rendered)
            self.assertNotIn("--repo \"", rendered)
            self.assertNotIn("{{", rendered)

    def test_long_portable_paths_do_not_invalidate_context_template(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / ("portable-" + ("x" * 180))
            rendered = render_managed_context(
                "codex-cli",
                root / "venv" / "bin" / "python",
                root / "engine clone",
                root / "runtime",
                root / "skills" / "external-intelligence",
                root / "knowledge",
            )
            self.assertGreaterEqual(len(rendered), 2600)
            self.assertEqual(rendered.count(BEGIN_MARKER), 1)
            self.assertEqual(rendered.count(END_MARKER), 1)
            self.assertNotIn("{{OBSERVE_COMMAND}}", rendered)
            self.assertNotIn("{{SKILL_LAUNCH_COMMAND}}", rendered)

            deep_python = root.joinpath(*(("segment-" + ("y" * 180),) * 8), "bin", "python")
            global_rendered = render_global_agents(deep_python)
            self.assertGreaterEqual(len(global_rendered), 1800)
            self.assertEqual(global_rendered.count(BEGIN_MARKER), 1)
            self.assertEqual(global_rendered.count(END_MARKER), 1)
            self.assertNotIn("{{OBSERVE_COMMAND}}", global_rendered)


if __name__ == "__main__":
    unittest.main()
