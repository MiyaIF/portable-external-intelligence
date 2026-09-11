import json
import sys
import tempfile
import unittest
from dataclasses import replace
from pathlib import Path

from ei.canary import CertificationReceipt, HOOK_REQUIRED_EVENTS, record_canary, record_skill_discovery, read_hook_status, skill_discovery_canary, static_canary
from ei.command_quote import build_hook_argv, quote_command, quote_posix_command, quote_windows_command
from ei.config import HostSpec, RuntimePaths
from tests.helpers import make_hook_settings


class CanaryTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        base = make_hook_settings(self.root)
        runtime = self.root.parent / (self.root.name + "-runtime")
        paths = RuntimePaths(repo_root=self.root, codex_home=self.root / "codex", runtime_dir=runtime, event_dir=self.root / "events", knowledge_dir=self.root / "knowledge", local_state_dir=runtime / "state", metrics_dir=runtime / "metrics", cache_dir=runtime / "cache", locks_dir=runtime / "locks", config_path=self.root / "codex" / "config.toml", hooks_path=self.root / "codex" / "hooks.json", agents_path=self.root / "codex" / "AGENTS.md")
        self.settings = replace(base, paths=paths)

    def _render_installed_commands(self, value, host_id, settings):
        spec = settings.hosts.get(host_id)
        host_home = Path(spec.hook_config_path).parent if spec is not None else settings.paths.codex_home
        argv = build_hook_argv(
            sys.executable,
            host_id=host_id,
            engine_root=settings.paths.engine_root,
            knowledge_root=settings.paths.knowledge_root,
            runtime_root=settings.paths.runtime_root,
            host_home=host_home,
        )

        def render(child):
            if isinstance(child, dict):
                result = {key: render(item) for key, item in child.items()}
                if result.get("type") == "command":
                    if "commandWindows" in result:
                        result["command"] = quote_posix_command(argv)
                        result["commandWindows"] = quote_windows_command(argv)
                    elif "command" in result:
                        result["command"] = quote_command(argv)
                return result
            if isinstance(child, list):
                return [render(item) for item in child]
            return child

        return render(value)

    def _install_template(self, host_id="codex-cli"):
        source_name = "codex" if host_id.startswith("codex") else {"gemini-cli": "gemini", "claude-code": "claude", "qwen-code": "qwen"}[host_id]
        source = Path(__file__).parents[2] / "hooks" / source_name / "hooks.template.json"
        target = self.root / "hooks" / source_name / "hooks.template.json"
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(source.read_bytes())
        schema = self.root / "schemas" / "hook-event.schema.json"
        schema.parent.mkdir(parents=True, exist_ok=True)
        schema.write_bytes((Path(__file__).parents[2] / "schemas" / "hook-event.schema.json").read_bytes())
        template = json.loads(source.read_text(encoding="utf-8"))
        self.settings.paths.hooks_path.parent.mkdir(parents=True, exist_ok=True)
        installed = self._render_installed_commands(template, host_id, self.settings)
        self.settings.paths.hooks_path.write_text(json.dumps(installed), encoding="utf-8")
        self.settings.paths.config_path.write_text("[features]\nhooks = true\n", encoding="utf-8")

    def _real_receipts(self, host_id="codex-cli", instance="codex-cli"):
        for event_name in HOOK_REQUIRED_EVENTS:
            activation = "CONSENT_REQUIRED" if host_id == "gemini-cli" else "AUTO_ALLOWED"
            record_canary(CertificationReceipt(host_id, instance, mode="real", event_receipt_hashes={event_name: "sha256:" + "0" * 64}, skill_activation_mode=activation), self.settings)

    def test_valid_static_configuration_remains_unverified_without_real_events(self):
        self._install_template()
        static = static_canary("codex-cli", "cli-1", self.settings)
        self.assertTrue(static.valid)
        self.assertEqual(read_hook_status("codex-cli", "cli-1", self.settings).hook_status, "HOOK_UNVERIFIED")

    def test_only_same_instance_real_event_set_verifies(self):
        self._install_template()
        self._real_receipts(instance="cli-1")
        self.assertEqual(read_hook_status("codex-cli", "cli-1", self.settings).hook_status, "HOOK_VERIFIED")
        self.assertEqual(read_hook_status("codex-cli", "other", self.settings).hook_status, "HOOK_UNVERIFIED")

    def test_codex_cli_and_app_are_separate_instances(self):
        self._install_template()
        self._real_receipts(instance="codex-cli")
        self.assertEqual(read_hook_status("codex-app", "codex-app", self.settings).hook_status, "HOOK_UNVERIFIED")

    def test_fixture_receipts_never_verify(self):
        self._install_template()
        for event_name in HOOK_REQUIRED_EVENTS:
            record_canary(CertificationReceipt("codex-cli", "cli-1", mode="fixture", event_receipt_hashes={event_name: "sha256:" + "0" * 64}), self.settings)
        self.assertEqual(read_hook_status("codex-cli", "cli-1", self.settings).hook_status, "HOOK_UNVERIFIED")

    def _gemini_settings(self):
        root = self.root / "gemini"
        spec = HostSpec("gemini-cli", "Gemini CLI", ("gemini",), root / "settings.json", root / "GEMINI.md", (root / "skills",), {"SessionStart": "session.start", "BeforeAgent": "prompt.before", "AfterAgent": "turn.stop", "SessionEnd": "session.end"}, None, False, "CONSENT_REQUIRED", "HOOK_DIRECT", ("HOOK_DIRECT", "AGENT_SKILL", "NATIVE_SOURCE"), None)
        settings = replace(self.settings, hosts={"gemini-cli": spec})
        source = Path(__file__).parents[2] / "hooks" / "gemini" / "hooks.template.json"
        target = self.root / "hooks" / "gemini" / "hooks.template.json"
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(source.read_bytes())
        schema = self.root / "schemas" / "hook-event.schema.json"
        schema.parent.mkdir(parents=True, exist_ok=True)
        schema.write_bytes((Path(__file__).parents[2] / "schemas" / "hook-event.schema.json").read_bytes())
        root.mkdir(parents=True, exist_ok=True)
        installed = self._render_installed_commands(json.loads(source.read_text(encoding="utf-8")), "gemini-cli", settings)
        (root / "settings.json").write_text(json.dumps(installed), encoding="utf-8")
        return settings, root

    def test_gemini_verified_hook_coexists_with_consent_required_and_missing_skill(self):
        settings, _ = self._gemini_settings()
        self._real_receipts("gemini-cli", "gemini-cli")
        status = read_hook_status("gemini-cli", "gemini-cli", settings)
        self.assertEqual(status.hook_status, "HOOK_VERIFIED")
        self.assertEqual(status.skill_activation_mode, "CONSENT_REQUIRED")
        self.assertEqual(status.skill_discovery_status, "NOT_FOUND")

    def test_skill_path_alone_is_unverified_until_discovery_receipt(self):
        settings, root = self._gemini_settings()
        skill = root / "skills" / "external-intelligence"
        skill.mkdir(parents=True, exist_ok=True)
        (skill / "SKILL.md").write_text("# skill\n", encoding="utf-8")
        self.assertEqual(skill_discovery_canary("gemini-cli", "gemini-cli", settings), "UNVERIFIED")
        record_skill_discovery("gemini-cli", "gemini-cli", "DISCOVERED", settings)
        self.assertEqual(skill_discovery_canary("gemini-cli", "gemini-cli", settings), "DISCOVERED")

    def test_codex_unknown_feature_cannot_verify(self):
        self._install_template()
        self.settings.paths.config_path.unlink()
        self._real_receipts(instance="cli-unknown")
        status = read_hook_status("codex-cli", "cli-unknown", self.settings)
        self.assertEqual(status.hook_status, "HOOK_UNVERIFIED")
        self.assertIn("HOOK_FEATURE_UNKNOWN", status.reason_codes)


if __name__ == "__main__":
    unittest.main()
