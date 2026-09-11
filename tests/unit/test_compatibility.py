import json
import tempfile
import unittest
from pathlib import Path

from ei.compatibility import check_compatibility
from ei.config import load_settings


REPO_ROOT = Path(__file__).resolve().parents[2]


class CompatibilityTests(unittest.TestCase):
    def _settings(self, root: Path):
        return load_settings(
            repo_root=REPO_ROOT,
            runtime_root=root / "実行 runtime",
            host_homes={
                "codex-cli": root / "codex cli",
                "codex-app": root / "codex app",
                "claude-code": root / "claude",
                "gemini-cli": root / "gemini",
                "qwen-code": root / "qwen",
            },
        )

    def test_gemini_requires_skill_consent_and_uses_after_agent_primary(self):
        with tempfile.TemporaryDirectory() as tmp:
            gemini = self._settings(Path(tmp)).hosts["gemini-cli"]
            self.assertEqual(gemini.skill_activation_mode, "CONSENT_REQUIRED")
            self.assertEqual(gemini.capture_primary_path, "HOOK_DIRECT")
            self.assertEqual(gemini.event_mapping["AfterAgent"], "turn.stop")

    def test_codex_hooks_feature_uses_canonical_features_key(self):
        with tempfile.TemporaryDirectory() as tmp:
            codex = self._settings(Path(tmp)).hosts["codex-cli"]
            self.assertEqual(codex.hook_feature_key, "features.hooks")
            self.assertNotEqual(codex.hook_feature_key, "hooks")

    def test_unknown_host_returns_HOST_UNSUPPORTED(self):
        with tempfile.TemporaryDirectory() as tmp:
            settings = self._settings(Path(tmp))
            result = check_compatibility("unknown-host", None, None, settings)
            self.assertIn("HOST_UNSUPPORTED", result.reason_codes)
            self.assertFalse(result.installed)
            self.assertEqual(result.hook_feature_state, "UNKNOWN")

    def test_unicode_repo_and_runtime_paths_are_absolute(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            repo = root / "リポジトリ space"
            runtime = root / "ランタイム space"
            codex_home = root / "codex home"
            (repo / "config").mkdir(parents=True)
            (repo / "config" / "defaults.json").write_text(
                json.dumps({"schema_version": 1, "retrieval": {"max_chars": 5000, "max_results": 5}}),
                encoding="utf-8",
            )
            (repo / "config" / "hosts.json").write_text(
                json.dumps({"schema_version": 1, "hosts": {}}),
                encoding="utf-8",
            )
            settings = load_settings(repo_root=repo, codex_home=codex_home, runtime_root=runtime, host_homes={})
            self.assertTrue(settings.paths.repo_root.is_absolute())
            self.assertTrue(settings.paths.runtime_root.is_absolute())
            self.assertEqual(settings.paths.runtime_root, runtime.resolve())
            self.assertEqual(settings.paths.queue_dir, runtime.resolve() / "queue")

    def test_malformed_host_manifest_returns_HOST_MANIFEST_INVALID(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            repo = root / "repo"
            (repo / "config").mkdir(parents=True)
            (repo / "config" / "defaults.json").write_text(
                json.dumps({"schema_version": 1, "retrieval": {"max_chars": 5000, "max_results": 5}}),
                encoding="utf-8",
            )
            (repo / "config" / "hosts.json").write_text(
                json.dumps({"schema_version": 1, "hosts": {"broken": {"host_id": "broken"}}}),
                encoding="utf-8",
            )
            with self.assertRaisesRegex(ValueError, "HOST_MANIFEST_INVALID"):
                load_settings(repo_root=repo, codex_home=root / "codex", runtime_root=root / "runtime", host_homes={})


if __name__ == "__main__":
    unittest.main()
