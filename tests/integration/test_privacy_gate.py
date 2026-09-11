import subprocess
import tempfile
import unittest
from pathlib import Path

from ei.config import RuntimePaths, Settings
from ei.sync import CommandResult, sync_once


def _git(cwd: Path, *args: str) -> str:
    result = subprocess.run(["git", *args], cwd=cwd, capture_output=True, text=True, check=True)
    return result.stdout.strip()


def _settings(repo: Path, root: Path) -> Settings:
    home = root / "codex"
    runtime = home / "external-intelligence"
    paths = RuntimePaths(
        repo_root=repo,
        codex_home=home,
        runtime_dir=runtime,
        event_dir=repo / "events",
        knowledge_dir=repo / "knowledge",
        local_state_dir=runtime / "state",
        metrics_dir=runtime / "metrics",
        cache_dir=runtime / "cache",
        locks_dir=runtime / "locks",
        config_path=home / "config.toml",
        hooks_path=home / "hooks.json",
        agents_path=home / "AGENTS.md",
    )
    return Settings(paths=paths, sync_enabled=False)


class PrivacyGateIntegrationTests(unittest.TestCase):
    def test_rejected_secret_has_no_event_path(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            decision_text = "api_key=marker-api-key-123456789"
            (root / "sentinel.txt").write_text("sentinel", encoding="utf-8")
            from ei.privacy import inspect_text

            decision = inspect_text(decision_text, "private-reusable", "manual://secret")
            self.assertFalse(decision.allow_private_sync)
            self.assertEqual((root / "sentinel.txt").read_text(encoding="utf-8"), "sentinel")

    def test_sync_rejects_secret_before_git_add_and_does_not_echo_marker(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            repo = root / "repo"
            repo.mkdir()
            _git(repo, "init", "-b", "main")
            _git(repo, "config", "user.name", "Test User")
            _git(repo, "config", "user.email", "test@example.invalid")
            (repo / "README.md").write_text("seed\n", encoding="utf-8")
            _git(repo, "add", "README.md")
            _git(repo, "commit", "-m", "seed")
            event = repo / "events" / "2026" / "08" / "event.json"
            event.parent.mkdir(parents=True)
            marker = "ghp_" + "marker" * 8
            event.write_text("api_key=" + marker + "\n", encoding="utf-8")
            result = sync_once(_settings(repo, root))
            self.assertFalse(result.ok)
            self.assertEqual(result.reason_code, "PRIVACY_REJECTED")
            self.assertNotIn(marker, result.output)
            self.assertEqual(_git(repo, "diff", "--cached", "--name-only"), "")

    def test_sync_rejects_body_key_and_spool_paths(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            repo = root / "repo"
            repo.mkdir()
            for relative in ("knowledge/body.json", "knowledge/key.json", "events/spool/item.json"):
                self.assertFalse(
                    __import__("ei.sync", fromlist=["build_sync_plan"]).build_sync_plan(["?? " + relative]).allowed
                )


if __name__ == "__main__":
    unittest.main()
