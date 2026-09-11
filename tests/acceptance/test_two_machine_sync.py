import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from ei.certification import RECEIPT_KEYS
from ei.config import RuntimePaths, Settings
from ei.github_knowledge import GitHubRepositoryState
from ei.installer import SetupSelection, setup
from ei.journal import append_event, iter_events
from ei.knowledge_repository import bootstrap_knowledge_repository, inspect_knowledge_repository
from ei.models import Event
from ei.project import project_events
from ei.sync import sync_once


def run_git(cwd: Path, *args: str) -> str:
    completed = subprocess.run(["git", *args], cwd=cwd, capture_output=True, text=True, check=True)
    return completed.stdout.strip()


def make_settings(repo: Path, state_root: Path) -> Settings:
    home = state_root / "codex"
    runtime = home / "external-intelligence"
    return Settings(
        paths=RuntimePaths(
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
        ),
        retrieval_max_chars=5000,
        retrieval_max_results=5,
        sync_enabled=True,
        sync_remote="origin",
        sync_branch="main",
    )


class TwoMachineSyncTests(unittest.TestCase):
    def test_second_machine_restores_github_existing_without_runtime_state_copy(self):
        class ExistingPrivateRepository:
            def verify_authentication(self):
                return None

            def inspect_repository(self, repository):
                return GitHubRepositoryState(repository, True, "private", "main", False)

            def remote_url(self, repository):
                return f"https://github.com/{repository}.git"

            def create_private_repository(self, repository):
                raise AssertionError("existing mode must not create a repository")

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            engine = Path.cwd().resolve()
            source = root / "machine-a-knowledge"
            runtime_a = root / "machine-a-runtime"
            bootstrap_knowledge_repository(source, engine_root=engine, runtime_root=runtime_a)
            remote = root / "private-remote.git"
            run_git(root, "init", "--bare", str(remote))
            run_git(source, "remote", "add", "origin", str(remote))
            run_git(source, "push", "origin", "HEAD:refs/heads/main")
            (runtime_a / "state").mkdir(parents=True)
            (runtime_a / "state" / "machine-a-only.json").write_text("{}\n", encoding="utf-8")

            repository = "MiyaIF/private-knowledge-restore"
            github_url = f"https://github.com/{repository}.git"
            knowledge_b = root / "machine-b-knowledge"
            runtime_b = root / "machine-b-runtime"
            home_b = root / "machine-b-home"
            home_b.mkdir()
            selection = SetupSelection(
                engine_root=engine,
                knowledge_root=knowledge_b,
                runtime_root=runtime_b,
                hosts=("codex-cli",),
                organizer_provider="subscription-cli",
                organizer_host="codex-cli",
                host_homes={"codex-cli": home_b},
                python_exe=Path(__import__("sys").executable),
                skip_venv=True,
                non_interactive=True,
                accept_plan=True,
                knowledge_mode="github-existing",
                github_repository=repository,
                sync=True,
            )

            def clone_private_remote(plan, remote_url):
                self.assertEqual(remote_url, github_url)
                run_git(root, "clone", "--branch", "main", str(remote), str(plan.selection.knowledge_root))
                run_git(plan.selection.knowledge_root, "remote", "set-url", plan.selection.remote_name, remote_url)
                return inspect_knowledge_repository(
                    plan.selection.knowledge_root,
                    engine_root=plan.selection.engine_root,
                    runtime_root=plan.selection.runtime_root,
                )

            with patch("ei.github_knowledge.GitHubKnowledgeClient", return_value=ExistingPrivateRepository()), patch(
                "ei.github_knowledge._clone_existing_repository", side_effect=clone_private_remote
            ):
                result = setup(selection)

            self.assertTrue(result.ok, result.to_dict())
            self.assertEqual(result.knowledge["mode"], "github-existing")
            self.assertEqual(run_git(source, "rev-parse", "HEAD"), run_git(knowledge_b, "rev-parse", "HEAD"))
            self.assertFalse((runtime_b / "state" / "machine-a-only.json").exists())
            manifest = __import__("json").loads((runtime_b / "install-manifest.json").read_text(encoding="utf-8"))
            self.assertEqual(manifest["knowledge_repository"]["mode"], "github-existing")
            self.assertTrue(manifest["knowledge_repository"]["initial_push_complete"])

    def test_distinct_event_appends_survive_rebase_and_projection_matches(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            seed = root / "seed"
            remote = root / "remote.git"
            seed.mkdir()
            run_git(root, "init", "--bare", str(remote))
            run_git(seed, "init", "-b", "main")
            run_git(seed, "config", "user.name", "Test User")
            run_git(seed, "config", "user.email", "test@example.invalid")
            (seed / "README.md").write_text("seed\n", encoding="utf-8")
            run_git(seed, "add", "README.md")
            run_git(seed, "commit", "-m", "seed")
            run_git(seed, "remote", "add", "origin", str(remote))
            run_git(seed, "push", "-u", "origin", "main")
            machine_a = root / "machine-a"
            machine_b = root / "machine-b"
            run_git(root, "clone", "--branch", "main", str(remote), str(machine_a))
            run_git(root, "clone", "--branch", "main", str(remote), str(machine_b))
            for repo in (machine_a, machine_b):
                run_git(repo, "config", "user.name", "Test User")
                run_git(repo, "config", "user.email", "test@example.invalid")
            append_event(Event.create("observation.recorded", "2026-08-25T00:00:00+00:00", "test", "machine-a", {"observation_id": "obs_a", "claim": "A"}, event_id="evt_a"), machine_a / "events")
            append_event(Event.create("observation.recorded", "2026-08-25T00:00:01+00:00", "test", "machine-b", {"observation_id": "obs_b", "claim": "B"}, event_id="evt_b"), machine_b / "events")
            self.assertTrue(sync_once(make_settings(machine_a, root / "state-a")).ok)
            self.assertTrue(sync_once(make_settings(machine_b, root / "state-b")).ok)
            run_git(machine_a, "pull", "--rebase", "origin", "main")
            events_a = list(iter_events(machine_a / "events"))
            events_b = list(iter_events(machine_b / "events"))
            self.assertEqual({event.event_id for event in events_a}, {"evt_a", "evt_b"})
            self.assertEqual({event.event_id for event in events_b}, {"evt_a", "evt_b"})
            projection_a = project_events(events_a, root / "projection-a")
            projection_b = project_events(events_b, root / "projection-b")
            self.assertEqual(projection_a.manifest_sha256, projection_b.manifest_sha256)
            self.assertNotIn("evidence_commit_sha", RECEIPT_KEYS)


if __name__ == "__main__":
    unittest.main()
