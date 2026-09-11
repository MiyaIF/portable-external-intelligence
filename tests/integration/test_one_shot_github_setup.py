from __future__ import annotations

import tempfile
import subprocess
import unittest
from pathlib import Path
from unittest.mock import patch

from ei.github_knowledge import GitHubKnowledgeError, GitHubRepositoryState
from ei.knowledge_repository import bootstrap_knowledge_repository
from ei.knowledge_setup import KnowledgeSetupSelection, apply_knowledge_setup, plan_knowledge_setup
from ei.remote_assurance import RemoteDescriptor, normalize_remote


class _FakeGitHubClient:
    def __init__(
        self,
        timeline: list[tuple[str, ...]],
        *,
        visibility: str = "private",
        empty: bool = True,
        create_error: str | None = None,
        inspect_error: str | None = None,
        auth_error: str | None = None,
    ) -> None:
        self.timeline = timeline
        self.visibility = visibility
        self.empty = empty
        self.create_error = create_error
        self.inspect_error = inspect_error
        self.auth_error = auth_error

    def verify_authentication(self) -> None:
        self.timeline.append(("gh", "auth"))
        if self.auth_error:
            raise GitHubKnowledgeError(self.auth_error)

    def create_private_repository(self, repository: str) -> None:
        self.timeline.append(("gh", "repo", "create", repository, "--private"))
        if self.create_error:
            raise GitHubKnowledgeError(self.create_error)

    def inspect_repository(self, repository: str) -> GitHubRepositoryState:
        self.timeline.append(("gh", "api", f"repos/{repository}"))
        if self.inspect_error:
            raise GitHubKnowledgeError(self.inspect_error)
        return GitHubRepositoryState(repository, True, self.visibility, "main" if not self.empty else None, self.empty)

    def remote_url(self, repository: str) -> str:
        return f"https://github.com/{repository}.git"


class OneShotGitHubSetupTests(unittest.TestCase):
    def _git(self, root: Path, *arguments: str) -> str:
        return subprocess.run(
            ["git", *arguments],
            cwd=root,
            check=True,
            capture_output=True,
            text=True,
        ).stdout.strip()

    def _valid_remote(self, root: Path) -> tuple[Path, Path]:
        seed = root / "seed"
        remote = root / "private.git"
        bootstrap_knowledge_repository(seed)
        self._git(root, "clone", "--bare", str(seed), str(remote))
        return seed, remote

    def _selection(self, root: Path, *, mode: str = "github-new", confirmation: str | None = "MiyaIF/private-knowledge") -> KnowledgeSetupSelection:
        engine = root / "engine"
        engine.mkdir(exist_ok=True)
        return KnowledgeSetupSelection(
            mode=mode,
            engine_root=engine,
            knowledge_root=root / "knowledge",
            runtime_root=root / "runtime",
            github_repository="MiyaIF/private-knowledge",
            sync_enabled=True,
            confirm_github_create=confirmation if mode == "github-new" else None,
        )

    def _apply_with_fake(self, selection: KnowledgeSetupSelection, client: _FakeGitHubClient, timeline: list[tuple[str, ...]]):
        def connect(root: Path, remote_name: str, remote_url: str) -> None:
            timeline.append(("git", "remote", "add", remote_name, remote_url))

        def push(root: Path, remote_name: str, branch: str) -> str:
            timeline.append(("git", "push", remote_name, f"HEAD:refs/heads/{branch}"))
            return "a" * 40

        with (
            patch("ei.github_knowledge.GitHubKnowledgeClient", return_value=client),
            patch("ei.github_knowledge.connect_exact_remote", side_effect=connect),
            patch("ei.github_knowledge.push_and_verify", side_effect=push),
            patch("ei.github_knowledge.engine_remote_url", return_value=None),
        ):
            return apply_knowledge_setup(plan_knowledge_setup(selection))

    def test_github_new_verifies_private_before_connect_and_push(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            timeline: list[tuple[str, ...]] = []
            selection = self._selection(Path(tmp))
            result = self._apply_with_fake(selection, _FakeGitHubClient(timeline), timeline)

            self.assertTrue(result.ok, result)
            self.assertEqual(result.stage, "INITIAL_PUSH_VERIFIED")
            create = timeline.index(("gh", "repo", "create", "MiyaIF/private-knowledge", "--private"))
            verify = timeline.index(("gh", "api", "repos/MiyaIF/private-knowledge"))
            connect = timeline.index(("git", "remote", "add", "origin", "https://github.com/MiyaIF/private-knowledge.git"))
            push = timeline.index(("git", "push", "origin", "HEAD:refs/heads/main"))
            self.assertLess(create, verify)
            self.assertLess(verify, connect)
            self.assertLess(connect, push)
            self.assertEqual(result.remote["classification"], "private_verified")

    def test_creation_confirmation_is_required_before_any_mutation(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            timeline: list[tuple[str, ...]] = []
            selection = self._selection(Path(tmp), confirmation=None)
            result = self._apply_with_fake(selection, _FakeGitHubClient(timeline), timeline)
            self.assertFalse(result.ok)
            self.assertEqual(result.errors[0]["code"], "GITHUB_CREATE_CONFIRMATION_REQUIRED")
            self.assertFalse(selection.knowledge_root.exists())
            self.assertEqual(timeline, [])

    def test_existing_repository_public_visibility_and_engine_reuse_block_push(self) -> None:
        cases = (
            (_FakeGitHubClient([], create_error="GITHUB_REPOSITORY_ALREADY_EXISTS"), None, "GITHUB_REPOSITORY_ALREADY_EXISTS"),
            (_FakeGitHubClient([], visibility="public"), None, "PRIVATE_REMOTE_REQUIRED"),
            (_FakeGitHubClient([]), "https://github.com/MiyaIF/private-knowledge.git", "ENGINE_REMOTE_REUSE"),
        )
        for client, engine_remote, error_code in cases:
            with self.subTest(error_code=error_code), tempfile.TemporaryDirectory() as tmp:
                timeline = client.timeline
                selection = self._selection(Path(tmp))
                with (
                    patch("ei.github_knowledge.GitHubKnowledgeClient", return_value=client),
                    patch("ei.github_knowledge.connect_exact_remote") as connect,
                    patch("ei.github_knowledge.push_and_verify") as push,
                    patch("ei.github_knowledge.engine_remote_url", return_value=engine_remote),
                ):
                    result = apply_knowledge_setup(plan_knowledge_setup(selection))
                self.assertFalse(result.ok)
                self.assertEqual(result.errors[0]["code"], error_code)
                connect.assert_not_called()
                push.assert_not_called()

    def test_missing_github_authentication_stops_before_creation(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            timeline: list[tuple[str, ...]] = []
            selection = self._selection(Path(tmp))
            result = self._apply_with_fake(
                selection,
                _FakeGitHubClient(timeline, auth_error="GITHUB_AUTH_REQUIRED"),
                timeline,
            )
            self.assertFalse(result.ok)
            self.assertEqual(result.errors[0]["code"], "GITHUB_AUTH_REQUIRED")
            self.assertNotIn(("gh", "repo", "create", "MiyaIF/private-knowledge", "--private"), timeline)

    def test_post_create_failure_is_retained_and_resumed_without_second_create(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            first_timeline: list[tuple[str, ...]] = []
            selection = self._selection(root)
            failed = self._apply_with_fake(
                selection,
                _FakeGitHubClient(first_timeline, inspect_error="GITHUB_NETWORK_UNAVAILABLE"),
                first_timeline,
            )
            self.assertFalse(failed.ok)
            self.assertTrue(failed.recovery["external_repository_retained"])

            second_timeline: list[tuple[str, ...]] = []
            recovered = self._apply_with_fake(selection, _FakeGitHubClient(second_timeline), second_timeline)
            self.assertTrue(recovered.ok, recovered)
            self.assertNotIn(("gh", "repo", "create", "MiyaIF/private-knowledge", "--private"), second_timeline)

    def test_github_existing_empty_remote_connects_and_pushes_without_creation(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            timeline: list[tuple[str, ...]] = []
            selection = self._selection(Path(tmp), mode="github-existing", confirmation=None)
            result = self._apply_with_fake(selection, _FakeGitHubClient(timeline, empty=True), timeline)
            self.assertTrue(result.ok, result)
            self.assertNotIn(("gh", "repo", "create", "MiyaIF/private-knowledge", "--private"), timeline)
            self.assertIn(("git", "push", "origin", "HEAD:refs/heads/main"), timeline)

    def _apply_existing_remote(self, selection: KnowledgeSetupSelection, remote: Path):
        plan = plan_knowledge_setup(selection)
        descriptor = RemoteDescriptor(
            remote=str(remote),
            normalized=normalize_remote(remote),
            fingerprint=str(plan.remote_fingerprint),
            classification="private_verified",
            provider="github",
            owner="MiyaIF",
            repository="private-knowledge",
            visibility_source="explicit",
        )
        timeline: list[tuple[str, ...]] = []
        client = _FakeGitHubClient(timeline, empty=False)
        with (
            patch("ei.github_knowledge.GitHubKnowledgeClient", return_value=client),
            patch("ei.github_knowledge._assure_github_remote", return_value=descriptor),
        ):
            return apply_knowledge_setup(plan)

    def test_github_existing_nonempty_valid_remote_is_restored_atomically(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            _, remote = self._valid_remote(root)
            selection = self._selection(root, mode="github-existing", confirmation=None)

            result = self._apply_existing_remote(selection, remote)

            self.assertTrue(result.ok, result)
            self.assertEqual(result.repository["status"], "RESTORED")
            self.assertTrue((selection.knowledge_root / "knowledge-repository.json").is_file())
            self.assertFalse(any(root.glob(".knowledge.ei-restore-*")))

    def test_github_existing_invalid_remote_layout_is_blocked(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            seed = root / "invalid-seed"
            remote = root / "invalid.git"
            seed.mkdir()
            self._git(seed, "init", "-b", "main")
            (seed / "README.md").write_text("not a knowledge repository\n", encoding="utf-8")
            self._git(seed, "add", "README.md")
            self._git(seed, "-c", "user.name=Test User", "-c", "user.email=test@example.invalid", "commit", "-m", "invalid")
            self._git(root, "clone", "--bare", str(seed), str(remote))
            selection = self._selection(root, mode="github-existing", confirmation=None)

            result = self._apply_existing_remote(selection, remote)

            self.assertFalse(result.ok)
            self.assertEqual(result.errors[0]["code"], "KNOWLEDGE_REMOTE_LAYOUT_INVALID")
            self.assertFalse(selection.knowledge_root.exists())

    def test_existing_local_remote_mismatch_dirty_and_divergence_are_blocked(self) -> None:
        scenarios = ("remote-mismatch", "dirty", "diverged", "missing-remote")
        for scenario in scenarios:
            with self.subTest(scenario=scenario), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                seed, remote = self._valid_remote(root)
                selection = self._selection(root, mode="github-existing", confirmation=None)
                self._git(root, "clone", str(remote), str(selection.knowledge_root))
                if scenario == "remote-mismatch":
                    other = root / "other.git"
                    self._git(root, "init", "--bare", str(other))
                    self._git(selection.knowledge_root, "remote", "set-url", "origin", str(other))
                elif scenario == "dirty":
                    (selection.knowledge_root / "untracked.txt").write_text("dirty\n", encoding="utf-8")
                elif scenario == "missing-remote":
                    self._git(selection.knowledge_root, "remote", "remove", "origin")
                else:
                    self._git(selection.knowledge_root, "config", "user.name", "Test User")
                    self._git(selection.knowledge_root, "config", "user.email", "test@example.invalid")
                    (selection.knowledge_root / "knowledge" / "local-only.md").write_text("local\n", encoding="utf-8")
                    self._git(selection.knowledge_root, "add", "knowledge/local-only.md")
                    self._git(selection.knowledge_root, "commit", "-m", "local")
                    self._git(seed, "remote", "add", "origin", str(remote))
                    (seed / "knowledge" / "remote-only.md").write_text("remote\n", encoding="utf-8")
                    self._git(seed, "add", "knowledge/remote-only.md")
                    self._git(seed, "-c", "user.name=Test User", "-c", "user.email=test@example.invalid", "commit", "-m", "remote")
                    self._git(seed, "push", "origin", "main")

                result = self._apply_existing_remote(selection, remote)

                expected = {
                    "remote-mismatch": "KNOWLEDGE_REMOTE_URL_CONFLICT",
                    "dirty": "KNOWLEDGE_LOCAL_WORKTREE_DIRTY",
                    "diverged": "KNOWLEDGE_HISTORY_DIVERGED",
                    "missing-remote": "KNOWLEDGE_HISTORY_ALIGNMENT_REQUIRED",
                }[scenario]
                self.assertFalse(result.ok)
                self.assertEqual(result.errors[0]["code"], expected)


if __name__ == "__main__":
    unittest.main()
