from __future__ import annotations

import json
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from ei.github_knowledge import (
    GitHubKnowledgeClient,
    GitHubKnowledgeError,
    connect_exact_remote,
    engine_remote_url,
    push_and_verify,
)


class GitHubKnowledgeClientTests(unittest.TestCase):
    def test_private_repository_inspection_uses_direct_bounded_argv(self) -> None:
        response = subprocess.CompletedProcess(
            args=[],
            returncode=0,
            stdout=json.dumps({"visibility": "private", "size": 7, "default_branch": "main"}),
            stderr="",
        )
        with patch("ei.github_knowledge.subprocess.run", return_value=response) as run:
            state = GitHubKnowledgeClient("gh").inspect_repository("MiyaIF/private-knowledge")

        self.assertTrue(state.exists)
        self.assertEqual(state.visibility, "private")
        self.assertEqual(state.default_branch, "main")
        self.assertFalse(state.empty)
        argv = run.call_args.args[0]
        options = run.call_args.kwargs
        self.assertEqual(argv, ["gh", "api", "repos/MiyaIF/private-knowledge"])
        self.assertIs(options["shell"], False)
        self.assertEqual(options["timeout"], 30)
        self.assertIs(options["check"], False)

    def test_not_found_is_a_closed_absent_state(self) -> None:
        response = subprocess.CompletedProcess(args=[], returncode=1, stdout="", stderr="HTTP 404: Not Found")
        with patch("ei.github_knowledge.subprocess.run", return_value=response):
            state = GitHubKnowledgeClient("gh").inspect_repository("MiyaIF/missing")
        self.assertFalse(state.exists)
        self.assertIsNone(state.visibility)
        self.assertFalse(state.empty)

    def test_private_creation_and_remote_url_use_exact_slug(self) -> None:
        response = subprocess.CompletedProcess(args=[], returncode=0, stdout="created", stderr="")
        with patch("ei.github_knowledge.subprocess.run", return_value=response) as run:
            client = GitHubKnowledgeClient("gh")
            client.create_private_repository("MiyaIF/private-knowledge")
            remote = client.remote_url("MiyaIF/private-knowledge")

        self.assertEqual(run.call_args.args[0], ["gh", "repo", "create", "MiyaIF/private-knowledge", "--private"])
        self.assertEqual(remote, "https://github.com/MiyaIF/private-knowledge.git")

    def test_authentication_rate_limit_and_malformed_json_are_stable_errors(self) -> None:
        cases = (
            (subprocess.CompletedProcess(args=[], returncode=1, stdout="", stderr="HTTP 401: Bad credentials"), "GITHUB_AUTH_REQUIRED"),
            (subprocess.CompletedProcess(args=[], returncode=1, stdout="", stderr="API rate limit exceeded"), "GITHUB_RATE_LIMITED"),
            (subprocess.CompletedProcess(args=[], returncode=0, stdout="not-json", stderr=""), "GITHUB_RESPONSE_INVALID"),
        )
        for response, error_code in cases:
            with self.subTest(error_code=error_code):
                with patch("ei.github_knowledge.subprocess.run", return_value=response):
                    with self.assertRaisesRegex(GitHubKnowledgeError, f"^{error_code}$"):
                        GitHubKnowledgeClient("gh").inspect_repository("MiyaIF/private-knowledge")

    def test_timeout_and_missing_executable_do_not_expose_exception_text(self) -> None:
        for raised, error_code in (
            (subprocess.TimeoutExpired(cmd=["gh"], timeout=30, output="gh" + "p_" + "s" * 24, stderr="to" + "ken=secret"), "GITHUB_COMMAND_TIMEOUT"),
            (FileNotFoundError("C:/Profiles/private/" + "to" + "ken-gh"), "GITHUB_EXECUTABLE_UNAVAILABLE"),
        ):
            with self.subTest(error_code=error_code):
                with patch("ei.github_knowledge.subprocess.run", side_effect=raised):
                    with self.assertRaisesRegex(GitHubKnowledgeError, f"^{error_code}$") as caught:
                        GitHubKnowledgeClient("gh").inspect_repository("MiyaIF/private-knowledge")
                    self.assertNotIn("secret", str(caught.exception).casefold())
                    self.assertNotIn("users", str(caught.exception).casefold())

    def test_command_result_redacts_token_shaped_output(self) -> None:
        token = "ghp_" + "a" * 36
        response = subprocess.CompletedProcess(args=[], returncode=0, stdout=f'{{"token":"{token}"}}', stderr="")
        with patch("ei.github_knowledge.subprocess.run", return_value=response):
            result = GitHubKnowledgeClient("gh").run_read_only(("api", "user"))
        self.assertNotIn(token, result.stdout)
        self.assertIn("<redacted>", result.stdout)

    def test_git_helpers_connect_push_and_verify_exact_commit(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            remote = root / "private.git"
            local = root / "knowledge"
            subprocess.run(["git", "init", "--bare", str(remote)], check=True, capture_output=True)
            subprocess.run(["git", "init", "-b", "main", str(local)], check=True, capture_output=True)
            (local / "README.md").write_text("private\n", encoding="utf-8")
            subprocess.run(["git", "-C", str(local), "add", "README.md"], check=True)
            subprocess.run(
                [
                    "git",
                    "-C",
                    str(local),
                    "-c",
                    "user.name=Test User",
                    "-c",
                    "user.email=test@example.invalid",
                    "commit",
                    "-m",
                    "seed",
                ],
                check=True,
                capture_output=True,
            )

            connect_exact_remote(local, "origin", str(remote))
            commit = push_and_verify(local, "origin", "main")

            self.assertRegex(commit, r"^[0-9a-f]{40,64}$")
            self.assertEqual(engine_remote_url(local, "origin"), str(remote))
            remote_commit = subprocess.run(
                ["git", "--git-dir", str(remote), "rev-parse", "refs/heads/main"],
                check=True,
                capture_output=True,
                text=True,
            ).stdout.strip()
            self.assertEqual(commit, remote_commit)

    def test_connect_rejects_unequal_existing_remote(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            local = root / "knowledge"
            local.mkdir()
            subprocess.run(["git", "init", "-b", "main"], cwd=local, check=True, capture_output=True)
            subprocess.run(["git", "remote", "add", "origin", str(root / "first.git")], cwd=local, check=True)
            with self.assertRaisesRegex(GitHubKnowledgeError, "^KNOWLEDGE_REMOTE_URL_CONFLICT$"):
                connect_exact_remote(local, "origin", str(root / "second.git"))


if __name__ == "__main__":
    unittest.main()
