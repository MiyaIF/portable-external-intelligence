from __future__ import annotations

import os
import subprocess
import tempfile
import unittest
from pathlib import Path

from ei.knowledge_repository import KnowledgeRepositoryError, bootstrap_knowledge_repository, inspect_knowledge_repository


class KnowledgeRepositoryTests(unittest.TestCase):
    @unittest.skipUnless(os.name == "nt", "Windows junction fixture is platform-specific")
    def test_bootstrap_rejects_junction_root_before_writing(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            outside = base / "outside"
            outside.mkdir()
            junction = base / "knowledge"
            created = subprocess.run(
                ["cmd.exe", "/c", "mklink", "/J", str(junction), str(outside)],
                capture_output=True,
                text=True,
                check=False,
            )
            if created.returncode != 0 or not junction.exists():
                self.skipTest("junction fixture unavailable")

            with self.assertRaisesRegex(KnowledgeRepositoryError, "KNOWLEDGE_REPARSE_POINT"):
                bootstrap_knowledge_repository(junction, initialize_git=False)

            self.assertEqual(list(outside.iterdir()), [])

    def test_bootstrap_creates_independent_git_layout_with_sync_disabled(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            engine, knowledge, runtime = root / "engine", root / "knowledge", root / "runtime"
            engine.mkdir()
            status = bootstrap_knowledge_repository(knowledge, engine_root=engine, runtime_root=runtime)
            self.assertTrue(status.initialized)
            self.assertTrue(status.git_initialized)
            self.assertTrue(status.manifest_valid)
            self.assertFalse(status.sync_enabled)
            self.assertTrue((knowledge / ".git").exists())
            self.assertTrue((knowledge / "events" / ".gitkeep").is_file())
            self.assertTrue((knowledge / "knowledge" / "reusable-intelligence").is_dir())
            config = subprocess.run(["git", "-C", str(knowledge), "config", "--local", "--get-regexp", "user\\."], capture_output=True, text=True, check=False)
            self.assertEqual(config.returncode, 1)
            self.assertEqual(inspect_knowledge_repository(knowledge, engine_root=engine, runtime_root=runtime).remote_names, ())

    def test_bootstrap_rejects_engine_or_runtime_overlap(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            with self.assertRaisesRegex(KnowledgeRepositoryError, "KNOWLEDGE_ROOT_OVERLAPS_ENGINE_ROOT"):
                bootstrap_knowledge_repository(root / "engine" / "knowledge", engine_root=root / "engine")

    def test_existing_nonempty_files_are_not_overwritten(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            knowledge = root / "knowledge"
            knowledge.mkdir()
            (knowledge / "README.md").write_text("operator text\n", encoding="utf-8")
            status = bootstrap_knowledge_repository(knowledge, initialize_git=False)
            self.assertTrue(status.required_paths_present)
            self.assertEqual((knowledge / "README.md").read_text(encoding="utf-8"), "operator text\n")

    def test_existing_empty_directory_receives_initial_commit(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            knowledge = root / "knowledge"
            knowledge.mkdir()

            status = bootstrap_knowledge_repository(knowledge)

            self.assertTrue(status.git_initialized)
            count = subprocess.run(
                ["git", "-C", str(knowledge), "rev-list", "--count", "HEAD"],
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(count.returncode, 0, count.stderr)
            self.assertEqual(count.stdout.strip(), "1")


if __name__ == "__main__":
    unittest.main()
