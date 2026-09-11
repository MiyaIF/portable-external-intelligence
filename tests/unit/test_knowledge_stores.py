from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from ei.config import (
    KnowledgeStorePaths,
    KnowledgeStores,
    RootInvariantError,
    RuntimePaths,
    Settings,
    validate_runtime_roots,
)


class KnowledgeStoreTests(unittest.TestCase):
    def test_settings_exposes_personal_store_and_no_team_path(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            paths = RuntimePaths(
                engine_root=root / "engine",
                personal_knowledge_root=root / "personal",
                runtime_root=root / "runtime",
            )
            settings = Settings(paths)
            self.assertEqual(
                settings.knowledge_stores,
                KnowledgeStores(
                    personal=KnowledgeStorePaths(
                        "personal",
                        paths.personal_knowledge_root,
                        paths.personal_knowledge_root / "events",
                        paths.personal_knowledge_root / "knowledge",
                    ),
                    team=None,
                ),
            )
            self.assertEqual(paths.knowledge_root, paths.personal_knowledge_root)
            self.assertEqual(paths.event_dir, paths.personal_knowledge_root / "events")
            self.assertEqual(paths.knowledge_dir, paths.personal_knowledge_root / "knowledge")

    def test_team_store_is_explicit_and_root_is_validated(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            paths = RuntimePaths(
                engine_root=root / "engine",
                personal_knowledge_root=root / "personal",
                team_knowledge_root=root / "team",
                runtime_root=root / "runtime",
            )
            self.assertEqual(paths.team_knowledge_root, (root / "team").resolve())
            validate_runtime_roots(paths)

    def test_four_roots_reject_team_nested_under_personal(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            paths = RuntimePaths(
                engine_root=root / "engine",
                personal_knowledge_root=root / "personal",
                team_knowledge_root=root / "personal" / "team",
                runtime_root=root / "runtime",
            )
            with self.assertRaisesRegex(RootInvariantError, "ROOTS_MUST_NOT_OVERLAP"):
                validate_runtime_roots(paths)

    def test_personal_alias_conflict_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            with self.assertRaisesRegex(ValueError, "PERSONAL_KNOWLEDGE_ROOT_CONFLICT"):
                RuntimePaths(
                    engine_root=root / "engine",
                    knowledge_root=root / "legacy",
                    personal_knowledge_root=root / "personal",
                    runtime_root=root / "runtime",
                )


if __name__ == "__main__":
    unittest.main()
