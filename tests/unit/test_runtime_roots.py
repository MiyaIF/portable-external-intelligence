from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from ei.config import RuntimePaths, RootInvariantError, load_settings, validate_runtime_roots


class RuntimeRootTests(unittest.TestCase):
    def _engine(self, root: Path) -> Path:
        engine = root / "engine"
        (engine / "config").mkdir(parents=True)
        (engine / "config" / "defaults.json").write_text(json.dumps({"retrieval": {"max_chars": 5000, "max_results": 5}}), encoding="utf-8")
        return engine

    def test_explicit_three_roots_are_distinct_and_roles_are_derived(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            engine, knowledge, runtime = self._engine(root), root / "knowledge", root / "runtime"
            paths = RuntimePaths(engine_root=engine, knowledge_root=knowledge, runtime_root=runtime)
            validate_runtime_roots(paths)
            self.assertEqual(paths.engine_root, engine.resolve())
            self.assertEqual(paths.knowledge_root, knowledge.resolve())
            self.assertEqual(paths.event_dir, knowledge.resolve() / "events")
            self.assertEqual(paths.knowledge_dir, knowledge.resolve() / "knowledge")
            self.assertEqual(paths.queue_dir, runtime.resolve() / "queue")
            with self.assertRaises(AttributeError):
                paths.engine_root = root / "other"  # type: ignore[misc]

    def test_explicit_four_roots_are_distinct_and_team_is_not_derived(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            engine, personal, team, runtime = (
                self._engine(root),
                root / "個人 knowledge",
                root / "shared team",
                root / "runtime",
            )
            paths = RuntimePaths(
                engine_root=engine,
                personal_knowledge_root=personal,
                team_knowledge_root=team,
                runtime_root=runtime,
            )
            validate_runtime_roots(paths)
            self.assertEqual(paths.personal_knowledge_root, personal.resolve())
            self.assertEqual(paths.team_knowledge_root, team.resolve())

            personal_only = RuntimePaths(
                engine_root=engine,
                personal_knowledge_root=personal,
                runtime_root=root / "runtime-personal-only",
            )
            self.assertIsNone(personal_only.team_knowledge_root)

    def test_four_root_equal_or_nested_team_paths_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            engine, personal, runtime = self._engine(root), root / "personal", root / "runtime"
            cases = (
                root / "personal",
                root / "personal" / "nested",
                root.parent,
            )
            for team in cases:
                with self.subTest(team=team):
                    with self.assertRaises(RootInvariantError) as context:
                        validate_runtime_roots(
                            RuntimePaths(
                                engine_root=engine,
                                personal_knowledge_root=personal,
                                team_knowledge_root=team,
                                runtime_root=runtime,
                            )
                        )
                    self.assertIn(context.exception.code, {"ROOTS_MUST_BE_DISTINCT", "ROOTS_MUST_NOT_OVERLAP"})

    def test_equal_or_nested_roots_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            engine = self._engine(root)
            cases = ((engine, engine, root / "runtime"), (engine, engine / "knowledge", root / "runtime"), (engine, root / "knowledge", engine / "runtime"))
            for engine_root, knowledge_root, runtime_root in cases:
                with self.assertRaises(RootInvariantError) as context:
                    validate_runtime_roots(RuntimePaths(engine_root=engine_root, knowledge_root=knowledge_root, runtime_root=runtime_root))
                self.assertIn(context.exception.code, {"ROOTS_MUST_BE_DISTINCT", "ROOTS_MUST_NOT_OVERLAP"})

    def test_write_under_engine_root_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            paths = RuntimePaths(engine_root=root / "engine", knowledge_root=root / "knowledge", runtime_root=root / "runtime")
            with self.assertRaisesRegex(RootInvariantError, "ENGINE_ROOT_WRITE_FORBIDDEN"):
                paths.assert_write_allowed(paths.engine_root / "generated.json")
            paths.assert_write_allowed(paths.knowledge_root / "events" / "event.json")
            paths.assert_write_allowed(paths.runtime_root / "cache" / "item.json")

    def test_load_settings_requires_knowledge_for_explicit_engine(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            engine = self._engine(root)
            with self.assertRaisesRegex(ValueError, "KNOWLEDGE_ROOT_REQUIRED"):
                load_settings(engine_root=engine, runtime_root=root / "runtime", host_homes={})

    def test_load_settings_uses_engine_policies_and_knowledge_data(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            engine, knowledge, runtime = self._engine(root), root / "knowledge", root / "runtime"
            settings = load_settings(
                engine_root=engine,
                knowledge_root=knowledge,
                runtime_root=runtime,
                codex_home=root / "codex",
                host_homes={},
            )
            self.assertEqual(settings.repo_config_path, engine.resolve() / "config")
            self.assertEqual(settings.paths.event_dir, knowledge.resolve() / "events")
            self.assertEqual(settings.paths.knowledge_dir, knowledge.resolve() / "knowledge")
            self.assertEqual(settings.paths.runtime_root, runtime.resolve())


if __name__ == "__main__":
    unittest.main()
