import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from ei.adapters.codex_memory import CodexMemoryAdapter
from ei.config import load_settings
from ei.ingest import ingest_sources
from ei.ingest import coordinate_record, source_coordination
from ei.capture_recovery import _observation
from ei.operation_runtime import OperationBudget


class IngestCursorTests(unittest.TestCase):
    def test_event_route_journal_deadline_leaves_no_ack_and_reuses_same_event(self):
        from ei import ingest
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = root / "memory.md"
            source.write_text("## Reusable knowledge\n- Validate the saved workbook before reporting completion.\n", encoding="utf-8")
            settings = self._settings(root)
            adapter = CodexMemoryAdapter([source])
            record = next(iter(adapter.iter_records({})))
            observation = _observation(record)
            def run(budget=None):
                with source_coordination(settings, budget=budget):
                    return coordinate_record(settings, record, adapter.parser_version, "native_memory", observation, budget=budget)
            with self.assertRaises(TimeoutError):
                run(OperationBudget(0))
            self.assertFalse(settings.paths.event_dir.exists())
            budget = OperationBudget(5000)
            original_append = ingest.append_event
            def expire_inside_append(*args, **kwargs):
                budget.deadline = 0
                return original_append(*args, **kwargs)
            with patch("ei.ingest.append_event", side_effect=expire_inside_append):
                with self.assertRaises(TimeoutError):
                    run(budget)
            self.assertEqual(list(settings.paths.event_dir.rglob("*.json")), [])
            self.assertFalse((settings.paths.local_state_dir / "ingest-cursor.json").exists())
            receipt, event, created = run(OperationBudget(5000))
            self.assertIsNone(receipt)
            self.assertTrue(created)
            event_path = next(settings.paths.event_dir.rglob("*.json"))
            before = event_path.read_bytes()
            original_read = ingest.read_event
            budget = OperationBudget(5000)
            def expire_inside_read(*args, **kwargs):
                budget.deadline = 0
                return original_read(*args, **kwargs)
            with patch("ei.ingest.read_event", side_effect=expire_inside_read):
                with self.assertRaises(TimeoutError):
                    run(budget)
            self.assertEqual(event_path.read_bytes(), before)
            self.assertFalse((settings.paths.local_state_dir / "ingest-cursor.json").exists())
            _, replay, created = run()
            self.assertFalse(created)
            self.assertEqual(replay.event_id, event.event_id)
            self.assertEqual(event_path.read_bytes(), before)
            self.assertEqual(len(list(settings.paths.event_dir.rglob("*.json"))), 1)

    def _settings(self, root: Path):
        (root / "config").mkdir(exist_ok=True)
        (root / "config" / "defaults.json").write_text(
            '{"retrieval":{"max_chars":5000,"max_results":5}}',
            encoding="utf-8",
        )
        return load_settings(root, codex_home=root / "codex")

    def test_unchanged_source_is_ingested_once_and_changed_source_is_reprocessed(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = root / "memory.md"
            source.write_text(
                "## Reusable knowledge\n- 書込後は再読込して確認する\n",
                encoding="utf-8",
            )
            settings = self._settings(root)
            before_bytes = source.read_bytes()
            before_mtime = source.stat().st_mtime_ns
            first = ingest_sources(settings, [CodexMemoryAdapter([source])])
            event_file = next(settings.paths.event_dir.rglob("*.json"))
            event_text = event_file.read_text(encoding="utf-8")
            self.assertIn('"capture_path": "native_memory"', event_text)
            second = ingest_sources(settings, [CodexMemoryAdapter([source])])
            self.assertEqual(first.created_events, 1)
            self.assertEqual(first.health["native_memory"], 1)
            self.assertEqual(first.health["rollout_summary"], 0)
            self.assertEqual(second.created_events, 0)
            self.assertEqual(source.read_bytes(), before_bytes)
            self.assertEqual(source.stat().st_mtime_ns, before_mtime)
            cursor = json.loads((settings.paths.local_state_dir / "ingest-cursor.json").read_text(encoding="utf-8"))
            saved = next(iter(cursor["sources"].values()))
            for field in ("source_path_hash", "size_bytes", "mtime_ns", "content_hash", "parser_version", "last_record_fingerprint", "last_event_id"):
                self.assertIn(field, saved)
            source.write_text(
                "## Reusable knowledge\n- 書込後は再読込して数式を確認する\n",
                encoding="utf-8",
            )
            third = ingest_sources(settings, [CodexMemoryAdapter([source])])
            fourth = ingest_sources(settings, [CodexMemoryAdapter([source])])
            self.assertEqual(third.created_events, 1)
            self.assertEqual(fourth.created_events, 0)

    def test_parser_version_change_invalidates_once(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = root / "memory.md"
            source.write_text("## Reusable knowledge\n- safe parser version check\n", encoding="utf-8")
            settings = self._settings(root)
            self.assertEqual(ingest_sources(settings, [CodexMemoryAdapter([source])]).created_events, 1)
            adapter = CodexMemoryAdapter([source])
            adapter.parser_version = "codex-memory-test-version"
            changed = ingest_sources(settings, [adapter])
            repeat = ingest_sources(settings, [adapter])
            self.assertEqual(changed.created_events, 1)
            self.assertEqual(repeat.created_events, 0)

    def test_malformed_source_updates_health_without_fabrication(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = root / "memory.md"
            source.write_bytes(b"## Reusable knowledge\n- \xff\n")
            settings = self._settings(root)
            result = ingest_sources(settings, [CodexMemoryAdapter([source])])
            self.assertEqual(result.created_events, 0)
            self.assertGreaterEqual(result.parse_skipped, 1)
            self.assertEqual(list(settings.paths.event_dir.rglob("*")), [])


if __name__ == "__main__":
    unittest.main()
