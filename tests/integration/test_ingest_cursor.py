import json
import tempfile
import unittest
from pathlib import Path

from ei.adapters.codex_memory import CodexMemoryAdapter
from ei.config import load_settings
from ei.ingest import ingest_sources


class IngestCursorTests(unittest.TestCase):
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
