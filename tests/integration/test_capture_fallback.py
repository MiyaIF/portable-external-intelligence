import tempfile
import unittest
from pathlib import Path

from ei.adapters.base import SourceRecord
from ei.capture import reconcile_fallback
from ei.config import load_settings
from ei.journal import iter_events


class CaptureFallbackTests(unittest.TestCase):
    def test_native_observation_missing_from_direct_capture_is_attributable(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "config").mkdir()
            (root / "config" / "defaults.json").write_text('{"retrieval":{"max_chars":5000,"max_results":5}}', encoding="utf-8")
            settings = load_settings(root, codex_home=root / "codex")
            record = SourceRecord(
                "codex_memory", "memory.md", "hash-1", "2026-08-25T00:00:00+00:00", "native",
                "別経路から発見した再利用可能な判断知識", "project-a", "general", "success",
                "reduced_rework", "private-reusable", provenance_key="memory:hash-1",
                source_host_id="codex-cli", source_host_family="codex-compatible",
            )
            result = reconcile_fallback(settings, [], [record])
            self.assertEqual(result.recovered, 1)
            self.assertEqual(result.coverage_unknown, False)
            self.assertIn("capture.fallback_recovered", [event.event_type for event in iter_events(settings.paths.event_dir)])


if __name__ == "__main__":
    unittest.main()
