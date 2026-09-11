import tempfile
import unittest
from pathlib import Path

from ei.adapters.codex_memory import CodexMemoryAdapter


class CodexMemoryAdapterTests(unittest.TestCase):
    def test_extracts_reusable_bullets_without_writing_source(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = root / "memory.md"
            source.write_text(
                "# Memory\n\n## Reusable knowledge\n- 書込後は対象範囲を再読込して確認する\n",
                encoding="utf-8",
            )
            before = source.read_bytes()
            before_mtime = source.stat().st_mtime_ns
            adapter = CodexMemoryAdapter([source])
            records = list(adapter.iter_records({}))
            self.assertEqual(len(records), 1)
            self.assertEqual(records[0].domain, "memory")
            self.assertIn("再読込", records[0].claim)
            self.assertEqual(source.read_bytes(), before)
            self.assertEqual(source.stat().st_mtime_ns, before_mtime)

    def test_discover_is_limited_to_known_memory_names(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "memory.md").write_text("## Reusable knowledge\n- safe\n", encoding="utf-8")
            (root / "random.md").write_text("## Reusable knowledge\n- not discovered\n", encoding="utf-8")
            self.assertEqual(
                CodexMemoryAdapter.discover(root),
                (root.joinpath("memory.md").resolve(),),
            )


if __name__ == "__main__":
    unittest.main()
