import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from ei.adapters.codex_memory import CodexMemoryAdapter


class CodexMemoryAdapterTests(unittest.TestCase):
    def test_verified_bytes_reuse_parser_without_reopening_source(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "memory.md"
            path.write_text("## Reusable knowledge\n- Verify persisted results\n", encoding="utf-8")
            raw, metadata = path.read_bytes(), path.stat()
            expected = list(CodexMemoryAdapter([]).read(path))
            verified_path = path.resolve(strict=True)
            with patch.object(Path, "read_bytes", side_effect=AssertionError("reopened")), patch.object(Path, "stat", side_effect=AssertionError("restat")):
                actual = list(CodexMemoryAdapter([]).read_verified(verified_path, raw, metadata))
            self.assertEqual(actual, expected)
            self.assertTrue(actual[0].stable_record_id)

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
