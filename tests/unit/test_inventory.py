import json
import shutil
import sqlite3
import tempfile
import unittest
from pathlib import Path

from ei.config import load_settings
from ei.adapters.rollout_summary import RolloutSummaryAdapter
from ei.inventory import inventory_existing_state


def bearer_secret(marker: str) -> str:
    authorization = "Author" + "ization"
    bearer = "Bea" + "rer"
    return f"{authorization}: {bearer} {marker}"


class InventoryTests(unittest.TestCase):
    def _settings(self, root: Path):
        (root / "config").mkdir(exist_ok=True)
        (root / "config" / "defaults.json").write_text(
            json.dumps({"retrieval": {"max_chars": 5000, "max_results": 5}}),
            encoding="utf-8",
        )
        return load_settings(
            repo_root=root,
            codex_home=root / "codex",
            runtime_root=root / "runtime",
            host_homes={},
        )

    def test_inventory_balance_and_terminal_dispositions_cover_all_source_classes(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            memory = root / "memories"
            home = root / "codex"
            (memory / "patterns" / "raw-candidates").mkdir(parents=True)
            (memory / "skills" / "spreadsheet").mkdir(parents=True)
            (memory / "rollout_summaries").mkdir(parents=True)
            (memory / "extensions" / "ad_hoc" / "notes").mkdir(parents=True)
            (memory / "MEMORY.md").write_text("# Reusable knowledge\n- 検証済みの判断を別案件で再利用する\n", encoding="utf-8")
            (memory / "memory_summary.md").write_text("# Reusable knowledge\n- 同じ条件では同じ検証順序を使う\n", encoding="utf-8")
            (memory / "raw_memories.md").write_text("# Failures\n- 失敗原因を記録して次回の再発を防止する\n", encoding="utf-8")
            (memory / "patterns" / "index.md").write_text("# Active patterns\n- 状態は証拠から再構成する\n", encoding="utf-8")
            (memory / "patterns" / "raw-candidates" / "candidate.md").write_text("# Candidate\n- 観測を別案件で再確認する\n", encoding="utf-8")
            (memory / "skills" / "spreadsheet" / "SKILL.md").write_text("# Skill\nUse the reference only when the scope matches.\n", encoding="utf-8")
            (memory / "rollout_summaries" / "run.jsonl").write_text('{"type":"session_meta","payload":{"id":"s1"}}\n', encoding="utf-8")
            (memory / "extensions" / "ad_hoc" / "notes" / "note.md").write_text("# Correction\n- Preserve source boundaries\n", encoding="utf-8")
            (memory / "unknown.bin").write_bytes(b"unknown")
            (memory / "duplicate.md").write_bytes((memory / "MEMORY.md").read_bytes())
            (memory / "external_article_copy.md").write_text("# External reference\n- [external_article_copy] external reference only\n", encoding="utf-8")
            home.mkdir()
            (home / "AGENTS.md").write_text("# Global\n", encoding="utf-8")
            (home / "config.toml").write_text("model = 'test'\n", encoding="utf-8")
            (home / "hooks.json").write_text("{}\n", encoding="utf-8")
            inventory = inventory_existing_state(home, memory)
            self.assertTrue(inventory.balance_holds)
            self.assertEqual(inventory.unclassified, 0)
            self.assertEqual(inventory.discovered, inventory.imported + inventory.referenced + inventory.skipped_with_reason + inventory.rejected)
            self.assertGreater(inventory.imported, 0)
            self.assertGreater(inventory.referenced, 0)
            self.assertGreater(inventory.skipped_with_reason, 0)
            self.assertTrue(all(row.source_kind and row.normalized_path_hash and row.content_hash and row.provenance and row.disposition and row.reason_code for row in inventory.rows))
            serialized = json.dumps(inventory.to_dict(), ensure_ascii=False)
            self.assertNotIn("unknown.bin", serialized)

    def test_secret_is_rejected_without_returning_the_secret(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            memory = root / "memories"
            home = root / "codex"
            memory.mkdir(parents=True)
            home.mkdir()
            secret = bearer_secret("A" * 32)
            (memory / "MEMORY.md").write_text("# Reusable knowledge\n- " + secret + "\n", encoding="utf-8")
            inventory = inventory_existing_state(home, memory)
            self.assertEqual(inventory.rejected, 1)
            self.assertNotIn(secret, json.dumps(inventory.to_dict(), ensure_ascii=False))

    def test_new_api_covers_complete_fixture_with_exact_terminal_dispositions(self):
        fixture = Path("tests/fixtures/migration/complete-legacy-tree").resolve()
        with tempfile.TemporaryDirectory() as tmp:
            settings = self._settings(Path(tmp))
            inventory = inventory_existing_state([fixture], settings)
            terminal = {
                "imported",
                "referenced_only",
                "duplicate",
                "skipped_with_reason",
                "rejected_privacy",
                "rejected_secret",
                "unsupported_format",
            }
            self.assertTrue(inventory.balance_holds)
            self.assertEqual(inventory.unclassified, 0)
            self.assertTrue(inventory.rows)
            self.assertTrue(all(row.disposition in terminal for row in inventory.rows))
            article_rows = [row for row in inventory.rows if row.source_kind == "external_article_copy"]
            self.assertTrue(article_rows)
            self.assertTrue(all(row.disposition == "referenced_only" for row in article_rows))
            report = json.dumps(inventory.to_dict(), ensure_ascii=False)
            self.assertNotIn("48,350,000", report)
            self.assertNotIn("98.7%", report)
            self.assertNotIn(str(fixture), report)

    def test_auto_source_and_repository_root_are_rejected_before_enumeration(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            settings = self._settings(root)
            (settings.paths.codex_home / "memories").mkdir(parents=True)
            (settings.paths.codex_home / "memories" / "MEMORY.md").write_text(
                "# Reusable knowledge\n- global\n", encoding="utf-8"
            )
            with self.assertRaisesRegex(ValueError, "SOURCE_ROOT_NOT_AUTHORIZED"):
                inventory_existing_state(["auto"], settings)
            with self.assertRaisesRegex(ValueError, "SOURCE_ROOT_NOT_AUTHORIZED"):
                inventory_existing_state([settings.paths.repo_root], settings)

    def test_sqlite_inventory_records_schema_metadata_without_reading_rows(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            settings = self._settings(root)
            settings.paths.codex_home.mkdir(parents=True)
            database = settings.paths.codex_home / "usage.sqlite"
            connection = sqlite3.connect(database)
            try:
                connection.execute("CREATE TABLE turns (id INTEGER, message TEXT)")
                connection.execute("INSERT INTO turns VALUES (1, ?)", ("PRIVATE MESSAGE BODY",))
                connection.commit()
            finally:
                connection.close()
            source = root / "empty-source"
            source.mkdir()
            inventory = inventory_existing_state([source], settings)
            rows = [row for row in inventory.rows if row.source_kind == "sqlite_schema_metadata"]
            self.assertEqual(len(rows), 1)
            report = json.dumps(inventory.to_dict(), ensure_ascii=False)
            self.assertNotIn("PRIVATE MESSAGE BODY", report)
            self.assertNotIn("CREATE TABLE turns", report)

    def test_rollout_article_classification_stays_external_reference(self):
        with tempfile.TemporaryDirectory() as tmp:
            source = Path(tmp) / "external-article.jsonl"
            source.write_text(
                '{"type":"session_meta","payload":{"id":"s"}}\n'
                '{"type":"turn_context","cwd":"scope","domain":"article","outcome_status":"success"}\n'
                '{"type":"response_item","kind":"reusable_knowledge","title":"Article","claim":"Copied reference","benefit":"reference_only","classification":"external-reference"}\n',
                encoding="utf-8",
            )
            records = list(RolloutSummaryAdapter([source]).iter_records({}))
            self.assertEqual(len(records), 1)
            self.assertEqual(records[0].source_kind, "external_article_copy")
            self.assertEqual(records[0].classification, "external-reference")
    def test_explicit_root_preserves_source_bytes_and_mtime(self):
        fixture = Path("tests/fixtures/migration/complete-legacy-tree").resolve()
        with tempfile.TemporaryDirectory() as tmp:
            settings = self._settings(Path(tmp))
            before = {
                path.relative_to(fixture).as_posix(): (path.read_bytes(), path.stat().st_mtime_ns)
                for path in fixture.rglob("*")
                if path.is_file()
            }
            inventory_existing_state([fixture], settings)
            after = {
                path.relative_to(fixture).as_posix(): (path.read_bytes(), path.stat().st_mtime_ns)
                for path in fixture.rglob("*")
                if path.is_file()
            }
            self.assertEqual(before, after)


if __name__ == "__main__":
    unittest.main()
