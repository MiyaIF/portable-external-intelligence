import json
import subprocess
import tempfile
import unittest
from pathlib import Path

from ei.config import load_settings
from ei.inventory import inventory_existing_state


class LegacyGitHistoryTests(unittest.TestCase):
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

    def test_deleted_memory_revision_is_referenced_without_copying_blob(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            memory = root / "memories"
            memory.mkdir()
            settings = self._settings(root)
            subprocess.run(["git", "init", str(memory)], check=True, capture_output=True, text=True)
            source = memory / "MEMORY.md"
            source.write_text("# Reusable knowledge\n- Historical evidence remains reviewable\n", encoding="utf-8")
            subprocess.run(["git", "-C", str(memory), "add", "MEMORY.md"], check=True, capture_output=True, text=True)
            subprocess.run(["git", "-C", str(memory), "-c", "user.name=Inventory Test", "-c", "user.email=inventory@example.invalid", "commit", "-m", "legacy"], check=True, capture_output=True, text=True)
            source.unlink()
            subprocess.run(["git", "-C", str(memory), "add", "-A"], check=True, capture_output=True, text=True)
            subprocess.run(["git", "-C", str(memory), "-c", "user.name=Inventory Test", "-c", "user.email=inventory@example.invalid", "commit", "-m", "delete"], check=True, capture_output=True, text=True)
            inventory = inventory_existing_state([memory], settings)
            historical = [row for row in inventory.rows if row.historical]
            self.assertTrue(historical)
            self.assertEqual(inventory.historical_pending_review, len(historical))
            self.assertTrue(all(row.disposition == "referenced_only" for row in historical))
            self.assertNotIn("Historical evidence", json.dumps(inventory.to_dict(), ensure_ascii=False))
            self.assertTrue(all(row.content_hash.startswith("sha256") for row in historical))

    def test_changed_and_deleted_history_has_terminal_balance(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            memory = root / "memories"
            memory.mkdir()
            settings = self._settings(root)
            subprocess.run(["git", "init", str(memory)], check=True, capture_output=True, text=True)
            source = memory / "MEMORY.md"
            source.write_text("# Reusable knowledge\n- First\n", encoding="utf-8")
            subprocess.run(["git", "-C", str(memory), "add", "-A"], check=True, capture_output=True, text=True)
            subprocess.run(["git", "-C", str(memory), "-c", "user.name=Inventory Test", "-c", "user.email=inventory@example.invalid", "commit", "-m", "first"], check=True, capture_output=True, text=True)
            source.write_text("# Reusable knowledge\n- Second\n", encoding="utf-8")
            subprocess.run(["git", "-C", str(memory), "add", "-A"], check=True, capture_output=True, text=True)
            subprocess.run(["git", "-C", str(memory), "-c", "user.name=Inventory Test", "-c", "user.email=inventory@example.invalid", "commit", "-m", "second"], check=True, capture_output=True, text=True)
            inventory = inventory_existing_state([memory], settings)
            self.assertTrue(inventory.balance_holds)
            self.assertEqual(inventory.unclassified, 0)
            self.assertGreaterEqual(inventory.historical_pending_review, 1)


if __name__ == "__main__":
    unittest.main()
