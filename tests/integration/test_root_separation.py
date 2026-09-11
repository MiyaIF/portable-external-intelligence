from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from ei.cli import EXIT_INPUT, main


class RootSeparationIntegrationTests(unittest.TestCase):
    def test_explicit_roots_keep_recall_side_effects_out_of_engine(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            engine = root / "engine"
            (engine / "config").mkdir(parents=True)
            (engine / "config" / "defaults.json").write_text(json.dumps({"retrieval": {"max_chars": 5000, "max_results": 5}}), encoding="utf-8")
            knowledge, runtime, home = root / "knowledge", root / "runtime", root / "host home"
            code = main(
                [
                    "recall",
                    "--engine-root", str(engine),
                    "--knowledge-root", str(knowledge),
                    "--runtime-root", str(runtime),
                    "--codex-home", str(home),
                    "--query", "unseen task",
                    "--json",
                ]
            )
            self.assertEqual(code, 0)
            self.assertFalse((engine / "events").exists())
            self.assertFalse((engine / "knowledge").exists())
            self.assertFalse(runtime.exists())

    def test_mutating_command_without_knowledge_root_fails_before_write(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            engine = root / "engine"
            (engine / "config").mkdir(parents=True)
            (engine / "config" / "defaults.json").write_text(json.dumps({"capture": {"max_payload_bytes": 32768}}), encoding="utf-8")
            code = main(["observe", "--engine-root", str(engine), "--runtime-root", str(root / "runtime"), "--stdin-json", "--json"])
            self.assertEqual(code, EXIT_INPUT)
            self.assertFalse((engine / "events").exists())


if __name__ == "__main__":
    unittest.main()
