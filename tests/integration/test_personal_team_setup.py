from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path

from ei.installer import SetupSelection, setup


class PersonalTeamSetupTests(unittest.TestCase):
    def _selection(self, root: Path, *, team: bool | None = None, team_root: Path | None = None, member: str | None = None) -> SetupSelection:
        home = root / "codex-home"
        home.mkdir(parents=True, exist_ok=True)
        return SetupSelection(
            engine_root=Path.cwd(),
            personal_knowledge_root=root / "personal knowledge",
            team_knowledge_root=team_root,
            team_member_id=member,
            team_knowledge=team,
            runtime_root=root / "runtime",
            hosts=("codex-cli",),
            organizer_provider="subscription-cli",
            organizer_host="codex-cli",
            host_homes={"codex-cli": home},
            python_exe=Path(sys.executable),
            skip_venv=True,
            non_interactive=True,
            accept_plan=True,
        )

    def test_fresh_personal_only_setup_writes_schema_v8_and_empty_stores(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            result = setup(self._selection(root))
            self.assertTrue(result.ok, result.to_dict())
            self.assertEqual(result.status, "SETUP_COMPLETE")
            self.assertEqual(result.reconciliation["status"], "CREATED")
            self.assertEqual(result.knowledge_stores["team"]["status"], "DISABLED")
            manifest = json.loads((root / "runtime" / "install-manifest.json").read_text(encoding="utf-8"))
            self.assertEqual(manifest["schema_version"], 8)
            self.assertTrue(manifest["knowledge_stores"]["personal"]["enabled"])
            self.assertIsNone(manifest["knowledge_stores"]["team"])
            knowledge_dir = root / "personal knowledge" / "knowledge"
            self.assertEqual(list(knowledge_dir.rglob("*.md")), [])
            self.assertEqual(list((root / "personal knowledge" / "events").rglob("*.json")), [])

    def test_check_only_team_setup_does_not_create_team_root(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            team_root = root / "shared team"
            result = setup(self._selection(root, team=True, team_root=team_root, member="member-a"), check_only=True)
            self.assertTrue(result.ok, result.to_dict())
            self.assertFalse(team_root.exists())
            self.assertEqual(result.knowledge_stores["team"]["status"], "PLANNED")


if __name__ == "__main__":
    unittest.main()
