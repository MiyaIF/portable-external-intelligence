from __future__ import annotations

import hashlib
import json
import sys
import tempfile
import unittest
from pathlib import Path

from ei.config import load_settings
from ei.installer import SetupSelection, UninstallOptions, setup, uninstall, update


def _tree_hash(path: Path) -> str | None:
    if not path.exists():
        return None
    digest = hashlib.sha256()
    if path.is_file():
        digest.update(path.read_bytes())
        return digest.hexdigest()
    for child in sorted(item for item in path.rglob("*") if item.is_file()):
        digest.update(child.relative_to(path).as_posix().encode("utf-8"))
        digest.update(child.read_bytes())
    return digest.hexdigest()


class TeamLifecycleRetentionTests(unittest.TestCase):
    def _selection(self, root: Path, team_root: Path) -> SetupSelection:
        home = root / "codex-home"
        home.mkdir(parents=True, exist_ok=True)
        return SetupSelection(
            engine_root=Path.cwd(),
            personal_knowledge_root=root / "personal",
            team_knowledge_root=team_root,
            team_member_id="member-a",
            team_knowledge=True,
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

    def _install(self, root: Path) -> tuple[SetupSelection, Path, Path, Path, Path]:
        team_root = root / "shared-team"
        selection = self._selection(root, team_root)
        result = setup(selection)
        self.assertTrue(result.ok, result.to_dict())
        self.assertEqual(result.status, "SETUP_COMPLETE")
        manifest_path = root / "runtime" / "install-manifest.json"
        return selection, manifest_path, root / "personal", team_root, root / "runtime"

    def test_update_preserves_enabled_team_when_shared_root_is_offline(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            selection, manifest_path, personal, team_root, runtime = self._install(root)
            manifest_before = json.loads(manifest_path.read_text(encoding="utf-8"))
            store_id = manifest_before["knowledge_stores"]["team"]["store_id"]
            offline_root = root / "shared-team-offline"
            team_root.rename(offline_root)

            settings = load_settings(
                engine_root=Path.cwd(),
                personal_knowledge_root=personal,
                team_knowledge_root=team_root,
                runtime_root=runtime,
                codex_home=root / "codex-home",
                host_homes={"codex-cli": root / "codex-home"},
            )
            result = update(settings, check_only=False)
            self.assertTrue(result.ok, result.to_dict())
            self.assertEqual(result.knowledge_stores["team"]["status"], "DEFERRED")
            self.assertEqual(result.team["reason_code"], "TEAM_STORE_VALIDATION_DEFERRED")
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            self.assertTrue(manifest["knowledge_stores"]["team"]["enabled"])
            self.assertEqual(manifest["knowledge_stores"]["team"]["store_id"], store_id)
            self.assertEqual(manifest["knowledge_stores"]["team"]["root"], str(team_root.resolve()))
            self.assertTrue((offline_root / "team-manifest.json").is_file())

    def test_default_uninstall_retains_personal_team_and_runtime_team_data(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            _, manifest_path, personal, team_root, runtime = self._install(root)
            (personal / "events" / "sentinel.json").write_text("personal\n", encoding="utf-8")
            (team_root / "members" / "member-a" / "sentinel.json").parent.mkdir(parents=True, exist_ok=True)
            (team_root / "members" / "member-a" / "sentinel.json").write_text("team\n", encoding="utf-8")
            (runtime / "team-outbox").mkdir(parents=True, exist_ok=True)
            (runtime / "team-outbox" / "pending.json").write_text("outbox\n", encoding="utf-8")
            (runtime / "team-cache" / "store").mkdir(parents=True, exist_ok=True)
            (runtime / "team-cache" / "store" / "projection.json").write_text("cache\n", encoding="utf-8")

            retained_paths = (personal, team_root, runtime / "team-outbox", runtime / "team-cache", runtime / "team-identities")
            before = {str(path): _tree_hash(path) for path in retained_paths}
            result = uninstall(manifest_path, UninstallOptions())
            self.assertTrue(result["ok"], result)
            result_payload = result["result"]
            self.assertTrue(result_payload["knowledge_stores"]["personal"]["retained"])
            self.assertTrue(result_payload["knowledge_stores"]["team"]["enabled"])
            self.assertEqual(before, {str(path): _tree_hash(path) for path in retained_paths})
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            self.assertEqual(manifest["status"], "UNINSTALLED")
            self.assertTrue(manifest["knowledge_retained"])

    def test_remove_runtime_cache_only_removes_personal_and_team_caches(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            _, manifest_path, _, team_root, runtime = self._install(root)
            (runtime / "team-cache").mkdir(parents=True, exist_ok=True)
            (runtime / "team-cache" / "projection.json").write_text("cache\n", encoding="utf-8")
            (runtime / "team-outbox").mkdir(parents=True, exist_ok=True)
            (runtime / "team-outbox" / "pending.json").write_text("outbox\n", encoding="utf-8")
            result = uninstall(manifest_path, UninstallOptions(remove_runtime_cache=True))
            self.assertTrue(result["ok"], result)
            self.assertFalse((runtime / "team-cache").exists())
            self.assertTrue((runtime / "team-outbox" / "pending.json").is_file())
            self.assertTrue((team_root / "team-manifest.json").is_file())


if __name__ == "__main__":
    unittest.main()
