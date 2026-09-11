from __future__ import annotations

import hashlib
import json
import shutil
import sys
import tempfile
import unittest
from dataclasses import replace
from pathlib import Path
from unittest.mock import patch

from ei.installer import SetupSelection, setup


def product_hashes(root: Path, *, exclude: tuple[str, ...] = ()) -> dict[str, str]:
    ignored = set(exclude)
    values: dict[str, str] = {}
    for path in sorted(root.rglob("*")):
        if not path.is_file() or any(part in ignored for part in path.relative_to(root).parts):
            continue
        values[path.relative_to(root).as_posix()] = hashlib.sha256(path.read_bytes()).hexdigest()
    return values


class SetupRerunReconciliationTests(unittest.TestCase):
    def _selection(self, root: Path) -> SetupSelection:
        home = root / "codex-home"
        home.mkdir(parents=True, exist_ok=True)
        return SetupSelection(
            engine_root=Path.cwd(),
            personal_knowledge_root=root / "personal",
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

    def _multi_host_selection(self, root: Path, hosts: tuple[str, ...]) -> SetupSelection:
        homes = {host: root / (host + " home") for host in hosts}
        for home in homes.values():
            home.mkdir(parents=True, exist_ok=True)
        return SetupSelection(
            engine_root=Path.cwd(),
            personal_knowledge_root=root / "personal",
            runtime_root=root / "runtime",
            hosts=hosts,
            organizer_provider="subscription-cli",
            organizer_host=hosts[0],
            host_homes=homes,
            python_exe=Path(sys.executable),
            skip_venv=True,
            non_interactive=True,
            accept_plan=True,
        )

    def test_identical_second_setup_changes_only_append_only_receipt(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            selection = self._selection(root)
            first = setup(selection)
            self.assertTrue(first.ok, first.to_dict())
            before = product_hashes(first.manifest_path.parent, exclude=("setup-operations",))
            second = setup(selection)
            after = product_hashes(first.manifest_path.parent, exclude=("setup-operations",))
            self.assertEqual(second.status, "SETUP_COMPLETE")
            self.assertEqual(second.reconciliation["status"], "ALREADY_CURRENT")
            self.assertEqual(second.changed_paths, ())
            self.assertEqual(before, after)

    def test_team_disable_retains_descriptor_and_shared_files(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            team_root = root / "shared-team"
            enabled = setup(replace(self._selection(root), team_knowledge_root=team_root, team_member_id="member-a", team_knowledge=True))
            self.assertTrue(enabled.ok, enabled.to_dict())
            event = team_root / "members" / "member-a" / "sentinel.json"
            event.parent.mkdir(parents=True, exist_ok=True)
            event.write_text("keep\n", encoding="utf-8")
            disabled = setup(replace(self._selection(root), team_knowledge=False))
            self.assertTrue(disabled.ok, disabled.to_dict())
            manifest = json.loads(disabled.manifest_path.read_text(encoding="utf-8"))
            self.assertFalse(manifest["knowledge_stores"]["team"]["enabled"])
            self.assertEqual(manifest["knowledge_stores"]["team"]["status"], "DISABLED")
            self.assertTrue(event.is_file())

    def _assert_team_disable_skips_unavailable_root(self, *, broken: bool) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            team_root = root / ("broken-team" if broken else "missing-team")
            enabled = setup(replace(self._selection(root), team_knowledge_root=team_root, team_member_id="member-a", team_knowledge=True))
            self.assertTrue(enabled.ok, enabled.to_dict())
            if broken:
                (team_root / "team-manifest.json").write_text("{}", encoding="utf-8")
            else:
                shutil.rmtree(team_root)

            original_exists = Path.exists
            original_is_dir = Path.is_dir

            def forbid_team_exists(path: Path) -> bool:
                if path.resolve() == team_root.resolve():
                    raise AssertionError("disabled setup inspected team root")
                return original_exists(path)

            def forbid_team_is_dir(path: Path) -> bool:
                if path.resolve() == team_root.resolve():
                    raise AssertionError("disabled setup inspected team root")
                return original_is_dir(path)

            disabled_selection = replace(self._selection(root), team_knowledge=False)
            with patch("ei.installer.inspect_team_store", side_effect=AssertionError("team store inspected")), patch(
                "ei.installer.initialize_team_store", side_effect=AssertionError("team store initialized")
            ), patch(
                "ei.installer.load_or_create_writer_identity", side_effect=AssertionError("team identity loaded")
            ), patch.object(Path, "exists", forbid_team_exists), patch.object(Path, "is_dir", forbid_team_is_dir):
                checked = setup(disabled_selection, check_only=True)
                self.assertTrue(checked.ok, checked.to_dict())
                self.assertEqual(checked.status, "CHECK_ONLY")
                self.assertEqual(checked.team["status"], "PRESERVED")
                applied = setup(disabled_selection)

            self.assertTrue(applied.ok, applied.to_dict())
            manifest = json.loads(applied.manifest_path.read_text(encoding="utf-8"))
            self.assertFalse(manifest["knowledge_stores"]["team"]["enabled"])
            self.assertEqual(manifest["knowledge_stores"]["team"]["status"], "DISABLED")

    def test_team_disable_missing_root_skips_filesystem_and_service_work(self) -> None:
        self._assert_team_disable_skips_unavailable_root(broken=False)

    def test_team_disable_broken_root_skips_filesystem_and_service_work(self) -> None:
        self._assert_team_disable_skips_unavailable_root(broken=True)

    def test_team_member_change_keeps_store_identity_and_reports_continuity(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            team_root = root / "shared-team"
            first = setup(replace(self._selection(root), team_knowledge_root=team_root, team_member_id="member-a", team_knowledge=True))
            self.assertTrue(first.ok, first.to_dict())
            second = setup(replace(self._selection(root), team_knowledge_root=team_root, team_member_id="member-b", team_knowledge=True))
            self.assertTrue(second.ok, second.to_dict())
            self.assertIn("TEAM_MEMBER_CONTINUITY_CHANGED", second.compatibility_notices)
            manifest = json.loads(second.manifest_path.read_text(encoding="utf-8"))
            self.assertEqual(manifest["knowledge_stores"]["team"]["store_id"], first.knowledge_stores["team"]["store_id"])
            self.assertEqual(manifest["knowledge_stores"]["team"]["team_member_id"], "member-b")

    def test_explicit_runtime_change_is_migration_required_without_new_manifest(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            selection = self._selection(root)
            first = setup(selection)
            self.assertTrue(first.ok, first.to_dict())
            moved = setup(replace(selection, runtime_root=root / "runtime-moved"))
            self.assertFalse(moved.ok)
            self.assertEqual(moved.status, "SETUP_BLOCKED")
            self.assertEqual(moved.errors[0]["error_code"], "RUNTIME_ROOT_CHANGE_REQUIRES_MIGRATION")
            self.assertFalse((root / "runtime-moved" / "install-manifest.json").exists())

    def test_host_removal_removes_only_owned_skill_and_binding(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            first = setup(self._multi_host_selection(root, ("codex-cli", "claude-code")))
            self.assertTrue(first.ok, first.to_dict())
            first_manifest = json.loads(first.manifest_path.read_text(encoding="utf-8"))
            codex_record = first_manifest["hosts"]["codex-cli"]
            claude_record = first_manifest["hosts"]["claude-code"]
            codex_skill = Path(codex_record["skill_destination"])
            codex_binding = Path(codex_record["skill_binding_path"])
            claude_skill = Path(claude_record["skill_destination"])
            hook_path = Path(codex_record["hook_config_path"])
            hook_value = json.loads(hook_path.read_text(encoding="utf-8"))
            hook_value.setdefault("hooks", {}).setdefault("UserPromptSubmit", []).append({"id": "user-owned-hook", "matcher": "*", "hooks": []})
            hook_path.write_text(json.dumps(hook_value, ensure_ascii=False, sort_keys=True, indent=2) + "\n", encoding="utf-8")
            second = setup(self._multi_host_selection(root, ("claude-code",)))
            self.assertTrue(second.ok, second.to_dict())
            self.assertFalse(codex_skill.exists() or codex_skill.is_symlink())
            self.assertFalse(codex_binding.exists() or codex_binding.is_symlink())
            self.assertTrue(claude_skill.is_dir())
            retained_hooks = json.loads(hook_path.read_text(encoding="utf-8"))
            self.assertTrue(any(item.get("id") == "user-owned-hook" for item in retained_hooks["hooks"]["UserPromptSubmit"]))

    def test_user_modified_managed_hook_is_a_conflict_without_host_mutation(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            selection = self._selection(root)
            first = setup(selection)
            self.assertTrue(first.ok, first.to_dict())
            manifest = json.loads(first.manifest_path.read_text(encoding="utf-8"))
            hook_path = Path(manifest["hosts"]["codex-cli"]["hook_config_path"])
            original = json.loads(hook_path.read_text(encoding="utf-8"))
            original["hooks"]["SessionStart"][0]["hooks"][0]["command"] += " --tampered"
            hook_path.write_text(json.dumps(original, ensure_ascii=False, sort_keys=True, indent=2) + "\n", encoding="utf-8")
            blocked = setup(selection)
            self.assertFalse(blocked.ok)
            self.assertEqual(blocked.status, "SETUP_BLOCKED")
            self.assertEqual(blocked.errors[0]["error_code"], "MANAGED_TARGET_CONFLICT")
            self.assertIn("--tampered", hook_path.read_text(encoding="utf-8"))

    def test_binding_owned_by_another_runtime_is_blocked(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            selection = self._selection(root)
            first = setup(selection)
            self.assertTrue(first.ok, first.to_dict())
            manifest = json.loads(first.manifest_path.read_text(encoding="utf-8"))
            binding_path = Path(manifest["hosts"]["codex-cli"]["skill_binding_path"])
            binding = json.loads(binding_path.read_text(encoding="utf-8"))
            binding["runtime_root"] = str(root / "other-runtime")
            binding_path.write_text(json.dumps(binding, ensure_ascii=False, sort_keys=True, indent=2) + "\n", encoding="utf-8")
            blocked = setup(selection)
            self.assertFalse(blocked.ok)
            self.assertEqual(blocked.status, "SETUP_BLOCKED")
            self.assertEqual(blocked.errors[0]["error_code"], "ACTIVE_RUNTIME_MISMATCH")


if __name__ == "__main__":
    unittest.main()
