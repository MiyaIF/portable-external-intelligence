from __future__ import annotations

import json
import argparse
import hashlib
import io
import sys
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path

from ei.canary import CertificationReceipt, HOOK_REQUIRED_EVENTS, record_canary, read_hook_status
from ei.config import load_settings
from ei.doctor import run_doctor
from ei.installer import (
    SetupSelection,
    _Transaction,
    _managed_hook_hash,
    _manifest_state,
    _settings_for_selection,
    _source_skill,
    apply_owned_host_actions,
    setup,
)
from ei.journal import append_event
from ei.models import Event
from ei.project import project_events
from ei.retrieve import RetrievalQuery, host_scope_allowed
from ei.cli import _recall


class MultiHostLifecycleTests(unittest.TestCase):
    def _selection(self, root: Path, hosts: tuple[str, ...]) -> SetupSelection:
        homes = {host: root / f"{host}-home" for host in hosts}
        for home in homes.values():
            home.mkdir(parents=True, exist_ok=True)
        return SetupSelection(
            engine_root=Path.cwd(),
            knowledge_root=root / "personal-knowledge",
            runtime_root=root / "runtime",
            work_hosts=hosts,
            host_homes=homes,
            organizer_provider="subscription-cli",
            organizer_host=hosts[0],
            python_exe=Path(sys.executable),
            skip_venv=True,
            non_interactive=True,
            accept_plan=True,
        )

    def _shared_selection(self, root: Path, hosts: tuple[str, ...]) -> SetupSelection:
        custom_ids = tuple(host for host in hosts if host.startswith("test-compatible-cli-"))
        shared_home = root / "shared-custom-home"
        codex_home = root / "codex-home"
        shared_home.mkdir(parents=True, exist_ok=True)
        codex_home.mkdir(parents=True, exist_ok=True)
        documents = {
            host_id: {
                "schema_version": 1,
                "host_id": host_id,
                "display_name": host_id,
                "host_family": "gemini-compatible",
                "adapter_id": "gemini-cli",
                "executable_names": [host_id],
                "hook_config_path": ".config/shared/settings.json",
                "global_context_path": ".config/shared/context.md",
                "skill_roots": [".config/shared/skills"],
            }
            for host_id in custom_ids
        }
        homes = {host_id: (shared_home if host_id in custom_ids else codex_home) for host_id in hosts}
        return SetupSelection(
            engine_root=Path.cwd(),
            knowledge_root=root / "personal-knowledge",
            runtime_root=root / "runtime",
            work_hosts=hosts,
            host_homes=homes,
            host_profile_documents=documents or None,
            organizer_provider="subscription-cli",
            organizer_host="codex-cli",
            python_exe=Path(sys.executable),
            skip_venv=True,
            non_interactive=True,
            accept_plan=True,
        )

    def test_manifest_keeps_hook_ownership_per_host(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            result = setup(self._selection(root, ("codex-cli", "claude-code")))
            self.assertTrue(result.ok, result.to_dict())
            manifest = json.loads(result.manifest_path.read_text(encoding="utf-8"))
            codex_ids = set(manifest["hosts"]["codex-cli"]["managed_hook_ids"])
            claude_ids = set(manifest["hosts"]["claude-code"]["managed_hook_ids"])
            self.assertTrue(codex_ids)
            self.assertTrue(claude_ids)
            self.assertNotEqual(codex_ids, claude_ids)
            self.assertTrue(all("codex-cli" in item for item in codex_ids))
            self.assertTrue(all("claude-code" in item for item in claude_ids))

    def test_doctor_reports_one_organizer_and_each_work_host(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            result = setup(self._selection(root, ("codex-cli", "claude-code")))
            self.assertTrue(result.ok, result.to_dict())
            settings = load_settings(engine_root=Path.cwd(), runtime_root=root / "runtime", allow_uninstalled_manifest=True)
            value = run_doctor(settings, strict=False).to_dict()
            self.assertEqual(value["organizer"]["host_id"], "codex-cli")
            self.assertEqual(value["work_hosts"], ["codex-cli", "claude-code"])

    def test_receipt_for_one_instance_does_not_verify_another_host(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            result = setup(self._selection(root, ("codex-cli", "claude-code")))
            self.assertTrue(result.ok, result.to_dict())
            settings = load_settings(
                engine_root=Path.cwd(),
                personal_knowledge_root=root / "personal-knowledge",
                runtime_root=root / "runtime",
                host_homes={
                    "codex-cli": root / "codex-cli-home",
                    "claude-code": root / "claude-code-home",
                },
                allow_uninstalled_manifest=True,
            )
            # A complete receipt belongs only to codex-cli's instance.  The
            # same event names must not make Claude Code appear verified.
            receipt = CertificationReceipt(
                host_id="codex-cli",
                host_instance_id="codex-cli",
                event_receipt_hashes={name: "sha256:" + "0" * 64 for name in HOOK_REQUIRED_EVENTS},
                hook_status="HOOK_VERIFIED",
                outcome="PASSED",
            )
            record_canary(receipt, settings)
            self.assertEqual(read_hook_status("codex-cli", "codex-cli", settings).hook_status, "HOOK_VERIFIED")
            self.assertNotEqual(read_hook_status("claude-code", "claude-code", settings).hook_status, "HOOK_VERIFIED")

    def test_custom_host_removal_keeps_pattern_scoped_until_same_id_is_readded(self) -> None:
        document = {
            "schema_version": 1,
            "host_id": "test-compatible-cli",
            "display_name": "Test Compatible CLI",
            "host_family": "gemini-compatible",
            "adapter_id": "gemini-cli",
            "executable_names": ["test-compatible"],
            "hook_config_path": ".config/test-compatible/settings.json",
            "global_context_path": ".config/test-compatible/context.md",
            "skill_roots": [".config/test-compatible/skills"],
        }
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            custom_home = root / "custom-home"
            selected = SetupSelection(
                engine_root=Path.cwd(),
                knowledge_root=root / "personal-knowledge",
                runtime_root=root / "runtime",
                work_hosts=("codex-cli", "test-compatible-cli"),
                host_homes={"codex-cli": root / "codex-cli-home", "test-compatible-cli": custom_home},
                host_profile_documents={"test-compatible-cli": document},
                organizer_provider="subscription-cli",
                organizer_host="codex-cli",
                python_exe=Path(sys.executable),
                skip_venv=True,
                non_interactive=True,
                accept_plan=True,
            )
            first = setup(selected)
            self.assertTrue(first.ok, first.to_dict())
            profile_path = root / "runtime" / "host-profiles" / "test-compatible-cli.json"
            self.assertTrue(profile_path.is_file())
            pattern = {
                "source_host_id": "test-compatible-cli",
                "source_host_family": "gemini-compatible",
                "applicability_scope": "host",
                "applicable_host_ids": ["test-compatible-cli"],
                "applicable_host_families": [],
            }
            self.assertTrue(host_scope_allowed(RetrievalQuery(host_id="test-compatible-cli", host_family="gemini-compatible"), pattern))
            self.assertFalse(host_scope_allowed(RetrievalQuery(host_id="codex-cli", host_family="codex-compatible"), pattern))

            retained = SetupSelection(
                engine_root=Path.cwd(),
                knowledge_root=root / "personal-knowledge",
                runtime_root=root / "runtime",
                work_hosts=("codex-cli",),
                host_homes={"codex-cli": root / "codex-cli-home"},
                organizer_provider="subscription-cli",
                organizer_host="codex-cli",
                python_exe=Path(sys.executable),
                skip_venv=True,
                non_interactive=True,
                accept_plan=True,
            )
            removed = setup(retained)
            self.assertTrue(removed.ok, removed.to_dict())
            self.assertFalse(profile_path.exists())
            self.assertFalse(host_scope_allowed(RetrievalQuery(host_id="codex-cli", host_family="codex-compatible"), pattern))

            readded = setup(selected)
            self.assertTrue(readded.ok, readded.to_dict())
            self.assertTrue((root / "runtime" / "host-profiles" / "test-compatible-cli.json").is_file())
            self.assertTrue(host_scope_allowed(RetrievalQuery(host_id="test-compatible-cli", host_family="gemini-compatible"), pattern))

    def test_shared_custom_targets_are_aggregated_and_staged_removal_is_safe(self) -> None:
        host_a = "test-compatible-cli-" + "a"
        host_b = "test-compatible-cli-" + "b"
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            both = self._shared_selection(root, ("codex-cli", host_a, host_b))
            first = setup(both)
            self.assertTrue(first.ok, first.to_dict())
            manifest = json.loads(first.manifest_path.read_text(encoding="utf-8"))
            record_a = manifest["hosts"][host_a]
            record_b = manifest["hosts"][host_b]
            shared_hook = Path(record_a["hook_config_path"])
            shared_context = Path(record_a["context_path"])
            shared_skill = Path(record_a["skill_destination"])
            self.assertEqual(shared_hook, Path(record_b["hook_config_path"]))
            self.assertEqual(shared_context, Path(record_b["context_path"]))
            self.assertEqual(shared_skill, Path(record_b["skill_destination"]))
            self.assertEqual(record_a["hook_config_hash"], record_b["hook_config_hash"])
            hook_plans = [
                item
                for item in first.plan
                if str(item.target) == str(shared_hook) and item.details.get("kind") == "hook-config"
            ]
            self.assertEqual(len(hook_plans), 1)
            self.assertEqual(set(hook_plans[0].details["hosts"]), {host_a, host_b})
            self.assertEqual(
                set(hook_plans[0].details["managed_hook_ids"]),
                set(record_a["managed_hook_ids"]) | set(record_b["managed_hook_ids"]),
            )
            self.assertEqual(
                sum(str(item.target) == str(shared_context) for item in first.plan),
                1,
            )
            self.assertEqual(
                sum(str(item.target) == str(shared_skill) for item in first.plan),
                1,
            )
            self.assertEqual(
                sum(
                    str(item.target) == str(shared_skill.parent / ".external-intelligence-binding.json")
                    for item in first.plan
                ),
                1,
            )
            state = _manifest_state(manifest)
            managed_targets = state["managed_targets"]
            for target in (shared_hook, shared_context, shared_skill):
                self.assertEqual(managed_targets[str(target)]["host_ids"], sorted((host_a, host_b)))
                self.assertEqual(managed_targets[str(target)]["host_id"], min(host_a, host_b))

            rerun = setup(both)
            self.assertTrue(rerun.ok, rerun.to_dict())
            self.assertEqual(rerun.status, "SETUP_COMPLETE")
            self.assertEqual(rerun.reconciliation["status"], "ALREADY_CURRENT")

            settings = load_settings(
                engine_root=Path.cwd(),
                personal_knowledge_root=root / "personal-knowledge",
                runtime_root=root / "runtime",
                host_homes={"codex-cli": root / "codex-home", host_a: root / "shared-custom-home", host_b: root / "shared-custom-home"},
                allow_uninstalled_manifest=True,
            )
            pattern_event = Event.create(
                "pattern.promoted",
                "2026-09-10T00:00:00Z",
                "test",
                "machine",
                {
                    "pattern_id": "pat_shared_host",
                    "cluster_id": "cluster_shared_host",
                    "rule": "共有先のCLIで再利用する検証手順",
                    "provenances": ["source:shared-host"],
                    "scopes": ["general"],
                    "applicability": ["general"],
                    "benefit_count": 1,
                    "classification": "private-reusable",
                    "source_host_id": host_a,
                    "source_host_family": "gemini-compatible",
                    "applicability_scope": "host",
                    "applicable_host_ids": [host_a],
                    "applicable_host_families": [],
                },
                event_id="evt_shared_host_pattern",
            )
            append_event(pattern_event, settings.paths.event_dir)
            project_events([pattern_event], settings.paths.knowledge_dir)

            def recall(host_id: str) -> dict[str, object]:
                output = io.StringIO()
                with redirect_stdout(output):
                    self.assertEqual(
                        _recall(
                            argparse.Namespace(
                                query="共有先のCLIで再利用する検証手順",
                                max_chars=None,
                                cwd=None,
                                host=host_id,
                                session_id="shared-lifecycle",
                                settings=settings,
                            )
                        ),
                        0,
                    )
                return json.loads(output.getvalue())

            self.assertIn("pat_shared_host", {item["pattern_id"] for item in recall(host_a)["hits"]})
            self.assertNotIn("pat_shared_host", {item["pattern_id"] for item in recall("codex-cli")["hits"]})
            pattern_path = root / "personal-knowledge" / "knowledge" / "patterns" / "pat_shared_host.md"
            pattern_bytes = pattern_path.read_bytes()
            event_bytes = {
                path.relative_to(root / "personal-knowledge" / "events").as_posix(): path.read_bytes()
                for path in (root / "personal-knowledge" / "events").rglob("*.json")
            }

            without_b = self._shared_selection(root, ("codex-cli", host_a))
            removed_b = setup(without_b)
            self.assertTrue(removed_b.ok, removed_b.to_dict())
            self.assertTrue(shared_hook.is_file())
            self.assertTrue(shared_context.is_file())
            self.assertTrue(shared_skill.is_dir())
            hooks_after_b = json.loads(shared_hook.read_text(encoding="utf-8"))
            ids_after_b = {entry["id"] for entries in hooks_after_b["hooks"].values() for entry in entries if isinstance(entry, dict) and isinstance(entry.get("id"), str)}
            self.assertTrue(any(host_a in item for item in ids_after_b))
            self.assertFalse(any(host_b in item for item in ids_after_b))
            self.assertTrue((root / "runtime" / "host-profiles" / f"{host_a}.json").is_file())
            self.assertFalse((root / "runtime" / "host-profiles" / f"{host_b}.json").exists())

            without_custom = self._shared_selection(root, ("codex-cli",))
            removed_last = setup(without_custom)
            self.assertTrue(removed_last.ok, removed_last.to_dict())
            self.assertTrue(shared_hook.is_file())
            self.assertTrue(shared_context.is_file())
            self.assertFalse(shared_skill.exists())
            self.assertEqual(pattern_bytes, pattern_path.read_bytes())
            self.assertEqual(
                event_bytes,
                {
                    path.relative_to(root / "personal-knowledge" / "events").as_posix(): path.read_bytes()
                    for path in (root / "personal-knowledge" / "events").rglob("*.json")
                },
            )
            self.assertNotIn("pat_shared_host", {item["pattern_id"] for item in recall("codex-cli")["hits"]})

            readded = setup(both)
            self.assertTrue(readded.ok, readded.to_dict())
            settings = load_settings(
                engine_root=Path.cwd(),
                personal_knowledge_root=root / "personal-knowledge",
                runtime_root=root / "runtime",
                host_homes={"codex-cli": root / "codex-home", host_a: root / "shared-custom-home", host_b: root / "shared-custom-home"},
                allow_uninstalled_manifest=True,
            )
            self.assertIn("pat_shared_host", {item["pattern_id"] for item in recall(host_a)["hits"]})

    def test_shared_target_bytes_are_independent_of_host_selection_order(self) -> None:
        host_a = "test-compatible-cli-" + "a"
        host_b = "test-compatible-cli-" + "b"
        with tempfile.TemporaryDirectory() as first_raw, tempfile.TemporaryDirectory() as second_raw:
            # Windows runners can return 8.3 temporary-directory aliases while
            # setup deliberately records canonical target paths.
            first_root = Path(first_raw).resolve()
            second_root = Path(second_raw).resolve()
            first = setup(self._shared_selection(first_root, ("codex-cli", host_a, host_b)))
            second = setup(self._shared_selection(second_root, ("codex-cli", host_b, host_a)))
            self.assertTrue(first.ok, first.to_dict())
            self.assertTrue(second.ok, second.to_dict())
            first_manifest = json.loads(first.manifest_path.read_text(encoding="utf-8"))
            second_manifest = json.loads(second.manifest_path.read_text(encoding="utf-8"))
            for host_id in (host_a, host_b):
                first_record = first_manifest["hosts"][host_id]
                second_record = second_manifest["hosts"][host_id]
                self.assertEqual(
                    first_record["managed_hook_ids"],
                    second_record["managed_hook_ids"],
                    host_id,
                )
            first_a = first_manifest["hosts"][host_a]
            second_a = second_manifest["hosts"][host_a]

            def comparable_bytes(path: Path, root: Path) -> bytes:
                if path.is_dir():
                    return b"\n".join(
                        relative.read_bytes()
                        for relative in sorted(path.rglob("*"))
                        if relative.is_file()
                    )
                raw = path.read_bytes()
                return raw.replace(str(root).encode(), b"<TEST_ROOT>").replace(
                    str(root).replace("\\", "\\\\").encode(),
                    b"<TEST_ROOT>",
                )

            for key in ("hook_config_path", "context_path", "skill_destination", "skill_binding_path"):
                self.assertEqual(
                    comparable_bytes(Path(first_a[key]), first_root),
                    comparable_bytes(Path(second_a[key]), second_root),
                    key,
                )
            first_state = _manifest_state(first_manifest)
            second_state = _manifest_state(second_manifest)
            first_shared = next(
                item
                for item in first_state["managed_targets"].values()
                if item.get("host_ids") == sorted((host_a, host_b))
            )
            second_shared = next(
                item
                for item in second_state["managed_targets"].values()
                if item.get("host_ids") == sorted((host_a, host_b))
            )
            self.assertEqual(first_shared["host_id"], min(host_a, host_b))
            self.assertEqual(second_shared["host_id"], min(host_a, host_b))

    def test_shared_binding_updates_when_first_owner_is_removed(self) -> None:
        host_a = "test-compatible-cli-" + "a"
        host_b = "test-compatible-cli-" + "b"
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            first = setup(self._shared_selection(root, ("codex-cli", host_a, host_b)))
            self.assertTrue(first.ok, first.to_dict())
            first_manifest = json.loads(first.manifest_path.read_text(encoding="utf-8"))
            binding_path = Path(first_manifest["hosts"][host_a]["skill_binding_path"])
            self.assertEqual(json.loads(binding_path.read_text(encoding="utf-8"))["host_id"], host_a)

            retained = setup(self._shared_selection(root, ("codex-cli", host_b)))
            self.assertTrue(retained.ok, retained.to_dict())
            self.assertEqual(json.loads(binding_path.read_text(encoding="utf-8"))["host_id"], host_b)

    def test_legacy_shared_target_hashes_are_aggregated_without_rewriting_on_read(self) -> None:
        host_a = "test-compatible-cli-" + "a"
        host_b = "test-compatible-cli-" + "b"
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            both = self._shared_selection(root, ("codex-cli", host_a, host_b))
            first = setup(both)
            self.assertTrue(first.ok, first.to_dict())
            manifest_path = first.manifest_path
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            record_a = manifest["hosts"][host_a]
            record_b = manifest["hosts"][host_b]
            shared_hook = Path(record_a["hook_config_path"])
            self.assertEqual(shared_hook, Path(record_b["hook_config_path"]))

            # Recreate the pre-shared-target manifest shape: each host points
            # at the same file but carries the hash for only its own entries.
            record_a["hook_config_hash"] = _managed_hook_hash(shared_hook, record_a["managed_hook_ids"])
            record_b["hook_config_hash"] = _managed_hook_hash(shared_hook, record_b["managed_hook_ids"])
            self.assertNotEqual(record_a["hook_config_hash"], record_b["hook_config_hash"])
            manifest_path.write_text(json.dumps(manifest, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
            legacy_bytes = manifest_path.read_bytes()

            state = _manifest_state(manifest)
            self.assertEqual(legacy_bytes, manifest_path.read_bytes())
            aggregate = _managed_hook_hash(
                shared_hook,
                sorted(set(record_a["managed_hook_ids"]) | set(record_b["managed_hook_ids"])),
            )
            shared_state = state["managed_targets"][str(shared_hook)]
            self.assertEqual(shared_state["host_ids"], sorted((host_a, host_b)))
            self.assertEqual(shared_state["host_id"], min(host_a, host_b))
            self.assertEqual(shared_state["managed_hook_ids"], sorted(set(record_a["managed_hook_ids"]) | set(record_b["managed_hook_ids"])))
            self.assertEqual(shared_state["hash"], aggregate)

            rerun = setup(both)
            self.assertTrue(rerun.ok, rerun.to_dict())
            self.assertEqual(rerun.reconciliation["status"], "ALREADY_CURRENT")

            without_b = self._shared_selection(root, ("codex-cli", host_a))
            removed_b = setup(without_b)
            self.assertTrue(removed_b.ok, removed_b.to_dict())
            self.assertTrue(shared_hook.is_file())
            remaining_manifest = json.loads(removed_b.manifest_path.read_text(encoding="utf-8"))
            remaining_record = remaining_manifest["hosts"][host_a]
            remaining_state = _manifest_state(remaining_manifest)["managed_targets"][str(shared_hook)]
            self.assertEqual(remaining_state["host_ids"], [host_a])
            self.assertEqual(remaining_state["hash"], _managed_hook_hash(shared_hook, remaining_record["managed_hook_ids"]))

            # A last-owner removal must still fail closed if its aggregate
            # managed bytes changed after the legacy manifest was normalized.
            hooks = json.loads(shared_hook.read_text(encoding="utf-8"))
            first_event = next(iter(hooks["hooks"]))
            hooks["hooks"][first_event][0]["hooks"][0]["command"] += " --tampered"
            shared_hook.write_text(json.dumps(hooks, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
            removed_last = setup(self._shared_selection(root, ("codex-cli",)))
            self.assertFalse(removed_last.ok)
            self.assertEqual(removed_last.reconciliation["status"], "BLOCKED")
            self.assertTrue(shared_hook.is_file())

    def test_legacy_shared_context_skill_and_binding_hashes_rerun_and_remove_safely(self) -> None:
        """Pre-fix per-host hashes must not block shared generic targets."""

        host_a = "test-compatible-cli-" + "a"
        host_b = "test-compatible-cli-" + "b"
        fields = {
            "context_hash": "context_path",
            "installed_skill_hash": "skill_destination",
            "skill_binding_hash": "skill_binding_path",
        }
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            both = self._shared_selection(root, ("codex-cli", host_a, host_b))
            first = setup(both)
            self.assertTrue(first.ok, first.to_dict())
            manifest_path = first.manifest_path
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            record_a = manifest["hosts"][host_a]
            record_b = manifest["hosts"][host_b]
            state = _manifest_state(manifest)

            # Recreate the legacy ownership projection: one physical target
            # has two different, structurally valid per-host SHA-256 values.
            # The aggregate must be derived from the target bytes and the
            # sorted ownership set, not from whichever host was read first.
            for hash_key, path_key in fields.items():
                target = str(Path(record_a[path_key]))
                aggregate = state["managed_targets"][target]["hash"]
                record_a[hash_key] = aggregate
                record_b[hash_key] = "sha256:" + hashlib.sha256(
                    f"legacy|{hash_key}|{aggregate}|{host_b}".encode("utf-8")
                ).hexdigest()
                self.assertNotEqual(record_a[hash_key], record_b[hash_key])

            manifest_path.write_text(json.dumps(manifest, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
            legacy_bytes = manifest_path.read_bytes()
            projected = _manifest_state(manifest)
            self.assertEqual(legacy_bytes, manifest_path.read_bytes())
            for hash_key, path_key in fields.items():
                target = str(Path(record_a[path_key]))
                self.assertEqual(projected["managed_targets"][target]["hash"], state["managed_targets"][target]["hash"])
                self.assertEqual(projected["hosts"][host_a][hash_key], projected["hosts"][host_b][hash_key])

            rerun = setup(both)
            self.assertTrue(rerun.ok, rerun.to_dict())
            self.assertEqual(rerun.reconciliation["status"], "ALREADY_CURRENT")
            self.assertEqual(rerun.plan, ())

            shared_context = Path(record_a["context_path"])
            shared_skill = Path(record_a["skill_destination"])
            shared_binding = Path(record_a["skill_binding_path"])
            without_b = setup(self._shared_selection(root, ("codex-cli", host_a)))
            self.assertTrue(without_b.ok, without_b.to_dict())
            self.assertTrue(shared_context.is_file())
            self.assertTrue(shared_skill.is_dir())
            self.assertTrue(shared_binding.is_file())

            removed_last = setup(self._shared_selection(root, ("codex-cli",)))
            self.assertTrue(removed_last.ok, removed_last.to_dict())
            self.assertTrue(shared_context.is_file())
            self.assertFalse(shared_skill.exists())
            self.assertFalse(shared_binding.exists())

    def test_legacy_shared_generic_target_content_conflict_fails_closed(self) -> None:
        host_a = "test-compatible-cli-" + "a"
        host_b = "test-compatible-cli-" + "b"
        fields = {
            "context_hash": "context_path",
            "installed_skill_hash": "skill_destination",
            "skill_binding_hash": "skill_binding_path",
        }
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            hosts = ("codex-cli", host_a, host_b)
            selection = self._shared_selection(root, hosts)
            first = setup(selection)
            self.assertTrue(first.ok, first.to_dict())
            manifest_path = first.manifest_path
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            record_a = manifest["hosts"][host_a]
            record_b = manifest["hosts"][host_b]
            state = _manifest_state(manifest)
            for hash_key, path_key in fields.items():
                target = str(Path(record_a[path_key]))
                aggregate = state["managed_targets"][target]["hash"]
                record_a[hash_key] = aggregate
                record_b[hash_key] = "sha256:" + hashlib.sha256(
                    f"legacy-conflict|{hash_key}|{aggregate}|{host_b}".encode("utf-8")
                ).hexdigest()
            manifest_path.write_text(json.dumps(manifest, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
            context_path = Path(record_a["context_path"])
            context_path.write_text(context_path.read_text(encoding="utf-8") + "\nTAMPERED\n", encoding="utf-8")

            result = setup(selection)
            self.assertFalse(result.ok, result.to_dict())
            self.assertEqual(result.reconciliation["status"], "BLOCKED")
            self.assertTrue(any(item.get("error_code") == "MANAGED_TARGET_CONFLICT" for item in result.errors))
            self.assertIn("TAMPERED", context_path.read_text(encoding="utf-8"))

    def test_removing_all_shared_owners_in_one_call_processes_each_target_once(self) -> None:
        host_a = "test-compatible-cli-" + "a"
        host_b = "test-compatible-cli-" + "b"
        hosts = ("codex-cli", host_a, host_b)
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw).resolve()
            first = setup(self._shared_selection(root, hosts))
            self.assertTrue(first.ok, first.to_dict())
            manifest_path = first.manifest_path
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            record_a = manifest["hosts"][host_a]
            record_b = manifest["hosts"][host_b]
            shared_hook = Path(record_a["hook_config_path"])
            shared_context = Path(record_a["context_path"])
            shared_skill = Path(record_a["skill_destination"])
            shared_binding = Path(record_a["skill_binding_path"])
            adapter_target = root / "adapter-shared" / "state.json"
            profile_binding_target = root / "adapter-shared" / "profile-binding.json"
            adapter_target.parent.mkdir(parents=True, exist_ok=True)
            adapter_target.write_bytes(b"adapter-state\n")
            profile_binding_target.write_bytes(b"profile-binding\n")
            adapter_hash = "sha256:" + hashlib.sha256(adapter_target.read_bytes()).hexdigest()
            profile_binding_hash = "sha256:" + hashlib.sha256(profile_binding_target.read_bytes()).hexdigest()
            for record in (record_a, record_b):
                record["adapter_state_path"] = str(adapter_target)
                record["adapter_state_hash"] = adapter_hash
                record["profile_binding_path"] = str(profile_binding_target)
                record["profile_binding_hash"] = profile_binding_hash
            # Adapter-defined fields are intentionally outside the closed
            # public manifest schema.  Exercise the reconciliation/apply
            # boundary directly with the detached legacy record so the
            # generic target is still covered without weakening validation of
            # a persisted manifest.
            removal_selection = self._shared_selection(root, ("codex-cli",))
            settings = _settings_for_selection(removal_selection)
            transaction = _Transaction(root / "runtime")
            apply_owned_host_actions(
                removal_selection,
                settings,
                Path.cwd(),
                Path(sys.executable),
                _source_skill(Path.cwd()),
                manifest,
                transaction,
            )
            for target in (shared_hook, shared_context, shared_skill, shared_binding, adapter_target, profile_binding_target):
                self.assertEqual(
                    sum(Path(entry["target"]) == target for entry in transaction.entries),
                    1,
                    str(target),
                )
            transaction.commit()
            self.assertTrue(shared_hook.is_file())
            self.assertTrue(shared_context.is_file())
            self.assertFalse(shared_skill.exists())
            self.assertFalse(shared_binding.exists())
            self.assertFalse(adapter_target.exists())
            self.assertFalse(profile_binding_target.exists())

    def test_setup_removes_all_shared_builtin_targets_in_one_call(self) -> None:
        host_a = "test-compatible-cli-" + "a"
        host_b = "test-compatible-cli-" + "b"
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            first = setup(self._shared_selection(root, ("codex-cli", host_a, host_b)))
            self.assertTrue(first.ok, first.to_dict())
            manifest = json.loads(first.manifest_path.read_text(encoding="utf-8"))
            record = manifest["hosts"][host_a]
            targets = {
                "hook": Path(record["hook_config_path"]),
                "context": Path(record["context_path"]),
                "skill": Path(record["skill_destination"]),
                "binding": Path(record["skill_binding_path"]),
            }

            removed = setup(self._shared_selection(root, ("codex-cli",)))
            self.assertTrue(removed.ok, removed.to_dict())
            self.assertTrue(targets["hook"].is_file())
            self.assertTrue(targets["context"].is_file())
            self.assertFalse(targets["skill"].exists())
            self.assertFalse(targets["binding"].exists())

    def test_shared_removal_conflict_rolls_back_prior_target_mutation(self) -> None:
        host_a = "test-compatible-cli-" + "a"
        host_b = "test-compatible-cli-" + "b"
        hosts = ("codex-cli", host_a, host_b)
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            first = setup(self._shared_selection(root, hosts))
            self.assertTrue(first.ok, first.to_dict())
            manifest = json.loads(first.manifest_path.read_text(encoding="utf-8"))
            record_a = manifest["hosts"][host_a]
            shared_hook = Path(record_a["hook_config_path"])
            shared_context = Path(record_a["context_path"])
            shared_skill = Path(record_a["skill_destination"])
            shared_binding = Path(record_a["skill_binding_path"])
            context_before = shared_context.read_bytes()
            hook_document = json.loads(shared_hook.read_text(encoding="utf-8"))
            tampered = False
            for entries in hook_document.get("hooks", {}).values():
                for entry in entries:
                    if isinstance(entry, dict) and host_a in str(entry.get("id")):
                        entry["matcher"] = "TAMPERED"
                        tampered = True
                        break
                if tampered:
                    break
            self.assertTrue(tampered)
            shared_hook.write_text(json.dumps(hook_document, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
            hook_tampered = shared_hook.read_bytes()

            removal_selection = self._shared_selection(root, ("codex-cli",))
            settings = _settings_for_selection(removal_selection)
            transaction = _Transaction(root / "runtime")
            with self.assertRaisesRegex(ValueError, "MANAGED_TARGET_CONFLICT"):
                apply_owned_host_actions(
                    removal_selection,
                    settings,
                    Path.cwd(),
                    Path(sys.executable),
                    _source_skill(Path.cwd()),
                    manifest,
                    transaction,
                )
            rollback = transaction.rollback()
            self.assertEqual(rollback["status"], "ROLLED_BACK")
            self.assertEqual(context_before, shared_context.read_bytes())
            self.assertTrue(shared_skill.is_dir())
            self.assertTrue(shared_binding.is_file())
            self.assertEqual(hook_tampered, shared_hook.read_bytes())


if __name__ == "__main__":
    unittest.main()
