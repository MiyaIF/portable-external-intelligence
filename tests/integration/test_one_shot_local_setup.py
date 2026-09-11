from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import patch

import ei.knowledge_setup as knowledge_setup
from ei.config import load_settings
from ei.knowledge_repository import KnowledgeRepositoryError, inspect_knowledge_repository
from ei.knowledge_setup import (
    KnowledgeSetupSelection,
    apply_knowledge_setup,
    load_operation_receipt,
    operation_receipt_path,
    plan_knowledge_setup,
)
from ei.installer import SetupSelection, setup, update
from ei.journal import append_event
from ei.maintainer import run_maintenance
from ei.models import Event
from ei.project import project_events
from ei.skill_installer import canonical_tree_hash


class OneShotLocalSetupTests(unittest.TestCase):
    def test_update_installs_changed_source_skill_without_mutating_knowledge(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            engine = root / "engine"
            shutil.copytree(
                Path.cwd(),
                engine,
                ignore=shutil.ignore_patterns(".git", ".venv", "__pycache__", ".pycache-*", ".superpowers", "artifacts", "build"),
            )
            home = root / "codex-home"
            home.mkdir()
            knowledge = root / "knowledge"
            runtime = root / "runtime"
            selection = SetupSelection(
                engine_root=engine,
                knowledge_root=knowledge,
                runtime_root=runtime,
                hosts=("codex-cli",),
                organizer_provider="subscription-cli",
                organizer_host="codex-cli",
                host_homes={"codex-cli": home},
                python_exe=Path(sys.executable),
                skip_venv=True,
                non_interactive=True,
                accept_plan=True,
            )
            installed = setup(selection)
            self.assertTrue(installed.ok, installed.to_dict())
            manifest_path = runtime / "install-manifest.json"
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            destination = Path(manifest["hosts"]["codex-cli"]["skill_destination"])
            source_status = engine / "skills" / "external-intelligence" / "scripts" / "status.py"
            source_status.write_text(source_status.read_text(encoding="utf-8") + "\n# update fixture\n", encoding="utf-8")
            expected_hash = canonical_tree_hash(source_status.parents[1])
            before_knowledge = inspect_knowledge_repository(knowledge, engine_root=engine, runtime_root=runtime)

            updated = update(load_settings(engine, runtime_root=runtime))

            self.assertTrue(updated.ok, updated.to_dict())
            self.assertEqual((destination / "scripts" / "status.py").read_bytes(), source_status.read_bytes())
            updated_manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            self.assertEqual(updated_manifest["hosts"]["codex-cli"]["installed_skill_hash"], expected_hash)
            after_knowledge = inspect_knowledge_repository(knowledge, engine_root=engine, runtime_root=runtime)
            self.assertEqual(after_knowledge.root_digest, before_knowledge.root_digest)

    def test_new_local_install_supports_maintenance_update_and_restore(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            engine = Path.cwd()
            home = root / "codex-home"
            home.mkdir()
            selection = SetupSelection(
                engine_root=engine,
                knowledge_root=root / "knowledge",
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
            installed = setup(selection)
            self.assertTrue(installed.ok, installed.to_dict())
            settings = load_settings(
                engine_root=engine,
                knowledge_root=selection.knowledge_root,
                runtime_root=selection.runtime_root,
                host_homes=selection.host_homes,
            )
            pattern = Event.create(
                "pattern.promoted",
                "2026-01-01T00:00:00Z",
                "offline-certification",
                "offline-machine",
                {
                    "pattern_id": "pat_clean_clone",
                    "cluster_id": "cluster_clean_clone",
                    "rule": "Reload persisted values after writes.",
                    "provenances": ["fixture:clean-clone"],
                    "scopes": ["testing"],
                    "applicability": ["testing"],
                    "benefit_count": 1,
                    "evidence_count": 2,
                    "classification": "private-reusable",
                },
                event_id="evt_clean_clone_pattern",
            )
            project_events([pattern], settings.paths.knowledge_dir)
            append_event(
                Event.create(
                    "gate.decision",
                    datetime.now(timezone.utc).isoformat(),
                    "external-intelligence",
                    "offline-machine",
                    {
                        "decision": "NO",
                        "reason_code": "one_off_fact",
                        "provider_id": "manual-structured",
                        "classification": "private-reusable",
                        "evidence_count": 0,
                        "candidate_id_hash": "sha256:" + "0" * 64,
                    },
                    event_id="evt_gate_offline_fixture",
                ),
                settings.paths.event_dir,
            )

            result = run_maintenance(
                settings,
                source_paths=(),
                max_queue_items=10,
                time_budget_ms=5000,
                sync_policy="disabled",
            )

            self.assertEqual(result.status, "success", result.to_dict())
            self.assertEqual(result.errors, ())
            checked_update = update(settings, check_only=True)
            self.assertTrue(checked_update.ok, checked_update.to_dict())
            self.assertEqual(checked_update.status, "CHECK_ONLY")
            completed = subprocess.run(
                [
                    sys.executable,
                    "-B",
                    "-m",
                    "ei.installer",
                    "--update",
                    "--manifest",
                    str(selection.runtime_root / "install-manifest.json"),
                    "--check-only",
                    "--json",
                ],
                cwd=engine,
                env={**os.environ, "PYTHONPATH": str(engine / "src")},
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=30,
                check=False,
            )
            self.assertEqual(completed.returncode, 0, completed.stdout + completed.stderr)
            self.assertEqual(json.loads(completed.stdout)["status"], "CHECK_ONLY")
            manifest_path = selection.runtime_root / "install-manifest.json"
            manifest_before = manifest_path.read_bytes()
            unconfirmed = subprocess.run(
                [
                    sys.executable,
                    "-B",
                    "-m",
                    "ei.installer",
                    "--uninstall",
                    "--manifest",
                    str(manifest_path),
                    "--json",
                ],
                cwd=engine,
                env={**os.environ, "PYTHONPATH": str(engine / "src")},
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=30,
                check=False,
            )
            self.assertNotEqual(unconfirmed.returncode, 0)
            self.assertEqual(manifest_path.read_bytes(), manifest_before)
            uninstalled = subprocess.run(
                [
                    sys.executable,
                    "-B",
                    "-m",
                    "ei.installer",
                    "--uninstall",
                    "--manifest",
                    str(manifest_path),
                    "--confirm-manifest-sha256",
                    "sha256:" + hashlib.sha256(manifest_before).hexdigest(),
                    "--json",
                ],
                cwd=engine,
                env={**os.environ, "PYTHONPATH": str(engine / "src")},
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=30,
                check=False,
            )
            self.assertEqual(uninstalled.returncode, 0, uninstalled.stdout + uninstalled.stderr)
            self.assertEqual(json.loads(uninstalled.stdout)["result"]["status"], "UNINSTALLED")
            restored = setup(selection)
            self.assertTrue(restored.ok, restored.to_dict())
            self.assertEqual(restored.status, "SETUP_COMPLETE")

    def test_combined_setup_creates_and_connects_local_knowledge_before_hosts(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            engine = Path.cwd()
            home = root / "codex-home"
            home.mkdir()
            selection = SetupSelection(
                engine_root=engine,
                knowledge_root=root / "knowledge",
                runtime_root=root / "runtime",
                hosts=("codex-cli",),
                organizer_provider="subscription-cli",
                organizer_host="codex-cli",
                host_homes={"codex-cli": home},
                python_exe=Path(__import__("sys").executable),
                skip_venv=True,
                non_interactive=True,
                accept_plan=True,
            )
            checked = setup(selection, check_only=True)
            self.assertTrue(checked.ok, checked.to_dict())
            self.assertFalse(selection.knowledge_root.exists())
            self.assertEqual(checked.knowledge["mode"], "local")

            applied = setup(selection)

            self.assertTrue(applied.ok, applied.to_dict())
            self.assertEqual(applied.status, "SETUP_COMPLETE")
            self.assertEqual(applied.knowledge["repository"]["status"], "READY")
            self.assertTrue((selection.knowledge_root / ".git").is_dir())
    def _selection(self, root: Path) -> KnowledgeSetupSelection:
        engine = root / "engine source"
        engine.mkdir()
        return KnowledgeSetupSelection(
            mode="local",
            engine_root=engine,
            knowledge_root=root / "knowledge 日本語",
            runtime_root=root / "runtime 日本語",
        )

    def test_absent_root_is_created_and_second_setup_is_product_stable(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            selection = self._selection(Path(tmp))
            first_plan = plan_knowledge_setup(selection)

            first = apply_knowledge_setup(first_plan)

            self.assertTrue(first.ok, first)
            self.assertEqual(first.status, "COMPLETE")
            self.assertEqual(first.stage, "KNOWLEDGE_LOCAL_READY")
            self.assertEqual(first.repository["status"], "CREATED")
            self.assertTrue((selection.knowledge_root / ".git").exists())
            self.assertTrue((selection.knowledge_root / "knowledge-repository.json").is_file())
            self.assertFalse(first.remote["connected"])
            head_before = subprocess.run(
                ["git", "-C", str(selection.knowledge_root), "rev-parse", "HEAD"],
                capture_output=True,
                text=True,
                check=True,
            ).stdout.strip()
            status_before = inspect_knowledge_repository(
                selection.knowledge_root,
                engine_root=selection.engine_root,
                runtime_root=selection.runtime_root,
            )

            second_plan = plan_knowledge_setup(selection)
            second = apply_knowledge_setup(second_plan)

            self.assertTrue(second.ok, second)
            self.assertEqual(second.repository["status"], "ALREADY_CURRENT")
            status_after = inspect_knowledge_repository(
                selection.knowledge_root,
                engine_root=selection.engine_root,
                runtime_root=selection.runtime_root,
            )
            head_after = subprocess.run(
                ["git", "-C", str(selection.knowledge_root), "rev-parse", "HEAD"],
                capture_output=True,
                text=True,
                check=True,
            ).stdout.strip()
            self.assertEqual(head_before, head_after)
            self.assertEqual(status_before.root_digest, status_after.root_digest)
            receipt = load_operation_receipt(
                operation_receipt_path(second_plan),
                runtime_root=selection.runtime_root,
            )
            self.assertEqual(receipt["repository"]["status"], "ALREADY_CURRENT")

    def test_owned_partial_staging_is_recovered_without_touching_final_root(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            selection = self._selection(Path(tmp))
            plan = plan_knowledge_setup(selection)
            real_bootstrap = knowledge_setup.bootstrap_knowledge_repository

            def interrupt(staging: Path, **kwargs: object):
                Path(staging).mkdir(parents=True, exist_ok=True)
                (Path(staging) / "partial.txt").write_text("partial\n", encoding="utf-8")
                raise KnowledgeRepositoryError("FORCED_BOOTSTRAP_INTERRUPTION")

            with patch.object(knowledge_setup, "bootstrap_knowledge_repository", interrupt):
                failed = apply_knowledge_setup(plan)

            self.assertFalse(failed.ok)
            self.assertEqual(failed.status, "FAILED")
            self.assertFalse(selection.knowledge_root.exists())
            self.assertTrue(any(selection.knowledge_root.parent.glob(f".{selection.knowledge_root.name}.ei-setup-*")))

            with patch.object(knowledge_setup, "bootstrap_knowledge_repository", real_bootstrap):
                recovered = apply_knowledge_setup(plan_knowledge_setup(selection))

            self.assertTrue(recovered.ok, recovered)
            self.assertEqual(recovered.repository["status"], "CREATED")
            self.assertFalse(any(selection.knowledge_root.parent.glob(f".{selection.knowledge_root.name}.ei-setup-*")))


if __name__ == "__main__":
    unittest.main()
