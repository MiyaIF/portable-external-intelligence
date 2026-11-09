from __future__ import annotations

import json
import hashlib
import importlib.util
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from ei.command_quote import build_skill_launcher_argv
from ei.closeout_service import _event_audit
from ei.gate import GateDecision
from ei.journal import append_event, iter_events
from ei.install_manifest import normalize_install_manifest
from ei.models import Event
from ei.project import project_events
from ei.skill_installer import canonical_tree_hash
from ei.team_store import append_team_event, initialize_team_store


ROOT = Path(__file__).resolve().parents[2]
SCRIPTS = ROOT / "skills" / "external-intelligence" / "scripts"
SKILL_SOURCE = SCRIPTS.parent
SKILL_BINDING_NAME = ".external-intelligence-binding.json"


def _manifest(
    engine: Path,
    knowledge: Path,
    runtime: Path,
    *,
    host_home: Path,
    skill_destination: Path,
    installed_skill_hash: str,
    binding_path: Path,
    binding_hash: str,
    skill_mode: str = "copy",
) -> dict[str, object]:
    return {
        "schema_version": 8,
        "status": "INSTALLED",
        "installed_at": "2026-09-02T00:00:00+00:00",
        "repo_root": str(engine.resolve()),
        "engine_root": str(engine.resolve()),
        "knowledge_root": str(knowledge.resolve()),
        "runtime_root": str(runtime.resolve()),
        "root_ownership": {
            "engine_root": "public-source-read-only",
            "knowledge_root": "private-knowledge-git-or-local",
            "runtime_root": "machine-local-git-forbidden",
        },
        "supported_hosts": ["codex-cli", "claude-code", "gemini-cli", "qwen-code"],
        "organizer": {
            "status": "READY",
            "provider_id": "subscription-cli",
            "host_id": "codex-cli",
            "reason_code": None,
        },
        "work_hosts": ["codex-cli"],
        "hosts": {
            "codex-cli": {
                "host_id": "codex-cli",
                "home": str(host_home.resolve()),
                "hook_config_path": str((host_home / "hooks.json").resolve()),
                "context_path": str((host_home / "AGENTS.md").resolve()),
                "skill_destination": str(skill_destination.absolute()),
                "skill_root": str(skill_destination.parent.absolute()),
                "skill_mode": skill_mode,
                "source_skill_hash": installed_skill_hash,
                "installed_skill_hash": installed_skill_hash,
                "skill_binding_path": str(binding_path.absolute()),
                "skill_binding_hash": binding_hash,
                "hook_template_hash": "sha256:" + "3" * 64,
                "context_hash": None,
                "skill_activation_mode": "AUTO_ALLOWED",
                "capture_primary_path": "AGENT_SKILL",
                "managed_hook_ids": [],
            }
        },
        "legacy_host_migrations": [],
        "managed_marker": {"begin": "begin", "end": "end", "version": "v1"},
        "managed_hook_ids": [],
        "providers": ["subscription-cli"],
        "privacy_profile": "private-reusable",
        "sync_enabled": False,
        "experiment_enabled": False,
        "scheduler_requested": False,
        "skill_source": str((engine / "skills" / "external-intelligence").resolve()),
        "skill_source_hash": "sha256:" + "1" * 64,
        "hook_schema_hash": "sha256:" + "2" * 64,
        "skip_venv": True,
        "venv_created": False,
        "python_exe": str(Path(sys.executable).resolve()),
        "transaction_id": "tx-skill-boundary",
        "agents_block_version": "v1",
        "config_backup": None,
        "hooks_backup": None,
        "agents_backup": None,
        "agents_original_sha256": None,
        "agents_installed_sha256": None,
        "knowledge_repository": {
            "status": "READY",
            "mode": "local",
            "root": str(knowledge.resolve()),
            "remote_name": None,
            "remote_fingerprint": None,
            "remote_classification": None,
            "branch": None,
            "connected": False,
            "initial_push_complete": False,
            "sync_enabled": False,
        },
        "knowledge_stores": {
            "personal": {
                "enabled": True,
                "status": "READY",
                "mode": "local",
                "root": str(knowledge.resolve()),
                "remote_name": None,
                "remote_fingerprint": None,
                "remote_classification": None,
                "branch": None,
                "connected": False,
                "initial_push_complete": False,
                "sync_enabled": False,
            },
            "team": None,
        },
        "reconciliation": {"desired_state_digest": "sha256:" + "4" * 64},
    }


def _prepare_install(root: Path, engine: Path = ROOT, *, link: bool = False) -> tuple[Path, Path, Path, Path]:
    host_home = root / "host-home"
    skill_destination = host_home / "skills" / "external-intelligence"
    knowledge = root / "private-knowledge"
    runtime = root / "runtime"
    host_home.mkdir(parents=True, exist_ok=True)
    runtime.mkdir(parents=True, exist_ok=True)
    knowledge.mkdir(parents=True, exist_ok=True)
    if link:
        skill_destination.parent.mkdir(parents=True, exist_ok=True)
        os.symlink(SKILL_SOURCE, skill_destination, target_is_directory=True)
    else:
        shutil.copytree(SKILL_SOURCE, skill_destination, ignore=shutil.ignore_patterns("__pycache__", "*.pyc"))
    installed_skill_hash = canonical_tree_hash(skill_destination)
    binding_path = skill_destination.parent / SKILL_BINDING_NAME
    binding = {
        "schema_version": 1,
        "host_id": "codex-cli",
        "engine_root": str(engine.resolve()),
        "knowledge_root": str(knowledge.resolve()),
        "runtime_root": str(runtime.resolve()),
        "python_exe": str(Path(sys.executable).resolve()),
        "skill_destination": str(skill_destination.absolute()),
        "installed_skill_hash": installed_skill_hash,
    }
    binding_raw = (json.dumps(binding, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")
    binding_path.write_bytes(binding_raw)
    binding_hash = "sha256:" + hashlib.sha256(binding_raw).hexdigest()
    (runtime / "install-manifest.json").write_text(
        json.dumps(
            _manifest(
                engine,
                knowledge,
                runtime,
                host_home=host_home,
                skill_destination=skill_destination,
                installed_skill_hash=installed_skill_hash,
                binding_path=binding_path,
                binding_hash=binding_hash,
                skill_mode="link" if link else "copy",
            ),
            ensure_ascii=False,
        ),
        encoding="utf-8",
    )
    return skill_destination / "scripts", knowledge, runtime, binding_path


def _structured_yes_payload(*, claim: str = "Preserve explicit setup consent when updating managed installation state.") -> dict[str, object]:
    title = "Verified setup consent"
    return {
        "candidate": {
            "candidate_id": "skill-auto-apply-boundary",
            "source_host_id": "codex-cli",
            "source_host_family": "codex-compatible",
            "title": title,
            "claim": claim,
            "domain": "setup",
            "source_ref": "sha256:" + "b" * 64,
        },
        "gate_decision": {
            "decision": "YES",
            "reason_code": "evidence_verified",
            "candidate_title": title,
            "candidate_claim": claim,
            "evidence_refs": ["sha256:" + "a" * 64],
            "benefit": "reduced_rework",
            "classification": "private-reusable",
            "confidence": 0.9,
            "provider_id": "manual",
            "applicability_scope": "universal",
            "applicable_host_ids": [],
            "applicable_host_families": [],
        },
    }


class SkillRuntimeBoundaryTests(unittest.TestCase):
    def test_failed_actual_cwd_resolution_discards_caller_claimed_scope(self) -> None:
        script_path = SCRIPTS / "closeout.py"
        spec = importlib.util.spec_from_file_location("task14_skill_closeout", script_path)
        self.assertIsNotNone(spec)
        self.assertIsNotNone(spec.loader)
        closeout_module = importlib.util.module_from_spec(spec)
        prior_dont_write_bytecode = sys.dont_write_bytecode
        try:
            with patch.object(sys, "path", [str(SCRIPTS), *sys.path]):
                spec.loader.exec_module(closeout_module)
        finally:
            sys.dont_write_bytecode = prior_dont_write_bytecode

        candidate = {
            "cwd": "C:/caller/fake-project",
            "cwd_fingerprint": "sha256:" + "f" * 64,
        }
        with patch.object(closeout_module.Path, "cwd", side_effect=OSError("cwd unavailable")):
            scope_state = closeout_module._bind_verified_cwd_scope(candidate)

        self.assertEqual(scope_state, "UNKNOWN")
        self.assertNotIn("cwd", candidate)
        self.assertNotIn("cwd_fingerprint", candidate)

    def test_schema_v2_disabled_team_binding_does_not_require_retained_team_root(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            scripts, knowledge, runtime, binding_path = _prepare_install(root)
            binding = json.loads(binding_path.read_text(encoding="utf-8"))
            binding = {
                "schema_version": 2,
                "host_id": binding["host_id"],
                "engine_root": binding["engine_root"],
                "personal_knowledge_root": binding["knowledge_root"],
                "team_knowledge_root": None,
                "knowledge_root": binding["knowledge_root"],
                "runtime_root": binding["runtime_root"],
                "python_exe": binding["python_exe"],
                "skill_destination": binding["skill_destination"],
                "installed_skill_hash": binding["installed_skill_hash"],
            }
            binding_raw = (json.dumps(binding, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")
            binding_path.write_bytes(binding_raw)
            manifest = normalize_install_manifest(json.loads((runtime / "install-manifest.json").read_text(encoding="utf-8")))
            manifest["knowledge_stores"]["team"] = {
                "enabled": False,
                "root": str(root / "retained-team-that-is-offline"),
                "store_id": "team_0123456789abcdef",
                "layout": "member-writer-events-v1",
                "team_member_id": "member-a",
                "writer_id": "writer_0123456789abcdef",
                "transport": "external-shared-folder",
                "transport_managed": False,
                "status": "DISABLED",
            }
            binding_hash = "sha256:" + hashlib.sha256(binding_raw).hexdigest()
            manifest["hosts"]["codex-cli"]["skill_binding_hash"] = binding_hash
            (runtime / "install-manifest.json").write_text(json.dumps(manifest, ensure_ascii=False), encoding="utf-8")
            completed = self._run("status.py", ROOT, runtime, scripts=scripts)
            self.assertEqual(completed.returncode, 0, completed.stdout + completed.stderr)
            self.assertEqual(json.loads(completed.stdout)["status"], "success")

    def test_status_reports_effective_manifest_state_from_production_cli(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            scripts, _knowledge, runtime, _binding = _prepare_install(root)
            manifest_path = runtime / "install-manifest.json"
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            manifest["experiment_enabled"] = True
            manifest["sync_enabled"] = True
            manifest_path.write_text(json.dumps(manifest, ensure_ascii=False), encoding="utf-8")

            completed = self._run("status.py", ROOT, runtime, scripts=scripts)

            self.assertEqual(completed.returncode, 0, completed.stdout + completed.stderr)
            payload = json.loads(completed.stdout)
            self.assertEqual(payload["status"], "success", payload)
            self.assertTrue(payload["experiment"]["enabled"])
            self.assertTrue(payload["sync"]["enabled"])
            self.assertIn("doctor_ok", payload["Hook"])

    def test_skill_reader_normalizes_transitional_v8_provider_list(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            scripts, _knowledge, runtime, _binding = _prepare_install(root)
            manifest_path = runtime / "install-manifest.json"
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            manifest["providers"] = ["ollama", "subscription-cli", "subscription-cli"]
            manifest_path.write_text(json.dumps(manifest, ensure_ascii=False), encoding="utf-8")

            completed = self._run("status.py", ROOT, runtime, scripts=scripts)

            self.assertEqual(completed.returncode, 0, completed.stdout + completed.stderr)
            self.assertEqual(json.loads(completed.stdout)["status"], "success")

    def _run(
        self,
        name: str,
        engine: Path,
        runtime: Path,
        extra: list[str] | None = None,
        *,
        input_text: str | None = None,
        environment: dict[str, str] | None = None,
        scripts: Path = SCRIPTS,
        cwd: Path | None = None,
    ) -> subprocess.CompletedProcess[str]:
        command = [
            *build_skill_launcher_argv(
                sys.executable,
                skill_destination=scripts.parent,
                engine_root=engine,
                runtime_root=runtime,
            ),
            name.removesuffix(".py"),
            *(extra or []),
        ]
        return subprocess.run(
            command,
            cwd=cwd or ROOT,
            env=environment,
            input=input_text,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            check=False,
            timeout=30,
        )

    def test_every_skill_script_rejects_a_caller_selected_engine_before_import(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            scripts, _knowledge, runtime, _binding = _prepare_install(root)
            malicious = root / "active-project"
            marker = root / "attacker-code-ran.txt"
            package = malicious / "src" / "ei"
            package.mkdir(parents=True)
            (package / "__init__.py").write_text(
                "from pathlib import Path\n"
                f"Path({str(marker)!r}).write_text('executed', encoding='utf-8')\n",
                encoding="utf-8",
            )
            (package / "cli.py").write_text(
                "print('{\"ok\":true,\"status\":\"success\"}')\n",
                encoding="utf-8",
            )
            yes_payload = json.dumps(
                {
                    "gate_decision": {
                        "decision": "YES",
                        "reason_code": "reusable",
                        "candidate_title": "Portable boundary",
                        "candidate_claim": "Use only the setup-bound engine for Skill execution.",
                        "evidence_refs": ["sha256:" + "a" * 64],
                        "benefit": "Prevents repeated unsafe import resolution.",
                        "classification": "private-reusable",
                        "confidence": 1.0,
                        "provider_id": "manual",
                    },
                    "candidate": {},
                }
            )
            cases = (
                ("recall.py", ["--query", "portable boundary"], None),
                ("closeout.py", [], yes_payload),
                ("maintain.py", ["--dry-run"], None),
                ("sync.py", ["--dry-run"], None),
                ("repair.py", [], None),
                ("status.py", [], None),
            )
            for name, extra, input_text in cases:
                with self.subTest(script=name):
                    marker.unlink(missing_ok=True)
                    completed = self._run(name, malicious, runtime, extra, input_text=input_text, scripts=scripts)
                    self.assertNotEqual(completed.returncode, 0, completed.stdout)
                    self.assertFalse(marker.exists(), completed.stdout + completed.stderr)
                    self.assertIn("ACTIVE_MANIFEST_ENGINE_MISMATCH", completed.stdout)
                    self.assertNotIn(str(malicious), completed.stdout)

    def test_recall_uses_the_manifest_bound_separate_knowledge_root(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            scripts, knowledge, runtime, _binding = _prepare_install(root)
            project_events(
                [
                    Event.create(
                        "pattern.promoted",
                        "2026-09-01T00:00:00+00:00",
                        "test",
                        "machine",
                        {
                            "pattern_id": "pat_manifest_boundary",
                            "cluster_id": "cluster_manifest_boundary",
                            "rule": "Resolve Skill imports from the setup-bound engine and retrieve from the separate knowledge root.",
                            "provenances": ["source:a", "source:b"],
                            "scopes": ["portable"],
                            "applicability": ["security", "portable"],
                            "host_ids": ["codex-cli"],
                            "version_constraint": ">=1.0,<2",
                            "benefit_count": 1,
                            "classification": "private-reusable",
                        },
                        event_id="evt_manifest_boundary",
                    )
                ],
                knowledge / "knowledge",
            )

            completed = self._run(
                "recall.py",
                ROOT,
                runtime,
                [
                    "--query",
                    "setup-bound engine separate knowledge root",
                    "--host",
                    "codex-cli",
                    "--domain",
                    "security",
                    "--scope",
                    "portable",
                    "--version",
                    "1.4.0",
                ],
                scripts=scripts,
            )

            self.assertEqual(completed.returncode, 0, completed.stdout + completed.stderr)
            payload = json.loads(completed.stdout)
            self.assertEqual(payload["status"], "success")
            self.assertEqual([item["pattern_id"] for item in payload["hits"]], ["pat_manifest_boundary"])

    def test_recall_skill_passes_actual_cwd_for_project_reference_filtering(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            scripts, knowledge, runtime, _binding = _prepare_install(root)
            project = root / "actual-project"
            project.mkdir()
            cwd_fingerprint = "sha256:" + hashlib.sha256(str(project.resolve()).encode("utf-8")).hexdigest()
            project_events(
                [
                    Event.create(
                        "observation.recorded",
                        "2026-09-01T00:00:00+00:00",
                        "test",
                        "machine",
                        {
                            "observation_id": "obs_skill_project_reference",
                            "title": "Receipt check",
                            "claim": "Check the receipt before retrying the same operation.",
                            "cwd_fingerprint": cwd_fingerprint,
                            "classification": "private-reusable",
                        },
                        event_id="evt_skill_project_reference",
                    )
                ],
                knowledge / "knowledge",
            )

            completed = self._run(
                "recall.py",
                ROOT,
                runtime,
                ["--query", "check receipt before retrying", "--host", "codex-cli"],
                scripts=scripts,
                cwd=project,
            )

            self.assertEqual(completed.returncode, 0, completed.stdout + completed.stderr)
            payload = json.loads(completed.stdout)
            self.assertEqual([item["pattern_id"] for item in payload["hits"]], ["obs_skill_project_reference"])
            self.assertEqual(payload["hits"][0]["knowledge_kind"], "project-reference")
            self.assertIn("Project-only reference (unpromoted; verify applicability)", payload["context"])
            self.assertNotIn(str(project), completed.stdout)

    def test_recall_uses_enabled_team_store_from_the_bound_install(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            scripts, knowledge, runtime, binding_path = _prepare_install(root)
            project_events(
                [
                    Event.create(
                        "pattern.promoted",
                        "2026-09-01T00:00:00+00:00",
                        "test",
                        "machine",
                        {
                            "pattern_id": "pat_personal_bound_recall",
                            "cluster_id": "cluster_personal_bound_recall",
                            "rule": "Reuse the personal verification procedure and check only the changed behavior.",
                            "provenances": ["source:personal"],
                            "scopes": ["portable"],
                            "applicability": ["portable"],
                            "host_ids": ["codex-cli"],
                            "benefit_count": 1,
                            "classification": "private-reusable",
                        },
                        event_id="evt_personal_bound_recall",
                    )
                ],
                knowledge / "knowledge",
            )
            team_root = root / "shared-team"
            descriptor = initialize_team_store(
                team_root,
                now="2026-09-01T00:00:00+00:00",
                random_id=lambda: "0123456789abcdef",
            )
            idempotency_key = "sha256:" + "a" * 64
            append_team_event(
                team_root,
                "member-a",
                "writer_aaaaaaaaaaaaaaaa",
                Event.create_v2(
                    "team.knowledge.recorded",
                    actor="team-member-hash",
                    machine_id="team-machine-hash",
                    occurred_at=datetime(2026, 9, 1, tzinfo=timezone.utc),
                    idempotency_key=idempotency_key,
                    payload={
                        "knowledge_scope": "team",
                        "origin_event_hash": "sha256:" + "b" * 64,
                        "idempotency_key": idempotency_key,
                        "title": "Team verification procedure",
                        "claim": "Reuse the team verification procedure and check only the changed behavior.",
                        "scope": ["portable"],
                        "preconditions": ["The same problem structure recurs."],
                        "failure_modes": ["Skipping verification causes rework."],
                        "benefit": "reduced_rework",
                        "classification": "private-reusable",
                    },
                ),
            )

            binding = json.loads(binding_path.read_text(encoding="utf-8"))
            binding = {
                "schema_version": 2,
                "host_id": binding["host_id"],
                "engine_root": binding["engine_root"],
                "personal_knowledge_root": binding["knowledge_root"],
                "team_knowledge_root": str(team_root.resolve()),
                "knowledge_root": binding["knowledge_root"],
                "runtime_root": binding["runtime_root"],
                "python_exe": binding["python_exe"],
                "skill_destination": binding["skill_destination"],
                "installed_skill_hash": binding["installed_skill_hash"],
            }
            binding_raw = (json.dumps(binding, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")
            binding_path.write_bytes(binding_raw)
            manifest_path = runtime / "install-manifest.json"
            manifest = normalize_install_manifest(json.loads(manifest_path.read_text(encoding="utf-8")))
            manifest["knowledge_stores"]["team"] = {
                "enabled": True,
                "root": str(team_root.resolve()),
                "store_id": descriptor.store_id,
                "layout": "member-writer-events-v1",
                "team_member_id": "member-a",
                "writer_id": "writer_aaaaaaaaaaaaaaaa",
                "transport": "external-shared-folder",
                "transport_managed": False,
                "status": "READY",
            }
            manifest["hosts"]["codex-cli"]["skill_binding_hash"] = "sha256:" + hashlib.sha256(binding_raw).hexdigest()
            manifest_path.write_text(json.dumps(manifest, ensure_ascii=False), encoding="utf-8")

            completed = self._run(
                "recall.py",
                ROOT,
                runtime,
                ["--query", "reuse verification procedure changed behavior", "--host", "codex-cli"],
                scripts=scripts,
            )

            self.assertEqual(completed.returncode, 0, completed.stdout + completed.stderr)
            payload = json.loads(completed.stdout)
            self.assertEqual(payload["status"], "success")
            self.assertEqual({item["knowledge_scope"] for item in payload["hits"]}, {"personal", "team"})
            self.assertEqual(payload["knowledge_stores"]["team"]["status"], "READY")
            self.assertLessEqual(len(payload["hits"]), 5)
            self.assertLessEqual(payload["context_chars"], 5000)

    def test_closeout_accepts_one_utf8_object_with_surrounding_whitespace(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            scripts, _knowledge, runtime, _binding = _prepare_install(root)
            completed = self._run(
                "closeout.py",
                ROOT,
                runtime,
                scripts=scripts,
                input_text=' \n {"decision":"NO","reason_code":"NOT_REUSABLE"}\n ',
            )

            self.assertEqual(completed.returncode, 0, completed.stdout + completed.stderr)
            payload = json.loads(completed.stdout)
            self.assertEqual(payload["status"], "not_inherited")
            self.assertEqual(payload["decision"], "NO")

    def test_consent_enabled_closeout_applies_one_observation_and_replays_the_same_event(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            scripts, knowledge, runtime, _binding = _prepare_install(root)
            manifest_path = runtime / "install-manifest.json"
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            manifest["skill_auto_apply"] = True
            manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
            project = root / "current-project"
            project.mkdir()
            payload = {
                "candidate": {
                    "candidate_id": "skill-auto-apply-replay",
                    "source_host_id": "codex-cli",
                    "source_host_family": "codex-compatible",
                    "cwd": str(root / "candidate-claimed-project"),
                    "cwd_fingerprint": "sha256:" + "f" * 64,
                    "skill_auto_apply": False,
                    "host_id": "claude-code",
                    "host_is_work_host": True,
                    "skill_activation_mode": "AUTO_ALLOWED",
                    "runtime_root": str(root / "candidate-runtime"),
                    "title": "Verified setup consent",
                    "claim": "Preserve explicit setup consent when updating managed installation state.",
                    "domain": "setup",
                    "source_ref": "sha256:" + "b" * 64,
                "precondition": "Explicit setup consent is present.",
                "failure_mode": "Skipping consent validation can cause unintended writes.",
                "exception": "Proposal-only mode never applies the candidate.",
                "version_constraint": ">=1.0,<2",
                },
                "gate_decision": {
                    "decision": "YES",
                    "reason_code": "evidence_verified",
                    "candidate_title": "Verified setup consent",
                    "candidate_claim": "Preserve explicit setup consent when updating managed installation state.",
                    "evidence_refs": ["sha256:" + "a" * 64],
                    "benefit": "reduced_rework",
                    "classification": "private-reusable",
                    "confidence": 0.9,
                    "provider_id": "manual",
                    "applicability_scope": "universal",
                    "applicable_host_ids": [],
                    "applicable_host_families": [],
                },
            }
            encoded = json.dumps(payload, ensure_ascii=False)

            first = self._run("closeout.py", ROOT, runtime, input_text=encoded, scripts=scripts, cwd=project)

            self.assertEqual(first.returncode, 0, first.stdout + first.stderr)
            first_payload = json.loads(first.stdout)
            self.assertEqual(first_payload["knowledge"], "APPLIED")
            self.assertEqual(first_payload["association"]["status"], "UNKNOWN")
            self.assertTrue(first_payload["curation"]["event_ids"])
            first_events = list(iter_events(knowledge / "events"))
            first_observations = [event for event in first_events if event.event_type == "observation.recorded"]
            self.assertEqual(len(first_observations), 1)
            for field, expected in {
                "precondition": "Explicit setup consent is present.",
                "failure_mode": "Skipping consent validation can cause unintended writes.",
                "exception": "Proposal-only mode never applies the candidate.",
                "version_constraint": ">=1.0,<2",
            }.items():
                self.assertEqual(first_observations[0].payload.get(field), expected)
            expected_cwd_fingerprint = "sha256:" + hashlib.sha256(str(project.resolve()).encode("utf-8")).hexdigest()
            self.assertEqual(first_observations[0].payload["cwd_fingerprint"], expected_cwd_fingerprint)
            self.assertNotIn(str(project), json.dumps(first_observations[0].to_dict(), ensure_ascii=False))

            project_events(first_events, knowledge / "knowledge")
            outside_version = self._run(
                "recall.py",
                ROOT,
                runtime,
                ["--query", "explicit setup consent managed installation", "--host", "codex-cli", "--version", "2.0"],
                scripts=scripts,
                cwd=project,
            )
            self.assertEqual(outside_version.returncode, 0, outside_version.stdout + outside_version.stderr)
            self.assertEqual(json.loads(outside_version.stdout)["hits"], [])

            unknown_version = self._run(
                "recall.py",
                ROOT,
                runtime,
                ["--query", "explicit setup consent managed installation", "--host", "codex-cli"],
                scripts=scripts,
                cwd=project,
            )
            self.assertEqual(unknown_version.returncode, 0, unknown_version.stdout + unknown_version.stderr)
            self.assertEqual(json.loads(unknown_version.stdout)["hits"], [])

            inside_version = self._run(
                "recall.py",
                ROOT,
                runtime,
                ["--query", "explicit setup consent managed installation", "--host", "codex-cli", "--version", "1.5"],
                scripts=scripts,
                cwd=project,
            )
            self.assertEqual(inside_version.returncode, 0, inside_version.stdout + inside_version.stderr)
            inside_payload = json.loads(inside_version.stdout)
            self.assertEqual([item["pattern_id"] for item in inside_payload["hits"]], [first_observations[0].payload["observation_id"]])
            self.assertEqual(inside_payload["hits"][0]["knowledge_kind"], "project-reference")
            for detail in (
                "Precondition: Explicit setup consent is present.",
                "Failure mode: Skipping consent validation can cause unintended writes.",
                "Exception: Proposal-only mode never applies the candidate.",
                "Version constraint: >=1.0,<2",
            ):
                self.assertIn(detail, inside_payload["context"])

            second = self._run("closeout.py", ROOT, runtime, input_text=encoded, scripts=scripts, cwd=project)

            self.assertEqual(second.returncode, 0, second.stdout + second.stderr)
            second_payload = json.loads(second.stdout)
            self.assertTrue(second_payload["curation"]["already_applied"])
            self.assertEqual(second_payload["curation"]["event_ids"], first_payload["curation"]["event_ids"])
            final_events = list(iter_events(knowledge / "events"))
            self.assertEqual(sum(event.event_type == "observation.recorded" for event in final_events), 1)

    def test_closeout_without_verified_consent_or_host_activation_is_proposal_only(self) -> None:
        cases = (
            ("missing-consent", None, "AUTO_ALLOWED", ["codex-cli"], False),
            ("explicit-false", False, "AUTO_ALLOWED", ["codex-cli"], False),
            ("proposal-only", True, "AUTO_ALLOWED", ["codex-cli"], True),
            ("consent-required", True, "CONSENT_REQUIRED", ["codex-cli"], False),
            ("unverified-activation", True, "UNVERIFIED", ["codex-cli"], False),
            ("not-a-work-host", True, "AUTO_ALLOWED", ["claude-code"], False),
        )
        for name, consent, activation, work_hosts, force_proposal in cases:
            with self.subTest(name=name), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                scripts, knowledge, runtime, _binding = _prepare_install(root)
                manifest_path = runtime / "install-manifest.json"
                manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
                if consent is not None:
                    manifest["skill_auto_apply"] = consent
                manifest["hosts"]["codex-cli"]["skill_activation_mode"] = activation
                manifest["work_hosts"] = work_hosts
                if "claude-code" in work_hosts:
                    other_host = dict(manifest["hosts"]["codex-cli"])
                    other_host.update({
                        "host_id": "claude-code",
                        "skill_activation_mode": "AUTO_ALLOWED",
                    })
                    manifest["hosts"]["claude-code"] = other_host
                manifest_path.write_text(json.dumps(manifest, ensure_ascii=False), encoding="utf-8")
                payload = _structured_yes_payload()
                args = ["--proposal-only"] if force_proposal else None

                completed = self._run(
                    "closeout.py",
                    ROOT,
                    runtime,
                    extra=args,
                    input_text=json.dumps(payload, ensure_ascii=False),
                    scripts=scripts,
                )

                self.assertEqual(completed.returncode, 0, completed.stdout + completed.stderr)
                result = json.loads(completed.stdout)
                self.assertEqual(result["status"], "changeset_ready", result)
                self.assertEqual(result["decision"], "YES")
                self.assertTrue(result["validation"]["valid"])
                self.assertEqual(list(iter_events(knowledge / "events")), [])

    def test_closeout_rejects_a_candidate_bound_to_another_host(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            scripts, knowledge, runtime, _binding = _prepare_install(root)
            manifest_path = runtime / "install-manifest.json"
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            manifest["skill_auto_apply"] = True
            manifest_path.write_text(json.dumps(manifest, ensure_ascii=False), encoding="utf-8")
            payload = _structured_yes_payload()
            payload["candidate"]["source_host_id"] = "claude-code"
            payload["candidate"]["source_host_family"] = "claude-code"

            completed = self._run(
                "closeout.py",
                ROOT,
                runtime,
                input_text=json.dumps(payload, ensure_ascii=False),
                scripts=scripts,
            )

            self.assertEqual(completed.returncode, 2, completed.stdout + completed.stderr)
            self.assertEqual(json.loads(completed.stdout)["error_code"], "CLOSEOUT_SOURCE_HOST_PAIR_MISMATCH")
            self.assertEqual(list(iter_events(knowledge / "events")), [])

    def test_closeout_privacy_rejection_never_appends_observation_or_claim_text(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            scripts, knowledge, runtime, _binding = _prepare_install(root)
            manifest_path = runtime / "install-manifest.json"
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            manifest["skill_auto_apply"] = True
            manifest_path.write_text(json.dumps(manifest, ensure_ascii=False), encoding="utf-8")
            marker = "api_key=task14-synthetic-marker-123456789"
            payload = _structured_yes_payload(claim=marker)

            completed = self._run(
                "closeout.py",
                ROOT,
                runtime,
                input_text=json.dumps(payload, ensure_ascii=False),
                scripts=scripts,
            )

            self.assertEqual(completed.returncode, 2, completed.stdout + completed.stderr)
            self.assertEqual(json.loads(completed.stdout)["error_code"], "SECRET_PATTERN_MATCH")
            self.assertNotIn(marker, completed.stdout + completed.stderr)
            events = list(iter_events(knowledge / "events"))
            self.assertFalse(any(event.event_type == "observation.recorded" for event in events))
            self.assertNotIn(marker, json.dumps([event.to_dict() for event in events], ensure_ascii=False))

    def test_closeout_sanitizes_audit_event_id_collision_without_traceback_or_path(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            scripts, knowledge, runtime, _binding = _prepare_install(root)
            manifest_path = runtime / "install-manifest.json"
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            manifest["skill_auto_apply"] = True
            manifest_path.write_text(json.dumps(manifest, ensure_ascii=False), encoding="utf-8")
            payload = _structured_yes_payload()
            gate = payload["gate_decision"]
            candidate = payload["candidate"]
            decision = GateDecision.from_mapping(
                gate,
                provider_id=gate["provider_id"],
                source_host_id=candidate["source_host_id"],
                source_host_family=candidate["source_host_family"],
            )
            captured: list[Event] = []
            audit_settings = SimpleNamespace(paths=SimpleNamespace(event_dir=knowledge / "events"))
            with patch(
                "ei.closeout_service.append_event",
                side_effect=lambda event, _event_root, **_kwargs: captured.append(event),
            ):
                _event_audit(audit_settings, decision, candidate)
            expected_audit = captured[0]
            conflicting_event = Event.create(
                "gate.decision",
                expected_audit.occurred_at,
                expected_audit.actor,
                expected_audit.machine_id,
                {"decision": "NO", "classification": "private-reusable"},
                event_id=expected_audit.event_id,
            )
            append_event(conflicting_event, knowledge / "events")

            completed = self._run(
                "closeout.py",
                ROOT,
                runtime,
                input_text=json.dumps(payload, ensure_ascii=False),
                scripts=scripts,
            )

            result = json.loads(completed.stdout)
            self.assertEqual(completed.returncode, 2, completed.stdout + completed.stderr)
            self.assertEqual(result["status"], "rejected")
            self.assertEqual(result["error_code"], f"EVENT_ID_COLLISION:{expected_audit.event_id}")
            self.assertNotIn("Traceback", completed.stdout + completed.stderr)
            self.assertNotIn(str(root), completed.stdout + completed.stderr)
            events = list(iter_events(knowledge / "events"))
            self.assertEqual(len(events), 1)
            self.assertEqual(events[0].canonical_dict(), conflicting_event.canonical_dict())

    def test_personal_auto_apply_skips_team_routing_without_mutating_team_settings(self) -> None:
        from ei.closeout_service import _team_result

        team_store = {"enabled": True, "store_id": "team_0123456789abcdef"}
        settings = SimpleNamespace(knowledge_stores=SimpleNamespace(team=team_store))
        with patch(
            "ei.team_routing.route_applied_personal_knowledge",
            side_effect=AssertionError("personal Skill auto-save must not invoke team routing"),
        ) as route:
            result = _team_result(
                settings,
                applied=True,
                changeset=None,
                event_ids=("evt_20261104T000000000000Z_0123456789ab",),
                candidate={"candidate_id": "task14-team-routing-boundary"},
                route_team=False,
            )
        self.assertEqual(result, {"status": "SKIPPED", "reason_code": "TEAM_ROUTING_NOT_REQUESTED"})
        self.assertTrue(settings.knowledge_stores.team["enabled"])
        route.assert_not_called()

    def test_team_routing_suppression_rejects_trusted_context_before_side_effects(self) -> None:
        from ei.closeout_service import InputError, process_closeout

        with self.assertRaisesRegex(
            InputError,
            "CLOSEOUT_TEAM_ROUTING_POLICY_UNSUPPORTED_FOR_TRUSTED_CONTEXT",
        ):
            process_closeout({}, SimpleNamespace(), validation=object(), route_team=False)

    def test_trusted_child_ignores_parent_pythonpath_sitecustomize(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            scripts, _knowledge, runtime, _binding = _prepare_install(root)
            poison = root / "poison"
            marker = root / "sitecustomize-ran.txt"
            poison.mkdir()
            (poison / "sitecustomize.py").write_text(
                "from pathlib import Path\n"
                f"Path({str(marker)!r}).write_text('executed', encoding='utf-8')\n",
                encoding="utf-8",
            )
            environment = os.environ.copy()
            environment["PYTHONPATH"] = str(poison)

            completed = self._run(
                "status.py",
                ROOT,
                runtime,
                environment=environment,
                scripts=scripts,
            )

            self.assertEqual(completed.returncode, 0, completed.stdout + completed.stderr)
            self.assertFalse(marker.exists(), completed.stdout + completed.stderr)
            self.assertEqual(json.loads(completed.stdout)["status"], "success")

    def test_direct_nonisolated_script_is_rejected_without_writing_bytecode(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            scripts, _knowledge, runtime, _binding = _prepare_install(root)
            bytecode = scripts / "__pycache__"
            shutil.rmtree(bytecode, ignore_errors=True)
            environment = os.environ.copy()
            environment.pop("PYTHONDONTWRITEBYTECODE", None)

            completed = subprocess.run(
                [
                    sys.executable,
                    str(scripts / "status.py"),
                    "--engine-root",
                    str(ROOT),
                    "--runtime-root",
                    str(runtime),
                ],
                cwd=ROOT,
                env=environment,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                check=False,
                timeout=30,
            )

            self.assertEqual(completed.returncode, 2, completed.stdout + completed.stderr)
            tree = [path.relative_to(scripts.parent).as_posix() for path in scripts.parent.rglob("*")]
            expected_hash = json.loads((runtime / "install-manifest.json").read_text(encoding="utf-8"))["hosts"]["codex-cli"]["installed_skill_hash"]
            actual_hash = canonical_tree_hash(scripts.parent)
            changed = [
                path.relative_to(scripts.parent).as_posix()
                for path in scripts.parent.rglob("*")
                if path.is_file()
                and (SKILL_SOURCE / path.relative_to(scripts.parent)).is_file()
                and path.read_bytes() != (SKILL_SOURCE / path.relative_to(scripts.parent)).read_bytes()
            ]
            diagnostics = f"{completed.stdout}{completed.stderr}\nexpected={expected_hash} actual={actual_hash} changed={changed}\n{tree}"
            self.assertIn("SKILL_LAUNCHER_REQUIRED", completed.stdout, diagnostics)
            self.assertFalse(bytecode.exists(), diagnostics)

    def test_isolated_launcher_works_from_link_install_without_mutating_source(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            try:
                scripts, _knowledge, runtime, _binding = _prepare_install(Path(tmp), link=True)
            except OSError:
                self.skipTest("symbolic links are unavailable in this environment")

            completed = self._run("status.py", ROOT, runtime, scripts=scripts)

            self.assertEqual(completed.returncode, 0, completed.stdout + completed.stderr)
            self.assertEqual(json.loads(completed.stdout)["status"], "success")
            self.assertFalse((SKILL_SOURCE / "scripts" / "__pycache__").exists())

    def test_bound_skill_rejects_manifest_engine_rebinding_before_import(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            scripts, knowledge, runtime, _binding = _prepare_install(root)
            malicious = root / "forged-engine"
            marker = root / "forged-engine-ran.txt"
            package = malicious / "src" / "ei"
            package.mkdir(parents=True)
            (malicious / "config").mkdir()
            (malicious / "config" / "defaults.json").write_text("{}\n", encoding="utf-8")
            (package / "__init__.py").write_text(
                "from pathlib import Path\n"
                f"Path({str(marker)!r}).write_text('executed', encoding='utf-8')\n",
                encoding="utf-8",
            )
            (package / "cli.py").write_text("print('{\"ok\":true}')\n", encoding="utf-8")
            manifest = json.loads((runtime / "install-manifest.json").read_text(encoding="utf-8"))
            manifest["repo_root"] = str(malicious.resolve())
            manifest["engine_root"] = str(malicious.resolve())
            (runtime / "install-manifest.json").write_text(json.dumps(manifest), encoding="utf-8")

            completed = self._run("status.py", ROOT, runtime, scripts=scripts)

            self.assertNotEqual(completed.returncode, 0, completed.stdout)
            self.assertFalse(marker.exists(), completed.stdout + completed.stderr)
            self.assertIn("SKILL_BINDING_MANIFEST_MISMATCH", completed.stdout)
            self.assertNotIn(str(malicious), completed.stdout)


if __name__ == "__main__":
    unittest.main()
