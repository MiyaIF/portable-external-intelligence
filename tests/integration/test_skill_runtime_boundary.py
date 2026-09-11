from __future__ import annotations

import json
import hashlib
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path

from ei.command_quote import build_skill_launcher_argv
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


class SkillRuntimeBoundaryTests(unittest.TestCase):
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
            cwd=ROOT,
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
