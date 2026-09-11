import json
import os
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import ei.config as config_module
from ei.config import discover_codex_home, load_active_install_manifest, load_settings
from ei.setup_contract import OrganizerSelection, resolve_organizer


class ConfigTests(unittest.TestCase):
    @staticmethod
    def _active_manifest(engine: Path, knowledge: Path, runtime: Path) -> dict[str, object]:
        digest = "sha256:" + "0" * 64
        host = {
            "host_id": "codex-cli",
            "home": str(engine),
            "hook_config_path": str(engine / "hooks.json"),
            "context_path": str(engine / "context.md"),
            "skill_destination": str(engine / "skills" / "ei"),
            "skill_root": str(engine / "skills"),
            "skill_mode": "copy",
            "source_skill_hash": digest,
            "installed_skill_hash": digest,
            "skill_binding_path": str(engine / "skills" / "binding.json"),
            "skill_binding_hash": digest,
            "hook_template_hash": digest,
            "context_hash": digest,
            "skill_activation_mode": "AUTO_ALLOWED",
            "capture_primary_path": "HOOK_DIRECT",
            "managed_hook_ids": [],
        }
        repository = {
            "status": "READY",
            "mode": "local",
            "root": str(knowledge),
            "remote_name": None,
            "remote_fingerprint": None,
            "remote_classification": None,
            "branch": None,
            "connected": False,
            "initial_push_complete": False,
            "sync_enabled": False,
        }
        return {
            "schema_version": 8,
            "status": "INSTALLED",
            "installed_at": "2026-08-30T00:00:00+00:00",
            "repo_root": str(engine),
            "engine_root": str(engine),
            "knowledge_root": str(knowledge),
            "runtime_root": str(runtime),
            "root_ownership": {
                "engine_root": "public-source-read-only",
                "knowledge_root": "private-knowledge-git-or-local",
                "runtime_root": "machine-local-git-forbidden",
            },
            "supported_hosts": ["codex-cli", "claude-code", "gemini-cli", "qwen-code"],
            "hosts": {"codex-cli": host},
            "organizer": {
                "status": "READY",
                "provider_id": "ollama",
                "host_id": None,
                "reason_code": None,
            },
            "work_hosts": ["codex-cli"],
            "legacy_host_migrations": [],
            "managed_marker": {"begin": "begin", "end": "end", "version": "v1"},
            "managed_hook_ids": [],
            "providers": ["ollama"],
            "privacy_profile": "private-reusable",
            "sync_enabled": False,
            "experiment_enabled": False,
            "scheduler_requested": False,
            "skill_source": str(engine / "skills" / "external-intelligence"),
            "skill_source_hash": "sha256:" + "1" * 64,
            "hook_schema_hash": "sha256:" + "2" * 64,
            "skip_venv": True,
            "venv_created": False,
            "python_exe": "python",
            "transaction_id": "tx-test",
            "agents_block_version": "v1",
            "config_backup": None,
            "hooks_backup": None,
            "agents_backup": None,
            "agents_original_sha256": None,
            "agents_installed_sha256": None,
            "knowledge_repository": repository,
            "knowledge_stores": {"personal": {"enabled": True, **repository}, "team": None},
            "reconciliation": {"desired_state_digest": digest},
        }

    @unittest.skipUnless(os.name == "nt", "Windows junction fixture is platform-specific")
    def test_active_manifest_rejects_runtime_path_through_parent_junction(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            outside = root / "outside"
            engine = root / "engine"
            knowledge = root / "knowledge"
            runtime_real = outside / "runtime"
            for path in (outside, engine, knowledge, runtime_real):
                path.mkdir(parents=True, exist_ok=True)
            junction = root / "linked-parent"
            created = subprocess.run(
                ["cmd.exe", "/c", "mklink", "/J", str(junction), str(outside)],
                capture_output=True,
                text=True,
                check=False,
            )
            if created.returncode != 0 or not junction.exists():
                self.skipTest("junction fixture unavailable")
            runtime_via_junction = junction / "runtime"
            manifest = self._active_manifest(engine, knowledge, runtime_real.resolve())
            (runtime_real / "install-manifest.json").write_text(json.dumps(manifest), encoding="utf-8")

            with self.assertRaisesRegex(ValueError, "^ACTIVE_MANIFEST_RUNTIME_INVALID$"):
                load_active_install_manifest(runtime_via_junction)
            with self.assertRaisesRegex(ValueError, "^ACTIVE_MANIFEST_RUNTIME_INVALID$"):
                load_settings(engine_root=engine, runtime_root=runtime_via_junction, host_homes={})

    @unittest.skipUnless(os.name == "nt", "Windows junction fixture is platform-specific")
    def test_load_hosts_rejects_empty_profile_directory_junction(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            repo = root / "repo"
            (repo / "config").mkdir(parents=True)
            source_hosts = Path(__file__).resolve().parents[2] / "config" / "hosts.json"
            (repo / "config" / "hosts.json").write_bytes(source_hosts.read_bytes())
            runtime = root / "runtime"
            runtime.mkdir()
            outside = root / "outside"
            outside.mkdir()
            junction = runtime / "host-profiles"
            created = subprocess.run(
                ["cmd.exe", "/c", "mklink", "/J", str(junction), str(outside)],
                capture_output=True,
                text=True,
                check=False,
            )
            if created.returncode != 0 or not junction.exists():
                self.skipTest("junction fixture unavailable")
            host_homes = {
                host_id: root / host_id
                for host_id in ("codex-cli", "claude-code", "gemini-cli", "qwen-code")
            }
            with self.assertRaisesRegex(ValueError, "^HOST_PROFILE_LOCATOR_INVALID$"):
                config_module._load_hosts(repo, host_homes, runtime_root=runtime)

    def test_active_manifest_rejects_non_string_nested_knowledge_root(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            engine, knowledge, runtime = root / "engine", root / "knowledge", root / "runtime"
            for path in (engine, knowledge, runtime):
                path.mkdir()
            manifest = self._active_manifest(engine, knowledge, runtime)
            manifest["knowledge_repository"]["root"] = 123  # type: ignore[index]
            (runtime / "install-manifest.json").write_text(json.dumps(manifest), encoding="utf-8")

            with self.assertRaisesRegex(ValueError, "^ACTIVE_MANIFEST_KNOWLEDGE_STORE_MISMATCH$"):
                load_active_install_manifest(runtime)

    def test_active_manifest_normalizes_transitional_v8_provider_list(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            engine, knowledge, runtime = root / "engine", root / "knowledge", root / "runtime"
            for path in (engine, knowledge, runtime):
                path.mkdir()
            manifest = self._active_manifest(engine, knowledge, runtime)
            manifest["organizer"] = {
                "status": "READY",
                "provider_id": "subscription-cli",
                "host_id": "codex-cli",
                "reason_code": None,
            }
            manifest["providers"] = ["ollama", "subscription-cli"]
            (runtime / "install-manifest.json").write_text(json.dumps(manifest), encoding="utf-8")

            loaded = load_active_install_manifest(runtime)

            self.assertEqual(loaded["providers"], ["subscription-cli"])

    def test_active_manifest_accepts_lexical_aliases_for_the_same_canonical_roots(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            engine, knowledge, runtime = root / "engine", root / "knowledge", root / "runtime"
            for path in (engine, knowledge, runtime):
                path.mkdir()
            manifest = self._active_manifest(engine, knowledge, runtime)
            (runtime / "install-manifest.json").write_text(json.dumps(manifest), encoding="utf-8")

            runtime_alias = root / "RUNTIME~1"
            engine_alias = root / "ENGINE~1"
            real_assert = config_module.assert_no_reparse_components
            real_canonical = config_module.canonical_path

            def lexical_alias(value, **kwargs):
                del kwargs
                if isinstance(value, str) and value == str(runtime):
                    return runtime_alias
                if isinstance(value, str) and value == str(engine):
                    return engine_alias
                return real_assert(value)

            def canonical_alias(value, *, require_exists=False):
                candidate = Path(value)
                if candidate == runtime_alias:
                    return runtime.resolve()
                if candidate == engine_alias:
                    return engine.resolve()
                return real_canonical(value, require_exists=require_exists)

            with patch.object(config_module, "assert_no_reparse_components", side_effect=lexical_alias), patch.object(
                config_module,
                "canonical_path",
                side_effect=canonical_alias,
            ):
                loaded = load_active_install_manifest(runtime, expected_engine_root=engine)

            self.assertEqual(loaded["runtime_root"], str(runtime))
            self.assertEqual(loaded["engine_root"], str(engine))

    def test_active_manifest_missing_and_corrupt_fail_with_stable_codes(self):
        with tempfile.TemporaryDirectory() as tmp:
            runtime = Path(tmp) / "runtime"
            runtime.mkdir()
            with self.assertRaisesRegex(ValueError, "^ACTIVE_INSTALL_MANIFEST_MISSING$"):
                load_active_install_manifest(runtime)
            (runtime / "install-manifest.json").write_text("{}\n", encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "^ACTIVE_INSTALL_MANIFEST_INVALID$"):
                load_active_install_manifest(runtime)

    def test_uninstalled_manifest_requires_explicit_installer_opt_in(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            engine, knowledge, runtime = root / "engine", root / "knowledge", root / "runtime"
            for path in (engine, knowledge, runtime):
                path.mkdir()
            manifest = self._active_manifest(engine, knowledge, runtime)
            manifest["status"] = "UNINSTALLED"
            (runtime / "install-manifest.json").write_text(json.dumps(manifest), encoding="utf-8")

            with self.assertRaisesRegex(ValueError, "^ACTIVE_INSTALL_MANIFEST_INVALID$"):
                load_active_install_manifest(runtime)
            loaded = load_active_install_manifest(runtime, allow_uninstalled=True)

            self.assertEqual(loaded["status"], "UNINSTALLED")

    def test_explicit_host_home_does_not_mutate_environment(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            repo = root / "repo"
            runtime = root / "実行ルート"
            host_home = root / "ホスト設定"
            (repo / "config").mkdir(parents=True)
            (repo / "config" / "defaults.json").write_text(
                json.dumps({"schema_version": 1, "retrieval": {"max_chars": 5000, "max_results": 5}}),
                encoding="utf-8",
            )
            (repo / "config" / "hosts.json").write_text(
                (Path(__file__).resolve().parents[2] / "config" / "hosts.json").read_text(encoding="utf-8"),
                encoding="utf-8",
            )
            env_values = {
                "EI_REPO_ROOT": str(root / "環境repo"),
                "EI_RUNTIME_ROOT": str(root / "環境runtime"),
                "CODEX_HOME": str(root / "環境codex"),
            }
            with patch.dict(os.environ, env_values, clear=False):
                before = {name: os.environ[name] for name in env_values}
                settings = load_settings(
                    repo_root=repo,
                    runtime_root=runtime,
                    host_homes={"codex-cli": host_home, "claude-code": root / "claude", "gemini-cli": root / "gemini", "qwen-code": root / "qwen"},
                )
                self.assertEqual({name: os.environ[name] for name in env_values}, before)

            self.assertEqual(settings.paths.repo_root, repo.resolve())
            self.assertEqual(settings.paths.runtime_root, runtime.resolve())
            self.assertEqual(settings.paths.codex_home, host_home.resolve())
            self.assertEqual(
                settings.hosts["codex-cli"].hook_config_path,
                host_home.resolve() / "hooks.json",
            )
            self.assertNotIn("codex-app", settings.hosts)

    def test_settings_round_trip_includes_paths_policies_provider_order_and_machine_hash(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            repo = root / "repo"
            runtime = root / "ランタイム"
            home = root / "codex-home"
            (repo / "config").mkdir(parents=True)
            (repo / "config" / "defaults.json").write_text(
                json.dumps(
                    {
                        "schema_version": 7,
                        "retrieval": {"max_chars": 5000, "max_results": 5, "min_score": 0.35},
                        "context": {"prompt_max_chars": 5000, "always_on_hard_cap_chars": 12000},
                        "providers": {"order": ["local-openai-compatible", "ollama"], "cloud_spend_cap": 0},
                        "dependency_locks": {"ci_tools": ["detect-secrets", "pip-audit"]},
                    }
                ),
                encoding="utf-8",
            )
            settings = load_settings(repo_root=repo, codex_home=home, runtime_root=runtime, host_homes={})
            self.assertEqual(settings.schema_version, "7")
            self.assertEqual(settings.provider_order, ("local-openai-compatible", "ollama"))
            self.assertEqual(settings.paths.codex_home, home.resolve())
            self.assertEqual(settings.paths.queue_dir, runtime.resolve() / "queue")
            self.assertEqual(settings.paths.spool_dir, runtime.resolve() / "spool")
            self.assertEqual(settings.paths.emergency_spool_dir, runtime.resolve() / "emergency-spool")
            self.assertEqual(settings.paths.cursor_dir, runtime.resolve() / "cursor")
            self.assertEqual(settings.paths.lock_dir, runtime.resolve() / "locks")
            self.assertEqual(settings.paths.cache_dir, runtime.resolve() / "cache")
            self.assertEqual(settings.paths.log_dir, runtime.resolve() / "logs")
            self.assertEqual(settings.paths.backup_dir, runtime.resolve() / "backups")
            self.assertEqual(settings.paths.install_manifest_path, runtime.resolve() / "install-manifest.json")
            self.assertEqual(settings.privacy_policy_path, repo.resolve() / "policies" / "privacy-policy.json")
            self.assertEqual(settings.capture_policy_path, repo.resolve() / "policies" / "capture-policy.json")
            self.assertEqual(settings.promotion_policy_path, repo.resolve() / "policies" / "promotion-policy.json")
            self.assertEqual(settings.retrieval_policy_path, repo.resolve() / "policies" / "retrieval-policy.json")
            self.assertEqual(settings.budget_policy_path, repo.resolve() / "policies" / "budget-policy.json")
            self.assertEqual(settings.experiment_policy_path, repo.resolve() / "policies" / "experiment-policy.json")
            self.assertTrue(settings.machine_id_hash.startswith("sha256:"))
            self.assertEqual(settings.prompt_max_chars, 5000)
            self.assertEqual(settings.always_on_hard_cap_chars, 12000)

    def test_settings_contains_personal_knowledge_store_and_legacy_views(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            repo = root / "repo"
            personal = root / "personal"
            runtime = root / "runtime"
            (repo / "config").mkdir(parents=True)
            (repo / "config" / "defaults.json").write_text(
                json.dumps({"retrieval": {"max_chars": 5000, "max_results": 5}}),
                encoding="utf-8",
            )
            settings = load_settings(
                engine_root=repo,
                personal_knowledge_root=personal,
                runtime_root=runtime,
                codex_home=root / "codex",
                host_homes={},
            )
            self.assertEqual(settings.knowledge_stores.personal.root, personal.resolve())
            self.assertIsNone(settings.knowledge_stores.team)
            self.assertEqual(settings.paths.knowledge_root, personal.resolve())
            self.assertEqual(settings.paths.event_dir, personal.resolve() / "events")
            self.assertEqual(settings.paths.knowledge_dir, personal.resolve() / "knowledge")

    def test_explicit_codex_home_is_preserved_when_runtime_root_is_supplied(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            repo = root / "repo"
            codex_home = root / "portable-codex"
            runtime = root / "separate-runtime"
            (repo / "config").mkdir(parents=True)
            (repo / "config" / "defaults.json").write_text(
                json.dumps({"schema_version": 1, "retrieval": {"max_chars": 5000, "max_results": 5}}),
                encoding="utf-8",
            )
            settings = load_settings(repo_root=repo, codex_home=codex_home, runtime_root=runtime)
            self.assertEqual(settings.paths.codex_home, codex_home.resolve())
            self.assertEqual(settings.paths.runtime_root, runtime.resolve())
            self.assertEqual(settings.paths.config_path, codex_home.resolve() / "config.toml")
            self.assertEqual(settings.paths.hooks_path, codex_home.resolve() / "hooks.json")
            self.assertEqual(settings.paths.agents_path, codex_home.resolve() / "AGENTS.md")

    def test_explicit_codex_home_wins_without_hardcoded_user_path(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            repo = root / "repo"
            home = root / "portable-codex"
            (repo / "config").mkdir(parents=True)
            (repo / "config" / "defaults.json").write_text(
                json.dumps({"retrieval": {"max_chars": 5000, "max_results": 5}}),
                encoding="utf-8",
            )
            settings = load_settings(repo, codex_home=home)
            self.assertEqual(settings.paths.codex_home, home.resolve())
            self.assertEqual(settings.paths.runtime_dir, home.resolve() / "external-intelligence")
            self.assertEqual(settings.retrieval_max_chars, 5000)

    def test_environment_codex_home_is_read_without_modification(self):
        with tempfile.TemporaryDirectory() as tmp:
            value = str(Path(tmp) / "from-env")
            with patch.dict(os.environ, {"CODEX_HOME": value}, clear=False):
                before = os.environ["CODEX_HOME"]
                result = discover_codex_home()
                self.assertEqual(result, Path(value).resolve())
                self.assertEqual(os.environ["CODEX_HOME"], before)

    def test_missing_explicit_and_env_codex_home_fails_stably(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            repo = root / "repo"
            runtime = root / "runtime"
            (repo / "config").mkdir(parents=True)
            (repo / "config" / "defaults.json").write_text(
                json.dumps({"schema_version": 1, "retrieval": {"max_chars": 5000, "max_results": 5}}),
                encoding="utf-8",
            )
            with patch.dict(os.environ, {}, clear=True):
                with self.assertRaisesRegex(ValueError, "HOST_HOME_REQUIRED"):
                    load_settings(repo_root=repo, runtime_root=runtime, host_homes={})

    def test_repository_defaults_without_manifest_require_organizer_selection(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            repo = root / "repo"
            (repo / "config").mkdir(parents=True)
            (repo / "config" / "defaults.json").write_text(
                json.dumps({"retrieval": {"max_chars": 5000, "max_results": 5}}),
                encoding="utf-8",
            )

            settings = load_settings(repo_root=repo, codex_home=root / "codex", runtime_root=root / "runtime", host_homes={})

            self.assertIsInstance(settings.organizer, OrganizerSelection)
            self.assertEqual(settings.organizer.status, "SELECTION_REQUIRED")
            self.assertEqual(settings.organizer.reason_code, "ORGANIZER_SELECTION_REQUIRED")

    def test_resolve_organizer_never_selects_first_provider_or_host(self):
        ambiguous_provider = resolve_organizer(None, None, ["codex-cli"], {"ollama", "subscription-cli"})
        ambiguous_host = resolve_organizer("subscription-cli", None, ["codex-cli", "gemini-cli"], {"subscription-cli"})

        self.assertEqual(ambiguous_provider.status, "SELECTION_REQUIRED")
        self.assertEqual(ambiguous_host.status, "SELECTION_REQUIRED")
        self.assertIsNone(ambiguous_provider.provider_id)
        self.assertIsNone(ambiguous_host.host_id)


if __name__ == "__main__":
    unittest.main()
