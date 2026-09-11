from __future__ import annotations

import json
import unittest
from pathlib import Path
from unittest.mock import patch

from ei.install_manifest import (
    INSTALL_MANIFEST_SCHEMA_VERSION,
    manifest_knowledge_stores,
    migration_backup_bytes,
    normalize_install_manifest,
    validate_install_manifest,
)
from ei.setup_contract import migrate_legacy_organizer


def valid_v6_manifest() -> dict[str, object]:
    engine = "C:/engine"
    knowledge = "C:/private-knowledge"
    runtime = "C:/runtime"
    return {
        "schema_version": 6,
        "status": "INSTALLED",
        "installed_at": "2026-09-05T00:00:00+00:00",
        "repo_root": engine,
        "engine_root": engine,
        "knowledge_root": knowledge,
        "runtime_root": runtime,
        "root_ownership": {
            "engine_root": "public-source-read-only",
            "knowledge_root": "private-knowledge-git-or-local",
            "runtime_root": "machine-local-git-forbidden",
        },
        "supported_hosts": ["codex-cli"],
        "hosts": {},
        "legacy_host_migrations": [],
        "managed_marker": {"begin": "begin", "end": "end", "version": "v1"},
        "managed_hook_ids": [],
        "providers": ["ollama"],
        "privacy_profile": "private-reusable",
        "sync_enabled": False,
        "experiment_enabled": False,
        "scheduler_requested": False,
        "skill_source": "C:/engine/skills/external-intelligence",
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
        "knowledge_repository": {
            "status": "READY",
            "mode": "local",
            "root": knowledge,
            "remote_name": None,
            "remote_fingerprint": None,
            "remote_classification": None,
            "branch": None,
            "connected": False,
            "initial_push_complete": False,
            "sync_enabled": False,
        },
    }


def valid_v7_manifest(host_ids: tuple[str, ...] = ("codex-cli",)) -> dict[str, object]:
    manifest = valid_v6_manifest()
    manifest["schema_version"] = 7
    digest = "sha256:" + "0" * 64
    manifest["hosts"] = {
        host_id: {
            "host_id": host_id,
            "home": f"C:/{host_id}",
            "hook_config_path": f"C:/{host_id}/hooks.json",
            "context_path": f"C:/{host_id}/context.md",
            "skill_destination": f"C:/{host_id}/skills/ei",
            "skill_root": f"C:/{host_id}/skills",
            "skill_mode": "copy",
            "source_skill_hash": digest,
            "installed_skill_hash": digest,
            "skill_binding_path": f"C:/{host_id}/skills/binding.json",
            "skill_binding_hash": digest,
            "hook_template_hash": digest,
            "context_hash": digest,
            "hook_config_hash": digest,
            "skill_activation_mode": "AUTO_ALLOWED",
            "capture_primary_path": "HOOK_DIRECT",
            "managed_hook_ids": [],
        }
        for host_id in host_ids
    }
    repository = dict(manifest["knowledge_repository"])  # type: ignore[arg-type]
    manifest["knowledge_stores"] = {
        "personal": {"enabled": True, **repository},
        "team": None,
    }
    manifest["reconciliation"] = {"desired_state_digest": "sha256:" + "3" * 64}
    return manifest


class InstallManifestTests(unittest.TestCase):
    def test_schema_requires_at_least_one_work_host(self) -> None:
        schema = json.loads(Path("schemas/install-manifest.schema.json").read_text(encoding="utf-8"))

        self.assertEqual(schema["properties"]["work_hosts"]["minItems"], 1)

    def test_v8_empty_work_hosts_fail_closed(self) -> None:
        manifest = normalize_install_manifest(valid_v7_manifest())
        manifest["hosts"] = {}
        manifest["work_hosts"] = []
        manifest["organizer"] = {
            "status": "SELECTION_REQUIRED",
            "provider_id": None,
            "host_id": None,
            "reason_code": "ORGANIZER_SELECTION_REQUIRED",
        }
        manifest["providers"] = []

        with self.assertRaisesRegex(ValueError, "^ACTIVE_INSTALL_MANIFEST_INVALID$"):
            validate_install_manifest(manifest, require_live_personal=False)

    def test_v8_transitional_ready_organizer_canonicalizes_legacy_providers(self) -> None:
        manifest = normalize_install_manifest(valid_v7_manifest())
        manifest["organizer"] = {
            "status": "READY",
            "provider_id": "subscription-cli",
            "host_id": "codex-cli",
            "reason_code": None,
        }
        manifest["providers"] = ["ollama", "subscription-cli"]

        normalized = normalize_install_manifest(manifest)

        self.assertEqual(normalized["providers"], ["subscription-cli"])
        validated = validate_install_manifest(normalized, require_live_personal=False)
        self.assertEqual(validated["providers"], ["subscription-cli"])

    def test_v8_transitional_normalization_does_not_hide_unknown_organizer_provider(self) -> None:
        manifest = normalize_install_manifest(valid_v7_manifest())
        manifest["organizer"] = {
            "status": "READY",
            "provider_id": "unknown-provider",
            "host_id": None,
            "reason_code": None,
        }
        manifest["providers"] = ["ollama"]

        normalized = normalize_install_manifest(manifest)

        self.assertEqual(normalized["providers"], ["ollama"])
        with self.assertRaisesRegex(ValueError, "^ACTIVE_INSTALL_MANIFEST_INVALID$"):
            validate_install_manifest(normalized, require_live_personal=False)

    def test_v7_empty_hosts_migrate_safely_without_ready_organizer(self) -> None:
        manifest = valid_v7_manifest(host_ids=())

        migrated = normalize_install_manifest(manifest)

        self.assertEqual(migrated["work_hosts"], [])
        self.assertEqual(migrated["organizer"]["status"], "SELECTION_REQUIRED")  # type: ignore[index]
        with self.assertRaisesRegex(ValueError, "^ACTIVE_INSTALL_MANIFEST_INVALID$"):
            validate_install_manifest(migrated, require_live_personal=False)

    def test_v6_normalizes_to_personal_only_v7_without_mutating_input(self) -> None:
        v6_manifest = valid_v6_manifest()
        before = json.dumps(v6_manifest, sort_keys=True)

        migrated = normalize_install_manifest(v6_manifest)

        self.assertEqual(migrated["schema_version"], 8)
        self.assertEqual(migrated["knowledge_stores"]["personal"]["root"], v6_manifest["knowledge_root"])  # type: ignore[index]
        self.assertIsNone(migrated["knowledge_stores"]["team"])  # type: ignore[index]
        expected_repository = {
            key: value
            for key, value in migrated["knowledge_stores"]["personal"].items()  # type: ignore[index]
            if key != "enabled"
        }
        self.assertEqual(migrated["knowledge_repository"], expected_repository)
        self.assertEqual(json.dumps(v6_manifest, sort_keys=True), before)

    def test_disabled_team_descriptor_is_valid_but_not_opened(self) -> None:
        v7_manifest = normalize_install_manifest(valid_v7_manifest())
        v7_manifest["knowledge_stores"]["team"] = {  # type: ignore[index]
            "enabled": False,
            "root": "Z:/offline/team",
            "store_id": "team_0123456789abcdef",
            "layout": "member-writer-events-v1",
            "team_member_id": "member-a",
            "writer_id": "writer_0123456789abcdef",
            "transport": "external-shared-folder",
            "transport_managed": False,
            "status": "DISABLED",
        }
        with patch.object(Path, "iterdir", side_effect=AssertionError("team accessed")):
            validated = validate_install_manifest(v7_manifest, require_live_personal=False)
        self.assertEqual(validated["knowledge_stores"]["team"]["status"], "DISABLED")  # type: ignore[index]

    def test_unknown_fields_fail_closed(self) -> None:
        manifest = normalize_install_manifest(valid_v7_manifest())
        manifest["unexpected"] = True
        with self.assertRaisesRegex(ValueError, "^ACTIVE_INSTALL_MANIFEST_INVALID$"):
            validate_install_manifest(manifest, require_live_personal=False)

    def test_personal_compatibility_fields_must_match(self) -> None:
        manifest = normalize_install_manifest(valid_v7_manifest())
        manifest["knowledge_root"] = "C:/other"
        with self.assertRaisesRegex(ValueError, "^ACTIVE_MANIFEST_KNOWLEDGE_STORE_MISMATCH$"):
            validate_install_manifest(manifest, require_live_personal=False)

    def test_migration_backup_is_deterministic_and_v7_is_deep_copied(self) -> None:
        v6_manifest = valid_v6_manifest()
        backup = migration_backup_bytes(v6_manifest)
        expected = (json.dumps(v6_manifest, ensure_ascii=False, sort_keys=True, indent=2) + "\n").encode("utf-8")
        self.assertEqual(backup, expected)

        v7_manifest = normalize_install_manifest(valid_v7_manifest())
        normalized = normalize_install_manifest(v7_manifest)
        normalized["hosts"]["new"] = {}  # type: ignore[index]
        self.assertNotIn("new", v7_manifest["hosts"])  # type: ignore[operator]

    def test_manifest_knowledge_stores_returns_a_deep_copy(self) -> None:
        manifest = normalize_install_manifest(valid_v7_manifest())
        stores = manifest_knowledge_stores(manifest)
        stores["personal"]["root"] = "C:/changed"
        self.assertEqual(manifest["knowledge_stores"]["personal"]["root"], "C:/private-knowledge")  # type: ignore[index]

    def test_disabled_team_requires_disabled_status(self) -> None:
        manifest = normalize_install_manifest(valid_v7_manifest())
        manifest["knowledge_stores"]["team"] = {  # type: ignore[index]
            "enabled": False,
            "root": "Z:/offline/team",
            "store_id": "team_0123456789abcdef",
            "layout": "member-writer-events-v1",
            "team_member_id": "member-a",
            "writer_id": "writer_0123456789abcdef",
            "transport": "external-shared-folder",
            "transport_managed": False,
            "status": "READY",
        }
        with self.assertRaisesRegex(ValueError, "^ACTIVE_INSTALL_MANIFEST_INVALID$"):
            validate_install_manifest(manifest, require_live_personal=False)

    def test_v7_multiple_providers_migrate_without_choosing_first(self) -> None:
        manifest = valid_v7_manifest()
        manifest["providers"] = ["ollama", "subscription-cli"]

        migrated = normalize_install_manifest(manifest)

        self.assertEqual(migrated["schema_version"], 8)
        self.assertEqual(
            migrated["organizer"],
            {
                "status": "SELECTION_REQUIRED",
                "provider_id": None,
                "host_id": None,
                "reason_code": "ORGANIZER_SELECTION_REQUIRED",
            },
        )

    def test_v7_single_subscription_and_single_host_migrate_deterministically(self) -> None:
        manifest = valid_v7_manifest(host_ids=("gemini-cli",))
        manifest["providers"] = ["subscription-cli"]

        migrated = normalize_install_manifest(manifest)

        self.assertEqual(migrated["schema_version"], 8)
        self.assertEqual(migrated["organizer"]["provider_id"], "subscription-cli")  # type: ignore[index]
        self.assertEqual(migrated["organizer"]["host_id"], "gemini-cli")  # type: ignore[index]

    def test_organizer_host_is_the_only_allowed_managed_host_difference(self) -> None:
        manifest = valid_v7_manifest(host_ids=("codex-cli", "gemini-cli"))
        manifest["providers"] = ["subscription-cli"]
        manifest = normalize_install_manifest(manifest)
        digest = "sha256:" + "0" * 64
        manifest["hosts"] = {
            host_id: {
                "host_id": host_id,
                "home": f"C:/{host_id}",
                "hook_config_path": f"C:/{host_id}/hooks.json",
                "context_path": f"C:/{host_id}/context.md",
                "skill_destination": f"C:/{host_id}/skills/ei",
                "skill_root": f"C:/{host_id}/skills",
                "skill_mode": "copy",
                "source_skill_hash": digest,
                "installed_skill_hash": digest,
                "skill_binding_path": f"C:/{host_id}/skills/binding.json",
                "skill_binding_hash": digest,
                "hook_config_hash": digest,
                "hook_template_hash": digest,
                "context_hash": digest,
                "skill_activation_mode": "AUTO_ALLOWED",
                "capture_primary_path": "HOOK_DIRECT",
                "managed_hook_ids": [],
            }
            for host_id in ("codex-cli", "gemini-cli")
        }
        manifest["work_hosts"] = ["codex-cli"]
        manifest["organizer"] = {
            "status": "READY",
            "provider_id": "subscription-cli",
            "host_id": "gemini-cli",
            "reason_code": None,
        }
        manifest["providers"] = ["subscription-cli"]

        with patch.object(Path, "is_dir", return_value=True):
            validated = validate_install_manifest(manifest, require_live_personal=False)

        self.assertEqual(validated["work_hosts"], ["codex-cli"])

    def test_custom_host_record_requires_safe_id_and_runtime_profile_descriptor(self) -> None:
        manifest = normalize_install_manifest(valid_v7_manifest(host_ids=("codex-cli",)))
        digest = "sha256:" + "0" * 64
        custom = dict(manifest["hosts"]["codex-cli"])  # type: ignore[index]
        custom["host_id"] = "test-compatible-cli"
        custom["profile_hash"] = digest
        custom["profile_path"] = "host-profiles/test-compatible-cli.json"
        manifest["hosts"] = {"test-compatible-cli": custom}
        manifest["work_hosts"] = ["test-compatible-cli"]
        manifest["organizer"] = {
            "status": "READY",
            "provider_id": "ollama",
            "host_id": None,
            "reason_code": None,
        }
        manifest["providers"] = ["ollama"]

        validated = validate_install_manifest(manifest, require_live_personal=False)

        self.assertIn("test-compatible-cli", validated["hosts"])
        serialized = json.dumps(validated["hosts"]["test-compatible-cli"])
        self.assertNotIn("display_name", serialized)
        self.assertNotIn("gemini-compatible", serialized)

    def test_custom_host_record_rejects_absolute_profile_location(self) -> None:
        manifest = normalize_install_manifest(valid_v7_manifest(host_ids=("codex-cli",)))
        custom = dict(manifest["hosts"]["codex-cli"])  # type: ignore[index]
        custom["host_id"] = "test-compatible-cli"
        custom["profile_hash"] = "sha256:" + "0" * 64
        custom["profile_path"] = "C:/private/source-profile.json"
        manifest["hosts"] = {"test-compatible-cli": custom}
        manifest["work_hosts"] = ["test-compatible-cli"]
        manifest["organizer"] = {
            "status": "READY",
            "provider_id": "ollama",
            "host_id": None,
            "reason_code": None,
        }
        manifest["providers"] = ["ollama"]

        with self.assertRaisesRegex(ValueError, "^ACTIVE_INSTALL_MANIFEST_INVALID$"):
            validate_install_manifest(manifest, require_live_personal=False)

    def test_legacy_migration_keeps_multiple_provider_selection_required(self) -> None:
        result = migrate_legacy_organizer(["ollama", "subscription-cli"], ["gemini-cli"])

        self.assertEqual(result.status, "SELECTION_REQUIRED")
        self.assertIsNone(result.provider_id)
        self.assertIsNone(result.host_id)
        self.assertEqual(result.reason_code, "ORGANIZER_SELECTION_REQUIRED")

        repeated = migrate_legacy_organizer(["ollama", "ollama"], ["gemini-cli"])
        self.assertEqual(repeated.status, "SELECTION_REQUIRED")
        self.assertEqual(repeated.reason_code, "ORGANIZER_SELECTION_REQUIRED")


if __name__ == "__main__":
    unittest.main()
