import base64
import json
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

from ei.crypto import CryptoError, decrypt_payload, encrypt_payload
from ei.key_provider import InMemoryKeyProvider, KeyProviderError
from ei.spool import SpoolError, delete_spool, read_spool, spool_health, write_spool
from ei.config import RuntimePaths, Settings
from ei.runtime_catalog import lookup as runtime_lookup, inventory_paths as runtime_inventory


NOW = datetime(2026, 8, 26, 12, 0, tzinfo=timezone.utc)

def make_isolated_hook_settings(root: Path) -> Settings:
    root = Path(root).resolve()
    repo = root / "repo"
    runtime = root / "machine-runtime"
    codex_home = root / "codex-home"
    paths = RuntimePaths(
        repo_root=repo,
        codex_home=codex_home,
        runtime_dir=runtime,
        event_dir=repo / "events",
        knowledge_dir=repo / "knowledge",
        local_state_dir=runtime / "state",
        metrics_dir=runtime / "metrics",
        cache_dir=runtime / "cache",
        locks_dir=runtime / "locks",
        config_path=codex_home / "config.toml",
        hooks_path=codex_home / "hooks.json",
        agents_path=codex_home / "AGENTS.md",
    )
    return Settings(paths=paths, retrieval_max_chars=5000, retrieval_max_results=5)



class NoKeyProvider:
    def current(self):
        raise KeyProviderError("KEY_UNAVAILABLE")

    def get(self, key_id):
        raise KeyProviderError("KEY_UNAVAILABLE")
class WrongKeyProvider(InMemoryKeyProvider):
    def __init__(self):
        super().__init__("wrong-key-v1", b"w" * 32)


class CryptoSpoolTests(unittest.TestCase):
    def test_pending_aad_authenticates_purpose_capture_and_version(self):
        key = InMemoryKeyProvider()
        envelope = encrypt_payload(b"candidate", "pending-test", "private-reusable", NOW + timedelta(days=1), key,
            created_at=NOW, aad_version=2, purpose="pending", capture_id="sha256:" + "a" * 64)
        self.assertEqual(decrypt_payload(envelope, key, now=NOW), b"candidate")
        for changes in ({"purpose": "legacy"}, {"purpose": "validated-result"}, {"aad_version": 1},
                        {"aad_version": 3}, {"capture_id": "sha256:" + "b" * 64}):
            with self.subTest(changes=changes), self.assertRaises(CryptoError):
                decrypt_payload(dict(envelope, **changes), key, now=NOW)
        downgraded = {k: v for k, v in envelope.items() if k not in {"aad_version", "purpose", "capture_id"}}
        with self.assertRaises(CryptoError):
            decrypt_payload(downgraded, key, now=NOW)

    def test_unknown_null_version_and_non_string_purpose_are_rejected(self):
        key = InMemoryKeyProvider()
        legacy = encrypt_payload(b"legacy", "old", "public", NOW + timedelta(days=1), key, created_at=NOW)
        for changes in ({"aad_version": None}, {"purpose": []}):
            with self.subTest(changes=changes), self.assertRaises(CryptoError):
                decrypt_payload(dict(legacy, **changes), key, now=NOW)

    def test_sensitive_payload_is_encrypted_and_plaintext_absent(self):
        with tempfile.TemporaryDirectory() as tmp:
            settings = make_isolated_hook_settings(Path(tmp))
            key = InMemoryKeyProvider()
            ref = write_spool("candidate claim is durable only in encrypted local spool", "private-reusable", settings, key_provider=key, now=NOW, spool_id="spool-sensitive")
            path = runtime_lookup(settings.paths.spool_dir, "spool-sensitive")
            serialized = path.read_text(encoding="utf-8")
            self.assertNotIn("candidate claim", serialized)
            self.assertEqual(read_spool(ref, settings, key_provider=key, now=NOW + timedelta(seconds=1)), b"candidate claim is durable only in encrypted local spool")
            self.assertTrue(ref.encrypted)

    def test_sensitive_payload_without_key_is_quarantined_not_plaintext(self):
        with tempfile.TemporaryDirectory() as tmp:
            settings = make_isolated_hook_settings(Path(tmp))
            with self.assertRaisesRegex(SpoolError, "SPOOL_KEY_UNAVAILABLE"):
                write_spool("payload that must never be written in plaintext", "private-reusable", settings, key_provider=NoKeyProvider(), now=NOW, spool_id="spool-no-key")
            self.assertFalse((runtime_lookup(settings.paths.spool_dir, "spool-no-key")).exists())
            quarantine = settings.paths.spool_dir / "quarantine" / "spool-no-key.json"
            self.assertTrue(quarantine.exists())
            self.assertNotIn("payload that must never", quarantine.read_text(encoding="utf-8"))

    def test_spool_survives_process_restart_until_expiry(self):
        with tempfile.TemporaryDirectory() as tmp:
            settings = make_isolated_hook_settings(Path(tmp))
            key_bytes = b"k" * 32
            first_key = InMemoryKeyProvider("restart-key", key_bytes)
            ref = write_spool("restart-safe payload", "private-reusable", settings, key_provider=first_key, now=NOW)
            second_key = InMemoryKeyProvider("restart-key", key_bytes)
            self.assertEqual(read_spool(ref, settings, key_provider=second_key, now=NOW + timedelta(seconds=2)), b"restart-safe payload")

    def test_wrong_key_id_fails_without_returning_payload(self):
        with tempfile.TemporaryDirectory() as tmp:
            settings = make_isolated_hook_settings(Path(tmp))
            ref = write_spool("wrong key must not disclose this", "private-reusable", settings, key_provider=InMemoryKeyProvider("right", b"r" * 32), now=NOW, spool_id="spool-wrong-key")
            path = runtime_lookup(settings.paths.spool_dir, "spool-wrong-key")
            original = path.read_bytes()
            with self.assertRaisesRegex(SpoolError, "SPOOL_DECRYPT_FAILED"):
                read_spool(ref, settings, key_provider=WrongKeyProvider(), now=NOW + timedelta(seconds=1))
            self.assertEqual(path.read_bytes(), original)
            self.assertFalse((settings.paths.spool_dir / "quarantine" / "spool-wrong-key.json").exists())
            from ei.runtime_catalog import RuntimeCatalog
            catalog = RuntimeCatalog(settings.paths.spool_dir)
            self.assertEqual(catalog.reservation(ref.spool_id)["size"], len(original))
            self.assertEqual(catalog.capacity("legacy"), (1, len(original)))
            restored_key = InMemoryKeyProvider("right", b"r" * 32)
            self.assertEqual(read_spool(ref, settings, key_provider=restored_key, now=NOW + timedelta(seconds=2)), b"wrong key must not disclose this")
            self.assertEqual(path.read_bytes(), original)
            write_spool("another candidate", "public", settings, key_provider=restored_key, now=NOW + timedelta(seconds=2))

    def test_content_hash_mismatch_quarantines_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            settings = make_isolated_hook_settings(Path(tmp))
            key = InMemoryKeyProvider()
            ref = write_spool("content hash guarded", "private-reusable", settings, key_provider=key, now=NOW, spool_id="spool-hash")
            path = runtime_lookup(settings.paths.spool_dir, "spool-hash")
            original_size = path.stat().st_size
            envelope = json.loads(path.read_text(encoding="utf-8"))
            envelope["content_sha256"] = "sha256:" + "0" * 64
            path.write_text(json.dumps(envelope), encoding="utf-8")
            tampered = path.read_bytes()
            with self.assertRaisesRegex(SpoolError, "SPOOL_REF_MISMATCH|SPOOL_DECRYPT_FAILED|SPOOL_AAD"):
                read_spool(ref, settings, key_provider=key, now=NOW + timedelta(seconds=1))
            self.assertEqual(path.read_bytes(), tampered)
            self.assertTrue((settings.paths.spool_dir / "quarantine" / "spool-hash.json").exists())
            from ei.runtime_catalog import RuntimeCatalog, CatalogUnknown
            catalog = RuntimeCatalog(settings.paths.spool_dir)
            self.assertEqual(catalog.reservation(ref.spool_id)["size"], original_size)
            with self.assertRaises(CatalogUnknown):
                catalog.capacity("legacy")

    def test_expired_spool_is_deleted_and_unreadable(self):
        with tempfile.TemporaryDirectory() as tmp:
            settings = make_isolated_hook_settings(Path(tmp))
            key = InMemoryKeyProvider()
            ref = write_spool("expires", "private-reusable", settings, key_provider=key, now=NOW, ttl_seconds=1, spool_id="spool-expired")
            with self.assertRaisesRegex(SpoolError, "SPOOL_EXPIRED"):
                read_spool(ref, settings, key_provider=key, now=NOW + timedelta(seconds=2))
            self.assertFalse((runtime_lookup(settings.paths.spool_dir, "spool-expired")).exists())
            self.assertFalse(delete_spool("spool-expired", settings))

    def test_spool_paths_are_outside_repository_allowlist(self):
        with tempfile.TemporaryDirectory() as tmp:
            settings = make_isolated_hook_settings(Path(tmp))
            ref = write_spool("outside repo", "public", settings, key_provider=InMemoryKeyProvider(), now=NOW)
            self.assertFalse(ref.spool_id in {path.name for path in settings.paths.repo_root.rglob("*.json")})
            health = spool_health(settings)
            self.assertEqual(health.items, 1)

    def test_private_plaintext_requires_encryption(self):
        with tempfile.TemporaryDirectory() as tmp:
            settings = make_isolated_hook_settings(Path(tmp))
            ref = write_spool("private encrypted only", "client-confidential", settings, key_provider=InMemoryKeyProvider(), now=NOW)
            self.assertTrue(ref.encrypted)
            envelope = json.loads((runtime_lookup(settings.paths.spool_dir, ref.spool_id)).read_text(encoding="utf-8"))
            self.assertEqual(envelope["algorithm"], "AES-256-GCM")
            self.assertNotIn("private encrypted only", json.dumps(envelope))


if __name__ == "__main__":
    unittest.main()
