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
    def test_sensitive_payload_is_encrypted_and_plaintext_absent(self):
        with tempfile.TemporaryDirectory() as tmp:
            settings = make_isolated_hook_settings(Path(tmp))
            key = InMemoryKeyProvider()
            ref = write_spool("candidate claim is durable only in encrypted local spool", "private-reusable", settings, key_provider=key, now=NOW, spool_id="spool-sensitive")
            path = settings.paths.spool_dir / "spool-sensitive.json"
            serialized = path.read_text(encoding="utf-8")
            self.assertNotIn("candidate claim", serialized)
            self.assertEqual(read_spool(ref, settings, key_provider=key, now=NOW + timedelta(seconds=1)), b"candidate claim is durable only in encrypted local spool")
            self.assertTrue(ref.encrypted)

    def test_sensitive_payload_without_key_is_quarantined_not_plaintext(self):
        with tempfile.TemporaryDirectory() as tmp:
            settings = make_isolated_hook_settings(Path(tmp))
            with self.assertRaisesRegex(SpoolError, "SPOOL_KEY_UNAVAILABLE"):
                write_spool("payload that must never be written in plaintext", "private-reusable", settings, key_provider=NoKeyProvider(), now=NOW, spool_id="spool-no-key")
            self.assertFalse((settings.paths.spool_dir / "spool-no-key.json").exists())
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
            with self.assertRaisesRegex(SpoolError, "SPOOL_DECRYPT_FAILED"):
                read_spool(ref, settings, key_provider=WrongKeyProvider(), now=NOW + timedelta(seconds=1))
            self.assertFalse((settings.paths.spool_dir / "spool-wrong-key.json").exists())

    def test_content_hash_mismatch_quarantines_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            settings = make_isolated_hook_settings(Path(tmp))
            key = InMemoryKeyProvider()
            ref = write_spool("content hash guarded", "private-reusable", settings, key_provider=key, now=NOW, spool_id="spool-hash")
            path = settings.paths.spool_dir / "spool-hash.json"
            envelope = json.loads(path.read_text(encoding="utf-8"))
            envelope["content_sha256"] = "sha256:" + "0" * 64
            path.write_text(json.dumps(envelope), encoding="utf-8")
            with self.assertRaisesRegex(SpoolError, "SPOOL_REF_MISMATCH|SPOOL_DECRYPT_FAILED|SPOOL_AAD"):
                read_spool(ref, settings, key_provider=key, now=NOW + timedelta(seconds=1))
            self.assertFalse(path.exists())

    def test_expired_spool_is_deleted_and_unreadable(self):
        with tempfile.TemporaryDirectory() as tmp:
            settings = make_isolated_hook_settings(Path(tmp))
            key = InMemoryKeyProvider()
            ref = write_spool("expires", "private-reusable", settings, key_provider=key, now=NOW, ttl_seconds=1, spool_id="spool-expired")
            with self.assertRaisesRegex(SpoolError, "SPOOL_EXPIRED"):
                read_spool(ref, settings, key_provider=key, now=NOW + timedelta(seconds=2))
            self.assertFalse((settings.paths.spool_dir / "spool-expired.json").exists())
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
            envelope = json.loads((settings.paths.spool_dir / f"{ref.spool_id}.json").read_text(encoding="utf-8"))
            self.assertEqual(envelope["algorithm"], "AES-256-GCM")
            self.assertNotIn("private encrypted only", json.dumps(envelope))


if __name__ == "__main__":
    unittest.main()