import json
import os
import subprocess
import sys
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import patch

from ei.capture_contract import PendingPolicy
from ei import spool

from ei.key_provider import InMemoryKeyProvider
from ei.spool import SpoolError, delete_spool, gc_expired_spool, read_spool, spool_health, write_spool
from ei.config import RuntimePaths, Settings
from ei.runtime_catalog import lookup as runtime_lookup, inventory_paths as runtime_inventory, RuntimeCatalog
from ei.operation_runtime import OperationBudget


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


class SpoolTests(unittest.TestCase):
    def test_detected_pending_corruption_blocks_admission_after_validation_cursor_moves(self):
        import sqlite3
        from contextlib import closing
        with tempfile.TemporaryDirectory() as tmp:
            settings = make_isolated_hook_settings(Path(tmp))
            key = InMemoryKeyProvider()
            capture = "sha256:" + "a" * 64
            refs = [write_spool("candidate", "public", settings, spool_id=f"pending_probe_{i:02}", purpose="pending", capture_id=capture, now=NOW, key_provider=key) for i in range(17)]
            root = settings.paths.spool_dir
            before = RuntimeCatalog(root).reservation(refs[0].spool_id)
            path = runtime_lookup(root, refs[0].spool_id)
            value = json.loads(path.read_bytes())
            value["ciphertext"] = ("A" if value["ciphertext"][0] != "A" else "B") + value["ciphertext"][1:]
            path.write_text(json.dumps(value), encoding="utf-8")
            damaged = path.read_bytes()
            with closing(sqlite3.connect(root / ".runtime-catalog.sqlite")) as connection:
                connection.execute("INSERT OR REPLACE INTO state VALUES ('cursor:validate','pending_probe_15')")
                connection.commit()
            with self.assertRaises(SpoolError):
                read_spool(refs[0], settings, now=NOW, key_provider=key, expected_capture_id=capture)
            with self.assertRaises(SpoolError):
                write_spool("next", "public", settings, purpose="pending", capture_id=capture, now=NOW, key_provider=key)
            self.assertEqual(path.read_bytes(), damaged)
            self.assertEqual(RuntimeCatalog(root).reservation(refs[0].spool_id), before)

    def test_non_corruption_read_failures_do_not_persist_unknown(self):
        from dataclasses import replace
        from ei.key_provider import KeyProviderError
        for fault in ("key", "capture", "reference", "expired", "io"):
            with self.subTest(fault=fault), tempfile.TemporaryDirectory() as tmp:
                settings = make_isolated_hook_settings(Path(tmp))
                key = InMemoryKeyProvider()
                capture = "sha256:" + "a" * 64
                ref = write_spool("candidate", "public", settings, now=NOW, key_provider=key, purpose="pending", capture_id=capture, ttl_seconds=60)
                root = settings.paths.spool_dir
                path = runtime_lookup(root, ref.spool_id)
                before = path.read_bytes()
                budget = OperationBudget(5000)
                options = dict(now=NOW + timedelta(seconds=61) if fault == "expired" else NOW, key_provider=key, budget=budget,
                               expected_capture_id="sha256:" + "b" * 64 if fault == "capture" else capture)
                supplied = replace(ref, content_hash="sha256:" + "0" * 64) if fault == "reference" else ref
                if fault == "io":
                    context = patch("ei.runtime_catalog.os.open", side_effect=PermissionError("transient read denial"))
                elif fault == "key":
                    context = patch.object(key, "get", side_effect=KeyProviderError("KEY_UNAVAILABLE"))
                else:
                    from contextlib import nullcontext
                    context = nullcontext()
                with context, self.assertRaises(SpoolError):
                    read_spool(supplied, settings, **options)
                self.assertEqual(path.read_bytes(), before)
                self.assertEqual(RuntimeCatalog(root).capacity("pending"), (1, len(before)))
                write_spool("next", "public", settings, now=NOW, key_provider=key, purpose="pending", capture_id=capture)

    def test_malformed_nonlegacy_reads_persist_unknown_under_same_root_lock_and_budget(self):
        from ei.runtime_catalog import CatalogUnknown
        for purpose, damage in (("pending", b"invalid json"), ("validated-result", b"{}")):
            with self.subTest(purpose=purpose), tempfile.TemporaryDirectory() as tmp:
                settings = make_isolated_hook_settings(Path(tmp))
                key = InMemoryKeyProvider()
                ref = write_spool("candidate", "public", settings, now=NOW, key_provider=key, purpose=purpose, capture_id="sha256:" + "a" * 64)
                root = settings.paths.spool_dir
                path = runtime_lookup(root, ref.spool_id)
                reserved = RuntimeCatalog(root).reservation(ref.spool_id)
                path.write_bytes(damage)
                budget = OperationBudget(5000)
                original = RuntimeCatalog.mark_unknown
                def checked(catalog, *args, **kwargs):
                    self.assertIs(kwargs["budget"], budget)
                    self.assertTrue((root / ".spool.lock").exists())
                    return original(catalog, *args, **kwargs)
                with patch.object(RuntimeCatalog, "mark_unknown", checked), self.assertRaises(SpoolError):
                    read_spool(ref, settings, now=NOW, key_provider=key, budget=budget)
                self.assertEqual(path.read_bytes(), damage)
                self.assertEqual(RuntimeCatalog(root).reservation(ref.spool_id), reserved)
                with self.assertRaisesRegex(CatalogUnknown, "RUNTIME_ENTRY_UNVERIFIED"):
                    RuntimeCatalog(root).capacity(purpose)


    def test_randomized_retry_preserves_original_expiry_and_one_reservation(self):
        with tempfile.TemporaryDirectory() as tmp:
            settings = make_isolated_hook_settings(Path(tmp))
            key = InMemoryKeyProvider()
            options = dict(settings=settings, key_provider=key, spool_id="pending-retry", purpose="pending", capture_id="sha256:" + "a" * 64, ttl_seconds=60)
            attempted = []
            real_encrypt = spool.encrypt_payload
            def encrypt(*args, **kwargs):
                value = real_encrypt(*args, **kwargs)
                attempted.append(value)
                return value
            real_write = spool._atomic_json
            def fail_payload(path, value, **kwargs):
                if path.name.startswith("."):
                    return real_write(path, value, **kwargs)
                raise OSError("full")
            with patch.object(spool, "encrypt_payload", encrypt):
                with patch.object(spool, "_atomic_json", fail_payload), self.assertRaises(OSError):
                    write_spool("candidate", "public", now=NOW, **options)
                ref = write_spool("candidate", "public", now=NOW + timedelta(seconds=10), **options)
            self.assertEqual(ref.created_at, "2026-08-26T12:00:00Z")
            self.assertEqual(ref.expires_at, "2026-08-26T12:01:00Z")
            self.assertEqual(len(attempted), 2)
            self.assertNotEqual(attempted[0]["nonce"], attempted[1]["nonce"])
            self.assertNotEqual(attempted[0]["ciphertext"], attempted[1]["ciphertext"])
            self.assertEqual(read_spool(ref, settings, now=NOW + timedelta(seconds=10), key_provider=key), b"candidate")
            self.assertEqual(RuntimeCatalog(settings.paths.spool_dir).capacity("pending")[0], 1)

    def test_absent_retry_rejects_changed_semantics_without_new_charge(self):
        for change in ({"payload": "different"}, {"classification": "private-reusable"}, {"purpose": "validated-result"},
                       {"capture_id": "sha256:" + "b" * 64}, {"ttl_seconds": 61}):
            with self.subTest(change=change), tempfile.TemporaryDirectory() as tmp:
                settings = make_isolated_hook_settings(Path(tmp))
                options = dict(payload="candidate", classification="public", settings=settings, key_provider=InMemoryKeyProvider(),
                    spool_id="pending-retry", purpose="pending", capture_id="sha256:" + "a" * 64, ttl_seconds=60, now=NOW)
                real_write = spool._atomic_json
                def fail_payload(path, value, **kwargs):
                    if path.name.startswith("."):
                        return real_write(path, value, **kwargs)
                    raise OSError("full")
                with patch.object(spool, "_atomic_json", fail_payload), self.assertRaises(OSError):
                    write_spool(**options)
                catalog = RuntimeCatalog(settings.paths.spool_dir)
                before = catalog.reservation("pending-retry")
                with self.assertRaises(SpoolError):
                    write_spool(**(options | change))
                self.assertEqual(catalog.reservation("pending-retry"), before)
                self.assertFalse(runtime_lookup(settings.paths.spool_dir, "pending-retry").exists())

    def test_existing_ciphertext_retry_reconciles_without_reencrypting(self):
        with tempfile.TemporaryDirectory() as tmp:
            settings = make_isolated_hook_settings(Path(tmp))
            options = dict(settings=settings, key_provider=InMemoryKeyProvider(), spool_id="pending-retry", purpose="pending", capture_id="sha256:" + "a" * 64)
            real_write = spool._atomic_json
            def crash(*args, **kwargs):
                real_write(*args, **kwargs)
                if not args[0].name.startswith("."):
                    raise KeyboardInterrupt()
            with patch.object(spool, "_atomic_json", crash), self.assertRaises(KeyboardInterrupt):
                write_spool("candidate", "public", now=NOW, **options)
            path = runtime_lookup(settings.paths.spool_dir, "pending-retry")
            before = path.read_bytes()
            with patch.object(spool, "encrypt_payload", side_effect=AssertionError("committed ciphertext must be reused")):
                write_spool("candidate", "public", now=NOW + timedelta(seconds=10), **options)
            self.assertEqual(path.read_bytes(), before)
            self.assertEqual(RuntimeCatalog(settings.paths.spool_dir).capacity("pending")[0], 1)

    def test_delete_crash_after_unlink_never_returns_already_deleted(self):
        import ei.runtime_catalog as catalog
        with tempfile.TemporaryDirectory() as tmp:
            settings = make_isolated_hook_settings(Path(tmp))
            ref = write_spool("candidate", "public", settings, now=NOW, key_provider=InMemoryKeyProvider())
            real_unlink = catalog.safe_unlink
            def crash(*args, **kwargs):
                real_unlink(*args, **kwargs)
                raise KeyboardInterrupt()
            with patch.object(catalog, "safe_unlink", crash), self.assertRaises(KeyboardInterrupt):
                delete_spool(ref, settings)
            with self.assertRaisesRegex(SpoolError, "RUNTIME_DELETE_UNCONFIRMED"):
                delete_spool(ref, settings)
            self.assertGreater(RuntimeCatalog(settings.paths.spool_dir).reservation(ref.spool_id)["size"], 0)

    def test_intake_and_delete_do_not_enumerate_full_spool_history(self):
        with tempfile.TemporaryDirectory() as tmp:
            settings = make_isolated_hook_settings(Path(tmp))
            key = InMemoryKeyProvider()
            with patch.object(spool, "_spool_files", side_effect=AssertionError("unbounded inventory in admission")):
                ref = write_spool("candidate", "public", settings, now=NOW, key_provider=key)
                self.assertTrue(delete_spool(ref, settings))

    def test_gc_settles_catalog_charge_and_next_admission_succeeds(self):
        with tempfile.TemporaryDirectory() as tmp:
            settings = make_isolated_hook_settings(Path(tmp))
            key = InMemoryKeyProvider()
            write_spool("expired", "public", settings, now=NOW, ttl_seconds=1, key_provider=key)
            self.assertEqual(gc_expired_spool(settings, now=NOW + timedelta(seconds=2)), 1)
            self.assertEqual(RuntimeCatalog(settings.paths.spool_dir).capacity("legacy"), (0, 0))
            write_spool("next", "public", settings, now=NOW + timedelta(seconds=2), key_provider=key)

    def test_managed_dead_temporary_is_cleaned_when_its_reservation_retries(self):
        from ei.runtime_catalog import managed_path
        with tempfile.TemporaryDirectory() as tmp:
            settings = make_isolated_hook_settings(Path(tmp))
            options = dict(settings=settings, now=NOW, key_provider=InMemoryKeyProvider(), spool_id="pending-retry", purpose="pending", capture_id="sha256:" + "a" * 64)
            real_write = spool._atomic_json
            def fail_payload(path, value, **kwargs):
                if path.name.startswith("."):
                    return real_write(path, value, **kwargs)
                raise OSError("full")
            with patch.object(spool, "_atomic_json", fail_payload), self.assertRaises(OSError):
                write_spool("candidate", "public", **options)
            target = managed_path(settings.paths.spool_dir, "pending-retry")
            orphan = target.with_name(target.name + ".12345678.1234abcd.tmp")
            orphan.write_bytes(b"encrypted fragment")
            with patch.object(spool, "_pid_state", return_value=False):
                ref = write_spool("candidate", "public", **options)
            self.assertFalse(orphan.exists())
            self.assertEqual(read_spool(ref, settings, now=NOW, key_provider=options["key_provider"]), b"candidate")

    def test_invalid_legacy_ciphertext_is_retained_and_charge_is_not_released(self):
        with tempfile.TemporaryDirectory() as tmp:
            settings = make_isolated_hook_settings(Path(tmp))
            key = InMemoryKeyProvider()
            ref = write_spool("candidate", "public", settings, now=NOW, key_provider=key)
            path = runtime_lookup(settings.paths.spool_dir, ref.spool_id)
            value = json.loads(path.read_bytes())
            value["ciphertext"] = "invalid"
            path.write_text(json.dumps(value), encoding="utf-8")
            before = path.read_bytes()
            with self.assertRaises(SpoolError):
                read_spool(ref, settings, now=NOW, key_provider=key)
            self.assertTrue(path.exists())
            self.assertEqual(path.read_bytes(), before)
            self.assertGreater(RuntimeCatalog(settings.paths.spool_dir).reservation(ref.spool_id)["size"], 0)
            with self.assertRaises(SpoolError):
                write_spool("next", "public", settings, now=NOW, key_provider=key)

    def test_registered_retry_rejects_changed_original_creation_metadata(self):
        with tempfile.TemporaryDirectory() as tmp:
            settings = make_isolated_hook_settings(Path(tmp))
            options = dict(settings=settings, now=NOW, key_provider=InMemoryKeyProvider(), spool_id="pending-retry", purpose="pending", capture_id="sha256:" + "a" * 64)
            ref = write_spool("candidate", "public", **options)
            path = runtime_lookup(settings.paths.spool_dir, ref.spool_id)
            value = json.loads(path.read_bytes())
            value["created_at"] = "2026-08-25T12:00:00Z"
            path.write_text(json.dumps(value), encoding="utf-8")
            with self.assertRaises(SpoolError):
                write_spool("candidate", "public", ttl_seconds=31 * 24 * 60 * 60, **options)
            self.assertTrue(path.exists())

    def test_managed_temporary_owner_exit_is_relevant_recovery_state(self):
        from ei.runtime_catalog import managed_path
        with tempfile.TemporaryDirectory() as tmp:
            settings = make_isolated_hook_settings(Path(tmp))
            options = dict(settings=settings, now=NOW, key_provider=InMemoryKeyProvider(), spool_id="pending-retry", purpose="pending", capture_id="sha256:" + "a" * 64)
            with patch.object(spool, "_atomic_json", side_effect=OSError("full")), self.assertRaises(OSError):
                write_spool("candidate", "public", **options)
            target = managed_path(settings.paths.spool_dir, "pending-retry")
            orphan = target.with_name(target.name + ".12345678.1234abcd.tmp")
            orphan.write_bytes(b"encrypted fragment")
            with patch.object(spool, "_pid_state", return_value=True), self.assertRaisesRegex(SpoolError, "SPOOL_TEMP_CLEANUP_UNCONFIRMED"):
                write_spool("candidate", "public", **options)
            self.assertTrue(orphan.exists())
            with patch.object(spool, "_pid_state", return_value=False):
                ref = write_spool("candidate", "public", **options)
            self.assertFalse(orphan.exists())
            self.assertEqual(read_spool(ref, settings, now=NOW, key_provider=options["key_provider"]), b"candidate")

    def test_small_shared_deadlines_resume_a_normal_candidate(self):
        with tempfile.TemporaryDirectory() as tmp:
            settings = make_isolated_hook_settings(Path(tmp))
            key = InMemoryKeyProvider()
            ref = None
            for _ in range(8):
                budget = OperationBudget(500)
                deadline = budget.deadline
                try:
                    ref = write_spool("candidate", "public", settings, now=NOW, key_provider=key, spool_id="pending-small", purpose="pending", capture_id="sha256:" + "a" * 64, budget=budget)
                except (TimeoutError, SpoolError):
                    continue
                finally:
                    self.assertEqual(budget.deadline, deadline)
                break
            self.assertIsNotNone(ref, "repeated caller-sized deadlines made no ordinary-candidate progress")
            self.assertEqual(read_spool(ref, settings, now=NOW, key_provider=key), b"candidate")

    def test_known_invalid_ciphertext_blocks_admission_beyond_validation_page(self):
        with tempfile.TemporaryDirectory() as tmp:
            settings = make_isolated_hook_settings(Path(tmp))
            key = InMemoryKeyProvider()
            ref = write_spool("candidate", "public", settings, now=NOW, key_provider=key)
            path = runtime_lookup(settings.paths.spool_dir, ref.spool_id)
            path.write_bytes(b"invalid")
            with self.assertRaises(SpoolError):
                read_spool(ref, settings, now=NOW, key_provider=key)
            # The caller already knows this entry is unsafe; skipping the next
            # bounded validation sample must not erase that durable fact.
            with patch.object(RuntimeCatalog, "validate_page", return_value=None):
                with self.assertRaises(SpoolError):
                    write_spool("next", "public", settings, now=NOW, key_provider=key)

    def test_actual_legacy_flat_delete_authenticates_then_settles_charge(self):
        from ei.crypto import encrypt_payload
        with tempfile.TemporaryDirectory() as tmp:
            settings = make_isolated_hook_settings(Path(tmp))
            key = InMemoryKeyProvider()
            root = settings.paths.spool_dir
            root.mkdir(parents=True)
            path = root / "spool-legacy.json"
            value = encrypt_payload(b"legacy", path.stem, "public", NOW + timedelta(days=1), key, created_at=NOW)
            path.write_text(json.dumps(value), encoding="utf-8")
            self.assertTrue(delete_spool(path.stem, settings, key_provider=key))
            self.assertFalse(runtime_lookup(root, path.stem).exists())
            self.assertEqual(RuntimeCatalog(root).capacity("legacy"), (0, 0))

    def test_matching_flat_duplicate_is_reconciled_before_delete(self):
        with tempfile.TemporaryDirectory() as tmp:
            settings = make_isolated_hook_settings(Path(tmp))
            key = InMemoryKeyProvider()
            ref = write_spool("candidate", "public", settings, now=NOW, key_provider=key)
            root = settings.paths.spool_dir
            flat = root / (ref.spool_id + ".json")
            flat.write_bytes(runtime_lookup(root, ref.spool_id).read_bytes())
            self.assertTrue(delete_spool(ref, settings, key_provider=key))
            self.assertFalse(runtime_lookup(root, ref.spool_id).exists())
            self.assertEqual(RuntimeCatalog(root).capacity("legacy"), (0, 0))

    def test_new_write_uses_managed_layout_and_legacy_read_delete_can_find_it(self):
        from ei.runtime_catalog import lookup
        with tempfile.TemporaryDirectory() as tmp:
            settings = make_isolated_hook_settings(Path(tmp))
            key = InMemoryKeyProvider()
            ref = write_spool("managed", "public", settings, now=NOW, key_provider=key)
            self.assertIn("managed", lookup(settings.paths.spool_dir, ref.spool_id).parts)
            self.assertFalse((settings.paths.spool_dir / (ref.spool_id + ".json")).exists())
            self.assertEqual(read_spool(ref, settings, now=NOW, key_provider=key), b"managed")
            self.assertTrue(delete_spool(ref, settings))
            self.assertFalse(lookup(settings.paths.spool_dir, ref.spool_id).exists())

    def test_read_budget_exhaustion_never_quarantines_valid_ciphertext(self):
        with tempfile.TemporaryDirectory() as tmp:
            settings = make_isolated_hook_settings(Path(tmp))
            key = InMemoryKeyProvider()
            ref = write_spool("keep", "public", settings, now=NOW, key_provider=key)
            with patch("ei.spool._read_envelope", side_effect=TimeoutError("deadline")):
                with self.assertRaises(TimeoutError):
                    read_spool(ref, settings, now=NOW, key_provider=key)
            self.assertEqual(read_spool(ref, settings, now=NOW, key_provider=key), b"keep")

    def test_expected_capture_binding_authenticates_without_deleting_other_candidate(self):
        with tempfile.TemporaryDirectory() as tmp:
            settings = make_isolated_hook_settings(Path(tmp))
            key = InMemoryKeyProvider()
            capture = "sha256:" + "a" * 64
            ref = write_spool("validated", "public", settings, now=NOW, key_provider=key, purpose="validated-result", capture_id=capture)
            options = dict(now=NOW, key_provider=key)
            self.assertEqual(read_spool(ref, settings, expected_capture_id=capture, **options), b"validated")
            path = runtime_lookup(settings.paths.spool_dir, ref.spool_id)
            before = path.read_bytes()
            for wrong in ("sha256:" + "b" * 64, "invalid"):
                with self.assertRaises(SpoolError):
                    read_spool(ref, settings, expected_capture_id=wrong, **options)
                self.assertEqual(path.read_bytes(), before)
            legacy = write_spool("legacy", "public", settings, **options)
            with self.assertRaises(SpoolError):
                read_spool(legacy, settings, expected_capture_id=capture, **options)
            self.assertEqual(read_spool(legacy, settings, **options), b"legacy")
            envelope = json.loads(before)
            envelope["capture_id"] = "sha256:" + "b" * 64
            path.write_text(json.dumps(envelope), encoding="utf-8")
            with self.assertRaises(SpoolError):
                read_spool(ref, settings, expected_capture_id=envelope["capture_id"], **options)
            self.assertTrue(path.exists())

    def test_atomic_write_and_fsync_errors_remove_their_own_temporary(self):
        for boundary in ("write", "fsync"):
            with self.subTest(boundary=boundary), tempfile.TemporaryDirectory() as tmp:
                path = Path(tmp) / "spool_failure.json"
                with patch("ei.spool.os." + boundary, side_effect=OSError("disk full")), self.assertRaises(OSError):
                    spool._atomic_json(path, {"ciphertext": "synthetic"})
                self.assertEqual(list(Path(tmp).glob("*.tmp")), [])
                self.assertFalse(path.exists())

    def test_real_exit_before_replace_is_cleaned_before_new_spool_intake(self):
        with tempfile.TemporaryDirectory() as tmp:
            settings = make_isolated_hook_settings(Path(tmp))
            settings.paths.spool_dir.mkdir(parents=True)
            target = settings.paths.spool_dir / ("pending_" + "a" * 64 + ".json")
            code = "import os,sys; from pathlib import Path; from unittest.mock import patch; from ei.spool import _atomic_json; from ei.crypto import encrypt_payload; from ei.key_provider import InMemoryKeyProvider; from datetime import datetime,timedelta,timezone; n=datetime.now(timezone.utc); p=Path(sys.argv[1]); e=encrypt_payload(b'child candidate',p.stem,'public',n+timedelta(days=30),InMemoryKeyProvider(),created_at=n,aad_version=2,purpose='pending',capture_id='sha256:'+'a'*64); patch('ei.spool.os.replace',side_effect=lambda *a:os._exit(73)).start(); _atomic_json(p,e)"
            result = subprocess.run([sys.executable, "-B", "-X", "utf8", "-c", code, str(target)], capture_output=True, timeout=15)
            self.assertEqual(result.returncode, 73)
            self.assertEqual(len(list(settings.paths.spool_dir.glob("*.tmp"))), 1)
            self.assertFalse(target.exists())
            write_spool("next candidate", "public", settings, now=NOW, key_provider=InMemoryKeyProvider())
            self.assertEqual(list(settings.paths.spool_dir.glob("*.tmp")), [])
            self.assertFalse(target.exists())

    def test_live_current_pid_and_unverifiable_temporary_are_retained_without_acceptance(self):
        for state in ("live", "unknown"):
            with self.subTest(state=state), tempfile.TemporaryDirectory() as tmp:
                settings = make_isolated_hook_settings(Path(tmp))
                settings.paths.spool_dir.mkdir(parents=True)
                path = settings.paths.spool_dir / ("pending_" + "b" * 64 + f".json.{os.getpid()}.1234abcd.tmp")
                path.write_bytes(b"synthetic encrypted fragment")
                if state == "unknown":
                    guard = patch("ei.spool._pid_state", return_value=None, create=True)
                else:
                    from contextlib import nullcontext
                    guard = nullcontext()
                with guard, self.assertRaisesRegex(SpoolError, "SPOOL_TEMP_CLEANUP_UNCONFIRMED"):
                    write_spool("new candidate", "public", settings, now=NOW, key_provider=InMemoryKeyProvider())
                self.assertEqual(path.read_bytes(), b"synthetic encrypted fragment")
                self.assertEqual(list(settings.paths.spool_dir.glob("*.json")), [])

    def test_pid_probe_never_uses_kill_outside_posix(self):
        with patch("ei.spool.os.name", "unknown"), patch("ei.spool.os.kill", side_effect=AssertionError("must not signal")):
            self.assertIsNone(spool._pid_state(os.getpid()))
        if os.name == "nt":
            with patch("ei.spool.os.kill", side_effect=AssertionError("must not signal")):
                self.assertTrue(spool._pid_state(os.getpid()))

    def test_unknown_temporary_name_is_not_deleted(self):
        with tempfile.TemporaryDirectory() as tmp:
            settings = make_isolated_hook_settings(Path(tmp))
            settings.paths.spool_dir.mkdir(parents=True)
            path = settings.paths.spool_dir / "user-notes.tmp"
            path.write_bytes(b"unrelated")
            write_spool("candidate", "public", settings, now=NOW, key_provider=InMemoryKeyProvider())
            self.assertEqual(path.read_bytes(), b"unrelated")

    def test_reparse_temporary_is_not_deleted_or_followed(self):
        with tempfile.TemporaryDirectory() as tmp:
            settings = make_isolated_hook_settings(Path(tmp))
            settings.paths.spool_dir.mkdir(parents=True)
            target = Path(tmp) / "outside"
            target.mkdir()
            protected = target / "keep.txt"
            protected.write_bytes(b"unrelated")
            link = settings.paths.spool_dir / ("pending_" + "c" * 64 + ".json.12345678.1234abcd.tmp")
            try:
                link.symlink_to(target, target_is_directory=True)
            except OSError:
                if os.name != "nt":
                    self.skipTest("This platform does not permit creating a test symlink")
                result = subprocess.run(["cmd.exe", "/c", "mklink", "/J", str(link), str(target)], capture_output=True, timeout=10)
                if result.returncode != 0:
                    self.skipTest("This platform does not permit creating a test junction")
            with patch("ei.spool._pid_state", return_value=False, create=True), self.assertRaisesRegex(SpoolError, "SPOOL_TEMP_CLEANUP_UNCONFIRMED"):
                write_spool("candidate", "public", settings, now=NOW, key_provider=InMemoryKeyProvider())
            self.assertTrue(link.is_symlink() or getattr(link, "is_junction", lambda: False)())
            self.assertEqual(protected.read_bytes(), b"unrelated")

    def test_gc_reaches_orphan_cleanup_without_deleting_committed_pending(self):
        with tempfile.TemporaryDirectory() as tmp:
            settings = make_isolated_hook_settings(Path(tmp))
            key = InMemoryKeyProvider()
            ref = write_spool("committed", "public", settings, now=NOW, key_provider=key, purpose="pending", capture_id="sha256:" + "a" * 64)
            orphan = settings.paths.spool_dir / ("pending_" + "b" * 64 + ".json.12345678.1234abcd.tmp")
            orphan.write_bytes(b"fragment")
            with patch("ei.spool._pid_state", return_value=False, create=True):
                gc_expired_spool(settings, now=NOW + timedelta(days=31))
            self.assertFalse(orphan.exists())
            self.assertTrue((runtime_lookup(settings.paths.spool_dir, ref.spool_id)).exists())

    def test_atomic_write_handles_short_os_writes(self):
        import os
        real_write = os.write
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "test.json"
            with patch("ei.spool.os.write", side_effect=lambda fd, data: real_write(fd, data[:7])):
                spool._atomic_json(path, {"marker": "complete durable metadata"})
            self.assertEqual(json.loads(path.read_text(encoding="utf-8")), {"marker": "complete durable metadata"})

    def test_generic_gc_and_expired_read_do_not_delete_pending_before_receipt(self):
        with tempfile.TemporaryDirectory() as tmp:
            settings = make_isolated_hook_settings(Path(tmp))
            key = InMemoryKeyProvider()
            ref = write_spool("candidate", "public", settings, now=NOW, ttl_seconds=1, key_provider=key, purpose="pending", capture_id="sha256:" + "a" * 64)
            self.assertEqual(gc_expired_spool(settings, now=NOW + timedelta(seconds=1)), 0)
            with self.assertRaises(SpoolError):
                read_spool(ref, settings, now=NOW + timedelta(seconds=1), key_provider=key)
            self.assertTrue((runtime_lookup(settings.paths.spool_dir, ref.spool_id)).exists())

    def test_unknown_envelope_fields_fail_semantic_validation(self):
        with tempfile.TemporaryDirectory() as tmp:
            settings = make_isolated_hook_settings(Path(tmp))
            key = InMemoryKeyProvider()
            ref = write_spool("candidate", "public", settings, now=NOW, key_provider=key, purpose="pending", capture_id="sha256:" + "a" * 64)
            path = runtime_lookup(settings.paths.spool_dir, ref.spool_id)
            value = json.loads(path.read_text(encoding="utf-8"))
            value["body"] = "forbidden plaintext metadata"
            path.write_text(json.dumps(value), encoding="utf-8")
            with self.assertRaises(SpoolError):
                read_spool(ref, settings, now=NOW, key_provider=key)

    def test_pending_default_ttl_and_legacy_budget_are_independent(self):
        with tempfile.TemporaryDirectory() as tmp:
            settings = make_isolated_hook_settings(Path(tmp))
            key = InMemoryKeyProvider()
            pending = write_spool("candidate", "public", settings, now=NOW, key_provider=key, purpose="pending", capture_id="sha256:" + "a" * 64)
            self.assertEqual(datetime.fromisoformat(pending.expires_at.replace("Z", "+00:00")) - NOW, timedelta(days=30))
            settings.capture_policy_path.parent.mkdir(parents=True, exist_ok=True)
            settings.capture_policy_path.write_text(json.dumps({"max_items": 1}), encoding="utf-8")
            write_spool("legacy", "public", settings, now=NOW, key_provider=key)

    def test_tampered_pending_cannot_escape_capacity_by_downgrade(self):
        with tempfile.TemporaryDirectory() as tmp:
            settings = make_isolated_hook_settings(Path(tmp))
            key = InMemoryKeyProvider()
            options = dict(settings=settings, now=NOW, key_provider=key, purpose="pending", capture_id="sha256:" + "a" * 64)
            ref = write_spool("first", "public", **options)
            path = runtime_lookup(settings.paths.spool_dir, ref.spool_id)
            value = json.loads(path.read_text(encoding="utf-8"))
            for field in ("aad_version", "purpose", "capture_id"):
                value.pop(field)
            path.write_text(json.dumps(value), encoding="utf-8")
            with self.assertRaisesRegex(SpoolError, "SPOOL_CAPACITY_UNVERIFIED"):
                write_spool("second", "public", **options)

    def test_permission_and_stat_lock_failures_are_bounded(self):
        for failure in (PermissionError(), FileExistsError()):
            with self.subTest(failure=type(failure).__name__), tempfile.TemporaryDirectory() as tmp:
                with patch("ei.spool.os.open", side_effect=failure), patch.object(Path, "stat", side_effect=OSError()) as stat_probe, patch("ei.spool.time.monotonic", side_effect=[0, 0, 6]), patch("ei.spool.time.sleep") as retry_sleep:
                    with self.assertRaisesRegex(SpoolError, "SPOOL_LOCK_PERMISSION_DENIED|SPOOL_LOCK_TIMEOUT"):
                        spool._acquire(Path(tmp))
                    self.assertEqual(stat_probe.call_count, int(isinstance(failure, FileExistsError)))
                    self.assertEqual(retry_sleep.call_count, int(isinstance(failure, FileExistsError)))

    def test_pending_and_result_share_bytes_but_only_candidate_counts(self):
        with tempfile.TemporaryDirectory() as tmp:
            settings = make_isolated_hook_settings(Path(tmp))
            key = InMemoryKeyProvider()
            policy = PendingPolicy(max_items=1, max_bytes=4000)
            options = dict(settings=settings, now=NOW, key_provider=key, retention=policy, capture_id="sha256:" + "a" * 64)
            ref = write_spool("candidate", "public", spool_id="pending-first", purpose="pending", **options)
            result = write_spool("result", "public", spool_id="result-first", purpose="validated-result", **options)
            self.assertEqual(read_spool(result, settings, now=NOW, key_provider=key), b"result")
            with self.assertRaisesRegex(SpoolError, "SPOOL_FULL"):
                write_spool("second candidate", "public", spool_id="pending-second", purpose="pending", **options)
            with self.assertRaisesRegex(SpoolError, "SPOOL_FULL"):
                write_spool("x" * 3000, "public", spool_id="result-second", purpose="validated-result", **options)
            with self.assertRaisesRegex(SpoolError, "SPOOL_ID_COLLISION"):
                write_spool("other", "public", spool_id="pending-first", purpose="pending", **options)
            self.assertEqual(read_spool(ref, settings, now=NOW, key_provider=key), b"candidate")
            write_spool("legacy", "public", settings, now=NOW, key_provider=key)

    def test_spool_and_emergency_paths_are_outside_git_allowlist(self):
        with tempfile.TemporaryDirectory() as tmp:
            settings = make_isolated_hook_settings(Path(tmp))
            key = InMemoryKeyProvider("spool-key", b"s" * 32)
            ref = write_spool("allowlisted repository must not contain runtime payload", "private-reusable", settings, key_provider=key, now=NOW, spool_id="spool-boundary")
            self.assertFalse(ref.spool_id + ".json" in {path.name for path in settings.paths.repo_root.rglob("*.json")})
            self.assertFalse(settings.paths.spool_dir.is_relative_to(settings.paths.repo_root))
            self.assertFalse(settings.paths.emergency_spool_dir.is_relative_to(settings.paths.repo_root))
            self.assertEqual(spool_health(settings).items, 1)

    def test_delete_is_idempotent_and_reason_audit_is_sanitized(self):
        with tempfile.TemporaryDirectory() as tmp:
            settings = make_isolated_hook_settings(Path(tmp))
            key = InMemoryKeyProvider("spool-key", b"s" * 32)
            ref = write_spool("delete twice safely", "private-reusable", settings, key_provider=key, now=NOW, spool_id="spool-delete")
            self.assertTrue(delete_spool(ref, settings, reason_code="NO_DISCARDED"))
            self.assertFalse(delete_spool(ref, settings, reason_code="NO_DISCARDED"))
            audit = (settings.paths.runtime_dir / "spool-audit.jsonl").read_text(encoding="utf-8")
            self.assertNotIn("delete twice safely", audit)
            self.assertNotIn(str(settings.paths.runtime_dir), audit)
            self.assertIn("NO_DISCARDED", audit)

    def test_expiry_gc_deletes_expired_items_and_keeps_live_item(self):
        with tempfile.TemporaryDirectory() as tmp:
            settings = make_isolated_hook_settings(Path(tmp))
            key = InMemoryKeyProvider("spool-key", b"s" * 32)
            expired = write_spool("expired gc item", "private-reusable", settings, key_provider=key, now=NOW, ttl_seconds=1, spool_id="spool-gc-expired")
            live = write_spool("live gc item", "private-reusable", settings, key_provider=key, now=NOW, ttl_seconds=60, spool_id="spool-gc-live")
            self.assertEqual(gc_expired_spool(settings, now=NOW + timedelta(seconds=2)), 1)
            with self.assertRaisesRegex(SpoolError, "SPOOL_NOT_FOUND"):
                read_spool(expired, settings, key_provider=key, now=NOW + timedelta(seconds=2))
            self.assertEqual(read_spool(live, settings, key_provider=key, now=NOW + timedelta(seconds=2)), b"live gc item")


if __name__ == "__main__":
    unittest.main()
