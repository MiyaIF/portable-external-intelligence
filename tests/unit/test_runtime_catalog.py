import json
import os
import sqlite3
import tempfile
import unittest
from contextlib import closing
from pathlib import Path
from unittest.mock import patch

from ei.operation_runtime import OperationBudget


class CatalogTests(unittest.TestCase):
    def test_tagged_paths_never_returns_truncated_untagged_or_changed_inventory(self):
        from ei.runtime_catalog import CatalogUnknown
        catalog = self.catalog()
        catalog.migrate_page()
        catalog.write("item_a", b"first", purpose="intent", tag="session-a")
        catalog.write("item_b", b"second", purpose="intent", tag="session-a")
        paths = catalog.tagged_paths("session-a", limit=2, budget=OperationBudget(5000))
        self.assertEqual({path.read_bytes() for path in paths}, {b"first", b"second"})
        with self.assertRaises(CatalogUnknown):
            catalog.tagged_paths("session-a", limit=1, budget=OperationBudget(5000))
        with self.assertRaises(TimeoutError):
            catalog.tagged_paths("session-a", limit=2, budget=OperationBudget(0))
        catalog.write("item_c", b"unknown", purpose="intent")
        with self.assertRaises(CatalogUnknown):
            catalog.tagged_paths("session-absent", limit=2, budget=OperationBudget(5000))
        catalog.write("item_c", b"unknown", purpose="intent", tag="session-c")
        paths[0].write_bytes(b"changed")
        with self.assertRaises(CatalogUnknown):
            catalog.tagged_paths("session-a", limit=2, budget=OperationBudget(5000))

    def test_unapplied_update_keeps_incomplete_shard_evidence_across_rollback(self):
        import ei.runtime_catalog as runtime
        from contextlib import contextmanager
        catalog = self.interrupted_update()
        shard = runtime.managed_path(self.root, "item_a").parent
        before = self.row("item_a")
        class Budget:
            allowance = 1000
            def remaining_ms(self):
                return self.allowance
            def check(self):
                if self.allowance <= 0:
                    raise TimeoutError("expired")
        budget = Budget()
        real_scandir = runtime.os.scandir
        scans = []
        @contextmanager
        def interrupted(path):
            with real_scandir(path) as entries:
                if Path(path) == shard:
                    scans.append(path)
                    budget.allowance = 0
                yield entries
        for allowance in (1000, 1000, 900):
            budget.allowance = allowance
            with patch.object(runtime.os, "scandir", interrupted), self.assertRaises(runtime.CatalogUnknown):
                catalog.migrate_page(budget=budget, inspect_update=self.old_metadata)
            self.assertEqual(self.row("item_a"), before)
        self.assertEqual(len(scans), 1)
        with closing(sqlite3.connect(self.root / ".runtime-catalog.sqlite")) as connection:
            blocked = connection.execute("SELECT value FROM state WHERE name=?", ("blocked:" + shard.name,)).fetchone()
        self.assertTrue(blocked and blocked[0].endswith("/1000"))
        budget.allowance = 1500
        self.assertTrue(catalog.migrate_page(budget=budget, inspect_update=self.old_metadata).complete)
        self.assertEqual(catalog.capacity("queue"), (1, 3))

    def test_restore_validation_deadline_stops_before_beginning_commit(self):
        import ei.runtime_catalog as runtime
        catalog = self.interrupted_update()
        before = self.row("item_a")
        class Budget:
            allowance = 1000
            def remaining_ms(self):
                return self.allowance
            def check(self):
                if self.allowance <= 0:
                    raise TimeoutError("expired")
        budget = Budget()
        original_membership = catalog._membership
        calls = 0
        def expire_after_validation(passed):
            nonlocal calls
            actual = original_membership(passed)
            calls += 1
            if calls == 3:
                budget.allowance = 0
            return actual
        statements = []
        original_connect = runtime.sqlite3.connect
        def connect(*args, **kwargs):
            connection = original_connect(*args, **kwargs)
            connection.set_trace_callback(statements.append)
            return connection
        with patch.object(catalog, "_membership", side_effect=expire_after_validation), patch.object(runtime.sqlite3, "connect", side_effect=connect), self.assertRaises(TimeoutError):
            catalog.migrate_page(budget=budget, inspect_update=self.old_metadata)
        self.assertEqual(self.row("item_a"), before)
        self.assertFalse(any(statement.startswith("BEGIN") for statement in statements))


    def interrupted_update(self, *, replaced=False, tag="stable"):
        import ei.runtime_catalog as runtime
        catalog = self.catalog()
        catalog.migrate_page()
        catalog.write("item_a", b"old", purpose="queue", tag="stable", created_at="original", expires_at="expiry")
        original = runtime.safe_atomic_write
        def interrupt(*args, **kwargs):
            if replaced:
                original(*args, **kwargs)
            raise KeyboardInterrupt()
        with patch.object(runtime, "safe_atomic_write", interrupt), self.assertRaises(KeyboardInterrupt):
            catalog.write("item_a", b"new larger value", purpose="queue", tag=tag, created_at="original", expires_at="expiry")
        return catalog

    @staticmethod
    def old_metadata(path):
        if path.read_bytes() != b"old":
            raise ValueError("not original")
        return dict(purpose="queue", tag="stable", retry_tag="", created_at="original", expires_at="expiry")

    def test_verified_unapplied_update_restores_old_size_and_state(self):
        catalog = self.interrupted_update()
        self.assertTrue(catalog.migrate_page(inspect_update=self.old_metadata).complete)
        self.assertEqual(catalog.capacity("queue"), (1, 3))
        self.assertEqual((self.row("item_a")["phase"], self.row("item_a")["old_digest"]), ("registered", ""))

    def test_post_replace_update_is_settled_without_old_version_callback(self):
        from ei.runtime_catalog import managed_path
        catalog = self.interrupted_update(replaced=True)
        self.assertTrue(catalog.migrate_page(inspect_update=self.old_metadata).complete)
        self.assertEqual(managed_path(self.root, "item_a").read_bytes(), b"new larger value")
        self.assertEqual(catalog.capacity("queue"), (1, 16))

    def test_unapplied_update_mismatch_missing_and_changed_tag_keep_charge(self):
        from ei.runtime_catalog import CatalogUnknown, managed_path
        for fault in ("missing", "digest", "tag", "other-shard"):
            with self.subTest(fault=fault), tempfile.TemporaryDirectory() as tmp:
                self.root = Path(tmp)
                catalog = self.interrupted_update(tag="changed" if fault == "tag" else "stable")
                path = managed_path(self.root, "item_a")
                if fault == "missing":
                    path.unlink()
                elif fault == "digest":
                    path.write_bytes(b"wrong")
                elif fault == "other-shard":
                    other = managed_path(self.root, "item_other", create=True)
                    self.assertNotEqual(other.parent, path.parent)
                    other.write_bytes(b"unknown")
                try:
                    page = catalog.migrate_page(inspect_update=self.old_metadata)
                except CatalogUnknown:
                    page = None
                self.assertFalse(page is not None and page.complete)
                self.assertEqual((self.row("item_a")["phase"], self.row("item_a")["size"]), ("writing", 16))

    def test_old_version_restoration_transaction_crash_retains_reservation(self):
        from ei.runtime_catalog import RuntimeCatalog
        catalog = self.interrupted_update()
        original = RuntimeCatalog._set
        def fail(connection, name, value):
            if name == "membership":
                raise KeyboardInterrupt()
            return original(connection, name, value)
        with patch.object(RuntimeCatalog, "_set", side_effect=fail), self.assertRaises(KeyboardInterrupt):
            catalog.migrate_page(inspect_update=self.old_metadata)
        self.assertEqual((self.row("item_a")["phase"], self.row("item_a")["size"]), ("writing", 16))
        self.assertTrue(catalog.migrate_page(inspect_update=self.old_metadata).complete)

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)

    def catalog(self):
        from ei.runtime_catalog import RuntimeCatalog
        return RuntimeCatalog(self.root, prefix="item_")

    def row(self, entry_id):
        with closing(sqlite3.connect(self.root / ".runtime-catalog.sqlite")) as connection:
            connection.row_factory = sqlite3.Row
            return dict(connection.execute("SELECT * FROM entries WHERE id=?", (entry_id,)).fetchone())

    def crash_write(self, entry_id="item_a"):
        import ei.runtime_catalog as catalog
        real_write = catalog.safe_atomic_write
        def crash(*args, **kwargs):
            real_write(*args, **kwargs)
            raise KeyboardInterrupt()
        with patch.object(catalog, "safe_atomic_write", crash), self.assertRaises(KeyboardInterrupt):
            self.catalog().write(entry_id, b"payload", purpose="pending")

    def test_repair_does_not_accept_changed_untouched_shard(self):
        from ei.runtime_catalog import CatalogUnknown, managed_path
        self.catalog().migrate_page()
        self.catalog().write("item_other", b"other", purpose="pending")
        self.crash_write()
        untouched = managed_path(self.root, "item_other").parent
        self.assertNotEqual(untouched, managed_path(self.root, "item_a").parent)
        (untouched / "unregistered.json").write_bytes(b"unknown")
        with self.assertRaisesRegex(CatalogUnknown, "RUNTIME_MEMBERSHIP_UNKNOWN"):
            self.catalog().migrate_page()
        self.assertEqual(self.row("item_a")["phase"], "writing")

    def test_phase_and_membership_settlement_roll_back_together(self):
        from ei.runtime_catalog import RuntimeCatalog
        self.catalog().migrate_page()
        real_set = RuntimeCatalog._set
        def crash(connection, name, value):
            if name == "membership":
                raise KeyboardInterrupt()
            return real_set(connection, name, value)
        with patch.object(RuntimeCatalog, "_set", side_effect=crash), self.assertRaises(KeyboardInterrupt):
            self.catalog().write("item_a", b"payload", purpose="pending")
        self.assertEqual(self.row("item_a")["phase"], "writing")
        self.assertTrue(self.catalog().migrate_page().complete)
        self.assertEqual(self.catalog().capacity("pending"), (1, 7))

    def test_move_repair_validates_direct_membership_before_registering(self):
        import ei.runtime_catalog as catalog
        (self.root / "item_a.json").write_bytes(b"payload")
        real_move = catalog.safe_replace
        def crash(*args, **kwargs):
            real_move(*args, **kwargs)
            raise KeyboardInterrupt()
        with patch.object(catalog, "safe_replace", crash), self.assertRaises(KeyboardInterrupt):
            self.catalog().migrate_page()
        extra = catalog.managed_path(self.root, "item_a").parent / "unknown.json"
        extra.write_bytes(b"retained")
        with self.assertRaisesRegex(catalog.CatalogUnknown, "RUNTIME_SHARD_INVENTORY_UNKNOWN"):
            self.catalog().migrate_page()
        self.assertEqual(self.row("item_a")["phase"], "prepared")
        self.assertEqual(extra.read_bytes(), b"retained")

    def test_repair_rejects_missing_registered_member_in_same_shard(self):
        from ei.runtime_catalog import CatalogUnknown, managed_path
        self.catalog().migrate_page()
        prefix = managed_path(self.root, "item_a").parent.name
        sibling = next(f"item_{i}" for i in range(10000) if managed_path(self.root, f"item_{i}").parent.name == prefix)
        self.catalog().write(sibling, b"other", purpose="pending")
        self.crash_write()
        managed_path(self.root, sibling).unlink()
        with self.assertRaisesRegex(CatalogUnknown, "RUNTIME_SHARD_INVENTORY_UNKNOWN"):
            self.catalog().migrate_page()
        self.assertEqual(self.row("item_a")["phase"], "writing")

    def test_semantic_absent_retry_replaces_cipher_digest_within_reservation(self):
        import ei.runtime_catalog as catalog
        self.catalog().migrate_page()
        options = dict(purpose="pending", retry_tag="sha256:" + "a" * 64,
            created_at="2026-09-20T00:00:00Z", expires_at="2026-10-20T00:00:00Z")
        with patch.object(catalog, "safe_atomic_write", side_effect=OSError("full")), self.assertRaises(OSError):
            self.catalog().write("item_a", b"cipher-one", **options)
        self.catalog().write("item_a", b"cipher-two", **options)
        self.assertEqual(self.catalog().capacity("pending"), (1, 10))
        self.assertEqual(catalog.lookup(self.root, "item_a").read_bytes(), b"cipher-two")

    def test_semantic_retry_rejects_growth_changed_binding_and_other_unknown(self):
        import ei.runtime_catalog as catalog
        self.catalog().migrate_page()
        self.catalog().write("item_other", b"other", purpose="pending")
        options = dict(purpose="pending", retry_tag="sha256:" + "a" * 64,
            created_at="2026-09-20T00:00:00Z", expires_at="2026-10-20T00:00:00Z")
        with patch.object(catalog, "safe_atomic_write", side_effect=OSError("full")), self.assertRaises(OSError):
            self.catalog().write("item_a", b"cipher-one", **options)
        for change, payload in (({}, b"cipher-too-large"), ({"retry_tag": "sha256:" + "b" * 64}, b"cipher-two"),
                                ({"expires_at": "2026-10-21T00:00:00Z"}, b"cipher-two")):
            with self.subTest(change=change, payload=payload), self.assertRaises(catalog.CatalogUnknown):
                self.catalog().write("item_a", payload, **(options | change))
        (catalog.managed_path(self.root, "item_other").parent / "unknown.json").write_bytes(b"retained")
        with self.assertRaises(catalog.CatalogUnknown):
            self.catalog().write("item_a", b"cipher-two", **options)
        self.assertFalse(catalog.managed_path(self.root, "item_a").exists())
        self.assertEqual(self.row("item_a")["size"], 10)

    def test_absent_deleting_target_remains_charged_and_actionable(self):
        import ei.runtime_catalog as catalog
        self.catalog().migrate_page()
        self.catalog().write("item_a", b"payload", purpose="pending")
        real_unlink = catalog.safe_unlink
        def crash(*args, **kwargs):
            real_unlink(*args, **kwargs)
            raise KeyboardInterrupt()
        with patch.object(catalog, "safe_unlink", crash), self.assertRaises(KeyboardInterrupt):
            self.catalog().delete("item_a")
        for operation in (self.catalog().migrate_page, lambda: self.catalog().capacity("pending"), lambda: self.catalog().delete("item_a")):
            with self.assertRaisesRegex(catalog.CatalogUnknown, "RUNTIME_DELETE_UNCONFIRMED"):
                operation()
        self.assertEqual((self.row("item_a")["phase"], self.row("item_a")["size"]), ("deleting", 7))
        page = self.catalog().page("diagnostic", advance=False)
        self.assertFalse(page.complete)
        self.assertEqual(page.reason_code, "RUNTIME_DELETE_UNCONFIRMED")

    def test_present_deleting_target_can_retry(self):
        import ei.runtime_catalog as catalog
        self.catalog().migrate_page()
        self.catalog().write("item_a", b"payload", purpose="pending")
        with patch.object(catalog, "safe_unlink", side_effect=KeyboardInterrupt()), self.assertRaises(KeyboardInterrupt):
            self.catalog().delete("item_a")
        self.assertTrue(self.catalog().delete("item_a"))
        self.assertEqual(self.catalog().capacity("pending"), (0, 0))

    def test_delete_validates_changed_shard_without_hiding_unknown_or_missing_entries(self):
        import ei.runtime_catalog as runtime
        for fault in ("unknown", "missing-neighbor", "other-shard", "digest"):
            with self.subTest(fault=fault), tempfile.TemporaryDirectory() as tmp:
                self.root = Path(tmp)
                catalog = self.catalog()
                catalog.migrate_page()
                path = catalog.write("item_a", b"payload", purpose="pending")
                if fault == "unknown":
                    (path.parent / "unknown.json").write_bytes(b"retain")
                elif fault == "missing-neighbor":
                    neighbor = next("item_" + str(i) for i in range(10000)
                                    if runtime.managed_path(self.root, "item_" + str(i)).parent == path.parent)
                    catalog.write(neighbor, b"neighbor", purpose="pending").unlink()
                elif fault == "other-shard":
                    runtime.managed_path(self.root, "item_other", create=True).write_bytes(b"retain")
                else:
                    path.write_bytes(b"altered")
                with self.assertRaises(runtime.CatalogUnknown):
                    catalog.delete("item_a")
                self.assertTrue(path.exists())
                self.assertEqual((self.row("item_a")["phase"], self.row("item_a")["size"]), ("registered", 7))

    def test_delete_changed_shard_cleanup_interruption_keeps_body_and_charge(self):
        import ei.runtime_catalog as runtime
        self.catalog().migrate_page()
        path = self.catalog().write("item_a", b"payload", purpose="pending")
        temporary = path.with_suffix(".tmp")
        temporary.write_bytes(b"fragment")
        def cleanup(candidate):
            candidate.unlink()
            raise KeyboardInterrupt()
        catalog = runtime.RuntimeCatalog(self.root, prefix="item_", clean_temporary=cleanup)
        with self.assertRaises(KeyboardInterrupt):
            catalog.delete("item_a")
        self.assertTrue(path.exists())
        self.assertEqual((self.row("item_a")["phase"], self.row("item_a")["size"]), ("registered", 7))
        self.assertTrue(catalog.delete("item_a"))
        self.assertEqual(catalog.capacity("pending"), (0, 0))

    def test_delete_shard_validation_exhausts_original_budget_without_unlink(self):
        catalog = self.catalog()
        catalog.migrate_page()
        path = catalog.write("item_a", b"payload", purpose="pending")
        budget = OperationBudget(5000)
        def expire(connection, shard, passed, **kwargs):
            self.assertIs(passed, budget)
            raise TimeoutError("same deadline")
        with patch.object(catalog, "_validate_shard", side_effect=expire), self.assertRaises(TimeoutError):
            catalog.delete("item_a", budget=budget)
        self.assertTrue(path.exists())
        self.assertEqual((self.row("item_a")["phase"], self.row("item_a")["size"]), ("registered", 7))

    def test_missing_accounting_row_never_becomes_zero_capacity(self):
        from ei.runtime_catalog import CatalogUnknown
        self.catalog().migrate_page()
        self.catalog().write("item_a", b"payload", purpose="pending")
        with closing(sqlite3.connect(self.root / ".runtime-catalog.sqlite")) as connection:
            connection.execute("DELETE FROM accounting")
            connection.commit()
        with self.assertRaises(CatalogUnknown):
            self.catalog().capacity("pending")

    def test_opened_descriptor_must_match_verified_path(self):
        import ei.runtime_catalog as catalog
        path = self.root / "item_a.json"
        path.write_bytes(b"expected")
        other = self.root / "other"
        other.write_bytes(b"replaced")
        real_open = os.open
        with patch.object(catalog.os, "open", side_effect=lambda *args: real_open(other, os.O_RDONLY | getattr(os, "O_BINARY", 0))):
            with self.assertRaises(catalog.CatalogUnknown):
                catalog._digest(self.root, path, None)

    def test_incomplete_shard_uses_start_allowance_and_larger_retry_can_finish(self):
        import ei.runtime_catalog as catalog
        self.catalog().migrate_page()
        self.crash_write()
        shard = catalog.managed_path(self.root, "item_a").parent
        class Budget:
            allowance = 1000
            def remaining_ms(self):
                return self.allowance
            def check(self):
                if self.allowance <= 0:
                    raise TimeoutError("expired")
        budget = Budget()
        real_scandir = catalog.os.scandir
        from contextlib import contextmanager
        @contextmanager
        def interrupted(path):
            with real_scandir(path) as entries:
                if Path(path) == shard:
                    budget.allowance = 0
                yield entries
        with patch.object(catalog.os, "scandir", interrupted), self.assertRaisesRegex(catalog.CatalogUnknown, "RUNTIME_SHARD_INVENTORY_UNKNOWN"):
            self.catalog().migrate_page(budget=budget)
        self.assertEqual(self.row("item_a")["phase"], "writing")
        def no_repeat(path):
            if Path(path) == shard:
                raise AssertionError("same allowance repeated an incomplete direct scan")
            return real_scandir(path)
        for allowance in (900, 1000, 1001, 1499):
            budget.allowance = allowance
            with self.subTest(allowance=allowance), patch.object(catalog.os, "scandir", no_repeat), self.assertRaisesRegex(catalog.CatalogUnknown, "RUNTIME_SHARD_INVENTORY_UNKNOWN"):
                self.catalog().migrate_page(budget=budget)
        budget.allowance = 1500
        self.assertTrue(self.catalog().migrate_page(budget=budget).complete)

    def test_unexpected_large_root_is_actionable_without_repeated_scan(self):
        import ei.runtime_catalog as catalog
        for number in range(300):
            (self.root / f"unrelated-{number}.tmp").write_bytes(b"keep")
        with self.assertRaisesRegex(catalog.CatalogUnknown, "RUNTIME_ROOT_INVENTORY_UNKNOWN"):
            self.catalog().migrate_page()
        with patch.object(catalog.os, "scandir", side_effect=AssertionError("halted root must not repeat prefix scan")):
            with self.assertRaisesRegex(catalog.CatalogUnknown, "RUNTIME_ROOT_INVENTORY_UNKNOWN"):
                self.catalog().migrate_page()
        self.assertEqual(len(list(self.root.glob("*.tmp"))), 300)

    def test_existing_purpose_cannot_be_reclassified_by_replacement(self):
        from ei.runtime_catalog import CatalogUnknown
        self.catalog().migrate_page()
        self.catalog().write("item_a", b"pending", purpose="pending")
        with self.assertRaises(CatalogUnknown):
            self.catalog().write("item_a", b"legacy", purpose="legacy")
        self.assertEqual(self.catalog().capacity("pending"), (1, 7))

    def test_unsafe_flat_entry_halts_without_repeating_prefix(self):
        import ei.runtime_catalog as catalog
        path = self.root / "item_a.json"
        path.write_bytes(b"retained")
        def reject(_path):
            raise catalog.CatalogUnknown("RUNTIME_ENTRY_UNVERIFIED")
        with self.assertRaisesRegex(catalog.CatalogUnknown, "RUNTIME_ENTRY_UNVERIFIED"):
            self.catalog().migrate_page(inspect_metadata=reject)
        with patch.object(catalog.os, "scandir", side_effect=AssertionError("halted entry must not rescan")):
            with self.assertRaisesRegex(catalog.CatalogUnknown, "RUNTIME_ENTRY_UNVERIFIED"):
                self.catalog().migrate_page(inspect_metadata=reject)
        self.assertEqual(path.read_bytes(), b"retained")

    def test_empty_interrupted_schema_initialization_can_resume(self):
        with closing(sqlite3.connect(self.root / ".runtime-catalog.sqlite")):
            pass
        self.assertTrue(self.catalog().migrate_page().complete)

    def test_retry_does_not_bypass_unrelated_missing_accounting(self):
        import ei.runtime_catalog as catalog
        self.catalog().migrate_page()
        self.catalog().write("item_other", b"legacy", purpose="legacy")
        options = dict(purpose="pending", retry_tag="sha256:" + "a" * 64,
            created_at="2026-09-20T00:00:00Z", expires_at="2026-10-20T00:00:00Z")
        with patch.object(catalog, "safe_atomic_write", side_effect=OSError("full")), self.assertRaises(OSError):
            self.catalog().write("item_a", b"cipher-one", **options)
        with closing(sqlite3.connect(self.root / ".runtime-catalog.sqlite")) as connection:
            connection.execute("DELETE FROM accounting WHERE purpose='legacy'")
            connection.commit()
        with self.assertRaises(catalog.CatalogUnknown):
            self.catalog().write("item_a", b"cipher-two", **options)
        self.assertFalse(catalog.managed_path(self.root, "item_a").exists())

    def test_delete_does_not_release_charge_while_a_matching_flat_copy_remains(self):
        from ei.runtime_catalog import CatalogUnknown
        self.catalog().migrate_page()
        self.catalog().write("item_a", b"payload", purpose="pending")
        flat = self.root / "item_a.json"
        flat.write_bytes(b"payload")
        with self.assertRaises(CatalogUnknown):
            self.catalog().delete("item_a")
        self.assertEqual(self.row("item_a")["size"], 7)
        self.assertTrue(flat.exists())

    def test_restarts_migrate_successive_flat_entries_without_changing_bytes(self):
        from ei.runtime_catalog import lookup
        for number in range(5):
            (self.root / f"item_{number}.json").write_bytes(b'{"body":"unchanged"}')
        for remaining in (3, 1, 0):
            result = self.catalog().migrate_page(limit=2)
            self.assertEqual(len(list(self.root.glob("item_*.json"))), remaining)
            self.assertEqual(result.complete, remaining == 0)
        for number in range(5):
            path = lookup(self.root, f"item_{number}")
            self.assertIn("managed", path.parts)
            self.assertEqual(path.read_bytes(), b'{"body":"unchanged"}')
        raw = (self.root / ".runtime-catalog.sqlite").read_bytes()
        self.assertNotIn(b"unchanged", raw)

    def test_crash_after_move_repairs_original_id_and_content(self):
        import ei.runtime_catalog as catalog
        path = self.root / "item_a.json"
        path.write_bytes(b"payload")
        real_move = catalog.safe_replace
        def crash(*args, **kwargs):
            real_move(*args, **kwargs)
            raise KeyboardInterrupt()
        with patch.object(catalog, "safe_replace", crash), self.assertRaises(KeyboardInterrupt):
            self.catalog().migrate_page(limit=1)
        self.assertFalse(path.exists())
        self.assertTrue(self.catalog().migrate_page(limit=2).complete)
        self.assertEqual(catalog.lookup(self.root, "item_a").read_bytes(), b"payload")

    def test_conflicting_duplicate_stays_unknown_and_preserves_both_files(self):
        from ei.runtime_catalog import managed_path, CatalogUnknown
        flat = self.root / "item_a.json"
        flat.write_bytes(b"original")
        managed = managed_path(self.root, "item_a", create=True)
        managed.write_bytes(b"conflict")
        with self.assertRaises(CatalogUnknown):
            self.catalog().migrate_page(limit=2)
        self.assertEqual(flat.read_bytes(), b"original")
        self.assertEqual(managed.read_bytes(), b"conflict")

    def test_page_cursor_rotates_past_terminal_prefix_on_restart(self):
        for number in range(5):
            (self.root / f"item_{number}.json").write_text("{}", encoding="utf-8")
        self.catalog().migrate_page(limit=10)
        seen = []
        for _ in range(3):
            page = self.catalog().page("consumer", limit=2)
            seen.extend(path.stem for path in page.paths)
        self.assertEqual(set(seen), {f"item_{number}" for number in range(5)})

    def test_zero_budget_does_not_create_catalog(self):
        with self.assertRaises(TimeoutError):
            self.catalog().migrate_page(limit=1, budget=OperationBudget(0))
        self.assertEqual(list(self.root.iterdir()), [])

    def test_partial_inventory_is_not_capacity_evidence(self):
        from ei.runtime_catalog import CatalogUnknown
        for number in range(3):
            (self.root / f"item_{number}.json").write_text("{}", encoding="utf-8")
        self.assertFalse(self.catalog().migrate_page(limit=1).complete)
        with self.assertRaises(CatalogUnknown):
            self.catalog().capacity("pending")

    def test_corrupt_database_does_not_replace_existing_bytes(self):
        from ei.runtime_catalog import CatalogUnknown
        database = self.root / ".runtime-catalog.sqlite"
        database.write_bytes(b"corrupt")
        with self.assertRaises(CatalogUnknown):
            self.catalog().migrate_page(limit=1)
        self.assertEqual(database.read_bytes(), b"corrupt")

    def test_missing_catalog_with_managed_files_is_unknown_but_lookup_works(self):
        from ei.runtime_catalog import lookup, CatalogUnknown
        (self.root / "item_a.json").write_bytes(b"payload")
        self.catalog().migrate_page()
        (self.root / ".runtime-catalog.sqlite").unlink()
        with self.assertRaises(CatalogUnknown):
            self.catalog().migrate_page()
        self.assertEqual(lookup(self.root, "item_a").read_bytes(), b"payload")
        self.assertFalse((self.root / ".runtime-catalog.sqlite").exists())

    def test_registered_write_and_confirmed_delete_update_admission_accounting(self):
        from ei.runtime_catalog import lookup
        self.catalog().migrate_page()
        self.catalog().write("item_a", b"ciphertext", purpose="pending")
        self.assertEqual(self.catalog().capacity("pending"), (1, 10))
        self.assertEqual(lookup(self.root, "item_a").read_bytes(), b"ciphertext")
        self.assertTrue(self.catalog().delete("item_a"))
        self.assertEqual(self.catalog().capacity("pending"), (0, 0))

    def test_external_disappearance_never_releases_reserved_capacity(self):
        from ei.runtime_catalog import lookup, CatalogUnknown
        self.catalog().migrate_page()
        self.catalog().write("item_a", b"ciphertext", purpose="pending")
        lookup(self.root, "item_a").unlink()
        with self.assertRaises(CatalogUnknown):
            self.catalog().capacity("pending")
        with self.assertRaises(CatalogUnknown):
            self.catalog().delete("item_a")
        with closing(sqlite3.connect(self.root / ".runtime-catalog.sqlite")) as connection:
            self.assertEqual(connection.execute("SELECT size FROM entries WHERE id='item_a'").fetchone(), (10,))

    def test_interrupted_write_after_file_commit_repairs_without_body_replay(self):
        import ei.runtime_catalog as catalog
        self.catalog().migrate_page()
        original = catalog.safe_atomic_write
        def crash(*args, **kwargs):
            original(*args, **kwargs)
            raise KeyboardInterrupt()
        with patch.object(catalog, "safe_atomic_write", crash), self.assertRaises(KeyboardInterrupt):
            self.catalog().write("item_a", b"payload", purpose="pending")
        self.assertTrue(self.catalog().migrate_page().complete)
        self.assertEqual(self.catalog().capacity("pending"), (1, 7))

    def test_interrupted_write_before_file_commit_replays_exact_reserved_write(self):
        import ei.runtime_catalog as catalog
        self.catalog().migrate_page()
        with patch.object(catalog, "safe_atomic_write", side_effect=OSError("full")), self.assertRaises(OSError):
            self.catalog().write("item_a", b"payload", purpose="pending")
        self.assertFalse(self.catalog().migrate_page().complete)
        self.catalog().write("item_a", b"payload", purpose="pending")
        self.assertTrue(self.catalog().migrate_page().complete)
        self.assertEqual(self.catalog().capacity("pending"), (1, 7))

    def test_consumption_cursor_does_not_skip_unprocessed_page_suffix(self):
        for number in range(5):
            (self.root / f"item_{number}.json").write_text("{}", encoding="utf-8")
        self.catalog().migrate_page(limit=10)
        seen = []
        for _ in range(5):
            page = self.catalog().page("bounded", limit=3, advance=False)
            seen.append(page.paths[0].stem)
            self.catalog().advance("bounded", page.paths[0].stem)
        self.assertEqual(len(set(seen)), 5)
