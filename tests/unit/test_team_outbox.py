import json
import tempfile
import unittest
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from ei.config import RuntimePaths, Settings
from ei.inference.base import ProviderResult
from ei.key_provider import InMemoryKeyProvider
from ei.operation_runtime import OperationBudget
from ei.journal import event_integrity
from ei.redaction import domain_hash
from ei.team_store import append_team_event, scan_team_events, initialize_team_store
from tests.unit.test_team_projection import team_event, NOW
from ei.team_outbox import drain_team_outbox, enqueue_team_event, list_team_outbox, read_team_outbox_receipt


def settings_for(root: Path) -> Settings:
    repo = root / "engine"
    runtime = root / "runtime"
    personal = root / "personal"
    paths = RuntimePaths(engine_root=repo, personal_knowledge_root=personal, team_knowledge_root=root / "shared-team", runtime_root=runtime)
    return Settings(paths=paths)


def event_payload() -> dict[str, object]:
    return {
        "knowledge_scope": "team",
        "origin_event_hash": "sha256:" + "1" * 64,
        "idempotency_key": "sha256:" + "2" * 64,
        "title": "再利用できる検証手順",
        "claim": "外部書込後は対象範囲を再読込して数式と値を検証する",
        "scope": ["spreadsheet-operations"],
        "preconditions": ["外部書込が完了している"],
        "failure_modes": ["古い表示を正しい結果と誤認する"],
        "benefit": "reduced_rework",
        "classification": "private-reusable",
    }


class TeamOutboxTests(unittest.TestCase):
    def test_delivery_proof_survives_release_failure_and_next_retry(self):
        with tempfile.TemporaryDirectory() as raw:
            settings, key, shared, record = self._ready(Path(raw))
            with patch("ei.team_outbox.delete_spool", side_effect=OSError("private-path-must-not-escape")):
                result = drain_team_outbox(settings, key_provider=key, budget=OperationBudget(10000))
            receipt = json.loads(Path(record["receipt_path"]).read_text(encoding="utf-8"))
            self.assertEqual(receipt["status"], "DELIVERED")
            self.assertIsNotNone(receipt["spool_ref"])
            self.assertNotIn("private-path", json.dumps(result))
            drain_team_outbox(settings, key_provider=key, budget=OperationBudget(10000))
            self.assertIsNone(json.loads(Path(record["receipt_path"]).read_text(encoding="utf-8"))["spool_ref"])
            self.assertEqual(len(scan_team_events(shared).events), 1)

    def test_ciphertext_release_then_deadline_keeps_delivery_proof(self):
        from ei import team_outbox
        with tempfile.TemporaryDirectory() as raw:
            settings, key, shared, record = self._ready(Path(raw))
            original, budget = team_outbox.delete_spool, OperationBudget(10000)
            def release_then_expire(*args, **kwargs):
                result = original(*args, **kwargs)
                budget.deadline = 0
                return result
            with patch("ei.team_outbox.delete_spool", side_effect=release_then_expire):
                with self.assertRaises(TimeoutError):
                    drain_team_outbox(settings, key_provider=key, budget=budget)
            self.assertEqual(json.loads(Path(record["receipt_path"]).read_text(encoding="utf-8"))["status"], "DELIVERED")
            drain_team_outbox(settings, key_provider=key, budget=OperationBudget(10000))
            self.assertIsNone(json.loads(Path(record["receipt_path"]).read_text(encoding="utf-8"))["spool_ref"])
            self.assertEqual(len(scan_team_events(shared).events), 1)

    def _ready(self, root, *, bound=False):
        settings = settings_for(root)
        key = InMemoryKeyProvider("team-outbox-test-key", b"o" * 32)
        shared = settings.paths.team_knowledge_root
        descriptor = initialize_team_store(shared, now=NOW, random_id=lambda: "0123456789abcdef")
        event = team_event("evt_a", claim="外部書込後は対象範囲を再読込して数式と値を検証する", idempotency="sha256:" + "2" * 64)
        event = replace(event, integrity_sha256=event_integrity(event))
        payload = {"event": event.to_dict(), "member_id": "member-a", "writer_id": "writer_aaaaaaaaaaaaaaaa", "idempotency_key": event.idempotency_key}
        if bound:
            payload["team_root_hash"] = domain_hash(str(shared.resolve(strict=False)), "team-root")
        record = enqueue_team_event(settings, payload, personal_event_hash="sha256:" + "3" * 64, store_id=descriptor.store_id, member_id="member-a", writer_id="writer_aaaaaaaaaaaaaaaa", key_provider=key)
        return settings, key, shared, record

    def test_interrupted_idempotency_scan_is_not_absence(self):
        with tempfile.TemporaryDirectory() as raw:
            settings, key, shared, record = self._ready(Path(raw))
            before = Path(record["receipt_path"]).read_bytes()
            with patch("ei.team_outbox.scan_team_events", side_effect=TimeoutError("OPERATION_BUDGET_EXHAUSTED")), patch("ei.team_outbox.append_team_event") as append:
                with self.assertRaises(TimeoutError):
                    drain_team_outbox(settings, key_provider=key, budget=OperationBudget(10000))
                append.assert_not_called()
            self.assertEqual(Path(record["receipt_path"]).read_bytes(), before)

    def test_append_then_timeout_reuses_event_and_receipt_precedes_spool_release(self):
        with tempfile.TemporaryDirectory() as raw:
            settings, key, shared, record = self._ready(Path(raw))
            budget = OperationBudget(10000)

            def append_then_expire(*args, **kwargs):
                result = append_team_event(*args, **kwargs)
                budget.deadline = 0
                return result

            with patch("ei.team_outbox.append_team_event", side_effect=append_then_expire):
                with self.assertRaises(TimeoutError):
                    drain_team_outbox(settings, key_provider=key, budget=budget)
            self.assertEqual(len(scan_team_events(shared).events), 1)
            from ei import team_outbox
            real_delete = team_outbox.delete_spool

            def check_delivery_before_delete(*args, **kwargs):
                self.assertEqual(json.loads(Path(record["receipt_path"]).read_text(encoding="utf-8"))["status"], "DELIVERED")
                return real_delete(*args, **kwargs)

            with patch("ei.team_outbox.delete_spool", side_effect=check_delivery_before_delete):
                result = drain_team_outbox(settings, key_provider=key, budget=OperationBudget(10000))
            self.assertEqual(result["delivered"], 1)
            self.assertEqual(result["remaining"], 0)
            self.assertEqual(len(scan_team_events(shared).events), 1)

    def test_enqueue_is_body_free_and_idempotent(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            settings = settings_for(Path(raw))
            key_provider = InMemoryKeyProvider("team-outbox-test-key", b"o" * 32)
            first = enqueue_team_event(settings, event_payload(), personal_event_hash="sha256:" + "3" * 64, store_id="team_" + "a" * 16, member_id="member-a", writer_id="writer_" + "b" * 16, key_provider=key_provider)
            second = enqueue_team_event(settings, event_payload(), personal_event_hash="sha256:" + "3" * 64, store_id="team_" + "a" * 16, member_id="member-a", writer_id="writer_" + "b" * 16, key_provider=key_provider)
            self.assertEqual(first["receipt_id"], second["receipt_id"])
            self.assertEqual(list_team_outbox(settings).count, 1)
            receipt = json.loads(Path(first["receipt_path"]).read_text(encoding="utf-8"))
            self.assertNotIn("title", receipt)
            self.assertNotIn("claim", receipt)

    def test_offline_drain_keeps_receipt_for_retry(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            settings = settings_for(Path(raw))
            key_provider = InMemoryKeyProvider("team-outbox-test-key", b"o" * 32)
            enqueue_team_event(settings, event_payload(), personal_event_hash="sha256:" + "3" * 64, store_id="team_" + "a" * 16, member_id="member-a", writer_id="writer_" + "b" * 16, key_provider=key_provider)
            result = drain_team_outbox(settings, key_provider=key_provider)
            self.assertEqual(result["status"], "DEFERRED")
            self.assertEqual(list_team_outbox(settings).count, 1)

    def test_saved_team_root_binding_prevents_outbox_redirect(self):
        with tempfile.TemporaryDirectory() as raw:
            base = Path(raw)
            settings = settings_for(base)
            key = InMemoryKeyProvider("team-outbox-test-key", b"o" * 32)
            original_root = settings.paths.team_knowledge_root
            descriptor = initialize_team_store(original_root, now=NOW, random_id=lambda: "0123456789abcdef")
            event = team_event("evt_a", claim="外部書込後は対象範囲を再読込して数式と値を検証する", idempotency="sha256:" + "2" * 64)
            event = replace(event, integrity_sha256=event_integrity(event))
            root_hash = domain_hash(str(original_root.resolve(strict=False)), "team-root")
            record = enqueue_team_event(
                settings,
                {
                    "event": event.to_dict(), "member_id": "member-a", "writer_id": "writer_aaaaaaaaaaaaaaaa",
                    "idempotency_key": event.idempotency_key, "team_root_hash": root_hash,
                },
                personal_event_hash="sha256:" + "3" * 64,
                store_id=descriptor.store_id,
                member_id="member-a",
                writer_id="writer_aaaaaaaaaaaaaaaa",
                key_provider=key,
            )
            receipt = read_team_outbox_receipt(settings, str(record["receipt_id"]))
            self.assertEqual(receipt["team_root_hash"], root_hash)

            changed_root = base / "other-team"
            initialize_team_store(changed_root, now=NOW, random_id=lambda: "fedcba9876543210")
            settings = replace(settings, paths=replace(settings.paths, team_knowledge_root=changed_root))
            result = drain_team_outbox(settings, key_provider=key, budget=OperationBudget(10000))

            saved = read_team_outbox_receipt(settings, str(record["receipt_id"]))
            self.assertEqual(result["deferred"], 1)
            self.assertEqual(saved["last_error_code"], "TEAM_TARGET_BINDING_CHANGED")
            self.assertEqual(scan_team_events(changed_root).events, ())
            self.assertEqual(list_team_outbox(settings).count, 1)

    def test_same_path_replaced_store_id_stays_deferred_with_ciphertext(self):
        import shutil
        from ei.spool import read_spool

        with tempfile.TemporaryDirectory() as raw:
            base = Path(raw)
            settings, key, shared, record = self._ready(base, bound=True)
            replacement = base / "replacement-team"
            initialize_team_store(replacement, now=NOW, random_id=lambda: "fedcba9876543210")
            shutil.copyfile(replacement / "team-manifest.json", shared / "team-manifest.json")

            result = drain_team_outbox(settings, key_provider=key, budget=OperationBudget(10000))

            saved = read_team_outbox_receipt(settings, str(record["receipt_id"]))
            self.assertEqual(result["status"], "DEFERRED")
            self.assertEqual((result["delivered"], result["deferred"], result["remaining"]), (0, 1, 1))
            self.assertEqual(saved["status"], "DEFERRED")
            self.assertEqual(saved["last_error_code"], "TEAM_TARGET_BINDING_CHANGED")
            self.assertEqual(saved["spool_ref"], record["spool_ref"])
            self.assertEqual(scan_team_events(shared).events, ())
            retained = json.loads(read_spool(saved["spool_ref"], settings, key_provider=key).decode("utf-8"))
            self.assertEqual(retained["member_id"], "member-a")
            self.assertEqual(retained["writer_id"], "writer_aaaaaaaaaaaaaaaa")

    def test_saved_member_and_writer_hashes_must_match_encrypted_event(self):
        from ei.spool import read_spool

        for field, value, domain in (
            ("member_id_hash", "member-b", "team-member-id"),
            ("writer_id_hash", "writer_cccccccccccccccc", "team-writer-id"),
        ):
            with self.subTest(field=field), tempfile.TemporaryDirectory() as raw:
                settings, key, shared, record = self._ready(Path(raw), bound=True)
                receipt_path = Path(record["receipt_path"])
                receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
                receipt[field] = domain_hash(value, domain)
                receipt_path.write_text(json.dumps(receipt, sort_keys=True), encoding="utf-8")

                result = drain_team_outbox(settings, key_provider=key, budget=OperationBudget(10000))

                saved = read_team_outbox_receipt(settings, str(record["receipt_id"]))
                self.assertEqual(result["status"], "DEFERRED")
                self.assertEqual((result["delivered"], result["deferred"]), (0, 1))
                self.assertEqual(saved["last_error_code"], "TEAM_TARGET_BINDING_CHANGED")
                self.assertEqual(saved["spool_ref"], record["spool_ref"])
                self.assertEqual(scan_team_events(shared).events, ())
                retained = json.loads(read_spool(saved["spool_ref"], settings, key_provider=key).decode("utf-8"))
                self.assertEqual(retained["member_id"], "member-a")
                self.assertEqual(retained["writer_id"], "writer_aaaaaaaaaaaaaaaa")

    def test_replaced_store_identity_does_not_release_delivered_ciphertext(self):
        import shutil

        with tempfile.TemporaryDirectory() as raw:
            base = Path(raw)
            settings, key, shared, record = self._ready(base, bound=True)
            with patch("ei.team_outbox.delete_spool", side_effect=OSError("private path")):
                delivered = drain_team_outbox(settings, key_provider=key, budget=OperationBudget(10000))
            self.assertEqual(delivered["delivered"], 1)
            saved_before = read_team_outbox_receipt(settings, str(record["receipt_id"]))
            self.assertEqual(saved_before["status"], "DELIVERED")
            self.assertEqual(saved_before["spool_ref"], record["spool_ref"])
            event_snapshot = tuple(scan_team_events(shared).events)

            replacement = base / "replacement-team"
            initialize_team_store(replacement, now=NOW, random_id=lambda: "fedcba9876543210")
            shutil.copyfile(replacement / "team-manifest.json", shared / "team-manifest.json")
            with patch("ei.team_outbox.delete_spool") as delete:
                result = drain_team_outbox(settings, key_provider=key, budget=OperationBudget(10000))
                delete.assert_not_called()

            saved_after = read_team_outbox_receipt(settings, str(record["receipt_id"]))
            self.assertEqual(result["errors"][0]["reason_code"], "TEAM_TARGET_BINDING_CHANGED")
            self.assertEqual(saved_after["status"], "DELIVERED")
            self.assertEqual(saved_after["spool_ref"], record["spool_ref"])
            self.assertEqual(tuple(scan_team_events(shared).events), event_snapshot)


if __name__ == "__main__":
    unittest.main()
