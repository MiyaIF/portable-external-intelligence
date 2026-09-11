import json
import tempfile
from dataclasses import replace
from datetime import datetime, timezone
from pathlib import Path
import unittest
from unittest import mock

from ei.journal import JournalIntegrityError, append_event, iter_events
from ei.models import Event


class JournalTests(unittest.TestCase):
    def test_append_is_atomic_idempotent_and_integrity_checked(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            event = Event.create(
                event_id="evt_20260825T000000000000Z_mach12345678_rnd123456789",
                event_type="observation.recorded",
                occurred_at="2026-08-25T00:00:00Z",
                actor="test",
                machine_id="mach12345678",
                payload={"observation_id": "obs_1", "claim": "rule"},
            )
            path = append_event(event, root)
            self.assertTrue(path.exists())
            self.assertEqual(append_event(event, root), path)
            self.assertEqual(len(list(iter_events(root))), 1)
            raw = json.loads(path.read_text(encoding="utf-8"))
            raw["payload"]["claim"] = "tampered"
            path.write_text(json.dumps(raw), encoding="utf-8")
            with self.assertRaises(JournalIntegrityError):
                list(iter_events(root))

    def test_event_path_is_partitioned_by_year_and_month(self):
        with tempfile.TemporaryDirectory() as tmp:
            event = Event.create(
                event_id="evt_20260115T120000000000Z_mach12345678_rnd123456789",
                event_type="health.snapshot",
                occurred_at="2026-01-15T12:00:00Z",
                actor="test",
                machine_id="mach12345678",
                payload={"status": "ok"},
            )
            path = append_event(event, Path(tmp))
            self.assertEqual(path.parent.name, "01")
            self.assertEqual(path.parent.parent.name, "2026")

    def test_v2_event_has_idempotency_provenance_and_integrity(self):
        event = Event.create_v2(
            event_type="observation.recorded",
            actor="host:test",
            machine_id="machine-a",
            payload={"claim": "reusable rule", "source_hash": "sha256:" + "1" * 64},
            occurred_at=datetime(2026, 8, 26, tzinfo=timezone.utc),
        )
        self.assertEqual(event.schema_version, 2)
        self.assertRegex(event.idempotency_key, r"^sha256:[0-9a-f]{64}$")
        self.assertEqual(event.provenance, ())
        self.assertEqual(event.integrity["algorithm"], "sha256")
        self.assertRegex(event.integrity["canonical_payload_hash"], r"^sha256:[0-9a-f]{64}$")

    def test_v1_event_remains_readable_without_rewrite(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            event = Event.create(
                event_id="evt_20260825T000000000000Z_mach12345678_rnd123456789",
                event_type="health.snapshot",
                occurred_at="2026-08-25T00:00:00Z",
                actor="test",
                machine_id="mach12345678",
                payload={"status": "ok"},
            )
            path = append_event(event, root)
            before = path.read_bytes()
            loaded = list(iter_events(root))
            self.assertEqual(loaded, [Event.from_dict(json.loads(before))])
            self.assertEqual(path.read_bytes(), before)
            self.assertEqual(loaded[0].schema_version, 1)

    def test_v2_default_idempotency_key_distinguishes_legitimate_recurring_events(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            first = Event.create_v2(
                "observation.recorded",
                "host:test",
                "machine-a",
                {"claim": "same"},
                occurred_at=datetime(2026, 8, 26, 0, 0, tzinfo=timezone.utc),
            )
            second = Event.create_v2(
                "observation.recorded",
                "host:test",
                "machine-a",
                {"claim": "same"},
                occurred_at=datetime(2026, 8, 26, 0, 5, tzinfo=timezone.utc),
            )

            self.assertNotEqual(first.idempotency_key, second.idempotency_key)
            first_path = append_event(first, root)
            second_path = append_event(second, root)
            self.assertNotEqual(first_path, second_path)
            self.assertEqual(len(list(iter_events(root))), 2)

            replay = replace(first, event_id="evt_20260826T000000000000Z_deadbeef9999")
            self.assertEqual(append_event(replay, root), first_path)
            self.assertEqual(len(list(iter_events(root))), 2)

    def test_v2_idempotency_reuses_same_content_and_rejects_collision(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            occurred_at = datetime(2026, 8, 26, tzinfo=timezone.utc)
            first = Event.create_v2(
                "observation.recorded",
                "host:test",
                "machine-a",
                {"claim": "same"},
                occurred_at=occurred_at,
                idempotency_key="sha256:" + "a" * 64,
            )
            duplicate = Event.create_v2(
                "observation.recorded",
                "host:test",
                "machine-a",
                {"claim": "same"},
                occurred_at=occurred_at,
                idempotency_key="sha256:" + "a" * 64,
            )
            first_path = append_event(first, root)
            self.assertEqual(append_event(duplicate, root), first_path)
            self.assertEqual(len(list(iter_events(root))), 1)

            collision = Event.create_v2(
                "observation.recorded",
                "host:test",
                "machine-a",
                {"claim": "different"},
                occurred_at=occurred_at,
                idempotency_key="sha256:" + "a" * 64,
            )
            with self.assertRaisesRegex(JournalIntegrityError, "^EVENT_ID_COLLISION"):
                append_event(collision, root)

    def test_interrupted_atomic_replace_removes_same_directory_temporary_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            event = Event.create_v2(
                "health.snapshot",
                "host:test",
                "machine-a",
                {"status": "ok"},
                occurred_at=datetime(2026, 8, 26, tzinfo=timezone.utc),
            )

            def fail_replace(source, target):
                self.assertEqual(Path(source).parent, Path(target).parent)
                raise OSError("simulated interruption")

            with mock.patch("ei.journal.os.replace", side_effect=fail_replace):
                with self.assertRaises(OSError):
                    append_event(event, root)
            self.assertEqual(list(root.rglob("*.tmp")), [])
            self.assertEqual(list(root.rglob("*.json")), [])

    def test_v2_rejects_invalid_supplied_integrity_before_write(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            event = Event.create_v2(
                "health.snapshot",
                "host:test",
                "machine-a",
                {"status": "ok"},
                occurred_at=datetime(2026, 8, 26, tzinfo=timezone.utc),
            )

            invalid_algorithm = replace(
                event,
                integrity={
                    "algorithm": "sha999",
                    "canonical_payload_hash": event.integrity["canonical_payload_hash"],
                },
            )
            with self.assertRaisesRegex(JournalIntegrityError, "^EVENT_SCHEMA_INVALID:integrity.algorithm"):
                append_event(invalid_algorithm, root)
            self.assertEqual(list(root.rglob("*.json")), [])

            invalid_hash = replace(
                event,
                integrity={
                    "algorithm": "sha256",
                    "canonical_payload_hash": "sha256:" + "0" * 64,
                },
            )
            with self.assertRaisesRegex(JournalIntegrityError, "^EVENT_INTEGRITY_INVALID:canonical_payload_hash"):
                append_event(invalid_hash, root)
            self.assertEqual(list(root.rglob("*.json")), [])

    def test_v2_stable_schema_integrity_and_payload_size_errors(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            invalid = Event.create_v2(
                "",
                "host:test",
                "machine-a",
                {"status": "ok"},
                occurred_at=datetime(2026, 8, 26, tzinfo=timezone.utc),
            )
            with self.assertRaisesRegex(JournalIntegrityError, "^EVENT_SCHEMA_INVALID"):
                append_event(invalid, root)

            oversized = Event.create_v2(
                "health.snapshot",
                "host:test",
                "machine-a",
                {"body": "x" * (1024 * 1024 + 1)},
                occurred_at=datetime(2026, 8, 26, tzinfo=timezone.utc),
            )
            with self.assertRaisesRegex(JournalIntegrityError, "^EVENT_PAYLOAD_TOO_LARGE"):
                append_event(oversized, root)

    def test_generic_event_rejects_unknown_raw_note_and_plain_session_identifier(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            raw_note = Event.create(
                "health.snapshot",
                "2026-08-26T00:00:00Z",
                "host:test",
                "machine-a",
                {"status": "ok", "note": "verbatim operator conversation"},
                event_id="evt_health_raw_note",
            )
            with self.assertRaisesRegex(JournalIntegrityError, r"EVENT_PRIVACY_INVALID:/note:UNKNOWN_FIELD"):
                append_event(raw_note, root)

            plain_session = Event.create(
                "health.snapshot",
                "2026-08-26T00:00:00Z",
                "host:test",
                "machine-a",
                {"status": "ok", "session_id": "live-session-123"},
                event_id="evt_health_plain_session",
            )
            with self.assertRaisesRegex(JournalIntegrityError, r"EVENT_PRIVACY_INVALID:/session_id:UNKNOWN_FIELD"):
                append_event(plain_session, root)

            self.assertEqual(list(root.rglob("*.json")), [])


if __name__ == "__main__":
    unittest.main()
