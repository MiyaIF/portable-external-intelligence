from __future__ import annotations

import json
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import patch

from dataclasses import replace

from ei.journal import event_integrity
from ei.models import Event
from ei.team_store import (
    append_team_event,
    initialize_team_store,
    inspect_team_store,
    load_or_create_writer_identity,
    scan_team_events,
    writer_identity_path,
)


NOW = datetime(2026, 9, 5, tzinfo=timezone.utc)


def team_event(event_id: str, claim: str = "rule") -> Event:
    event = Event.create_v2(
        event_type="team.knowledge.recorded",
        actor="team:member-a",
        machine_id="machine-hash",
        payload={
            "knowledge_scope": "team",
            "origin_event_hash": "sha256:" + "1" * 64,
            "idempotency_key": "sha256:" + "2" * 64,
            "title": "Reusable rule",
            "claim": f"{claim} is a reusable team rule with enough detail",
            "scope": ["general"],
            "preconditions": [],
            "failure_modes": [],
            "benefit": "reduced_rework",
            "classification": "private-reusable",
        },
        occurred_at=NOW,
    )
    event = replace(event, event_id=event_id)
    return replace(event, integrity_sha256=event_integrity(event))


def initialized_team_root(root: Path):
    return initialize_team_store(root, now=NOW, random_id=lambda: "0123456789abcdef")


class TeamStoreTests(unittest.TestCase):
    def test_team_event_rejects_personal_path_before_append(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = initialized_team_root(Path(raw) / "shared team").root
            unsafe = team_event(
                "evt_20260905T000000000000Z_ffffffffffff",
                claim="Reuse the private path " + "C:" + r"\Users\alice\client-secrets in every project",
            )

            with self.assertRaisesRegex(ValueError, "^TEAM_EVENT_PRIVACY_INVALID$"):
                append_team_event(root, "member-a", "writer_aaaaaaaaaaaaaaaa", unsafe)

    def test_initialize_empty_store_is_idempotent_and_contains_no_events(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw) / "shared team"
            descriptor = initialized_team_root(root)
            self.assertEqual(descriptor.store_id, "team_0123456789abcdef")
            self.assertEqual(descriptor.layout, "member-writer-events-v1")
            self.assertEqual(descriptor.event_schema_version, 2)
            self.assertEqual(inspect_team_store(root), descriptor)
            scan = scan_team_events(root)
            self.assertEqual(scan.events, ())
            self.assertEqual(scan.issues, ())

            manifest_before = (root / "team-manifest.json").read_bytes()
            self.assertEqual(initialize_team_store(root, now=NOW, random_id=lambda: "fedcba9876543210"), descriptor)
            self.assertEqual((root / "team-manifest.json").read_bytes(), manifest_before)

    def test_non_empty_unknown_root_is_rejected_without_mutation(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw) / "shared team"
            root.mkdir()
            unknown = root / "do-not-touch.txt"
            unknown.write_text("existing", encoding="utf-8")
            before = unknown.read_bytes()
            with self.assertRaisesRegex(ValueError, "^TEAM_ROOT_CONTRACT_INVALID$"):
                initialize_team_store(root, now=NOW, random_id=lambda: "0123456789abcdef")
            self.assertEqual(unknown.read_bytes(), before)
            self.assertEqual(sorted(path.name for path in root.iterdir()), ["do-not-touch.txt"])

    def test_writer_identity_is_machine_local_and_stable(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            runtime = Path(raw) / "runtime"
            store_id = "team_0123456789abcdef"
            first = load_or_create_writer_identity(runtime, store_id, random_id=lambda: "abcdef0123456789")
            second = load_or_create_writer_identity(runtime, store_id, random_id=lambda: "0000000000000000")
            self.assertEqual(first, "writer_abcdef0123456789")
            self.assertEqual(second, first)
            identity = writer_identity_path(runtime, store_id)
            self.assertTrue(identity.is_file())
            self.assertEqual(json.loads(identity.read_text(encoding="utf-8"))["store_id"], store_id)

    def test_two_writers_have_independent_shards(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = initialized_team_root(Path(raw) / "shared team").root
            first = append_team_event(root, "member-a", "writer_aaaaaaaaaaaaaaaa", team_event("evt_20260905T000000000000Z_aaaaaaaaaaaa"))
            second = append_team_event(root, "member-a", "writer_bbbbbbbbbbbbbbbb", team_event("evt_20260905T000100000000Z_bbbbbbbbbbbb"))
            self.assertNotEqual(first, second)
            self.assertEqual(
                first.relative_to(root).parts[:5],
                ("members", "member-a", "writers", "writer_aaaaaaaaaaaaaaaa", "events"),
            )
            self.assertEqual(
                second.relative_to(root).parts[:5],
                ("members", "member-a", "writers", "writer_bbbbbbbbbbbbbbbb", "events"),
            )

    def test_event_id_hash_conflict_preserves_original(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw) / "shared team"
            initialized_team_root(root)
            event_id = "evt_20260905T000000000000Z_cccccccccccc"
            original = team_event(event_id, claim="first")
            conflicting = team_event(event_id, claim="second")
            target = append_team_event(root, "member-a", "writer_aaaaaaaaaaaaaaaa", original)
            before = target.read_bytes()
            self.assertEqual(append_team_event(root, "member-a", "writer_aaaaaaaaaaaaaaaa", original), target)
            with self.assertRaisesRegex(ValueError, "^TEAM_EVENT_ID_CONFLICT$"):
                append_team_event(root, "member-a", "writer_aaaaaaaaaaaaaaaa", conflicting)
            self.assertEqual(target.read_bytes(), before)

    def test_scan_reports_partial_and_invalid_files_but_keeps_valid_events(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw) / "shared team"
            initialized_team_root(root)
            valid = append_team_event(
                root,
                "member-a",
                "writer_aaaaaaaaaaaaaaaa",
                team_event("evt_20260905T000000000000Z_dddddddddddd"),
            )
            valid.parent.joinpath(".partial-write").write_text("{", encoding="utf-8")
            valid.parent.joinpath("event.json (Conflict)").write_text("{}", encoding="utf-8")
            valid.parent.joinpath("invalid.json").write_text("{not-json", encoding="utf-8")
            scan = scan_team_events(root)
            self.assertEqual([event.event_id for event in scan.events], ["evt_20260905T000000000000Z_dddddddddddd"])
            codes = {str(issue["code"]) for issue in scan.issues}
            self.assertTrue({"TEAM_PARTIAL_FILE", "TEAM_CONFLICT_COPY", "TEAM_EVENT_INVALID"}.issubset(codes))

    def test_store_id_mismatch_does_not_change_manifest(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw) / "shared team"
            initialized_team_root(root)
            manifest = root / "team-manifest.json"
            before = manifest.read_bytes()
            with self.assertRaisesRegex(ValueError, "^TEAM_STORE_ID_MISMATCH$"):
                inspect_team_store(root, expected_store_id="team_fedcba9876543210")
            self.assertEqual(manifest.read_bytes(), before)

    def test_member_and_writer_identifiers_are_closed(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw) / "shared team"
            initialized_team_root(root)
            event = team_event("evt_20260905T000000000000Z_eeeeeeeeeeee")
            with self.assertRaisesRegex(ValueError, "^TEAM_MEMBER_ID_INVALID$"):
                append_team_event(root, "Member A", "writer_aaaaaaaaaaaaaaaa", event)
            with self.assertRaisesRegex(ValueError, "^TEAM_WRITER_ID_INVALID$"):
                append_team_event(root, "member-a", "writer_bad", event)


if __name__ == "__main__":
    unittest.main()
