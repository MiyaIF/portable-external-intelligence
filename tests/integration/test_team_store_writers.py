from __future__ import annotations

import concurrent.futures
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path
from threading import Barrier
from dataclasses import replace

from ei.journal import event_integrity
from ei.models import Event
from ei.team_store import append_team_event, initialize_team_store, scan_team_events


NOW = datetime(2026, 9, 5, tzinfo=timezone.utc)


def team_event(event_id: str) -> Event:
    event = Event.create_v2(
        event_type="team.knowledge.recorded",
        actor="team:member-a",
        machine_id="machine-hash",
        payload={
            "knowledge_scope": "team",
            "origin_event_hash": "sha256:" + "1" * 64,
            "idempotency_key": "sha256:" + "2" * 64,
            "title": "Concurrent rule",
            "claim": "Concurrent writers keep their own append-only shards isolated",
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


class TeamStoreWriterIntegrationTests(unittest.TestCase):
    def test_two_concurrent_writers_never_edit_the_same_path(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw) / "shared team"
            descriptor = initialize_team_store(root, now=NOW, random_id=lambda: "0123456789abcdef")
            barrier = Barrier(2)

            def write(member: str, writer: str, event_id: str):
                barrier.wait()
                return append_team_event(root, member, writer, team_event(event_id))

            with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
                futures = (
                    pool.submit(write, "member-a", "writer_aaaaaaaaaaaaaaaa", "evt_20260905T010000000000Z_aaaaaaaaaaaa"),
                    pool.submit(write, "member-a", "writer_bbbbbbbbbbbbbbbb", "evt_20260905T010100000000Z_bbbbbbbbbbbb"),
                )
                first, second = (future.result() for future in futures)

            self.assertNotEqual(first, second)
            self.assertTrue(first.is_file())
            self.assertTrue(second.is_file())
            self.assertNotIn("partial", first.read_text(encoding="utf-8"))
            self.assertNotIn("partial", second.read_text(encoding="utf-8"))
            self.assertEqual(descriptor.store_id, "team_0123456789abcdef")
            self.assertEqual(len(scan_team_events(root).events), 2)


if __name__ == "__main__":
    unittest.main()
