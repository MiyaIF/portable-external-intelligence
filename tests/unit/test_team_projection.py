from __future__ import annotations

import json
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path

from ei.models import Event
from ei.team_projection import refresh_team_projection, team_cache_paths
from ei.team_store import TeamEventScan, append_team_event, initialize_team_store


NOW = datetime(2026, 9, 5, tzinfo=timezone.utc)


def team_event(event_id: str, *, claim: str, idempotency: str) -> Event:
    return Event.create_v2(
        "team.knowledge.recorded",
        actor="team-member-hash",
        machine_id="team-machine-hash",
        occurred_at=NOW,
        idempotency_key=idempotency,
        payload={
            "knowledge_scope": "team",
            "origin_event_hash": "sha256:" + event_id[-1] * 64,
            "idempotency_key": idempotency,
            "title": "Team rule",
            "claim": claim,
            "scope": ["spreadsheet"],
            "preconditions": ["同じ問題構造が再発している"],
            "failure_modes": ["検証を省略して再作業になる"],
            "benefit": "reduced_rework",
            "classification": "private-reusable",
        },
    )


class TeamProjectionTests(unittest.TestCase):
    def test_paths_and_projection_are_local_and_rebuildable(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            shared = root / "shared"
            runtime = root / "runtime"
            descriptor = initialize_team_store(shared, now=NOW, random_id=lambda: "0123456789abcdef")
            event = team_event(
                "evt_20260905T000000000000Z_aaaaaaaaaaaa",
                claim="同じ案件では前回の検証手順を再利用し、変更点だけを追加確認する",
                idempotency="sha256:" + "1" * 64,
            )
            append_team_event(shared, "member-a", "writer_aaaaaaaaaaaaaaaa", event)

            paths = team_cache_paths(runtime, descriptor.store_id)
            self.assertEqual(paths.root, runtime / "team-cache" / descriptor.store_id)
            self.assertEqual(paths.knowledge_dir, paths.root / "knowledge")
            result = refresh_team_projection(shared, runtime, descriptor.store_id)

            self.assertEqual(result.status, "UPDATED")
            self.assertIsNotNone(result.index)
            assert result.index is not None
            self.assertEqual(len(result.index.active_pattern_ids), 1)
            self.assertTrue(result.knowledge_dir.is_dir())
            cursor = json.loads(paths.cursor_path.read_text(encoding="utf-8"))
            self.assertEqual(
                set(cursor),
                {"schema_version", "store_id", "last_total_order_key", "accepted_event_count", "projection_hash", "issue_counts"},
            )
            self.assertEqual(cursor["store_id"], descriptor.store_id)
            self.assertEqual(cursor["accepted_event_count"], 1)
            self.assertNotIn(str(shared), paths.cursor_path.read_text(encoding="utf-8"))

    def test_conflicting_idempotency_key_is_excluded_as_a_group(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            shared = root / "shared"
            descriptor = initialize_team_store(shared, now=NOW, random_id=lambda: "0123456789abcdef")
            conflict_key = "sha256:" + "2" * 64
            append_team_event(
                shared,
                "member-a",
                "writer_aaaaaaaaaaaaaaaa",
                team_event("evt_20260905T000000000000Z_bbbbbbbbbbbb", claim="最初の説明を使うが、内容が違うため衝突として扱う", idempotency=conflict_key),
            )
            append_team_event(
                shared,
                "member-a",
                "writer_aaaaaaaaaaaaaaaa",
                team_event("evt_20260905T000100000000Z_cccccccccccc", claim="別の説明を使うため同じキーの衝突として除外する", idempotency=conflict_key),
            )
            append_team_event(
                shared,
                "member-a",
                "writer_aaaaaaaaaaaaaaaa",
                team_event("evt_20260905T000200000000Z_dddddddddddd", claim="衝突していない有効な知識はローカル投影へ取り込む", idempotency="sha256:" + "3" * 64),
            )

            result = refresh_team_projection(shared, root / "runtime", descriptor.store_id)
            codes = {str(issue["code"]) for issue in result.issues}
            self.assertIn("TEAM_IDEMPOTENCY_CONFLICT", codes)
            self.assertIsNotNone(result.index)
            assert result.index is not None
            self.assertEqual(len(result.index.active_pattern_ids), 1)

    def test_offline_refresh_keeps_last_known_good_cache(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            shared = root / "shared"
            runtime = root / "runtime"
            descriptor = initialize_team_store(shared, now=NOW, random_id=lambda: "0123456789abcdef")
            append_team_event(
                shared,
                "member-a",
                "writer_aaaaaaaaaaaaaaaa",
                team_event("evt_20260905T000000000000Z_eeeeeeeeeeee", claim="オフライン前に作成した有効なチーム知識を保持する", idempotency="sha256:" + "4" * 64),
            )
            first = refresh_team_projection(shared, runtime, descriptor.store_id)
            self.assertIsNotNone(first.index)
            shared.rename(root / "shared-offline")

            second = refresh_team_projection(shared, runtime, descriptor.store_id)
            self.assertEqual(second.status, "UNAVAILABLE")
            self.assertEqual(second.issues[0]["code"], "TEAM_KNOWLEDGE_UNAVAILABLE")
            self.assertIsNotNone(second.index)
            assert second.index is not None and first.index is not None
            self.assertEqual(second.index.manifest_sha256, first.index.manifest_sha256)

    def test_scan_double_is_called_once_and_incremental_refresh_reuses_cache(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            shared = root / "shared"
            runtime = root / "runtime"
            descriptor = initialize_team_store(shared, now=NOW, random_id=lambda: "0123456789abcdef")
            event = team_event(
                "evt_20260905T000000000000Z_ffffffffffff",
                claim="一度投影した同じ共有イベントは再度の投影処理を実行しない",
                idempotency="sha256:" + "5" * 64,
            )
            calls = 0

            def scan_double(_root: Path | str) -> TeamEventScan:
                nonlocal calls
                calls += 1
                return TeamEventScan((event,), ())

            first = refresh_team_projection(shared, runtime, descriptor.store_id, scan_fn=scan_double)
            second = refresh_team_projection(shared, runtime, descriptor.store_id, scan_fn=scan_double)
            self.assertEqual(calls, 2)
            self.assertEqual(second.status, "UNCHANGED")
            self.assertIsNotNone(first.index)
            self.assertIsNotNone(second.index)
            assert first.index is not None and second.index is not None
            self.assertEqual(first.index.manifest_sha256, second.index.manifest_sha256)


if __name__ == "__main__":
    unittest.main()
