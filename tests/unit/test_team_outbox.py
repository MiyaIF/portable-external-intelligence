import json
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace

from ei.config import RuntimePaths, Settings
from ei.inference.base import ProviderResult
from ei.key_provider import InMemoryKeyProvider
from ei.team_outbox import drain_team_outbox, enqueue_team_event, list_team_outbox


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


if __name__ == "__main__":
    unittest.main()
