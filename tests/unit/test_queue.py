import json
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import patch

from ei.hooks.registry import normalize_hook_event
from ei.key_provider import InMemoryKeyProvider
from ei.queue import (
    QueueError,
    QueueItem,
    QueueState,
    claim_queue_item,
    enqueue_receipt,
    queue_health,
    read_queue_item,
    recover_emergency_spool,
    write_emergency_envelope,
    transition_queue_item,
)
from ei.spool import read_spool, write_spool
from ei.config import RuntimePaths, Settings
from ei.setup_contract import OrganizerSelection


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


def make_event(settings, event_name="Stop", turn_id="t1"):
    return normalize_hook_event(
        "codex-cli",
        {"hook_event_name": event_name, "session_id": "s1", "turn_id": turn_id, "cwd": "C:/work"},
        settings,
    )


class QueueTests(unittest.TestCase):
    def test_legacy_source_host_omission_is_read_without_rewriting_or_reprocessing(self):
        for state in ("NO_DISCARDED", "DONE"):
            with self.subTest(state=state), tempfile.TemporaryDirectory() as tmp:
                settings = make_isolated_hook_settings(Path(tmp))
                item = enqueue_receipt(make_event(settings), None, settings, now=NOW)
                raw = item.to_dict()
                raw.pop("source_host_id")
                raw.pop("source_host_family")
                raw["state"] = state
                path = settings.paths.queue_dir / f"{item.queue_id}.json"
                path.write_text(json.dumps(raw), encoding="utf-8")
                before = path.read_bytes(), path.stat().st_mtime_ns
                try:
                    loaded = read_queue_item(item.queue_id, settings)
                except QueueError as exc:
                    self.fail(f"valid legacy queue rejected: {exc}")
                self.assertEqual(loaded.source_host_id, "")
                self.assertNotIn("source_host_id", loaded.to_dict())
                self.assertEqual(queue_health(settings).corrupt, 0)
                self.assertIsNone(claim_queue_item("worker", settings, NOW))
                self.assertEqual((path.read_bytes(), path.stat().st_mtime_ns), before)

    def test_explicit_invalid_source_host_is_not_hidden_as_legacy(self):
        with tempfile.TemporaryDirectory() as tmp:
            settings = make_isolated_hook_settings(Path(tmp))
            raw = enqueue_receipt(make_event(settings), None, settings, now=NOW).to_dict()
            for fields in ({"source_host_id": "", "source_host_family": ""},
                           {"source_host_id": None, "source_host_family": None},
                           {"source_host_id": "codex-cli"},
                           {"source_host_family": "codex-cli"}):
                with self.subTest(fields=fields):
                    value = {k: v for k, v in raw.items()
                             if k not in {"source_host_id", "source_host_family"}}
                    value.update(fields)
                    with self.assertRaises(QueueError):
                        QueueItem.from_dict(value)

    def test_payload_is_durable_before_queue_receipt(self):
        with tempfile.TemporaryDirectory() as tmp:
            settings = make_isolated_hook_settings(Path(tmp))
            key = InMemoryKeyProvider("queue-key", b"q" * 32)
            ref = write_spool("durable before queue", "private-reusable", settings, key_provider=key, now=NOW, spool_id="spool-queue")
            item = enqueue_receipt(make_event(settings), ref, settings, now=NOW)
            self.assertTrue((settings.paths.spool_dir / "spool-queue.json").exists())
            self.assertTrue((settings.paths.queue_dir / f"{item.queue_id}.json").exists())
            self.assertEqual(read_spool(ref, settings, key_provider=key, now=NOW + timedelta(seconds=1)), b"durable before queue")

    def test_idempotent_replay_reuses_same_queue_item_and_collision_is_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            settings = make_isolated_hook_settings(Path(tmp))
            key = InMemoryKeyProvider("queue-key", b"q" * 32)
            event = make_event(settings)
            first_ref = write_spool("first", "private-reusable", settings, key_provider=key, now=NOW, spool_id="spool-first")
            first = enqueue_receipt(event, first_ref, settings, now=NOW)
            replay = enqueue_receipt(event, first_ref, settings, now=NOW + timedelta(seconds=1))
            self.assertEqual(replay.queue_id, first.queue_id)
            second_ref = write_spool("second", "private-reusable", settings, key_provider=key, now=NOW, spool_id="spool-second")
            with self.assertRaisesRegex(QueueError, "IDEMPOTENCY_COLLISION"):
                enqueue_receipt(event, second_ref, settings, now=NOW + timedelta(seconds=2))

    def test_claim_lease_stale_reclaim_and_transition(self):
        with tempfile.TemporaryDirectory() as tmp:
            settings = make_isolated_hook_settings(Path(tmp))
            item = enqueue_receipt(make_event(settings), None, settings, now=NOW)
            claimed = claim_queue_item("worker-a", settings, NOW, lease_seconds=1)
            self.assertEqual(claimed.state, QueueState.IN_PROGRESS)
            self.assertEqual(claimed.attempts, 1)
            reclaimed = claim_queue_item("worker-b", settings, NOW + timedelta(seconds=2), lease_seconds=10)
            self.assertEqual(reclaimed.state, QueueState.IN_PROGRESS)
            self.assertEqual(reclaimed.attempts, 2)
            done = transition_queue_item(reclaimed, QueueState.DONE, settings, now=NOW + timedelta(seconds=3), reason_code="APPLIED")
            self.assertEqual(done.state, QueueState.DONE)
            self.assertIsNone(claim_queue_item("worker-c", settings, NOW + timedelta(seconds=4)))

    def test_quota_transition_retains_spool_reference(self):
        with tempfile.TemporaryDirectory() as tmp:
            settings = make_isolated_hook_settings(Path(tmp))
            key = InMemoryKeyProvider("queue-key", b"q" * 32)
            ref = write_spool("quota candidate", "private-reusable", settings, key_provider=key, now=NOW, spool_id="spool-quota")
            item = enqueue_receipt(make_event(settings), ref, settings, now=NOW)
            updated = transition_queue_item(item, QueueState.DEFERRED_QUOTA, settings, now=NOW, reason_code="DEFERRED_QUOTA", next_eligible_at=NOW + timedelta(minutes=5))
            self.assertEqual(updated.state, QueueState.DEFERRED_QUOTA)
            self.assertIsNotNone(updated.payload_ref)
            self.assertEqual(read_spool(ref, settings, key_provider=key, now=NOW + timedelta(minutes=1)), b"quota candidate")

    def test_new_queue_item_records_only_the_selected_organizer(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = make_isolated_hook_settings(Path(tmp))
            settings = Settings(
                paths=base.paths,
                organizer=OrganizerSelection("READY", "ollama", None),
                provider_order=("ollama", "subscription-cli"),
            )
            item = enqueue_receipt(make_event(settings), None, settings, now=NOW)
            self.assertEqual(item.provider_preference, ("ollama",))

    def test_claim_rewrites_legacy_multi_provider_preference_to_current_organizer(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = make_isolated_hook_settings(Path(tmp))
            old_settings = Settings(
                paths=base.paths,
                organizer=OrganizerSelection("READY", "ollama", None),
                provider_order=("ollama", "subscription-cli"),
            )
            item = enqueue_receipt(make_event(old_settings, turn_id="legacy-organizer"), None, old_settings, now=NOW)
            path = old_settings.paths.queue_dir / f"{item.queue_id}.json"
            raw = item.to_dict()
            raw["provider_preference"] = ["ollama", "subscription-cli"]
            path.write_text(json.dumps(raw), encoding="utf-8")

            current_settings = Settings(
                paths=base.paths,
                organizer=OrganizerSelection("READY", "subscription-cli", "codex-cli"),
                provider_order=("subscription-cli",),
            )
            claimed = claim_queue_item("current-organizer", current_settings, NOW, lease_seconds=30)

            self.assertEqual(claimed.provider_preference, ("subscription-cli",))
            persisted = json.loads(path.read_text(encoding="utf-8"))
            self.assertEqual(persisted["provider_preference"], ["subscription-cli"])
            self.assertEqual(persisted["state"], QueueState.IN_PROGRESS.value)

    def test_retryable_failure_is_claimable_after_next_eligible_time(self):
        with tempfile.TemporaryDirectory() as tmp:
            settings = make_isolated_hook_settings(Path(tmp))
            item = enqueue_receipt(make_event(settings), None, settings, now=NOW)
            retryable = transition_queue_item(
                item,
                QueueState.FAILED_RETRYABLE,
                settings,
                now=NOW,
                reason_code="MALFORMED_RESPONSE",
                next_eligible_at=NOW + timedelta(minutes=5),
            )
            self.assertEqual(retryable.state, QueueState.FAILED_RETRYABLE)
            self.assertIsNone(claim_queue_item("too-early", settings, NOW + timedelta(minutes=4)))
            claimed = claim_queue_item("retry-worker", settings, NOW + timedelta(minutes=5))
            self.assertIsNotNone(claimed)
            self.assertEqual(claimed.state, QueueState.IN_PROGRESS)

    def test_legacy_queue_states_are_read_without_rewriting_history(self):
        with tempfile.TemporaryDirectory() as tmp:
            settings = make_isolated_hook_settings(Path(tmp))
            item = enqueue_receipt(make_event(settings), None, settings, now=NOW)
            path = settings.paths.queue_dir / f"{item.queue_id}.json"
            raw = item.to_dict()
            raw["state"] = "DEFERRED_QUOTA"
            path.write_text(json.dumps(raw), encoding="utf-8")
            loaded = __import__("ei.queue", fromlist=["read_queue_item"]).read_queue_item(item.queue_id, settings)
            self.assertEqual(loaded.state, QueueState.DEFERRED)
            self.assertEqual(json.loads(path.read_text(encoding="utf-8"))["state"], "DEFERRED_QUOTA")

    def test_no_discarded_deletes_payload_and_keeps_no_body(self):
        with tempfile.TemporaryDirectory() as tmp:
            settings = make_isolated_hook_settings(Path(tmp))
            key = InMemoryKeyProvider("queue-key", b"q" * 32)
            ref = write_spool("no body survives", "private-reusable", settings, key_provider=key, now=NOW, spool_id="spool-no")
            item = enqueue_receipt(make_event(settings), ref, settings, now=NOW)
            updated = transition_queue_item(item, QueueState.NO_DISCARDED, settings, now=NOW, reason_code="project_specific")
            self.assertIsNone(updated.payload_ref)
            self.assertFalse((settings.paths.spool_dir / "spool-no.json").exists())
            serialized = (settings.paths.queue_dir / f"{item.queue_id}.json").read_text(encoding="utf-8")
            self.assertNotIn("no body survives", serialized)

    def test_queue_write_failure_creates_bounded_emergency_envelope(self):
        with tempfile.TemporaryDirectory() as tmp:
            settings = make_isolated_hook_settings(Path(tmp))
            event = make_event(settings)
            original = __import__("ei.queue", fromlist=["_atomic_json"])._atomic_json

            def write(path, value):
                if path.parent == settings.paths.queue_dir:
                    raise OSError("simulated queue write failure")
                return original(path, value)

            with patch("ei.queue._atomic_json", side_effect=write):
                item = enqueue_receipt(event, None, settings, now=NOW)
            emergency = list(settings.paths.emergency_spool_dir.glob("emergency_*.json"))
            self.assertEqual(len(emergency), 1)
            data = json.loads(emergency[0].read_text(encoding="utf-8"))
            self.assertNotIn("body", data)
            self.assertEqual(item.state, QueueState.QUARANTINED)

    def test_emergency_recovery_deletes_only_after_normal_queue_success(self):
        with tempfile.TemporaryDirectory() as tmp:
            settings = make_isolated_hook_settings(Path(tmp))
            item = enqueue_receipt(make_event(settings), None, settings, now=NOW)
            path = settings.paths.queue_dir / f"{item.queue_id}.json"
            path.unlink()
            from ei.queue import write_emergency_envelope
            write_emergency_envelope(item, settings, reason_code="QUEUE_WRITE_FAILED", now=NOW)
            recovered = recover_emergency_spool(settings, now=NOW + timedelta(seconds=1))
            self.assertEqual(len(recovered), 1)
            self.assertTrue((settings.paths.queue_dir / f"{item.queue_id}.json").exists())
            self.assertEqual(len(list(settings.paths.emergency_spool_dir.glob("emergency_*.json"))), 0)

    def test_emergency_spool_full_reports_health_without_silent_eviction(self):
        with tempfile.TemporaryDirectory() as tmp:
            settings = make_isolated_hook_settings(Path(tmp))
            settings.capture_policy_path.parent.mkdir(parents=True, exist_ok=True)
            settings.capture_policy_path.write_text(json.dumps({"emergency_spool": {"max_items": 1, "max_bytes": 65536, "ttl_seconds": 60}}), encoding="utf-8")
            first = enqueue_receipt(make_event(settings, turn_id="full-1"), None, settings, now=NOW)
            second = enqueue_receipt(make_event(settings, turn_id="full-2"), None, settings, now=NOW)
            write_emergency_envelope(first, settings, reason_code="QUEUE_WRITE_FAILED", now=NOW)
            with self.assertRaisesRegex(QueueError, "EMERGENCY_SPOOL_FULL"):
                write_emergency_envelope(second, settings, reason_code="QUEUE_WRITE_FAILED", now=NOW)
            emergency = list(settings.paths.emergency_spool_dir.glob("emergency_*.json"))
            self.assertEqual(len(emergency), 1)
            health = json.loads((settings.paths.emergency_spool_dir / "health.json").read_text(encoding="utf-8"))
            self.assertEqual(health["status"], "EMERGENCY_SPOOL_FULL")
            self.assertEqual(health["items"], 1)
    def test_capture_order_never_returns_semantic_no_for_unknown_coverage(self):
        class Host:
            capture_order = ("HOOK_DIRECT",)

        from ei.capture import select_capture_path
        self.assertEqual(select_capture_path(Host(), {}), "capture_coverage_unknown")
        self.assertEqual(select_capture_path(Host(), {"HOOK_DIRECT": True}), "HOOK_DIRECT")


if __name__ == "__main__":
    unittest.main()
