import argparse
import io
import json
import tempfile
import unittest
from contextlib import redirect_stdout
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import patch

from ei.cli import _recall
from ei.config import RuntimePaths, Settings
from ei.doctor import _settings_check
from ei.inference.base import InferenceBudget, ProviderResult
from ei.inference.router import ProviderRouter
from ei.key_provider import InMemoryKeyProvider
from ei.maintainer import drain_queue
from ei.queue import QueueState, enqueue_receipt, queue_health, read_queue_item, transition_queue_item
from ei.spool import write_spool
from ei.setup_contract import OrganizerSelection
from ei.hooks.registry import normalize_hook_event
from ei.models import Event
from ei.project import project_events


class CountingProvider:
    locality = "local"

    def __init__(self, provider_id, result):
        self.provider_id = provider_id
        self.result = result
        self.calls = 0

    def available(self):
        return True

    def generate(self, schema_name, input_json, budget):
        del schema_name, input_json, budget
        self.calls += 1
        return self.result


def isolated_settings(root: Path) -> Settings:
    root = Path(root).resolve()
    repo = root / "repo"
    runtime = root / "runtime"
    home = root / "home"
    paths = RuntimePaths(
        repo_root=repo,
        codex_home=home,
        runtime_dir=runtime,
        event_dir=repo / "events",
        knowledge_dir=repo / "knowledge",
        local_state_dir=runtime / "state",
        metrics_dir=runtime / "metrics",
        cache_dir=runtime / "cache",
        locks_dir=runtime / "locks",
        config_path=home / "config.toml",
        hooks_path=home / "hooks.json",
        agents_path=home / "AGENTS.md",
    )
    return Settings(paths=paths, organizer=OrganizerSelection("READY", "ollama", None))


class SingleOrganizerIntegrationTests(unittest.TestCase):
    def setUp(self):
        self.spool_key_provider = InMemoryKeyProvider("single-organizer-test-key", b"s" * 32)
        provider_patch = patch("ei.spool.default_key_provider", return_value=self.spool_key_provider)
        provider_patch.start()
        self.addCleanup(provider_patch.stop)

    def test_selected_organizer_failure_does_not_call_other_provider(self):
        selected = CountingProvider("ollama", ProviderResult("ollama", "failed", error_code="PROVIDER_UNAVAILABLE"))
        other = CountingProvider("subscription-cli", ProviderResult("subscription-cli", output={"decision": "YES"}))
        router = ProviderRouter([selected, other], organizer=OrganizerSelection("READY", "ollama", None))
        result = router.generate("gate", "gate-decision", {"candidate": "safe"}, InferenceBudget())
        self.assertEqual(result.error_code, "PROVIDER_UNAVAILABLE")
        self.assertEqual(selected.calls, 1)
        self.assertEqual(other.calls, 0)

    def test_queue_health_reports_new_non_destructive_states(self):
        with tempfile.TemporaryDirectory() as tmp:
            settings = isolated_settings(Path(tmp))
            event = normalize_hook_event("codex-cli", {"hook_event_name": "Stop", "session_id": "s", "turn_id": "t", "cwd": "C:/work"}, settings)
            item = enqueue_receipt(event, None, settings)
            transition_queue_item(item, QueueState.DEFERRED, settings, reason_code="PROVIDER_UNAVAILABLE")
            health = queue_health(settings).to_dict()
            self.assertEqual(health["deferred"], 1)
            self.assertEqual(health["retryable"], 0)
            self.assertEqual(health["needs_attention"], 0)
            self.assertEqual(health["organizer"]["status"], "READY")

    def test_selection_required_defers_claim_without_calling_a_provider(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = isolated_settings(Path(tmp))
            settings = Settings(
                paths=base.paths,
                organizer=OrganizerSelection(
                    "SELECTION_REQUIRED", None, None, "ORGANIZER_SELECTION_REQUIRED"
                ),
            )
            event = normalize_hook_event(
                "codex-cli",
                {"hook_event_name": "Stop", "session_id": "s", "turn_id": "selection", "cwd": "C:/work"},
                settings,
            )
            payload_ref = write_spool(
                json.dumps({"title": "候補", "claim": "選択前の候補を破棄せずに保持して後で整理できる"}),
                "private-reusable",
                settings,
                now=datetime(2026, 9, 9, tzinfo=timezone.utc),
            )
            item = enqueue_receipt(event, payload_ref, settings)
            provider = CountingProvider(
                "ollama",
                ProviderResult("ollama", "success", output={"decision": "YES"}),
            )

            result = drain_queue(
                settings,
                provider=provider,
                max_items=1,
                now=datetime(2026, 9, 9, tzinfo=timezone.utc),
            )

            updated = read_queue_item(item.queue_id, settings)
            self.assertEqual(result.deferred, 1, result.to_dict())
            self.assertEqual(updated.state, QueueState.DEFERRED)
            self.assertEqual(updated.last_error_code, "ORGANIZER_SELECTION_REQUIRED")
            self.assertIsNotNone(updated.next_eligible_at)
            self.assertIsNotNone(updated.payload_ref)
            self.assertEqual(provider.calls, 0)

    def test_selection_required_defers_before_invalid_provider_config_read(self):
        cases = (
            ("invalid-structure", "[]", False),
            ("malformed-json", "{", False),
            ("missing", None, False),
            ("unreadable", None, True),
        )
        for label, content, is_directory in cases:
            with self.subTest(config=label), tempfile.TemporaryDirectory() as tmp:
                base = isolated_settings(Path(tmp))
                settings = Settings(
                    paths=base.paths,
                    organizer=OrganizerSelection(
                        "SELECTION_REQUIRED", None, None, "ORGANIZER_SELECTION_REQUIRED"
                    ),
                )
                config_path = settings.paths.engine_root / "config" / "inference-providers.json"
                config_path.parent.mkdir(parents=True, exist_ok=True)
                if is_directory:
                    config_path.mkdir()
                elif content is not None:
                    config_path.write_text(content, encoding="utf-8")
                event = normalize_hook_event(
                    "codex-cli",
                    {"hook_event_name": "Stop", "session_id": "s", "turn_id": label, "cwd": "C:/work"},
                    settings,
                )
                payload_ref = write_spool(
                    json.dumps({"title": "候補", "claim": "未選択の整理AI設定でも候補を保持して後で処理できる"}),
                    "private-reusable",
                    settings,
                    now=datetime(2026, 9, 9, tzinfo=timezone.utc),
                )
                item = enqueue_receipt(event, payload_ref, settings)

                with patch("ei.inference.router._read_config", side_effect=AssertionError("provider config was read")):
                    result = drain_queue(
                        settings,
                        max_items=1,
                        now=datetime(2026, 9, 9, tzinfo=timezone.utc),
                    )

                updated = read_queue_item(item.queue_id, settings)
                self.assertEqual(result.deferred, 1, result.to_dict())
                self.assertEqual(updated.state, QueueState.DEFERRED)
                self.assertEqual(updated.last_error_code, "ORGANIZER_SELECTION_REQUIRED")
                self.assertIsNotNone(updated.next_eligible_at)
                self.assertEqual(updated.payload_ref, payload_ref)

    def test_ready_invalid_provider_config_defers_without_aborting(self):
        cases = (
            ("invalid-structure", "[]", False, "INFERENCE_PROVIDER_CONFIG_INVALID"),
            ("malformed-json", "{", False, "INFERENCE_PROVIDER_CONFIG_READ_FAILED"),
            ("missing", None, False, "INFERENCE_PROVIDER_CONFIG_READ_FAILED"),
            ("unreadable", None, True, "INFERENCE_PROVIDER_CONFIG_READ_FAILED"),
        )
        for label, content, is_directory, expected_reason in cases:
            with self.subTest(config=label), tempfile.TemporaryDirectory() as tmp:
                settings = isolated_settings(Path(tmp))
                config_path = settings.paths.engine_root / "config" / "inference-providers.json"
                config_path.parent.mkdir(parents=True, exist_ok=True)
                if is_directory:
                    config_path.mkdir()
                elif content is not None:
                    config_path.write_text(content, encoding="utf-8")
                event = normalize_hook_event(
                    "codex-cli",
                    {"hook_event_name": "Stop", "session_id": "s", "turn_id": label, "cwd": "C:/work"},
                    settings,
                )
                payload_ref = write_spool(
                    json.dumps({"title": "候補", "claim": "設定エラー時にも候補を捨てず再選択後の処理へ回す"}),
                    "private-reusable",
                    settings,
                    now=datetime(2026, 9, 9, tzinfo=timezone.utc),
                )
                item = enqueue_receipt(event, payload_ref, settings)

                result = drain_queue(
                    settings,
                    max_items=1,
                    now=datetime(2026, 9, 9, tzinfo=timezone.utc),
                )

                updated = read_queue_item(item.queue_id, settings)
                self.assertEqual(result.deferred, 1, result.to_dict())
                self.assertEqual(result.failed, 0, result.to_dict())
                self.assertEqual(updated.state, QueueState.DEFERRED)
                self.assertEqual(updated.last_error_code, expected_reason)
                self.assertIsNotNone(updated.next_eligible_at)
                self.assertEqual(updated.payload_ref, payload_ref)

    def test_ready_selected_provider_construction_error_defers_without_fallback(self):
        with tempfile.TemporaryDirectory() as tmp:
            settings = isolated_settings(Path(tmp))
            config_path = settings.paths.engine_root / "config" / "inference-providers.json"
            config_path.parent.mkdir(parents=True, exist_ok=True)
            config_path.write_text(
                json.dumps({"provider_order": ["ollama"], "providers": {"ollama": {"argv": [1]}}}),
                encoding="utf-8",
            )
            event = normalize_hook_event(
                "codex-cli",
                {"hook_event_name": "Stop", "session_id": "s", "turn_id": "construction", "cwd": "C:/work"},
                settings,
            )
            payload_ref = write_spool(
                json.dumps({"title": "候補", "claim": "選択済み整理AIの構成不備でも別providerへ切り替えず保留する"}),
                "private-reusable",
                settings,
                now=datetime(2026, 9, 9, tzinfo=timezone.utc),
            )
            item = enqueue_receipt(event, payload_ref, settings)

            result = drain_queue(
                settings,
                max_items=1,
                now=datetime(2026, 9, 9, tzinfo=timezone.utc),
            )

            updated = read_queue_item(item.queue_id, settings)
            self.assertEqual(result.deferred, 1, result.to_dict())
            self.assertEqual(result.failed, 0, result.to_dict())
            self.assertEqual(updated.state, QueueState.DEFERRED)
            self.assertEqual(updated.last_error_code, "ORGANIZER_PROVIDER_CONFIG_INVALID")
            self.assertIsNotNone(updated.next_eligible_at)
            self.assertEqual(updated.payload_ref, payload_ref)

    def test_malformed_drain_attempts_count_claims_once(self):
        with tempfile.TemporaryDirectory() as tmp:
            settings = isolated_settings(Path(tmp))
            event = normalize_hook_event(
                "codex-cli",
                {"hook_event_name": "Stop", "session_id": "s", "turn_id": "malformed", "cwd": "C:/work"},
                settings,
            )
            payload_ref = write_spool(
                json.dumps({"title": "候補", "claim": "同じ構造を別案件でも検証し再利用可能な判断ルールとして記録する"}),
                "private-reusable",
                settings,
                now=datetime(2026, 9, 9, tzinfo=timezone.utc),
            )
            item = enqueue_receipt(event, payload_ref, settings)
            provider = CountingProvider(
                "ollama",
                ProviderResult("ollama", "success", output={"not_a_gate_decision": True}),
            )
            start = datetime(2026, 9, 9, tzinfo=timezone.utc)

            states = []
            for claim_number in range(3):
                drain_queue(
                    settings,
                    provider=provider,
                    max_items=1,
                    now=start + timedelta(seconds=300 * claim_number),
                )
                current = read_queue_item(item.queue_id, settings)
                states.append((current.state, current.attempts))

            self.assertEqual(
                states,
                [
                    (QueueState.FAILED_RETRYABLE, 1),
                    (QueueState.FAILED_RETRYABLE, 2),
                    (QueueState.FAILED_NEEDS_ATTENTION, 3),
                ],
            )
            self.assertEqual(provider.calls, 3)

    def test_doctor_validates_curation_retry_policy_from_defaults(self):
        with tempfile.TemporaryDirectory() as tmp:
            settings = isolated_settings(Path(tmp))
            defaults_path = settings.paths.engine_root / "config" / "defaults.json"
            defaults_path.parent.mkdir(parents=True, exist_ok=True)
            defaults_path.write_text(
                json.dumps(
                    {
                        "schema_version": 1,
                        "retrieval": {},
                        "context": {},
                        "hooks": {},
                        "providers": {},
                        "sync": {},
                        "capture": {},
                        "scheduler": {},
                        "experiment": {},
                        "curation": {"max_attempts": 3, "retry_delay_seconds": -1},
                    }
                ),
                encoding="utf-8",
            )

            check = _settings_check(settings, strict=True)

            self.assertFalse(check["ok"])
            self.assertEqual(check["reason_code"], "DEFAULTS_SCHEMA_INVALID")

    def test_recall_succeeds_when_organizer_is_stopped(self):
        with tempfile.TemporaryDirectory() as tmp:
            settings = isolated_settings(Path(tmp))
            event = Event.create(
                "pattern.promoted",
                datetime(2026, 9, 9, 0, 0).isoformat() + "Z",
                "test",
                "machine",
                {
                    "pattern_id": "pat_stopped_organizer",
                    "cluster_id": "cluster_stopped_organizer",
                    "rule": "既存の記憶は整理AIが停止していても取得し、作業の再確認に利用する",
                    "provenances": ["source:stopped-organizer"],
                    "scopes": ["general"],
                    "applicability": ["general"],
                    "benefit_count": 1,
                    "classification": "private-reusable",
                },
                event_id="evt_stopped_organizer",
            )
            project_events([event], settings.paths.knowledge_dir)
            args = argparse.Namespace(
                query="既存の記憶",
                max_chars=None,
                cwd=None,
                host="",
                session_id="stopped-organizer-session",
                settings=settings,
            )
            output = io.StringIO()
            with redirect_stdout(output):
                self.assertEqual(_recall(args), 0)
            result = json.loads(output.getvalue())
            self.assertEqual(result["status"], "ok")
            self.assertIn("pat_stopped_organizer", {item["pattern_id"] for item in result["hits"]})


if __name__ == "__main__":
    unittest.main()
