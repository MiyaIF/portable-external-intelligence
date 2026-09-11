import json
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace

from ei.gate import GateDecision, apply_gate_decision, decide_inheritance
from ei.hooks.registry import normalize_hook_event
from ei.inference.base import ProviderResult
from ei.key_provider import InMemoryKeyProvider
from ei.queue import QueueState, enqueue_receipt
from ei.spool import write_spool
from ei.config import RuntimePaths, Settings


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


class GateTests(unittest.TestCase):
    def test_yes_decision_reaches_curating_without_raw_body(self):
        with tempfile.TemporaryDirectory() as tmp:
            settings = make_isolated_hook_settings(Path(tmp))
            key = InMemoryKeyProvider("gate-key", b"g" * 32)
            ref = write_spool("raw candidate local only", "private-reusable", settings, key_provider=key, now=NOW, spool_id="spool-yes")
            event = normalize_hook_event("codex-cli", {"hook_event_name": "Stop", "session_id": "s1", "turn_id": "t1", "cwd": "C:/work"}, settings)
            item = enqueue_receipt(event, ref, settings, now=NOW)
            provider = ProviderResult("local", "success", output={"decision": "YES", "reason_code": "evidence_verified", "candidate_title": "再利用ルール", "candidate_claim": "検証済みの再利用可能な判断ルールを次回も適用する", "evidence_refs": ["sha256:" + "1" * 64], "benefit": "reduced_rework", "classification": "private-reusable", "confidence": 0.9, "applicability_scope": "universal", "applicable_host_ids": [], "applicable_host_families": []})
            decision = decide_inheritance({"title": "再利用ルール", "claim": "検証済みの再利用可能な判断ルールを次回も適用する", "classification": "private-reusable", "source_kind": "agent_direct", "source_ref": "safe", "source_host_id": "codex-cli", "source_host_family": "codex-compatible"}, provider)
            result = apply_gate_decision(decision, item, settings)
            self.assertEqual(result.state, QueueState.YES_CURATING)
            self.assertIsNotNone(result.queue_item.payload_ref)
            self.assertIn("yes_count", (Path(settings.paths.runtime_dir) / "gate-aggregate.json").read_text(encoding="utf-8"))

    def test_no_decision_records_only_aggregate_and_discards_payload(self):
        with tempfile.TemporaryDirectory() as tmp:
            settings = make_isolated_hook_settings(Path(tmp))
            key = InMemoryKeyProvider("gate-key", b"g" * 32)
            ref = write_spool("no candidate body", "private-reusable", settings, key_provider=key, now=NOW, spool_id="spool-no")
            event = normalize_hook_event("codex-cli", {"hook_event_name": "Stop", "session_id": "s1", "turn_id": "t1", "cwd": "C:/work"}, settings)
            item = enqueue_receipt(event, ref, settings, now=NOW)
            decision = GateDecision("NO", "project_specific", "", "", (), "", "private-reusable", 1.0, "local")
            result = apply_gate_decision(decision, item, settings)
            self.assertEqual(result.state, QueueState.NO_DISCARDED)
            self.assertIsNone(result.queue_item.payload_ref)
            aggregate = json.loads((Path(settings.paths.runtime_dir) / "gate-aggregate.json").read_text(encoding="utf-8"))
            self.assertEqual(list(aggregate["rows"].values())[0]["no_count"], 1)
            self.assertNotIn("no candidate body", json.dumps(aggregate))

    def test_semantic_reason_must_be_a_fixed_class(self):
        with self.assertRaisesRegex(ValueError, "GATE_REASON_CLASS_INVALID"):
            GateDecision("NO", "this is free text and must not be persisted")
    def test_quota_is_processing_state_not_no(self):
        with tempfile.TemporaryDirectory() as tmp:
            settings = make_isolated_hook_settings(Path(tmp))
            item = enqueue_receipt(normalize_hook_event("codex-cli", {"hook_event_name": "Stop", "session_id": "s1", "turn_id": "t1", "cwd": "C:/work"}, settings), None, settings, now=NOW)
            decision = decide_inheritance({"title": "candidate", "claim": "検証済みの候補判断知識を再利用できる", "classification": "private-reusable", "source_kind": "agent_direct", "source_ref": "safe"}, ProviderResult("subscription-cli", "deferred", error_code="QUOTA_EXHAUSTED", retry_after_seconds=300, next_eligible_at=NOW))
            result = apply_gate_decision(decision, item, settings)
            self.assertEqual(result.state, QueueState.DEFERRED_QUOTA)
            self.assertNotEqual(decision.decision, "NO")


if __name__ == "__main__":
    unittest.main()
