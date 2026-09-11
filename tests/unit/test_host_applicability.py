from __future__ import annotations

import unittest
from datetime import datetime, timezone
from dataclasses import replace
from pathlib import Path
import tempfile

from ei.curator import curate_candidate, normalize_host_applicability
from ei.gate import decide_inheritance
from ei.hooks.registry import normalize_hook_event
from ei.inference.base import ProviderResult
from ei.index import _parse_metadata
from ei.persistable_fields import inspect_changeset_payload
from ei.project import _pattern_markdown
from ei.queue import enqueue_receipt
from ei.config import RuntimePaths, Settings


class HostApplicabilityTests(unittest.TestCase):
    def test_missing_scope_is_limited_to_source_host(self):
        scope = normalize_host_applicability(
            {}, source_host_id="codex-cli", source_host_family="codex-compatible"
        )
        self.assertEqual(scope.scope, "host")
        self.assertEqual(scope.host_ids, ("codex-cli",))
        self.assertEqual(scope.host_families, ())

    def test_family_scope_requires_exact_source_family(self):
        scope = normalize_host_applicability(
            {
                "applicability_scope": "family",
                "applicable_host_families": ["gemini-compatible"],
            },
            source_host_id="test-compatible-cli",
            source_host_family="gemini-compatible",
        )
        self.assertEqual(scope.scope, "family")
        self.assertEqual(scope.host_families, ("gemini-compatible",))
        self.assertEqual(scope.host_ids, ())

    def test_malformed_universal_falls_back_to_source_host(self):
        scope = normalize_host_applicability(
            {
                "applicability_scope": "universal",
                "applicable_host_ids": ["codex-cli"],
                "applicable_host_families": ["codex-compatible"],
            },
            source_host_id="codex-cli",
            source_host_family="codex-compatible",
        )
        self.assertEqual((scope.scope, scope.host_ids, scope.host_families), ("host", ("codex-cli",), ()))

    def test_host_scope_requires_source_host_id(self):
        scope = normalize_host_applicability(
            {"applicability_scope": "host", "applicable_host_ids": ["other-cli"]},
            source_host_id="codex-cli",
            source_host_family="codex-compatible",
        )
        self.assertEqual((scope.scope, scope.host_ids, scope.host_families), ("host", ("codex-cli",), ()))

    def test_invalid_scope_and_empty_or_mixed_lists_fall_back_to_source_host(self):
        for value in (
            {"applicability_scope": "unknown"},
            {"applicability_scope": "family", "applicable_host_families": []},
            {"applicability_scope": "family", "applicable_host_families": ["gemini-compatible"], "applicable_host_ids": ["codex-cli"]},
            {"applicability_scope": "host", "applicable_host_ids": []},
        ):
            with self.subTest(value=value):
                scope = normalize_host_applicability(
                    value,
                    source_host_id="codex-cli",
                    source_host_family="codex-compatible",
                )
                self.assertEqual(scope.scope, "host")
                self.assertEqual(scope.host_ids, ("codex-cli",))
                self.assertEqual(scope.host_families, ())

    def test_hook_and_queue_retain_source_host_identity(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            repo = root / "repo"
            runtime = root / "runtime"
            settings = Settings(paths=RuntimePaths(
                repo_root=repo,
                codex_home=root / "home",
                runtime_dir=runtime,
                event_dir=repo / "events",
                knowledge_dir=repo / "knowledge",
                local_state_dir=runtime / "state",
                metrics_dir=runtime / "metrics",
                cache_dir=runtime / "cache",
                locks_dir=runtime / "locks",
                config_path=root / "home" / "config.toml",
                hooks_path=root / "home" / "hooks.json",
                agents_path=root / "home" / "AGENTS.md",
            ))
            event = normalize_hook_event(
                "codex-cli",
                {"hook_event_name": "Stop", "session_id": "s", "turn_id": "t", "cwd": "C:/work"},
                settings,
            )
            self.assertEqual(event.to_dict()["source_host_id"], "codex-cli")
            item = enqueue_receipt(event, None, settings, now=datetime(2026, 9, 9, tzinfo=timezone.utc))
            self.assertEqual(item.source_host_id, "codex-cli")
            self.assertEqual(item.source_host_family, "codex-compatible")

    def test_same_source_event_is_idempotent_but_other_source_host_is_distinct(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            repo = root / "repo"
            runtime = root / "runtime"
            settings = Settings(paths=RuntimePaths(
                repo_root=repo,
                codex_home=root / "home",
                runtime_dir=runtime,
                event_dir=repo / "events",
                knowledge_dir=repo / "knowledge",
                local_state_dir=runtime / "state",
                metrics_dir=runtime / "metrics",
                cache_dir=runtime / "cache",
                locks_dir=runtime / "locks",
                config_path=root / "home" / "config.toml",
                hooks_path=root / "home" / "hooks.json",
                agents_path=root / "home" / "AGENTS.md",
            ))
            event = normalize_hook_event(
                "codex-cli",
                {"hook_event_name": "Stop", "session_id": "s", "turn_id": "t", "cwd": "C:/work"},
                settings,
            )
            first = enqueue_receipt(event, None, settings, now=datetime(2026, 9, 9, tzinfo=timezone.utc))
            same = enqueue_receipt(event, None, settings, now=datetime(2026, 9, 9, tzinfo=timezone.utc))
            self.assertEqual(first.queue_id, same.queue_id)
            other_host = replace(
                event,
                event_id="evt_20260909T000000000000Z_abcdef123456",
                source_host_id="gemini-cli",
                source_host_family="gemini-compatible",
            )
            other = enqueue_receipt(other_host, None, settings, now=datetime(2026, 9, 9, tzinfo=timezone.utc))
            self.assertNotEqual(first.queue_id, other.queue_id)
            self.assertEqual(other.source_host_id, "gemini-cli")

    def test_host_label_lists_reject_empty_items(self):
        inspection = inspect_changeset_payload(
            {
                "source_host_id": "codex-cli",
                "applicability_scope": "host",
                "applicable_host_ids": [""],
                "applicable_host_families": [],
            }
        )
        self.assertFalse(inspection.valid)

    def test_legacy_pattern_is_universal_only_at_read_time(self):
        metadata = _parse_metadata(
            [
                "# pattern-legacy",
                "",
                "- Status: active",
                "- Classification: private-reusable",
                "",
                "Reusable legacy rule with no host metadata.",
            ],
            "pattern-legacy",
        )
        self.assertEqual(
            {key: metadata[key] for key in ("source_host_id", "source_host_family", "applicability_scope", "applicable_host_ids", "applicable_host_families")},
            {"source_host_id": "", "source_host_family": "", "applicability_scope": "universal", "applicable_host_ids": [], "applicable_host_families": []},
        )

    def test_pattern_projection_round_trips_host_metadata_without_local_paths(self):
        content = _pattern_markdown(
            {
                "pattern_id": "pat-host",
                "status": "active",
                "rule": "A host-specific rule is kept with its source metadata.",
                "classification": "private-reusable",
                "source_host_id": "codex-cli",
                "source_host_family": "codex-compatible",
                "applicability_scope": "family",
                "applicable_host_ids": [],
                "applicable_host_families": ["codex-compatible"],
            }
        )
        metadata = _parse_metadata(content.splitlines(), "pat-host")
        self.assertEqual(metadata["source_host_id"], "codex-cli")
        self.assertEqual(metadata["source_host_family"], "codex-compatible")
        self.assertEqual(metadata["applicability_scope"], "family")
        self.assertEqual(metadata["applicable_host_families"], ["codex-compatible"])
        self.assertNotIn("C:\\", content)

    def test_gate_copies_source_host_and_normalizes_provider_scope(self):
        result = decide_inheritance(
            {
                "title": "A reusable title",
                "claim": "A sufficiently long reusable claim for a host-aware candidate.",
                "classification": "private-reusable",
                "source_kind": "agent_direct",
                "source_ref": "safe",
                "source_host_id": "codex-cli",
                "source_host_family": "codex-compatible",
            },
            ProviderResult(
                "test-provider",
                "success",
                output={
                    "decision": "YES",
                    "reason_code": "evidence_verified",
                    "candidate_title": "A reusable title",
                    "candidate_claim": "A sufficiently long reusable claim for a host-aware candidate.",
                    "evidence_refs": ["sha256:" + "a" * 64],
                    "benefit": "reduced_rework",
                    "classification": "private-reusable",
                    "confidence": 0.9,
                    "source_host_id": "evil-provider-host",
                    "source_host_family": "evil-family",
                    "applicability_scope": "family",
                    "applicable_host_families": ["codex-compatible"],
                    "applicable_host_ids": [],
                },
            ),
        )
        self.assertEqual(result.source_host_id, "codex-cli")
        self.assertEqual(result.source_host_family, "codex-compatible")
        self.assertEqual(result.applicability_scope, "family")
        self.assertEqual(result.applicable_host_families, ("codex-compatible",))

    def test_gate_requires_scope_fields_for_every_yes_response(self):
        result = decide_inheritance(
            {
                "title": "A reusable title",
                "claim": "A sufficiently long reusable claim for a host-aware candidate.",
                "classification": "private-reusable",
                "source_kind": "agent_direct",
                "source_ref": "safe",
            },
            ProviderResult(
                "test-provider",
                "success",
                output={
                    "decision": "YES",
                    "reason_code": "evidence_verified",
                    "candidate_title": "A reusable title",
                    "candidate_claim": "A sufficiently long reusable claim for a host-aware candidate.",
                    "evidence_refs": ["sha256:" + "a" * 64],
                    "benefit": "reduced_rework",
                    "classification": "private-reusable",
                    "confidence": 0.9,
                },
            )
        )
        self.assertEqual((result.decision, result.reason_code), ("FAILED", "MALFORMED_RESPONSE"))

    def test_curator_writes_the_normalized_scope_to_changeset(self):
        candidate = {
            "decision": "YES",
            "title": "Reusable host-aware observation",
            "claim": "A sufficiently long reusable claim for a host-aware candidate.",
            "classification": "private-reusable",
            "source_host_id": "codex-cli",
            "source_host_family": "codex-compatible",
            "applicability_scope": "family",
            "applicable_host_families": ["codex-compatible"],
            "applicable_host_ids": [],
            "evidence_refs": ["sha256:" + "a" * 64, "sha256:" + "b" * 64],
            "benefit": "reduced_rework",
            "domain": "cli-agent",
        }
        changeset = curate_candidate(candidate, [], {"provider_id": "test-provider"})
        payload = changeset.operations[-1].payload
        self.assertEqual(payload["source_host_id"], "codex-cli")
        self.assertEqual(payload["applicability_scope"], "family")
        self.assertEqual(payload["applicable_host_families"], ["codex-compatible"])


if __name__ == "__main__":
    unittest.main()
