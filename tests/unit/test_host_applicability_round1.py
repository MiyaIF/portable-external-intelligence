from __future__ import annotations

import tempfile
import unittest
import contextlib
import io
import json
from dataclasses import replace
from datetime import datetime, timezone
from pathlib import Path

from ei.adapters.base import SourceRecord
from ei.adapters.claude import ClaudeAdapter
from ei.adapters.codex_memory import CodexMemoryAdapter
from ei.adapters.gemini import GeminiAdapter
from ei.adapters.qwen import QwenAdapter
from ei.adapters.rollout_summary import RolloutSummaryAdapter
from ei.adapters.transcript_metadata import TranscriptMetadataAdapter
from ei.capture import _claim_hash, reconcile_fallback, record_agent_observation
from ei.changeset import apply_changeset
from ei.curator import curate_candidate
from ei.config import RuntimePaths, Settings
from ei.gate import GateDecision
from ei.ingest import _source_key, ingest_sources
from ei.ids import fingerprint
from ei.index import _parse_metadata
from ei.journal import JournalIntegrityError, append_event, iter_events, validate_schema
from ei.models import CaptureContext, Event, ObservationInput, validate_host_applicability_mapping
from ei.persistable_fields import inspect_changeset_payload
from ei.reconciliation import _cluster_observations, _new_record, _observation_state


class HostApplicabilityRound1Tests(unittest.TestCase):
    def _settings(self, root: Path) -> Settings:
        repo = root / "repo"
        runtime = root / "runtime"
        return Settings(
            paths=RuntimePaths(
                repo_root=repo,
                codex_home=root / "codex",
                runtime_dir=runtime,
                event_dir=repo / "events",
                knowledge_dir=repo / "knowledge",
                local_state_dir=runtime / "state",
                metrics_dir=runtime / "metrics",
                cache_dir=runtime / "cache",
                locks_dir=runtime / "locks",
                config_path=root / "codex" / "config.toml",
                hooks_path=root / "codex" / "hooks.json",
                agents_path=root / "codex" / "AGENTS.md",
            )
        )

    def _observation_payload(self, **extra: object) -> dict[str, object]:
        payload: dict[str, object] = {
            "observation_id": "obs_round1",
            "title": "Host-aware observation",
            "claim": "A reusable claim with explicit source host applicability metadata.",
            "source_kind": "agent_direct",
            "source_hash": "sha256:" + "a" * 64,
            "provenance_key": "source:round1",
            "domain": "testing",
            "outcome_status": "success",
            "benefit": "reduced_rework",
            "classification": "private-reusable",
            "source_host_id": "gemini-cli",
            "source_host_family": "gemini-compatible",
            "applicability_scope": "family",
            "applicable_host_ids": [],
            "applicable_host_families": ["gemini-compatible"],
        }
        payload.update(extra)
        return payload

    def test_reconciliation_preserves_scope_on_observation_and_cluster(self):
        event = Event.create(
            "observation.recorded",
            "2026-09-09T00:00:00+00:00",
            "ingest",
            "machine",
            self._observation_payload(),
            event_id="evt_round1_000000000000",
        )
        observation = _observation_state(event)
        self.assertEqual(observation.source_host_id, "gemini-cli")
        self.assertEqual(observation.applicability_scope, "family")
        records, _ = _cluster_observations([event])
        cluster = next(iter(records.values())).state
        self.assertEqual(cluster.source_host_family, "gemini-compatible")
        self.assertEqual(cluster.applicable_host_families, ("gemini-compatible",))

    def test_reconciliation_legacy_missing_fields_is_universal_read_only(self):
        payload = self._observation_payload(
            source_host_id=None,
            source_host_family=None,
            applicability_scope=None,
            applicable_host_ids=None,
            applicable_host_families=None,
        )
        for key in ("source_host_id", "source_host_family", "applicability_scope", "applicable_host_ids", "applicable_host_families"):
            payload.pop(key, None)
        event = Event.create(
            "observation.recorded",
            "2026-09-09T00:00:00+00:00",
            "ingest",
            "machine",
            payload,
            event_id="evt_round1_legacy0000",
        )
        observation = _observation_state(event)
        self.assertEqual((observation.applicability_scope, observation.applicable_host_ids, observation.applicable_host_families), ("universal", (), ()))
        self.assertNotIn("source_host_id", event.payload)

    def test_direct_capture_requires_explicit_trusted_pair(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            settings = self._settings(root)
            missing = ObservationInput(
                "title",
                "A sufficiently long direct observation claim for testing.",
                "agent_direct",
                "session-local",
                "project",
                "testing",
                "success",
                "reduced_rework",
                "private-reusable",
            )
            result = record_agent_observation(missing, CaptureContext("session", "turn", 1), settings)
            self.assertFalse(result.created)
            self.assertEqual(result.reason_code, "CAPTURE_HOST_PAIR_REQUIRED")

    def test_direct_capture_persists_explicit_trusted_pair(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            settings = self._settings(root)
            observation = ObservationInput(
                "title",
                "A sufficiently long direct observation claim for testing.",
                "agent_direct",
                "session-local",
                "project",
                "testing",
                "success",
                "reduced_rework",
                "private-reusable",
                source_host_id="codex-cli",
                source_host_family="codex-compatible",
            )
            result = record_agent_observation(observation, CaptureContext("session", "turn", 1), settings)
            self.assertTrue(result.created)
            from ei.journal import iter_events

            event = next(iter_events(settings.paths.event_dir))
            self.assertEqual(event.payload["source_host_id"], "codex-cli")
            self.assertEqual(event.payload["source_host_family"], "codex-compatible")

    def test_builtin_adapters_declare_trusted_host_identity(self):
        cases = (
            (CodexMemoryAdapter, "tests/fixtures/sources/codex/memory.md", "codex-cli", "codex-compatible"),
            (RolloutSummaryAdapter, "tests/fixtures/sources/rollout/summary.jsonl", "codex-cli", "codex-compatible"),
            (ClaudeAdapter, "tests/fixtures/sources/claude/stable-memory.json", "claude-code", "claude-compatible"),
            (GeminiAdapter, "tests/fixtures/sources/gemini/session-metadata.json", "gemini-cli", "gemini-compatible"),
            (QwenAdapter, "tests/fixtures/sources/qwen/session-metadata.json", "qwen-code", "qwen-compatible"),
        )
        for adapter_type, raw_path, host_id, family in cases:
            with self.subTest(adapter=adapter_type.__name__):
                path = Path(raw_path)
                if not path.exists():
                    self.skipTest(f"fixture unavailable: {raw_path}")
                records = list(adapter_type([path.resolve()]).iter_records({}))
                self.assertTrue(records)
                self.assertEqual((records[0].source_host_id, records[0].source_host_family), (host_id, family))

    def test_transcript_metadata_without_explicit_pair_is_rejected(self):
        adapter = TranscriptMetadataAdapter(
            [{"session_id": "session", "turn_id": "turn", "cwd": "cwd:hash", "transcript_path": ""}]
        )
        self.assertEqual(list(adapter.iter_records({})), [])
        self.assertGreaterEqual(adapter.health["rejected"], 1)

    def test_unknown_adapter_record_without_pair_is_rejected_without_event(self):
        class UnknownAdapter:
            parser_version = "unknown-v1"
            capture_path = "manual"
            sources = ()

            def iter_records(self, cursor):
                del cursor
                yield SourceRecord(
                    source_kind="unknown",
                    source_ref="manual://unknown",
                    source_hash="sha256:" + "c" * 64,
                    observed_at="2026-09-09T00:00:00+00:00",
                    title="Unknown source",
                    claim="A sufficiently long unknown-source claim for rejection testing.",
                    cwd="",
                    domain="testing",
                    outcome_status="success",
                    benefit="reduced_rework",
                    classification="private-reusable",
                )

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            settings = self._settings(root)
            result = ingest_sources(settings, [UnknownAdapter()])
            self.assertEqual(result.created_events, 0)
            self.assertEqual(result.rejected_records, 1)
            self.assertEqual(tuple(settings.paths.event_dir.glob("*.json")), ())

    def test_gate_rejects_unknown_scope_and_non_string_list_items(self):
        base = {
            "decision": "YES",
            "reason_code": "evidence_verified",
            "candidate_title": "Host-aware title",
            "candidate_claim": "A sufficiently long reusable claim for gate validation.",
            "evidence_refs": ["sha256:" + "b" * 64],
            "benefit": "reduced_rework",
            "classification": "private-reusable",
            "confidence": 0.9,
            "applicable_host_ids": [],
            "applicable_host_families": ["codex-compatible"],
        }
        with self.assertRaises(ValueError):
            GateDecision.from_mapping({**base, "applicability_scope": "other"}, provider_id="provider")
        with self.assertRaises(ValueError):
            GateDecision.from_mapping({**base, "applicability_scope": "family", "applicable_host_families": [1]}, provider_id="provider")

    def test_index_rejects_private_path_as_host_metadata(self):
        lines = [
            "# pattern-private",
            "",
            "- Status: active",
            "- Classification: private-reusable",
            "- Source host: " + "C:" + chr(92) + "Users" + chr(92) + "Alice" + chr(92) + "private",
            "- Source host family: codex-compatible",
            "- Applicability scope: host",
            "- Host IDs: " + "C:" + chr(92) + "Users" + chr(92) + "Alice" + chr(92) + "private",
            "- Host families: ",
            "",
            "A valid-looking claim with an invalid host identifier.",
        ]
        with self.assertRaises(ValueError):
            _parse_metadata(lines, "pattern-private")

    def test_journal_rejects_mixed_scope_lists(self):
        with self.assertRaises(JournalIntegrityError):
            validate_schema(
                "observation",
                {
                    "observation_id": "obs_round1",
                    "title": "Title",
                    "claim": "A sufficiently long observation claim for validation.",
                    "domain": "testing",
                    "cwd_fingerprint": "",
                    "provenance_key": "source:round1",
                    "outcome_status": "success",
                    "benefit": "reduced_rework",
                    "classification": "private-reusable",
                    "source_host_id": "codex-cli",
                    "source_host_family": "codex-compatible",
                    "applicability_scope": "family",
                    "applicable_host_ids": ["codex-cli"],
                    "applicable_host_families": ["codex-compatible"],
                },
            )

    def test_persistence_and_journal_reject_missing_pair_for_host_scope(self):
        malformed = {
            "source_host_id": "",
            "source_host_family": "",
            "applicability_scope": "host",
            "applicable_host_ids": ["other-cli"],
            "applicable_host_families": [],
        }
        self.assertFalse(inspect_changeset_payload(malformed).valid)
        with self.assertRaises(JournalIntegrityError):
            validate_schema(
                "observation",
                {
                    "observation_id": "obs_round1",
                    "title": "Title",
                    "claim": "A sufficiently long observation claim for validation.",
                    "domain": "testing",
                    "cwd_fingerprint": "",
                    "provenance_key": "source:round1",
                    "outcome_status": "success",
                    "benefit": "reduced_rework",
                    "classification": "private-reusable",
                    **malformed,
                },
            )

    def _native_record(self, *, host_id: str, family: str, source_ref: str = "memory.md", claim: str = "A reusable fallback claim must remain distinct per trusted source host.") -> SourceRecord:
        return SourceRecord(
            source_kind="native_memory",
            source_ref=source_ref,
            source_hash="sha256:" + "d" * 64,
            observed_at="2026-09-09T00:00:00+00:00",
            title="Fallback observation",
            claim=claim,
            cwd="project",
            domain="testing",
            outcome_status="success",
            benefit="reduced_rework",
            classification="private-reusable",
            provenance_key="source:fallback",
            source_host_id=host_id,
            source_host_family=family,
        )

    def test_fallback_deduplicates_by_claim_and_trusted_pair(self):
        with tempfile.TemporaryDirectory() as tmp:
            settings = self._settings(Path(tmp))
            codex = self._native_record(host_id="codex-cli", family="codex-compatible")
            gemini = replace(codex, source_host_id="gemini-cli", source_host_family="gemini-compatible")
            first = reconcile_fallback(settings, [], [codex, gemini])
            second = reconcile_fallback(settings, [], [codex, gemini])
            self.assertEqual(first.recovered, 2)
            self.assertEqual(second.recovered, 0)
            events = [event for event in iter_events(settings.paths.event_dir) if event.event_type == "capture.fallback_recovered"]
            self.assertEqual({(event.payload["source_host_id"], event.payload["source_host_family"]) for event in events}, {
                ("codex-cli", "codex-compatible"),
                ("gemini-cli", "gemini-compatible"),
            })

    def test_fallback_validates_pair_before_duplicate_skip(self):
        with tempfile.TemporaryDirectory() as tmp:
            settings = self._settings(Path(tmp))
            valid = self._native_record(host_id="codex-cli", family="codex-compatible")
            malformed = replace(valid, source_host_id="", source_host_family="")
            first = reconcile_fallback(settings, [], [valid])
            second = reconcile_fallback(settings, [], [malformed])
            self.assertEqual(first.recovered, 1)
            self.assertEqual(second.recovered, 0)
            self.assertEqual(second.rejected, 1)

    def test_fallback_legacy_claim_only_key_is_consumed_once(self):
        with tempfile.TemporaryDirectory() as tmp:
            settings = self._settings(Path(tmp))
            claim = "A legacy fallback claim can be replayed once without suppressing another host."
            codex = self._native_record(host_id="codex-cli", family="codex-compatible", claim=claim)
            gemini = replace(codex, source_host_id="gemini-cli", source_host_family="gemini-compatible")
            # The persisted legacy key uses the old claim hash, not a host-aware key.
            from ei.capture import _claim_hash
            append_event(
                Event.create(
                    "capture.fallback_recovered",
                    "2026-09-08T00:00:00+00:00",
                    "capture_reconciler",
                    "machine",
                    {"observation_fingerprint": _claim_hash(claim), "capture_path": "fallback"},
                ),
                settings.paths.event_dir,
            )
            result = reconcile_fallback(settings, [], [codex, gemini])
            self.assertEqual(result.recovered, 1)
            recovered = [event for event in iter_events(settings.paths.event_dir) if event.event_type == "capture.fallback_recovered" and event.payload.get("source_host_id")]
            self.assertEqual(len(recovered), 1)

    def test_fallback_legacy_consumption_marker_persists_across_invocations(self):
        with tempfile.TemporaryDirectory() as tmp:
            settings = self._settings(Path(tmp))
            claim = "A legacy fallback claim must consume one trusted host pair across process invocations."
            legacy_event_id = "evt_legacy_round3_0001"
            append_event(
                Event.create(
                    "capture.fallback_recovered",
                    "2026-09-08T00:00:00+00:00",
                    "capture_reconciler",
                    "machine",
                    {"observation_fingerprint": _claim_hash(claim), "capture_path": "fallback"},
                    event_id=legacy_event_id,
                ),
                settings.paths.event_dir,
            )
            codex = self._native_record(host_id="codex-cli", family="codex-compatible", claim=claim)
            gemini = replace(codex, source_host_id="gemini-cli", source_host_family="gemini-compatible")

            first = reconcile_fallback(settings, [], [codex])
            second = reconcile_fallback(settings, [], [codex])
            third = reconcile_fallback(settings, [], [gemini])
            fourth = reconcile_fallback(settings, [], [gemini])

            self.assertEqual((first.recovered, second.recovered, third.recovered, fourth.recovered), (0, 0, 1, 0))
            markers = [event for event in iter_events(settings.paths.event_dir) if event.event_type == "capture.fallback_legacy_consumed"]
            self.assertEqual(len(markers), 1)
            self.assertEqual(
                (markers[0].payload["observation_fingerprint"], markers[0].payload["source_host_id"], markers[0].payload["source_host_family"]),
                (_claim_hash(claim), "codex-cli", "codex-compatible"),
            )
            self.assertEqual(markers[0].payload["legacy_source_event_id_hash"], fingerprint(legacy_event_id))

    def test_persistence_rejects_host_source_outside_applicable_host_ids(self):
        with tempfile.TemporaryDirectory() as tmp:
            settings = self._settings(Path(tmp))
            with self.assertRaises(ValueError):
                validate_host_applicability_mapping(
                    {
                        "source_host_id": "codex-cli",
                        "source_host_family": "codex-compatible",
                        "applicability_scope": "host",
                        "applicable_host_ids": ["gemini-cli"],
                        "applicable_host_families": [],
                    },
                    require_source_pair=True,
                )
            with self.assertRaises(JournalIntegrityError):
                append_event(
                    Event.create(
                        "host.scope.invalid",
                        "2026-09-09T00:00:00+00:00",
                        "test",
                        "machine",
                        {
                            "source_host_id": "codex-cli",
                            "source_host_family": "codex-compatible",
                            "applicability_scope": "host",
                            "applicable_host_ids": ["gemini-cli"],
                            "applicable_host_families": [],
                        },
                    ),
                    settings.paths.event_dir,
                )

    def test_persistence_rejects_family_source_outside_applicable_host_families(self):
        with tempfile.TemporaryDirectory() as tmp:
            settings = self._settings(Path(tmp))
            with self.assertRaises(ValueError):
                validate_host_applicability_mapping(
                    {
                        "source_host_id": "codex-cli",
                        "source_host_family": "codex-compatible",
                        "applicability_scope": "family",
                        "applicable_host_ids": [],
                        "applicable_host_families": ["gemini-compatible"],
                    },
                    require_source_pair=True,
                )
            with self.assertRaises(JournalIntegrityError):
                append_event(
                    Event.create(
                        "family.scope.invalid",
                        "2026-09-09T00:00:00+00:00",
                        "test",
                        "machine",
                        {
                            "source_host_id": "codex-cli",
                            "source_host_family": "codex-compatible",
                            "applicability_scope": "family",
                            "applicable_host_ids": [],
                            "applicable_host_families": ["gemini-compatible"],
                        },
                    ),
                    settings.paths.event_dir,
                )

    def test_ingest_cursor_is_keyed_by_source_path_and_trusted_pair(self):
        class Adapter:
            parser_version = "round2"
            capture_path = "native_memory"
            sources = ()

            def __init__(self, path: Path, host_id: str, family: str):
                self.sources = (path,)
                self.host_id = host_id
                self.host_family = family

            def iter_records(self, cursor):
                del cursor
                yield self.record

        with tempfile.TemporaryDirectory() as tmp:
            # GitHub's Windows runners may expose the temporary directory via
            # an 8.3 alias (for example RUNNER~1), while ingestion records use
            # canonical paths.  Keep the fixture in the same coordinate system
            # as the production adapters.
            root = Path(tmp).resolve()
            source = root / "memory.md"
            source.write_text("metadata", encoding="utf-8")
            settings = self._settings(root)
            codex_adapter = Adapter(source, "codex-cli", "codex-compatible")
            codex_adapter.record = self._native_record(host_id="codex-cli", family="codex-compatible", source_ref=str(source))
            gemini_adapter = Adapter(source, "gemini-cli", "gemini-compatible")
            gemini_adapter.record = replace(codex_adapter.record, source_host_id="gemini-cli", source_host_family="gemini-compatible")
            self.assertEqual(ingest_sources(settings, [codex_adapter]).created_events, 1)
            self.assertEqual(ingest_sources(settings, [codex_adapter]).created_events, 0)
            self.assertEqual(ingest_sources(settings, [gemini_adapter]).created_events, 1)
            self.assertEqual(ingest_sources(settings, [gemini_adapter]).created_events, 0)
            cursor = json.loads((settings.paths.local_state_dir / "ingest-cursor.json").read_text(encoding="utf-8"))
            self.assertEqual(len(cursor["sources"]), 2)

    def test_ingest_migrates_legacy_path_only_cursor_once(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp).resolve()
            source = root / "memory.md"
            source.write_text("metadata", encoding="utf-8")
            settings = self._settings(root)

            class Adapter:
                parser_version = "round2"
                capture_path = "native_memory"
                sources = (source,)
                host_id = "codex-cli"
                host_family = "codex-compatible"

                def iter_records(self, cursor):
                    del cursor
                    yield self.record

            adapter = Adapter()
            adapter.record = self._native_record(host_id="codex-cli", family="codex-compatible", source_ref=str(source))
            self.assertEqual(ingest_sources(settings, [adapter]).created_events, 1)
            cursor_path = settings.paths.local_state_dir / "ingest-cursor.json"
            cursor = json.loads(cursor_path.read_text(encoding="utf-8"))
            current_key, current_value = next(iter(cursor["sources"].items()))
            del cursor["sources"][current_key]
            legacy_key = _source_key(str(source))
            current_value.pop("source_host_id", None)
            current_value.pop("source_host_family", None)
            cursor["sources"][legacy_key] = current_value
            cursor_path.write_text(json.dumps(cursor), encoding="utf-8")
            self.assertEqual(ingest_sources(settings, [adapter]).created_events, 0)
            migrated = json.loads(cursor_path.read_text(encoding="utf-8"))["sources"]
            self.assertNotIn(legacy_key, migrated)
            self.assertEqual(len(migrated), 1)
            saved = next(iter(migrated.values()))
            self.assertEqual((saved["source_host_id"], saved["source_host_family"]), ("codex-cli", "codex-compatible"))

    def _host_candidate(self, *, host_id: str = "codex-cli", family: str = "codex-compatible", scope: str = "host", ids: tuple[str, ...] | None = None, families: tuple[str, ...] | None = None, claim: str = "When the same issue returns, record the verified cause and rerun the focused check.") -> GateDecision:
        return GateDecision(
            "YES",
            "evidence_verified",
            "Reusable finding",
            claim,
            ("sha256:" + "f" * 64,),
            "reduced_rework",
            "private-reusable",
            0.9,
            "test-provider",
            source_host_id=host_id,
            source_host_family=family,
            applicability_scope=scope,
            applicable_host_ids=ids if ids is not None else ((host_id,) if scope == "host" else ()),
            applicable_host_families=families if families is not None else ((family,) if scope == "family" else ()),
        )

    def test_curator_does_not_match_host_or_family_scope_mismatch(self):
        claim = "When the same issue returns, record the verified cause and rerun the focused check."
        host_target = {"pattern_id": "pat-gemini", "status": "active", "rule": claim, "source_host_id": "gemini-cli", "source_host_family": "gemini-compatible", "applicability_scope": "host", "applicable_host_ids": ["gemini-cli"], "applicable_host_families": []}
        family_target = {"pattern_id": "pat-gemini-family", "status": "active", "rule": claim, "source_host_id": "gemini-cli", "source_host_family": "gemini-compatible", "applicability_scope": "family", "applicable_host_ids": [], "applicable_host_families": ["gemini-compatible"]}
        for target in (host_target, family_target):
            with self.subTest(scope=target["applicability_scope"]):
                changeset = curate_candidate(self._host_candidate(claim=claim), [target], {"provider_id": "test-provider"})
                self.assertNotEqual(changeset.operations[0].operation, "ATTACH_EVIDENCE")

    def test_curator_matches_universal_cross_host_but_updates_keep_target_scope(self):
        claim = "When the same issue returns, record the verified cause and rerun the focused check."
        target = {"pattern_id": "pat-universal", "cluster_id": "cluster-universal", "status": "active", "rule": claim, "classification": "private-reusable", "source_host_id": "codex-cli", "source_host_family": "codex-compatible", "applicability_scope": "universal", "applicable_host_ids": [], "applicable_host_families": []}
        changeset = curate_candidate(self._host_candidate(host_id="gemini-cli", family="gemini-compatible", claim=claim), [target], {"provider_id": "test-provider"})
        self.assertEqual(changeset.operations[0].operation, "ATTACH_EVIDENCE")
        with tempfile.TemporaryDirectory() as tmp:
            settings = self._settings(Path(tmp))
            append_event(Event.create("pattern.promoted", "2026-09-09T00:00:00+00:00", "test", "machine", target, event_id="evt_target_universal"), settings.paths.event_dir)
            result = apply_changeset(changeset, settings)
            self.assertTrue(result.applied, result)
            revised = next(event for event in iter_events(settings.paths.event_dir) if event.event_type == "pattern.revised")
            self.assertEqual((revised.payload["source_host_id"], revised.payload["source_host_family"], revised.payload["applicability_scope"]), ("codex-cli", "codex-compatible", "universal"))

    def _direct_curator_mapping(self, **overrides):
        candidate = {
            "decision": "YES",
            "title": "Direct curator host scope",
            "claim": "A direct curator candidate must fail closed when its universal lists are malformed.",
            "benefit": "reduced_rework",
            "classification": "private-reusable",
            "evidence_refs": ["sha256:" + "c" * 64],
            "source_host_id": "codex-cli",
            "source_host_family": "codex-compatible",
            "applicability_scope": "universal",
            "applicable_host_ids": [],
            "applicable_host_families": [],
        }
        candidate.update(overrides)
        return candidate

    def _direct_curator_payload(self, candidate):
        changeset = curate_candidate(candidate, [], {"provider_id": "test-provider"})
        self.assertTrue(changeset.operations)
        return changeset.operations[0].payload

    def test_direct_curator_missing_universal_lists_fall_back_to_source_host(self):
        candidate = self._direct_curator_mapping()
        del candidate["applicable_host_ids"]
        del candidate["applicable_host_families"]
        payload = self._direct_curator_payload(candidate)
        self.assertEqual((payload["applicability_scope"], payload["applicable_host_ids"], payload["applicable_host_families"]), ("host", ["codex-cli"], []))

    def test_direct_curator_non_empty_universal_host_ids_fall_back_to_source_host(self):
        payload = self._direct_curator_payload(self._direct_curator_mapping(applicable_host_ids=["codex-cli"]))
        self.assertEqual((payload["applicability_scope"], payload["applicable_host_ids"], payload["applicable_host_families"]), ("host", ["codex-cli"], []))

    def test_direct_curator_non_empty_universal_host_families_fall_back_to_source_host(self):
        payload = self._direct_curator_payload(self._direct_curator_mapping(applicable_host_families=["codex-compatible"]))
        self.assertEqual((payload["applicability_scope"], payload["applicable_host_ids"], payload["applicable_host_families"]), ("host", ["codex-cli"], []))

    def test_direct_curator_duplicate_universal_lists_fall_back_to_source_host(self):
        payload = self._direct_curator_payload(self._direct_curator_mapping(applicable_host_ids=["codex-cli", "codex-cli"]))
        self.assertEqual((payload["applicability_scope"], payload["applicable_host_ids"], payload["applicable_host_families"]), ("host", ["codex-cli"], []))

    def test_direct_curator_non_column_universal_lists_fall_back_to_source_host(self):
        payload = self._direct_curator_payload(self._direct_curator_mapping(applicable_host_ids="codex-cli"))
        self.assertEqual((payload["applicability_scope"], payload["applicable_host_ids"], payload["applicable_host_families"]), ("host", ["codex-cli"], []))

    def test_direct_curator_valid_empty_universal_lists_remain_universal(self):
        payload = self._direct_curator_payload(self._direct_curator_mapping(applicable_host_ids=[], applicable_host_families=[]))
        self.assertEqual((payload["applicability_scope"], payload["applicable_host_ids"], payload["applicable_host_families"]), ("universal", [], []))

    def test_gate_rejects_duplicate_host_targets_without_normalizing(self):
        base = {
            "decision": "YES",
            "reason_code": "evidence_verified",
            "candidate_title": "Host-aware title",
            "candidate_claim": "A sufficiently long reusable claim for gate validation.",
            "evidence_refs": ["sha256:" + "b" * 64],
            "benefit": "reduced_rework",
            "classification": "private-reusable",
            "confidence": 0.9,
            "applicability_scope": "host",
            "applicable_host_ids": ["codex-cli", "codex-cli"],
            "applicable_host_families": [],
        }
        with self.assertRaisesRegex(ValueError, "GATE_HOST_LIST_INVALID"):
            GateDecision.from_mapping(base, source_host_id="codex-cli", source_host_family="codex-compatible")

    def test_root_closeout_uses_trusted_candidate_pair_and_preserves_gate_fields(self):
        from ei.cli import main
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "config").mkdir()
            (root / "config" / "defaults.json").write_text('{"retrieval":{"max_chars":5000,"max_results":5}}', encoding="utf-8")
            payload = {
                "candidate": {
                    "source_host_id": "codex-cli",
                    "source_host_family": "codex-compatible",
                    "source_ref": "safe-source",
                    "domain": "testing",
                },
                "gate_decision": {
                    "decision": "YES",
                    "reason_code": "evidence_verified",
                    "candidate_title": "Trusted closeout",
                    "candidate_claim": "A sufficiently long reusable claim for closeout validation.",
                    "evidence_refs": ["sha256:" + "a" * 64],
                    "benefit": "reduced_rework",
                    "classification": "private-reusable",
                    "confidence": 0.9,
                    "applicability_scope": "universal",
                    "applicable_host_ids": [],
                    "applicable_host_families": [],
                    "source_host_id": "gemini-cli",
                    "source_host_family": "gemini-compatible",
                },
            }
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                input_path = root / "closeout.json"
                input_path.write_text(json.dumps(payload), encoding="utf-8")
                code = main(["closeout", "--repo", str(root), "--codex-home", str(root / "codex"), "--runtime-root", str(root / "runtime"), "--input-json", str(input_path)])
            self.assertEqual(code, 0, output.getvalue())
            result = json.loads(output.getvalue())
            self.assertEqual(result["gate"]["source_host_id"], "codex-cli")
            self.assertEqual(result["gate"]["source_host_family"], "codex-compatible")
            self.assertEqual(result["gate"]["applicability_scope"], "universal")
            audit = next(event for event in iter_events(root / "events") if event.event_type == "gate.decision")
            self.assertEqual((audit.payload["source_host_id"], audit.payload["source_host_family"]), ("codex-cli", "codex-compatible"))

    def test_observation_and_pattern_schemas_declare_legacy_or_complete_applicability_branches(self):
        root = Path(__file__).resolve().parents[2]
        for name in ("observation.schema.json", "pattern.schema.json"):
            schema = json.loads((root / "schemas" / name).read_text(encoding="utf-8"))
            branches = schema.get("allOf", [])
            self.assertTrue(any(isinstance(branch, dict) and "oneOf" in branch for branch in branches), name)
            one_of = next(branch["oneOf"] for branch in branches if isinstance(branch, dict) and "oneOf" in branch)
            self.assertEqual(len(one_of), 2, name)
            self.assertIn("required", one_of[1], name)
            self.assertEqual(set(one_of[1]["required"]), {"source_host_id", "source_host_family", "applicability_scope", "applicable_host_ids", "applicable_host_families"})

    def test_applicability_schema_comments_point_to_authoritative_python_validator(self):
        root = Path(__file__).resolve().parents[2]
        for name in ("observation.schema.json", "pattern.schema.json", "change-set.schema.json"):
            schema = json.loads((root / "schemas" / name).read_text(encoding="utf-8"))
            self.assertIn("$comment", schema, name)
            self.assertIn("authoritative Python validator", schema["$comment"], name)
        installed = json.loads((root / "skills" / "external-intelligence" / "schemas" / "change-set.schema.json").read_text(encoding="utf-8"))
        self.assertIn("$comment", installed)
        self.assertIn("authoritative Python validator", installed["$comment"])

    def test_changeset_action_contract_is_scoped_at_operation_level(self):
        root = Path(__file__).resolve().parents[2]
        schema = json.loads((root / "schemas" / "change-set.schema.json").read_text(encoding="utf-8"))
        operation = schema["properties"]["operations"]["items"]
        self.assertIn("allOf", operation)
        payload = operation["properties"]["payload"]
        self.assertIn("allOf", payload)
        self.assertTrue(any("oneOf" in branch for branch in payload["allOf"]))
        self.assertFalse(schema["properties"]["source_host_id"]["pattern"].startswith("^$|"))
        self.assertFalse(schema["properties"]["source_host_family"]["pattern"].startswith("^$|"))

    def test_installed_closeout_script_keeps_the_same_trusted_pair_contract(self):
        root = Path(__file__).resolve().parents[2]
        script = (root / "skills" / "external-intelligence" / "scripts" / "closeout.py").read_text(encoding="utf-8")
        self.assertIn("trusted_source_host_id = candidate.get", script)
        self.assertIn("source_host_id=trusted_source_host_id", script)
        self.assertIn("applicability_scope", script)


if __name__ == "__main__":
    unittest.main()
