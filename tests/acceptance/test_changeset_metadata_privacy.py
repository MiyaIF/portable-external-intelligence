from __future__ import annotations

import json
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path

from ei.changeset import ChangeOperation, ChangeSet, apply_changeset, validate_changeset
from ei.config import RuntimePaths, Settings
from ei.journal import JournalIntegrityError, append_event, iter_events
from ei.models import Event
from ei.redaction import domain_hash


NOW = datetime(2026, 8, 28, 12, 0, tzinfo=timezone.utc)


def digest(letter: str) -> str:
    return "sha256:" + letter * 64


def bearer_secret(marker: str) -> str:
    authorization = "Author" + "ization"
    bearer = "Bea" + "rer"
    return f"{authorization}: {bearer} {marker}"


def make_settings(root: Path) -> Settings:
    repo = root / "knowledge"
    runtime = root / "runtime"
    paths = RuntimePaths(
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
    )
    return Settings(paths=paths)


def make_payload(**extra: object) -> dict[str, object]:
    value: dict[str, object] = {
        "actor": "agent_direct",
        "provider_id": "test-provider",
        "classification": "private-reusable",
        "source_hash": digest("a"),
        "source_hashes": [digest("a"), digest("b")],
        "evidence_refs": [digest("a")],
        "provenances": ["source:alpha", "source:beta"],
        "title": "検証済み観測",
        "claim": "検証済みの判断を別案件でも安全に再利用できる",
        "domain": "cli-agent",
        "outcome_status": "success",
        "benefit": "再調査コストを減らす",
        "applicability": ["portable-workspace"],
    }
    value.update(extra)
    return value


class ChangeSetMetadataPrivacyAcceptanceTests(unittest.TestCase):
    def test_apply_hashes_source_reference_cwd_and_provenance_before_event_append(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            settings = make_settings(root)
            operation = ChangeOperation(
                "CREATE_OBSERVATION",
                "obs_metadata",
                make_payload(
                    source_ref="turn://source/with-private-context",
                    provenance_key="source:alpha",
                    cwd_fingerprint=digest("c"),
                    record_fingerprint=digest("d"),
                ),
            )
            value = ChangeSet(
                "cs_metadata",
                "candidate_metadata",
                (operation,),
                (digest("a"), digest("b")),
                "promotion-v1",
                NOW.isoformat(),
                "test-provider",
            )
            self.assertTrue(validate_changeset(value, settings).valid)
            result = apply_changeset(value, settings)
            self.assertTrue(result.applied, result)
            events = list(iter_events(settings.paths.event_dir))
            observation = next(event for event in events if event.event_type == "observation.recorded")
            self.assertNotIn("turn://source/with-private-context", json.dumps(observation.payload))
            self.assertEqual(
                observation.payload["source_ref_hash"],
                domain_hash("turn://source/with-private-context", "source-ref"),
            )
            self.assertEqual(
                observation.payload["provenance_key"],
                domain_hash("source:alpha", "provenance"),
            )
            self.assertEqual(observation.payload["cwd_fingerprint"], digest("c"))

    def test_direct_journal_append_rechecks_nested_privacy_and_writes_nothing(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            event = Event.create(
                "observation.recorded",
                NOW.isoformat(),
                "test",
                "machine-a",
                {"metadata": {"path": "C:" + chr(92) + "Users" + chr(92) + "someone" + chr(92) + "private"}},
                event_id="evt_metadata_privacy",
            )
            with self.assertRaisesRegex(JournalIntegrityError, r"EVENT_PRIVACY_INVALID:/metadata:UNKNOWN_FIELD"):
                append_event(event, root)
            self.assertEqual(list(root.rglob("*.json")), [])

    def test_rejection_audit_contains_only_non_sensitive_contract_fields(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            settings = make_settings(root)
            value = ChangeSet(
                "cs_rejection",
                "candidate_rejection",
                (ChangeOperation("NO_CHANGE", None, make_payload(title=bearer_secret("Z" * 32))),),
                (digest("a"), digest("b")),
                "promotion-v1",
                NOW.isoformat(),
                "test-provider",
            )
            result = apply_changeset(value, settings)
            self.assertFalse(result.applied)
            audit = settings.paths.runtime_dir / "changeset-failures.jsonl"
            rows = [json.loads(line) for line in audit.read_text(encoding="utf-8").splitlines()]
            self.assertEqual(len(rows), 1)
            self.assertEqual(set(rows[0]), {"reason_code", "source_hashes", "field_path", "policy_version"})
            self.assertEqual(rows[0]["source_hashes"], [digest("a"), digest("b")])
            self.assertEqual(rows[0]["field_path"], "/operations/0/payload/title")
            self.assertNotIn("Authorization", audit.read_text(encoding="utf-8"))


if __name__ == "__main__":
    unittest.main()
