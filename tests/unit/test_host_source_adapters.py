import json
import tempfile
import time
import unittest
from pathlib import Path

from ei.adapters.base import SourceRecord, scan_read_only
from ei.adapters.claude import ClaudeAdapter, ClaudeCodeAdapter
from ei.adapters.gemini import GeminiAdapter, GeminiCliAdapter
from ei.adapters.qwen import QwenAdapter, QwenCodeAdapter
from ei.adapters.transcript_metadata import TranscriptMetadataAdapter
from ei.models import Event


class HostSourceAdapterTests(unittest.TestCase):
    def test_claude_stable_memory_is_read_only_and_normalized(self):
        path = Path("tests/fixtures/sources/claude/stable-memory.json").resolve()
        before_bytes = path.read_bytes()
        before_mtime = path.stat().st_mtime_ns
        records = list(ClaudeAdapter([path]).iter_records({}))
        self.assertIsInstance(ClaudeCodeAdapter([path]), ClaudeAdapter)
        self.assertEqual(len(records), 1)
        self.assertEqual(records[0].source_kind, "claude_stable_memory")
        self.assertEqual(path.read_bytes(), before_bytes)
        self.assertEqual(path.stat().st_mtime_ns, before_mtime)

    def test_gemini_and_qwen_metadata_are_read_without_transient_content(self):
        gemini = Path("tests/fixtures/sources/gemini/session-metadata.json").resolve()
        qwen = Path("tests/fixtures/sources/qwen/session-metadata.json").resolve()
        gemini_records = list(GeminiAdapter([gemini]).iter_records({}))
        qwen_records = list(QwenAdapter([qwen]).iter_records({}))
        self.assertIsInstance(GeminiCliAdapter([gemini]), GeminiAdapter)
        self.assertIsInstance(QwenCodeAdapter([qwen]), QwenAdapter)
        self.assertEqual(gemini_records[0].cwd, "cwd:beta")
        self.assertEqual(qwen_records[0].cwd, "cwd:gamma")
        self.assertIsNone(gemini_records[0].candidate_text)
        self.assertIsNone(qwen_records[0].candidate_text)

    def test_malformed_host_metadata_is_unsupported_without_fabricated_records(self):
        cases = (
            (ClaudeAdapter, "tests/fixtures/sources/claude/malformed.json"),
            (GeminiAdapter, "tests/fixtures/sources/gemini/malformed.json"),
            (QwenAdapter, "tests/fixtures/sources/qwen/malformed.json"),
        )
        for adapter_type, raw_path in cases:
            with self.subTest(adapter=adapter_type.__name__):
                adapter = adapter_type([Path(raw_path).resolve()])
                self.assertEqual(list(adapter.iter_records({})), [])
                self.assertGreaterEqual(adapter.health["unsupported_format"], 1)

    def test_transcript_metadata_never_reads_transcript_body(self):
        with tempfile.TemporaryDirectory() as tmp:
            transcript = Path(tmp) / "raw-transcript.jsonl"
            marker = "transient-marker-must-not-be-copied"
            transcript.write_text(marker, encoding="utf-8")
            adapter = TranscriptMetadataAdapter(
                [
                    {
                        "session_id": "session-1",
                        "turn_id": "turn-1",
                        "cwd": "cwd:hash",
                        "transcript_path": str(transcript),
                        "model": "test",
                    }
                ],
                source_host_id="codex-cli",
                source_host_family="codex-compatible",
            )
            records = list(adapter.iter_records({}))
            self.assertEqual(len(records), 1)
            self.assertEqual(records[0].claim, "")
            self.assertNotIn(marker, json.dumps(records[0].event_fields()))
            self.assertEqual(transcript.read_text(encoding="utf-8"), marker)

    def test_source_record_transient_candidate_is_not_serialized(self):
        marker = "candidate-transient-marker"
        record = SourceRecord(
            source_kind="manual",
            source_ref="manual://record",
            source_hash="sha256:source",
            observed_at="2026-08-26T00:00:00+00:00",
            title="title",
            claim="safe reusable claim",
            cwd="",
            domain="test",
            outcome_status="success",
            benefit="reduced_search",
            classification="private-reusable",
            candidate_text=marker,
        )
        fields = record.event_fields()
        self.assertNotIn(marker, json.dumps(fields, ensure_ascii=False))
        event = Event.create(
            "observation.recorded",
            record.observed_at,
            "test",
            "machine",
            fields,
            event_id="evt_test_transient",
        )
        self.assertNotIn(marker, json.dumps(event.to_dict(), ensure_ascii=False))

    def test_scan_read_only_excludes_denied_paths_and_does_not_modify_files(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            safe = root / "stable-memory.json"
            safe.write_text('{"schema_version": 1}', encoding="utf-8")
            denied = root / ".env"
            denied.write_text("not a source", encoding="utf-8")
            transcript_dir = root / "transcripts"
            transcript_dir.mkdir()
            (transcript_dir / "session.json").write_text("not a source", encoding="utf-8")
            before = safe.read_bytes()
            paths = scan_read_only(root)
            self.assertEqual(paths, (safe.resolve(),))
            self.assertEqual(safe.read_bytes(), before)

    def test_fingerprint_contains_stable_source_identity(self):
        path = Path("tests/fixtures/sources/claude/stable-memory.json").resolve()
        cursor = ClaudeAdapter([path]).fingerprint(path)
        self.assertTrue(cursor.source_path_hash.startswith("sha256:"))
        self.assertEqual(cursor.size_bytes, path.stat().st_size)
        self.assertTrue(cursor.content_hash.startswith("sha256:"))
        self.assertEqual(cursor.parser_version, ClaudeAdapter.parser_version)


if __name__ == "__main__":
    unittest.main()
