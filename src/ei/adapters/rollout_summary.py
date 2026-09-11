from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable, Mapping, Sequence

from .base import SourceCursor, SourceRecord, fingerprint_source, scan_read_only


class RolloutSummaryAdapter:
    """Read documented rollout summary records, never raw transcript content."""

    parser_version = "rollout-summary-v2"
    capture_path = "rollout_summary"
    host_id = "codex-cli"
    host_family = "codex-compatible"

    def __init__(self, sources: Iterable[Path]):
        self.sources = tuple(Path(source) for source in sources)
        self.parse_skipped = 0
        self.health: dict[str, int] = {
            "parsed": 0,
            "parse_skipped": 0,
            "unsupported_format": 0,
            "excluded": 0,
        }

    @staticmethod
    def _sha256(content: bytes) -> str:
        return "sha256:" + hashlib.sha256(content).hexdigest()

    @staticmethod
    def _domain_from_path(path: Path) -> str:
        value = "".join(char if char.isalnum() or char in "-_" else "-" for char in path.stem.casefold()).strip("-")
        return value or "rollout"

    @classmethod
    def discover(cls, root: Path) -> Sequence[Path]:
        return tuple(path for path in scan_read_only(root) if path.suffix.casefold() == ".jsonl" and "rollout" in path.name.casefold())

    def fingerprint(self, source: Path) -> SourceCursor:
        return fingerprint_source(Path(source), self.parser_version)

    def read(self, source: Path) -> Iterable[SourceRecord]:
        path = Path(source)
        before = path.stat()
        content = path.read_bytes()
        after = path.stat()
        if before.st_size != after.st_size or before.st_mtime_ns != after.st_mtime_ns:
            raise ValueError("SOURCE_CHANGED_DURING_READ")
        source_hash = self._sha256(content)
        observed_at = datetime.fromtimestamp(before.st_mtime, timezone.utc).isoformat()
        session_id = ""
        context: dict[str, str] = {
            "cwd": "",
            "domain": self._domain_from_path(path),
            "outcome_status": "unknown",
        }
        for line in content.decode("utf-8", errors="strict").splitlines():
            if not line.strip():
                continue
            try:
                item = json.loads(line)
            except (TypeError, json.JSONDecodeError):
                self.parse_skipped += 1
                self.health["parse_skipped"] += 1
                continue
            if not isinstance(item, dict):
                self.parse_skipped += 1
                self.health["parse_skipped"] += 1
                continue
            item_type = item.get("type")
            if not isinstance(item_type, str):
                self.parse_skipped += 1
                self.health["parse_skipped"] += 1
                continue
            if item_type == "session_meta":
                payload = item.get("payload")
                if isinstance(payload, dict) and isinstance(payload.get("id"), str) and payload["id"].strip():
                    session_id = payload["id"].strip()
                else:
                    self.parse_skipped += 1
                    self.health["parse_skipped"] += 1
                continue
            if item_type == "turn_context":
                values = {key: item.get(key) for key in ("cwd", "domain", "outcome_status")}
                if not isinstance(values["cwd"], str) or not isinstance(values["domain"], str):
                    self.parse_skipped += 1
                    self.health["parse_skipped"] += 1
                    continue
                if not values["cwd"].strip() or not values["domain"].strip():
                    self.parse_skipped += 1
                    self.health["parse_skipped"] += 1
                    continue
                context.update(
                    {
                        "cwd": values["cwd"].strip(),
                        "domain": values["domain"].strip(),
                        "outcome_status": values["outcome_status"].strip()
                        if isinstance(values["outcome_status"], str) and values["outcome_status"].strip()
                        else "unknown",
                    }
                )
                continue
            if item_type == "event_msg":
                continue
            if item_type != "response_item":
                self.parse_skipped += 1
                self.health["parse_skipped"] += 1
                continue
            kind = item.get("kind")
            if kind not in {"reusable_knowledge", "failure"}:
                self.parse_skipped += 1
                self.health["parse_skipped"] += 1
                continue
            title = item.get("title")
            claim = item.get("claim")
            benefit = item.get("benefit")
            classification_value = item.get("classification", "private-reusable")
            if not all(isinstance(value, str) and value.strip() for value in (title, claim, benefit, classification_value)):
                self.parse_skipped += 1
                self.health["parse_skipped"] += 1
                continue
            if not context["cwd"]:
                self.parse_skipped += 1
                self.health["parse_skipped"] += 1
                continue
            outcome_value = item.get("outcome_status", context["outcome_status"])
            outcome = outcome_value.strip() if isinstance(outcome_value, str) and outcome_value.strip() else "unknown"
            if kind == "failure" and outcome == "unknown":
                outcome = "failed"
            self.health["parsed"] += 1
            normalized_classification = classification_value.strip().casefold()
            external_reference = (
                normalized_classification in {"external-reference", "external_reference"}
                or "article" in path.name.casefold()
                or "[external_article_copy]" in claim.casefold()
            )
            record_source_kind = "external_article_copy" if external_reference else "rollout_summary"
            record_classification = "external-reference" if external_reference else classification_value.strip()
            yield SourceRecord(
                source_kind=record_source_kind,
                source_ref=str(path.resolve()),
                source_hash=source_hash,
                observed_at=observed_at,
                title=title.strip(),
                claim=claim.strip(),
                cwd=context["cwd"],
                domain=context["domain"],
                outcome_status=outcome,
                benefit=benefit.strip(),
                classification=record_classification,
                applicability=(context["domain"],),
                provenance_key=f"rollout:{session_id or source_hash}",
                source_host_id=self.host_id,
                source_host_family=self.host_family,
            )

    def iter_records(self, cursor: Mapping[str, Any]) -> Iterable[SourceRecord]:
        del cursor
        self.parse_skipped = 0
        self.health.update({"parsed": 0, "parse_skipped": 0, "unsupported_format": 0, "excluded": 0})
        for source in self.sources:
            try:
                yield from self.read(source)
            except (OSError, UnicodeError, ValueError):
                self.parse_skipped += 1
                self.health["parse_skipped"] += 1
                self.health["unsupported_format"] += 1
