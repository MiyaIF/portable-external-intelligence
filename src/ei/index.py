from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path, PurePosixPath
from typing import Any, Mapping

from .models import KnowledgeIndex, host_applicability_fields


_ALLOWED_CLASSES = {"public", "private-reusable"}


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _safe_relative(value: object) -> Path | None:
    if not isinstance(value, str) or not value:
        return None
    path = PurePosixPath(value)
    if path.is_absolute() or ".." in path.parts or not path.parts:
        return None
    return Path(*path.parts)


def _load_index_document(index_path: Path) -> tuple[dict[str, Any], bytes]:
    try:
        raw = index_path.read_bytes()
    except OSError as exc:
        raise ValueError("INDEX_UNREADABLE") from exc
    try:
        document = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError("INDEX_JSON_INVALID") from exc
    if not isinstance(document, dict) or document.get("schema_version") != 2:
        raise ValueError("INDEX_SCHEMA_UNSUPPORTED")
    for key in ("active_pattern_ids", "candidate_pattern_ids", "archive_pattern_ids", "observation_ids"):
        if not isinstance(document.get(key), list) or not all(isinstance(item, str) and item for item in document[key]):
            raise ValueError(f"INDEX_{key.upper()}_INVALID")
    files = document.get("files")
    if not isinstance(files, dict) or not all(isinstance(path, str) and isinstance(value, str) for path, value in files.items()):
        raise ValueError("INDEX_FILES_INVALID")
    return document, raw


def _manifest_hash(root: Path) -> tuple[Path | None, str]:
    manifest = root / "manifest.json"
    if not manifest.is_file():
        return None, ""
    try:
        raw = manifest.read_bytes()
    except OSError:
        return manifest, ""
    return manifest, _sha256(raw)


def _validate_projection_files(root: Path, document: Mapping[str, Any]) -> None:
    files = document.get("files", {})
    assert isinstance(files, Mapping)
    for raw_path, expected_hash in files.items():
        relative = _safe_relative(raw_path)
        if relative is None:
            raise ValueError("INDEX_FILE_PATH_INVALID")
        target = (root / relative).resolve()
        try:
            target.relative_to(root.resolve())
        except ValueError as exc:
            raise ValueError("INDEX_FILE_PATH_ESCAPE") from exc
        if not target.is_file():
            raise ValueError("INDEX_ITEM_MISSING")
        try:
            actual_hash = _sha256(target.read_bytes())
        except OSError as exc:
            raise ValueError("INDEX_ITEM_UNREADABLE") from exc
        if actual_hash != expected_hash:
            raise ValueError("INDEX_FILE_HASH_MISMATCH")


def build_index(knowledge_dir: Path, index_path: Path) -> KnowledgeIndex:
    root = Path(knowledge_dir).resolve()
    if not root.is_dir():
        raise ValueError("KNOWLEDGE_DIR_MISSING")
    requested = Path(index_path).resolve()
    if requested.parent != root:
        raise ValueError("INDEX_PATH_OUTSIDE_KNOWLEDGE_DIR")
    source = root / "index.json" if requested == root / "index.json" or not requested.exists() else requested
    if source != requested and requested.parent != root:
        raise ValueError("INDEX_PATH_OUTSIDE_KNOWLEDGE_DIR")
    document, raw = _load_index_document(source)
    _validate_projection_files(source.parent, document)
    if source != requested:
        requested.parent.mkdir(parents=True, exist_ok=True)
        temporary = requested.with_name(requested.name + f".{os.getpid()}.tmp")
        temporary.write_bytes(raw)
        try:
            os.replace(temporary, requested)
        finally:
            if temporary.exists():
                temporary.unlink()
        source = requested
    manifest_path, manifest_hash = _manifest_hash(root)
    item_count = sum(len(document[key]) for key in ("active_pattern_ids", "candidate_pattern_ids", "archive_pattern_ids", "observation_ids"))
    return KnowledgeIndex(
        index_path=source,
        generation_hash=manifest_hash or _sha256(raw),
        item_count=item_count,
        schema_version="2",
        manifest_path=manifest_path,
        manifest_sha256=manifest_hash,
        active_pattern_ids=tuple(document["active_pattern_ids"]),
        archive_pattern_ids=tuple(document["archive_pattern_ids"]),
        observation_count=len(document["observation_ids"]),
        always_on_chars=int(document.get("always_on_chars", 0) or 0),
        candidate_pattern_ids=tuple(document.get("candidate_pattern_ids", ())),
    )


def _item_kind(document: Mapping[str, Any], item_id: str) -> tuple[str, Path] | None:
    for key, directory in (
        ("active_pattern_ids", "rules"),
        ("candidate_pattern_ids", "library"),
        ("archive_pattern_ids", "archive"),
        ("observation_ids", "memories"),
    ):
        values = document.get(key, ())
        if item_id in values:
            return key, Path(directory) / f"{item_id}.md"
    return None


def _parse_metadata(lines: list[str], item_id: str) -> dict[str, Any]:
    metadata: dict[str, Any] = {"pattern_id": item_id, "observation_id": item_id}
    rule_start = len(lines)
    for index, line in enumerate(lines):
        stripped = line.strip()
        if stripped.startswith("# "):
            continue
        if stripped.startswith("- ") and ":" in stripped:
            label, value = stripped[2:].split(":", 1)
            normalized = label.strip().casefold().replace(" ", "_")
            value = value.strip()
            if normalized in {"status", "classification", "precondition", "failure_mode", "version_constraint", "domain", "provenance", "cluster"}:
                key = "cluster_id" if normalized == "cluster" else normalized
                metadata[key] = None if value.casefold() in {"none", "null"} else value
            elif normalized in {"applicability", "provenances", "scopes"}:
                metadata[normalized] = [item.strip() for item in value.split(",") if item.strip()]
            elif normalized in {"applicability_scope", "source_host", "source_host_id", "source_host_family"}:
                key = "source_host_id" if normalized == "source_host" else normalized
                metadata[key] = value
            elif normalized in {"host_families", "host_ids", "applicable_host_families", "applicable_host_ids"}:
                key = "applicable_host_families" if normalized in {"host_families", "applicable_host_families"} else "applicable_host_ids"
                metadata[key] = [item.strip() for item in value.split(",") if item.strip()]
            elif normalized in {"benefit_evidence", "evidence_count"}:
                try:
                    metadata["benefit_count" if normalized == "benefit_evidence" else "evidence_count"] = int(value)
                except ValueError:
                    metadata["benefit_count" if normalized == "benefit_evidence" else "evidence_count"] = 0
            elif normalized == "updated":
                metadata["updated_at"] = value
            rule_start = index + 1
        elif stripped and index > 0 and not stripped.startswith("-"):
            rule_start = min(rule_start, index)
    rule_lines = [line for line in lines[rule_start:] if line.strip()]
    if rule_lines:
        metadata["rule"] = "\n".join(rule_lines).strip()
    metadata.setdefault("rule", "")
    metadata.setdefault("status", "active")
    metadata.setdefault("classification", "private-reusable")
    metadata.setdefault("applicability", metadata.get("scopes", []))
    metadata.setdefault("provenances", [])
    metadata.setdefault("evidence_count", len(metadata["provenances"]))
    metadata.setdefault("benefit_count", 0)
    metadata["cluster_id"] = metadata.get("cluster_id", item_id)
    host_fields = {
        "source_host_id", "source_host_family", "applicability_scope",
        "applicable_host_ids", "applicable_host_families",
    }
    if not host_fields.intersection(metadata):
        # Legacy pattern files are universal at read time only; their source
        # history is never rewritten by this compatibility default.
        metadata.update({
            "source_host_id": "",
            "source_host_family": "",
            "applicability_scope": "universal",
            "applicable_host_ids": [],
            "applicable_host_families": [],
        })
    else:
        normalized = host_applicability_fields(metadata, allow_legacy=False, require_source_pair=True)
        metadata.update(normalized)
    metadata.setdefault("source_host_id", "")
    metadata.setdefault("source_host_family", "")
    return metadata


def _read_item(document: Mapping[str, Any], root: Path, item_id: str) -> dict[str, Any]:
    if not isinstance(item_id, str) or not item_id or "/" in item_id or "\\" in item_id or item_id in {".", ".."}:
        raise ValueError("INDEX_ITEM_ID_INVALID")
    located = _item_kind(document, item_id)
    if located is None:
        raise KeyError(item_id)
    _, relative = located
    target = (root / relative).resolve()
    try:
        target.relative_to(root.resolve())
    except ValueError as exc:
        raise ValueError("INDEX_ITEM_PATH_ESCAPE") from exc
    expected = document.get("files", {}).get(relative.as_posix())
    if isinstance(expected, str):
        if not target.is_file() or _sha256(target.read_bytes()) != expected:
            raise ValueError("INDEX_ITEM_HASH_MISMATCH")
    try:
        lines = target.read_text(encoding="utf-8", errors="strict").splitlines()
    except (OSError, UnicodeError) as exc:
        raise ValueError("INDEX_ITEM_UNREADABLE") from exc
    item = _parse_metadata(lines, item_id)
    item["item_id"] = item_id
    return item


def read_index_item(index: KnowledgeIndex, item_id: str) -> Mapping[str, Any]:
    if not isinstance(index, KnowledgeIndex):
        raise TypeError("KNOWLEDGE_INDEX_REQUIRED")
    document, _ = _load_index_document(Path(index.index_path).resolve())
    return _read_item(document, Path(index.index_path).resolve().parent, item_id)


def read_index_items(index: KnowledgeIndex, item_ids: tuple[str, ...] | list[str] | None = None) -> tuple[Mapping[str, Any], ...]:
    if not isinstance(index, KnowledgeIndex):
        raise TypeError("KNOWLEDGE_INDEX_REQUIRED")
    index_path = Path(index.index_path).resolve()
    document, _ = _load_index_document(index_path)
    ids = tuple(item_ids) if item_ids is not None else tuple(document["active_pattern_ids"])
    return tuple(_read_item(document, index_path.parent, item_id) for item_id in ids)


__all__ = ["build_index", "read_index_item", "read_index_items"]
