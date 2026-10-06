from __future__ import annotations

import hashlib
import json
import os
import re
import stat
from pathlib import Path, PurePosixPath
from typing import Any, Mapping

from .models import KnowledgeIndex, host_applicability_fields
from .projection_state import validate_source_state
from .safe_fs import assert_safe_target


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


def _read_projection_bytes(path, *, budget=None, maximum=8 * 1024 * 1024):
    if budget is not None:
        budget.check()
    assert_safe_target(path.parent, path, allow_missing=False, expected_type="file")
    before = path.stat(follow_symlinks=False)
    identity = lambda value: (value.st_dev, value.st_ino, value.st_size, value.st_mtime_ns)
    if not stat.S_ISREG(before.st_mode) or before.st_size > maximum:
        raise ValueError("PROJECTION_STORAGE_LIMIT")
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0))
    with os.fdopen(descriptor, "rb") as stream:
        if identity(os.fstat(stream.fileno())) != identity(before):
            raise ValueError("INDEX_FILE_CHANGED")
        chunks, total = [], 0
        while True:
            if budget is not None:
                budget.check()
            chunk = stream.read(min(65536, maximum + 1 - total))
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
            if total > maximum:
                raise ValueError("PROJECTION_STORAGE_LIMIT")
        if identity(os.fstat(stream.fileno())) != identity(before):
            raise ValueError("INDEX_FILE_CHANGED")
    assert_safe_target(path.parent, path, allow_missing=False, expected_type="file")
    if identity(path.stat(follow_symlinks=False)) != identity(before):
        raise ValueError("INDEX_FILE_CHANGED")
    if budget is not None:
        budget.check()
    return b"".join(chunks)


def _load_index_document(index_path: Path, *, budget=None) -> tuple[dict[str, Any], bytes]:
    try:
        if index_path.parent.parent.name == ".projection-generations" and not index_path.is_file():
            raise ValueError("INDEX_GENERATION_EXPIRED")
        raw = _read_projection_bytes(index_path, budget=budget) if budget is not None or index_path.parent.parent.name == ".projection-generations" else index_path.read_bytes()
    except TimeoutError:
        raise
    except OSError as exc:
        raise ValueError("INDEX_UNREADABLE") from exc
    try:
        document = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError("INDEX_JSON_INVALID") from exc
    if not isinstance(document, dict) or document.get("schema_version") != 2:
        raise ValueError("INDEX_SCHEMA_UNSUPPORTED")
    if "source_state" in document:
        validate_source_state(document["source_state"])
    for key in ("active_pattern_ids", "candidate_pattern_ids", "archive_pattern_ids", "observation_ids"):
        if not isinstance(document.get(key), list) or not all(isinstance(item, str) and item for item in document[key]):
            raise ValueError(f"INDEX_{key.upper()}_INVALID")
    files = document.get("files")
    if not isinstance(files, dict) or not all(isinstance(path, str) and isinstance(value, str) for path, value in files.items()):
        raise ValueError("INDEX_FILES_INVALID")
    return document, raw


def _generation_reference(root, value):
    if not isinstance(value, dict) or set(value) != {"path", "manifest_sha256"} or not isinstance(value["path"], str) or not re.fullmatch(r"\.projection-generations/[0-9a-f]{64}", value["path"]) or not isinstance(value["manifest_sha256"], str) or not re.fullmatch(r"[0-9a-f]{64}", value["manifest_sha256"]):
        raise ValueError("INDEX_GENERATION_INVALID")
    if value["path"].split("/")[-1] != value["manifest_sha256"]:
        raise ValueError("INDEX_GENERATION_INVALID")
    return assert_safe_target(root, root / value["path"], allow_missing=False, expected_type="dir")


def _resolve_generation(root, document, *, budget=None, manifest_hash=None):
    if "projection_generation" not in document:
        return None
    descriptor = document["projection_generation"]
    if not isinstance(descriptor, dict) or set(descriptor) != {"path", "manifest_sha256", "previous", "mirror_sha256"} or not isinstance(descriptor["mirror_sha256"], str) or not re.fullmatch(r"[0-9a-f]{64}", descriptor["mirror_sha256"]):
        raise ValueError("INDEX_GENERATION_INVALID")
    selected = {key: descriptor[key] for key in ("path", "manifest_sha256")}
    if descriptor["previous"] is not None:
        _generation_reference(root, descriptor["previous"])
    current = manifest_hash is None or manifest_hash == selected["manifest_sha256"]
    if not current:
        selected = descriptor["previous"]
        if selected is None or selected["manifest_sha256"] != manifest_hash:
            raise ValueError("INDEX_GENERATION_EXPIRED")
    generation = _generation_reference(root, selected)
    manifest = _read_projection_bytes(generation / "manifest.json", budget=budget)
    if _sha256(manifest) != selected["manifest_sha256"]:
        raise ValueError("INDEX_GENERATION_INVALID")
    generated, raw = _load_index_document(generation / "index.json", budget=budget)
    if "projection_generation" in generated or current and {key: value for key, value in document.items() if key != "projection_generation"} != generated:
        raise ValueError("INDEX_GENERATION_INVALID")
    return generation, generated, raw


def _manifest_hash(root: Path, *, budget=None) -> tuple[Path | None, str]:
    if budget is not None:
        budget.check()
    manifest = root / "manifest.json"
    if not manifest.is_file():
        return None, ""
    try:
        raw = _read_projection_bytes(manifest, budget=budget)
    except TimeoutError:
        raise
    except OSError:
        return manifest, ""
    return manifest, _sha256(raw)


def _validate_projection_files(root: Path, document: Mapping[str, Any], *, budget=None) -> None:
    files = document.get("files", {})
    assert isinstance(files, Mapping)
    if (budget is not None or root.parent.name == ".projection-generations") and len(files) > 120000:
        raise ValueError("PROJECTION_STORAGE_LIMIT")
    total = 0
    for raw_path, expected_hash in files.items():
        if budget is not None:
            budget.check()
        relative = _safe_relative(raw_path)
        if relative is None:
            raise ValueError("INDEX_FILE_PATH_INVALID")
        target = assert_safe_target(root, root / relative, allow_missing=True, expected_type="file")
        try:
            target.relative_to(root.resolve())
        except ValueError as exc:
            raise ValueError("INDEX_FILE_PATH_ESCAPE") from exc
        if not target.is_file():
            if root.parent.name == ".projection-generations":
                raise ValueError("INDEX_GENERATION_EXPIRED")
            raise ValueError("INDEX_ITEM_MISSING")
        try:
            raw = _read_projection_bytes(target, budget=budget) if budget is not None or root.parent.name == ".projection-generations" else target.read_bytes()
            total += len(raw)
            if total > 64 * 1024 * 1024 and (budget is not None or root.parent.name == ".projection-generations"):
                raise ValueError("PROJECTION_STORAGE_LIMIT")
            actual_hash = _sha256(raw)
        except TimeoutError:
            raise
        except OSError as exc:
            raise ValueError("INDEX_ITEM_UNREADABLE") from exc
        if actual_hash != expected_hash:
            raise ValueError("INDEX_FILE_HASH_MISMATCH")


def build_index(knowledge_dir: Path, index_path: Path, *, budget=None) -> KnowledgeIndex:
    if budget is not None:
        from .safe_fs import assert_no_reparse_components
        budget.check()
        assert_no_reparse_components(Path(knowledge_dir))
        assert_no_reparse_components(Path(index_path))
        budget.check()
    root = Path(knowledge_dir).resolve()
    if not root.is_dir():
        raise ValueError("KNOWLEDGE_DIR_MISSING")
    requested = Path(index_path).resolve()
    if requested.parent != root:
        raise ValueError("INDEX_PATH_OUTSIDE_KNOWLEDGE_DIR")
    source = root / "index.json" if requested == root / "index.json" or not requested.exists() else requested
    if source != requested and requested.parent != root:
        raise ValueError("INDEX_PATH_OUTSIDE_KNOWLEDGE_DIR")
    document, raw = _load_index_document(source, budget=budget)
    resolved = _resolve_generation(root, document, budget=budget)
    if resolved is not None:
        root, document, raw = resolved
        source = root / "index.json"
    _validate_projection_files(source.parent, document, budget=budget)
    if "source_state" in document:
        # The manifest is published last. An interrupted generation must not
        # reuse its predecessor's generation hash with a newly written index.
        try:
            manifest_document = json.loads(_read_projection_bytes(root / "manifest.json", budget=budget))
        except TimeoutError:
            raise
        except (OSError, UnicodeError, json.JSONDecodeError) as exc:
            raise ValueError("PROJECTION_MANIFEST_MISMATCH") from exc
        manifest_files = manifest_document.get("files") if isinstance(manifest_document, Mapping) else None
        if not isinstance(manifest_files, Mapping) or manifest_files.get("index.json") != _sha256(raw):
            raise ValueError("PROJECTION_MANIFEST_MISMATCH")
    if source != requested and resolved is None:
        requested.parent.mkdir(parents=True, exist_ok=True)
        temporary = requested.with_name(requested.name + f".{os.getpid()}.tmp")
        temporary.write_bytes(raw)
        try:
            os.replace(temporary, requested)
        finally:
            if temporary.exists():
                temporary.unlink()
        source = requested
    manifest_path, manifest_hash = _manifest_hash(root, budget=budget)
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


def _parse_metadata(lines: list[str], item_id: str, *, budget=None) -> dict[str, Any]:
    metadata: dict[str, Any] = {"pattern_id": item_id, "observation_id": item_id}
    rule_start = len(lines)
    for index, line in enumerate(lines):
        if budget is not None:
            budget.check()
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


def _read_item(document: Mapping[str, Any], root: Path, item_id: str, *, budget=None) -> dict[str, Any]:
    if budget is not None:
        budget.check()
    if not isinstance(item_id, str) or not item_id or "/" in item_id or "\\" in item_id or item_id in {".", ".."}:
        raise ValueError("INDEX_ITEM_ID_INVALID")
    located = _item_kind(document, item_id)
    if located is None:
        raise KeyError(item_id)
    _, relative = located
    target = assert_safe_target(root, root / relative, allow_missing=True, expected_type="file")
    try:
        target.relative_to(root.resolve())
    except ValueError as exc:
        raise ValueError("INDEX_ITEM_PATH_ESCAPE") from exc
    expected = document.get("files", {}).get(relative.as_posix())
    if not target.is_file() and root.parent.name == ".projection-generations":
        raise ValueError("INDEX_GENERATION_EXPIRED")
    try:
        raw = _read_projection_bytes(target, budget=budget) if budget is not None or root.parent.name == ".projection-generations" else target.read_bytes()
        if isinstance(expected, str) and _sha256(raw) != expected:
            raise ValueError("INDEX_ITEM_HASH_MISMATCH")
        lines = raw.decode("utf-8", errors="strict").splitlines()
    except TimeoutError:
        raise
    except (OSError, UnicodeError) as exc:
        raise ValueError("INDEX_ITEM_UNREADABLE") from exc
    item = _parse_metadata(lines, item_id, budget=budget)
    item["item_id"] = item_id
    return item


def read_index_item(index: KnowledgeIndex, item_id: str, *, budget=None) -> Mapping[str, Any]:
    if not isinstance(index, KnowledgeIndex):
        raise TypeError("KNOWLEDGE_INDEX_REQUIRED")
    document, root = _bound_document(index, budget=budget)
    return _read_item(document, root, item_id, budget=budget)


def _bound_document(index, *, budget=None):
    if budget is not None:
        budget.check()
    root = Path(index.index_path).resolve().parent
    document, raw = _load_index_document(Path(index.index_path), budget=budget)
    resolved = _resolve_generation(root, document, budget=budget, manifest_hash=index.manifest_sha256 or index.generation_hash)
    if resolved is not None:
        root, document, raw = resolved
    if root.parent.name == ".projection-generations":
        manifest_raw = _read_projection_bytes(root / "manifest.json", budget=budget)
        if _sha256(manifest_raw) != index.manifest_sha256 or root.name != index.manifest_sha256:
            raise ValueError("INDEX_GENERATION_INVALID")
        manifest = json.loads(manifest_raw)
        if not isinstance(manifest, dict) or not isinstance(manifest.get("files"), dict) or manifest["files"].get("index.json") != _sha256(raw):
            raise ValueError("PROJECTION_MANIFEST_MISMATCH")
    return document, root


def read_index_items(index: KnowledgeIndex, item_ids: tuple[str, ...] | list[str] | None = None, *, budget=None) -> tuple[Mapping[str, Any], ...]:
    if not isinstance(index, KnowledgeIndex):
        raise TypeError("KNOWLEDGE_INDEX_REQUIRED")
    document, root = _bound_document(index, budget=budget)
    ids = tuple(item_ids) if item_ids is not None else tuple(document["active_pattern_ids"])
    return tuple(_read_item(document, root, item_id, budget=budget) for item_id in ids)


__all__ = ["build_index", "read_index_item", "read_index_items"]
