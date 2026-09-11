from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Mapping

from .canary import build_canary_receipt_from_event, record_canary
from .config import Settings, load_settings
from .context import build_context
from .experiment import prepare_exposure
from .hooks.base import HookResult, MAX_HOOK_INPUT_BYTES, NormalizedHookEvent, fail_open_result
from .hooks.registry import canonical_host_id, encode_hook_result, normalize_hook_event as _normalize_hook_event
from .queue import QueueError, enqueue_receipt
from .retrieve import ExposureRecord, RetrievalQuery, rank_patterns, record_retrieval_exposure


_BUDGET_ATTRS = {"session.start": "session_start_budget_ms", "prompt.before": "prompt_budget_ms", "turn.stop": "stop_budget_ms", "session.end": "session_end_budget_ms"}


def _hash(value: object) -> str:
    return hashlib.sha256(str(value).encode("utf-8", "replace")).hexdigest()[:24]


def _full_hash(value: object) -> str:
    return "sha256:" + hashlib.sha256(str(value).encode("utf-8", "replace")).hexdigest()


def _atomic_json(path: Path, value: Mapping[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(path.name + f".{os.getpid()}.tmp")
    temporary.write_text(json.dumps(dict(value), ensure_ascii=False, sort_keys=True, indent=2) + "\n", encoding="utf-8", newline="\n")
    try:
        os.replace(temporary, path)
    finally:
        if temporary.exists():
            temporary.unlink()


def _append_jsonl(path: Path, value: Mapping[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    line = (json.dumps(dict(value), ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")
    flags = os.O_APPEND | os.O_CREAT | os.O_WRONLY
    if hasattr(os, "O_BINARY"):
        flags |= os.O_BINARY
    descriptor = os.open(str(path), flags, 0o600)
    try:
        os.write(descriptor, line)
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _record_error(settings: Settings, reason_code: str, event_name: str) -> None:
    try:
        safe_event = "unsupported" if reason_code == "HOOK_EVENT_UNSUPPORTED" else (event_name if event_name in {"SessionStart", "SessionEnd", "UserPromptSubmit", "Stop", "PreToolUse", "PostToolUse"} else "unknown")
        _append_jsonl(settings.paths.runtime_dir / "hook-errors.jsonl", {"event": safe_event, "reason_code": reason_code, "recorded_at": datetime.now(timezone.utc).isoformat()})
    except Exception:
        return


def _parse_patterns(settings: Settings) -> list[dict[str, Any]]:
    knowledge = settings.paths.knowledge_dir
    index_json = knowledge / "index.json"
    if index_json.exists():
        try:
            from .index import build_index, read_index_items
            return [dict(item) for item in read_index_items(build_index(knowledge, index_json))]
        except (OSError, ValueError, KeyError, TypeError):
            _record_error(settings, "INDEX_UNAVAILABLE", "recall")
            return []
    index = knowledge / "index.md"
    if not index.exists():
        return []
    try:
        lines = index.read_text(encoding="utf-8", errors="strict").splitlines()
    except (OSError, UnicodeError):
        _record_error(settings, "INDEX_READ_FAILED", "recall")
        return []
    patterns: list[dict[str, Any]] = []
    section = ""
    for line in lines:
        stripped = line.strip()
        if stripped.startswith("## "):
            section = stripped[3:].casefold()
        if section and section != "active patterns":
            continue
        if stripped.startswith("- [") and "]" in stripped:
            end = stripped.find("]")
            pattern_id = stripped[3:end]
            rule = stripped[end + 1 :].strip()
            if pattern_id and rule:
                patterns.append({"pattern_id": pattern_id, "cluster_id": pattern_id, "status": "active", "classification": "private-reusable", "rule": rule, "evidence_count": 1, "benefit_count": 1, "updated_at": "1970-01-01T00:00:00+00:00"})
    if patterns:
        return patterns
    fallback = " ".join(line.strip() for line in lines if line.strip() and not line.lstrip().startswith("#"))
    return [{"pattern_id": "index-fallback-" + _hash(fallback), "cluster_id": "index-fallback", "status": "active", "classification": "private-reusable", "rule": fallback, "evidence_count": 1, "benefit_count": 1, "updated_at": "1970-01-01T00:00:00+00:00"}] if fallback else []


def normalize_hook_event(host_id: str, payload: Mapping[str, Any], settings: Settings) -> NormalizedHookEvent:
    return _normalize_hook_event(canonical_host_id(host_id), payload, settings)


def _deadline_ms(event: NormalizedHookEvent, settings: Settings) -> int:
    value = getattr(settings, _BUDGET_ATTRS.get(event.normalized_event_name, ""), 1000)
    return int(value) if type(value) is int and value > 0 else 1000


def _deadline_exceeded(started: float, event: NormalizedHookEvent, settings: Settings) -> bool:
    return (time.monotonic() - started) * 1000.0 > _deadline_ms(event, settings)


def _write_receipt(event: NormalizedHookEvent, settings: Settings, status: str) -> None:
    _append_jsonl(settings.paths.runtime_dir / "hook-receipts.jsonl", {**event.to_dict(), "status": status})
    try:
        record_canary(build_canary_receipt_from_event(event, settings), settings)
    except (OSError, TypeError, ValueError):
        _record_error(settings, "CANARY_RECEIPT_WRITE_FAILED", event.host_event_name)


def _write_turn_receipt(event: NormalizedHookEvent, settings: Settings) -> None:
    _append_jsonl(settings.paths.local_state_dir / "hook-queue.jsonl", {"event_id": event.event_id, "idempotency_key": event.idempotency_key, "normalized_event_name": event.normalized_event_name, "host_id": event.host_id, "host_instance_id": event.host_instance_id, "session_id_hash": event.session_id_hash, "turn_id_hash": event.turn_id_hash, "cwd_hash": event.cwd_hash, "source_hash": event.source_hash, "payload_hash": event.payload_hash, "received_at": event.to_dict()["received_at"]})


def _write_session_marker(event: NormalizedHookEvent, settings: Settings, filename: str) -> None:
    _append_jsonl(settings.paths.local_state_dir / filename, {"event_id": event.event_id, "idempotency_key": event.idempotency_key, "host_id": event.host_id, "host_instance_id": event.host_instance_id, "session_id_hash": event.session_id_hash, "turn_id_hash": event.turn_id_hash, "source_hash": event.source_hash, "payload_hash": event.payload_hash, "occurred_at": event.to_dict()["received_at"]})


def _record_exposure(event: NormalizedHookEvent, prompt: str, hit_ids: list[str], context: str, started: float, settings: Settings) -> None:
    try:
        record_retrieval_exposure(ExposureRecord(exposure_id=event.event_id, experiment_id=getattr(settings, "experiment_id", "retrieval-v1"), session_id_hash=event.session_id_hash, arm="treatment" if context else "control", selected_ids=tuple(hit_ids), query_fingerprint=_full_hash(prompt), injection_chars=len(context), retrieval_latency_ms=max(0, int((time.monotonic() - started) * 1000)), host_id=event.host_id, recorded_at=datetime.now(timezone.utc)), settings.paths.runtime_dir / "retrieval-exposures.jsonl")
    except (OSError, ValueError, TypeError):
        _record_error(settings, "EXPOSURE_WRITE_FAILED", event.host_event_name)


def _recall(event: NormalizedHookEvent, prompt: str, settings: Settings, layer: str, max_chars: int) -> tuple[list[Any], str]:
    patterns = _parse_patterns(settings)
    query = RetrievalQuery(
        prompt=prompt,
        cwd_hash=event.cwd_hash,
        host_id=event.source_host_id,
        host_family=event.source_host_family,
    )
    hits = rank_patterns(query, patterns)
    context = build_context(hits, max_chars, layer=layer) if hits else ""
    return hits, context


def handle_normalized_hook(event: NormalizedHookEvent, settings: Settings) -> HookResult:
    started = time.monotonic()
    try:
        _write_receipt(event, settings, "received")
    except (OSError, ValueError, TypeError):
        _record_error(settings, "RECEIPT_WRITE_FAILED", event.host_event_name)
        return fail_open_result(event.host_event_name, "RECEIPT_WRITE_FAILED")
    try:
        if _deadline_exceeded(started, event, settings):
            _record_error(settings, "DEADLINE_EXCEEDED", event.host_event_name)
            return fail_open_result(event.host_event_name, "DEADLINE_EXCEEDED")
        if event.normalized_event_name == "turn.stop":
            try:
                enqueue_receipt(event, None, settings)
            except (QueueError, OSError, ValueError) as exc:
                _record_error(settings, "QUEUE_ENQUEUE_FAILED", event.host_event_name)
                del exc
            try:
                _write_turn_receipt(event, settings)
            except (OSError, ValueError, TypeError):
                _record_error(settings, "LOCAL_QUEUE_WRITE_FAILED", event.host_event_name)
            status = "DEADLINE_EXCEEDED" if _deadline_exceeded(started, event, settings) else "ok"
            if status != "ok":
                _record_error(settings, status, event.host_event_name)
            return HookResult(True, "", event.event_id, status, event.host_event_name)
        if event.normalized_event_name == "session.end":
            _append_jsonl(settings.paths.runtime_dir / "session-end.jsonl", event.to_dict())
            _write_session_marker(event, settings, "session-cursors.jsonl")
            status = "DEADLINE_EXCEEDED" if _deadline_exceeded(started, event, settings) else "ok"
            return HookResult(True, "", event.event_id, status, event.host_event_name)
        if event.normalized_event_name == "session.start":
            hits, context = _recall(event, event.transient_input or "", settings, "session_start", min(int(getattr(settings, "session_start_max_chars", 2000)), 2000))
            _write_session_marker(event, settings, "session-start.jsonl")
            if _deadline_exceeded(started, event, settings):
                _record_error(settings, "DEADLINE_EXCEEDED", event.host_event_name)
                context = ""
                status = "DEADLINE_EXCEEDED"
            else:
                status = "ok"
            if not context:
                return HookResult(True, "", event.event_id, status, event.host_event_name)
            _record_exposure(event, event.transient_input or "", [hit.pattern_id for hit in hits], context, started, settings)
            return HookResult(True, context, event.event_id, status, event.host_event_name)
        if event.normalized_event_name != "prompt.before":
            return fail_open_result(event.host_event_name, "HOOK_EVENT_UNSUPPORTED")
        prompt = event.transient_input or ""
        if getattr(settings, "experiment_enabled", False) and event.session_id_hash:
            patterns = _parse_patterns(settings)
            exposure = prepare_exposure(event.session_id_hash, getattr(settings, "experiment_id", "retrieval-v1"), prompt, patterns, cwd_fingerprint=event.cwd_hash, record_path=settings.paths.runtime_dir / "experiment-exposures.jsonl", observed_at=datetime.now(timezone.utc).isoformat(), host_id=event.source_host_id, host_family=event.source_host_family)
            hit_ids = list(exposure.candidate_ids)
            context = exposure.additional_context
        else:
            hits, context = _recall(event, prompt, settings, "prompt", min(int(getattr(settings, "retrieval_max_chars", 5000)), int(getattr(settings, "prompt_max_chars", 5000))))
            hit_ids = [hit.pattern_id for hit in hits]
        status = "DEADLINE_EXCEEDED" if _deadline_exceeded(started, event, settings) else "ok"
        if status != "ok":
            _record_error(settings, status, event.host_event_name)
            context = ""
        _record_exposure(event, prompt, hit_ids, context, started, settings)
        state = {"occurred_at": datetime.now(timezone.utc).isoformat(), "prompt_hash": _hash(prompt), "hit_count": len(hit_ids), "context_chars": len(context), "status": status}
        _append_jsonl(settings.paths.runtime_dir / "last-successful-query.jsonl", state)
        _atomic_json(settings.paths.local_state_dir / "last-successful-query.json", state)
        return HookResult(True, context, event.event_id, status, event.host_event_name)
    except Exception as exc:
        _record_error(settings, type(exc).__name__, event.host_event_name)
        return fail_open_result(event.host_event_name, type(exc).__name__)


def run_hook(host_id: str, stdin: bytes, deadline_ms: int, settings: Settings) -> HookResult:
    started = time.monotonic()
    event_name = ""
    try:
        if not isinstance(stdin, (bytes, bytearray, memoryview)):
            raise ValueError("HOOK_INPUT_BYTES_REQUIRED")
        raw = bytes(stdin)
        if len(raw) > MAX_HOOK_INPUT_BYTES:
            raise ValueError("HOOK_INPUT_TOO_LARGE")
        try:
            decoded = raw.decode("utf-8")
            payload = json.loads(decoded)
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ValueError("HOOK_INPUT_INVALID") from exc
        if not isinstance(payload, Mapping):
            raise ValueError("HOOK_INPUT_NOT_OBJECT")
        event_name = str(payload.get("hook_event_name", payload.get("event_name", payload.get("event", ""))))
        if os.environ.get("EI_INTERNAL") == "1":
            return fail_open_result(event_name, "RECURSION_GUARD")
        event = normalize_hook_event(host_id, payload, settings)
        result = handle_normalized_hook(event, settings)
        try:
            requested = int(deadline_ms)
        except (TypeError, ValueError):
            requested = _deadline_ms(event, settings)
        if requested > 0 and (time.monotonic() - started) * 1000.0 > requested:
            return HookResult(True, "", result.receipt_id, "DEADLINE_EXCEEDED", event.host_event_name)
        return result
    except ValueError as exc:
        _record_error(settings, str(exc), event_name)
        return fail_open_result(event_name, str(exc))
    except Exception as exc:
        _record_error(settings, type(exc).__name__, event_name)
        return fail_open_result(event_name, type(exc).__name__)


def _response(host_id: str, result: HookResult) -> dict[str, Any]:
    try:
        return dict(encode_hook_result(host_id, result))
    except Exception:
        return {"continue": True}


def handle_hook(input_json: Mapping[str, Any], settings: Settings, host_id: str | None = None) -> dict[str, Any]:
    if os.environ.get("EI_INTERNAL") == "1":
        return {"continue": True}
    if not isinstance(input_json, Mapping):
        return {"continue": True}
    selected_host = canonical_host_id(host_id or str(input_json.get("host_id", "codex-cli")))
    try:
        event = normalize_hook_event(selected_host, input_json, settings)
        return _response(selected_host, handle_normalized_hook(event, settings))
    except ValueError as exc:
        _record_error(settings, str(exc), str(input_json.get("hook_event_name", "")))
        return {"continue": True}
    except Exception as exc:
        _record_error(settings, type(exc).__name__, str(input_json.get("hook_event_name", "")))
        return {"continue": True}


def _read_stdin_bounded(limit: int = MAX_HOOK_INPUT_BYTES) -> str:
    binary = getattr(sys.stdin, "buffer", None)
    if binary is not None:
        raw = binary.read(limit + 1)
        if not isinstance(raw, bytes):
            raise ValueError("HOOK_INPUT_INVALID")
        if len(raw) > limit:
            raise ValueError("HOOK_INPUT_TOO_LARGE")
        try:
            return raw.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise ValueError("HOOK_INPUT_INVALID") from exc
    text = sys.stdin.read(limit + 1)
    if not isinstance(text, str):
        raise ValueError("HOOK_INPUT_INVALID")
    if len(text.encode("utf-8", "strict")) > limit:
        raise ValueError("HOOK_INPUT_TOO_LARGE")
    return text


def _write_stdout_json(value: Mapping[str, Any], *, ensure_ascii: bool = True) -> None:
    encoded = (json.dumps(dict(value), ensure_ascii=ensure_ascii, separators=(",", ":")) + "\n").encode("utf-8")
    binary = getattr(sys.stdout, "buffer", None)
    if binary is not None:
        binary.write(encoded)
        binary.flush()
        return
    sys.stdout.write(encoded.decode("utf-8"))
    sys.stdout.flush()


def _main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("event", nargs="?")
    parser.add_argument("--repo-root")
    parser.add_argument("--engine-root")
    parser.add_argument("--knowledge-root")
    parser.add_argument("--personal-knowledge-root")
    parser.add_argument("--team-knowledge-root")
    parser.add_argument("--runtime-root")
    parser.add_argument("--codex-home")
    parser.add_argument("--host-id", default="codex-cli")
    arguments = parser.parse_args()
    try:
        raw = _read_stdin_bounded()
        payload = json.loads(raw)
        if not isinstance(payload, dict):
            raise ValueError("HOOK_INPUT_NOT_OBJECT")
    except Exception:
        _write_stdout_json({"continue": True})
        return 2
    if arguments.event:
        payload.setdefault("hook_event_name", arguments.event)
    if os.environ.get("EI_INTERNAL") == "1":
        _write_stdout_json({"continue": True})
        return 0
    try:
        if not arguments.repo_root and not arguments.engine_root:
            raise ValueError("ENGINE_ROOT_REQUIRED")
        personal_root = arguments.personal_knowledge_root
        legacy_root = arguments.knowledge_root
        if personal_root is not None and legacy_root is not None:
            left = os.path.normcase(os.path.abspath(os.fspath(personal_root)))
            right = os.path.normcase(os.path.abspath(os.fspath(legacy_root)))
            if left != right:
                raise ValueError("PERSONAL_KNOWLEDGE_ROOT_CONFLICT")
        if personal_root is None:
            personal_root = legacy_root
        if arguments.engine_root or personal_root or arguments.team_knowledge_root:
            settings = load_settings(
                engine_root=Path(arguments.engine_root or arguments.repo_root),
                knowledge_root=Path(legacy_root) if legacy_root else None,
                personal_knowledge_root=Path(personal_root) if personal_root else None,
                team_knowledge_root=Path(arguments.team_knowledge_root) if arguments.team_knowledge_root else None,
                codex_home=Path(arguments.codex_home) if arguments.codex_home else None,
                runtime_root=Path(arguments.runtime_root) if arguments.runtime_root else None,
            )
        else:
            settings = load_settings(
                Path(arguments.repo_root),
                Path(arguments.codex_home) if arguments.codex_home else None,
                runtime_root=Path(arguments.runtime_root) if arguments.runtime_root else None,
            )
        _write_stdout_json(handle_hook(payload, settings, arguments.host_id), ensure_ascii=False)
    except Exception:
        _write_stdout_json({"continue": True})
    return 0


if __name__ == "__main__":
    raise SystemExit(_main())
