from __future__ import annotations

import json
import math
import os
import re
import time
from contextlib import contextmanager
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable, Literal, Mapping

from .ids import fingerprint, stable_hash


Arm = Literal["control", "treatment"]
_MEASUREMENT_DIR = "measurements"
_FORBIDDEN_FIELDS = frozenset(
    {
        "prompt",
        "response",
        "query",
        "raw_query",
        "transcript",
        "tool_output",
        "raw_tool_output",
        "content",
        "raw_content",
        "claim",
        "message",
    }
)
_ID_RE = re.compile(r"^[A-Za-z0-9_.:-]{1,160}$")
_HASH_RE = re.compile(r"^sha256:[0-9a-f]{12,64}$")
_METRIC_NAMES = (
    "repeated_search",
    "rework",
    "failure",
    "uncached_input",
    "cached_input",
    "turns_to_completion",
    "tool_calls",
    "retrieval_latency_ms",
    "incorrect_pattern_application",
    "explicit_correction",
    "privacy_incident",
)
_KNOWLEDGE_SCOPES = frozenset({"personal", "team"})


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _timestamp(value: str) -> str:
    if not value:
        return _now_iso()
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except (TypeError, ValueError) as exc:
        raise ValueError("MEASUREMENT_TIMESTAMP_INVALID") from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ValueError("MEASUREMENT_TIMESTAMP_TIMEZONE_REQUIRED")
    return parsed.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def _hash_identifier(value: object, field_name: str, *, allow_empty: bool = False) -> str:
    if value is None or str(value) == "":
        if allow_empty:
            return ""
        raise ValueError(f"MEASUREMENT_{field_name.upper()}_REQUIRED")
    text = str(value)
    if _HASH_RE.fullmatch(text) or (field_name == "exposure_id" and text.startswith("exp_") and _ID_RE.fullmatch(text)):
        return text
    return fingerprint(text)


def _safe_label(value: object, field_name: str, *, default: str = "unknown") -> str:
    text = default if value is None or str(value) == "" else str(value)
    if len(text) > 160 or "\x00" in text or re.match(r"^(?:[A-Za-z]:[\\\\/]|[/\\\\])", text) or any(marker in text.casefold() for marker in ("authorization:", "bearer ", "api_key", "token=")):
        raise ValueError(f"MEASUREMENT_{field_name.upper()}_INVALID")
    return text


def _safe_id_list(value: object) -> tuple[str, ...]:
    if value is None:
        return ()
    if not isinstance(value, (list, tuple, set, frozenset)):
        raise ValueError("MEASUREMENT_ID_LIST_INVALID")
    result: list[str] = []
    for item in value:
        text = str(item)
        if not _ID_RE.fullmatch(text):
            raise ValueError("MEASUREMENT_KNOWLEDGE_ID_INVALID")
        result.append(text)
    return tuple(sorted(set(result)))


def _safe_scope_list(value: object, count: int, field_name: str) -> tuple[str, ...]:
    if value in (None, "", (), [], set(), frozenset()):
        return ()
    if isinstance(value, str) or not isinstance(value, (list, tuple, set, frozenset)):
        raise ValueError(f"MEASUREMENT_{field_name.upper()}_INVALID")
    values = tuple(str(item) for item in value)
    if len(values) != count or any(item not in _KNOWLEDGE_SCOPES for item in values):
        raise ValueError(f"MEASUREMENT_{field_name.upper()}_INVALID")
    return values


def _number(value: object, field_name: str, *, allow_none: bool = True) -> float | None:
    if value is None or value == "":
        if allow_none:
            return None
        raise ValueError(f"MEASUREMENT_{field_name.upper()}_REQUIRED")
    try:
        number = float(value)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"MEASUREMENT_{field_name.upper()}_INVALID") from exc
    if not math.isfinite(number) or number < 0:
        raise ValueError(f"MEASUREMENT_{field_name.upper()}_INVALID")
    return int(number) if number.is_integer() else number


def _safe_sources(value: object) -> dict[str, str]:
    if value is None:
        return {}
    if not isinstance(value, Mapping):
        raise ValueError("MEASUREMENT_METRIC_SOURCES_INVALID")
    result: dict[str, str] = {}
    for key, source in value.items():
        name = str(key)
        if name not in _METRIC_NAMES:
            continue
        result[name] = _safe_label(source, f"{name}_source", default="")
    return dict(sorted(result.items()))


def _reject_raw_mapping(value: Mapping[str, Any]) -> None:
    present = sorted(key for key in value if str(key).casefold() in _FORBIDDEN_FIELDS)
    if present:
        raise ValueError("MEASUREMENT_RAW_FIELD_FORBIDDEN")


def _measurement_dir(settings: Any) -> Path:
    paths = getattr(settings, "paths", None)
    runtime = getattr(paths, "runtime_root", None) or getattr(paths, "runtime_dir", None)
    if runtime is None:
        raise ValueError("MEASUREMENT_RUNTIME_REQUIRED")
    return Path(runtime).resolve() / _MEASUREMENT_DIR


@dataclass(frozen=True)
class ExposureRecord:
    experiment_id: str
    session_id_hash: str
    query_fingerprint: str = ""
    arm: Arm = "control"
    candidate_ids: tuple[str, ...] = ()
    selected_ids: tuple[str, ...] = ()
    injected_chars: int = 0
    retrieval_latency_ms: int = 0
    host_id: str = "unknown"
    observed_at: str = ""
    protocol_hash: str = ""
    task_id_hash: str = ""
    model_family: str = "unknown"
    domain: str = ""
    eligible: bool = True
    shadow_retrieval: bool = True
    context_injected: bool = False
    contamination: bool = False
    source: str = "recall"
    host_instance_hash: str = ""
    exposure_id: str = ""
    candidate_knowledge_ids: tuple[str, ...] = ()
    selected_knowledge_ids: tuple[str, ...] = ()
    candidate_scopes: tuple[str, ...] = ()
    selected_scopes: tuple[str, ...] = ()
    empty_result: bool = False
    team_unavailable: bool = False
    scope: str = ""

    def __post_init__(self) -> None:
        if not self.experiment_id or len(self.experiment_id) > 160:
            raise ValueError("MEASUREMENT_EXPERIMENT_ID_INVALID")
        if self.arm not in {"control", "treatment"}:
            raise ValueError("MEASUREMENT_ARM_INVALID")
        session = _hash_identifier(self.session_id_hash, "session_id_hash")
        task = _hash_identifier(self.task_id_hash, "task_id_hash", allow_empty=True)
        if not task:
            task = _hash_identifier(f"{self.experiment_id}:{session}:{self.observed_at}", "task_id_hash")
        query = _hash_identifier(self.query_fingerprint, "query_fingerprint", allow_empty=True)
        candidates = _safe_id_list(self.candidate_ids or self.candidate_knowledge_ids)
        selected = _safe_id_list(self.selected_ids or self.selected_knowledge_ids)
        candidate_scopes = _safe_scope_list(self.candidate_scopes, len(candidates), "candidate_scopes")
        if not candidate_scopes:
            candidate_scopes = ("personal",) * len(candidates)
        selected_scopes = _safe_scope_list(self.selected_scopes, len(selected), "selected_scopes")
        if not selected_scopes:
            scope_by_id = dict(zip(candidates, candidate_scopes))
            selected_scopes = tuple(scope_by_id.get(item, "personal") for item in selected)
        scope_values = set(candidate_scopes)
        scope = str(self.scope or (next(iter(scope_values)) if len(scope_values) == 1 else "mixed" if scope_values else "personal"))
        if scope not in {"personal", "team", "mixed"}:
            raise ValueError("MEASUREMENT_SCOPE_INVALID")
        if not set(selected).issubset(set(candidates)):
            raise ValueError("MEASUREMENT_SELECTED_ID_NOT_CANDIDATE")
        injected = _number(self.injected_chars, "injected_chars", allow_none=False)
        latency = _number(self.retrieval_latency_ms, "retrieval_latency_ms", allow_none=False)
        if injected is None or latency is None:
            raise ValueError("MEASUREMENT_NUMBER_REQUIRED")
        observed = _timestamp(self.observed_at)
        host_instance = _hash_identifier(self.host_instance_hash, "host_instance_hash", allow_empty=True)
        explicit_contamination = bool(self.contamination)
        protocol_hash = _safe_label(self.protocol_hash, "protocol_hash", default="")
        source = _safe_label(self.source, "source", default="recall")
        object.__setattr__(self, "session_id_hash", session)
        object.__setattr__(self, "task_id_hash", task)
        object.__setattr__(self, "query_fingerprint", query)
        object.__setattr__(self, "candidate_ids", candidates)
        object.__setattr__(self, "selected_ids", selected)
        object.__setattr__(self, "candidate_knowledge_ids", candidates)
        object.__setattr__(self, "selected_knowledge_ids", selected)
        object.__setattr__(self, "candidate_scopes", candidate_scopes)
        object.__setattr__(self, "selected_scopes", selected_scopes)
        object.__setattr__(self, "scope", scope)
        object.__setattr__(self, "injected_chars", int(injected))
        object.__setattr__(self, "retrieval_latency_ms", int(latency))
        object.__setattr__(self, "observed_at", observed)
        object.__setattr__(self, "host_id", _safe_label(self.host_id, "host_id"))
        object.__setattr__(self, "host_instance_hash", host_instance)
        object.__setattr__(self, "model_family", _safe_label(self.model_family, "model_family"))
        object.__setattr__(self, "domain", _safe_label(self.domain, "domain", default=""))
        object.__setattr__(self, "protocol_hash", protocol_hash)
        object.__setattr__(self, "source", source)
        violates_control = self.arm == "control" and (bool(selected) or int(injected) > 0 or self.context_injected)
        object.__setattr__(self, "contamination", explicit_contamination or violates_control)
        if not self.exposure_id:
            material = {
                "experiment_id": self.experiment_id,
                "session_id_hash": session,
                "task_id_hash": task,
                "query_fingerprint": query,
                "arm": self.arm,
                "candidate_ids": list(candidates),
                "selected_ids": list(selected),
                "candidate_scopes": list(candidate_scopes),
                "selected_scopes": list(selected_scopes),
                "empty_result": bool(self.empty_result),
                "team_unavailable": bool(self.team_unavailable),
                "scope": scope,
                "injected_chars": int(injected),
                "retrieval_latency_ms": int(latency),
                "host_id": self.host_id,
                "observed_at": observed,
                "protocol_hash": protocol_hash,
            }
            object.__setattr__(self, "exposure_id", "exp_" + stable_hash(material)[:24])
        elif not _ID_RE.fullmatch(self.exposure_id):
            raise ValueError("MEASUREMENT_EXPOSURE_ID_INVALID")

    @property
    def variant(self) -> str:
        return self.arm

    @property
    def host(self) -> str:
        return self.host_id

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": 1,
            "exposure_id": self.exposure_id,
            "experiment_id": self.experiment_id,
            "protocol_hash": self.protocol_hash,
            "session_id_hash": self.session_id_hash,
            "task_id_hash": self.task_id_hash,
            "query_fingerprint": self.query_fingerprint,
            "arm": self.arm,
            "variant": self.arm,
            "candidate_ids": list(self.candidate_ids),
            "selected_ids": list(self.selected_ids),
            "injected_chars": self.injected_chars,
            "retrieval_latency_ms": self.retrieval_latency_ms,
            "host_id": self.host_id,
            "host_instance_hash": self.host_instance_hash,
            "model_family": self.model_family,
            "domain": self.domain,
            "observed_at": self.observed_at,
            "eligible": bool(self.eligible),
            "shadow_retrieval": bool(self.shadow_retrieval),
            "context_injected": bool(self.context_injected),
            "contamination": bool(self.contamination),
            "source": self.source,
            "candidate_scopes": list(self.candidate_scopes),
            "selected_scopes": list(self.selected_scopes),
            "empty_result": bool(self.empty_result),
            "team_unavailable": bool(self.team_unavailable),
            "scope": self.scope,
        }

    @classmethod
    def from_mapping(cls, value: Mapping[str, Any]) -> "ExposureRecord":
        _reject_raw_mapping(value)
        return cls(
            experiment_id=str(value.get("experiment_id", "")),
            protocol_hash=str(value.get("protocol_hash", "")),
            session_id_hash=str(value.get("session_id_hash", value.get("session_id", ""))),
            task_id_hash=str(value.get("task_id_hash", value.get("task_id", ""))),
            query_fingerprint=str(value.get("query_fingerprint", "")),
            arm=str(value.get("arm", value.get("variant", "control"))),
            candidate_ids=value.get("candidate_ids", value.get("candidate_knowledge_ids", ())),
            selected_ids=value.get("selected_ids", value.get("selected_knowledge_ids", ())),
            candidate_scopes=value.get("candidate_scopes", ()),
            selected_scopes=value.get("selected_scopes", ()),
            empty_result=bool(value.get("empty_result", False)),
            team_unavailable=bool(value.get("team_unavailable", False)),
            scope=str(value.get("scope", "")),
            injected_chars=value.get("injected_chars", 0),
            retrieval_latency_ms=value.get("retrieval_latency_ms", 0),
            host_id=str(value.get("host_id", value.get("host", "unknown"))),
            host_instance_hash=str(value.get("host_instance_hash", "")),
            model_family=str(value.get("model_family", "unknown")),
            domain=str(value.get("domain", "")),
            observed_at=str(value.get("observed_at", "")),
            eligible=bool(value.get("eligible", True)),
            shadow_retrieval=bool(value.get("shadow_retrieval", True)),
            context_injected=bool(value.get("context_injected", False)),
            contamination=bool(value.get("contamination", False)),
            source=str(value.get("source", "recall")),
            exposure_id=str(value.get("exposure_id", "")),
        )


@dataclass(frozen=True)
class OutcomeRecord:
    experiment_id: str
    session_id_hash: str
    task_id_hash: str = ""
    exposure_id: str = ""
    observed_at: str = ""
    host_id: str = "unknown"
    host_instance_hash: str = ""
    model_family: str = "unknown"
    domain: str = ""
    retry_count: int = 0
    repeated_search: float | None = None
    rework: float | None = None
    failure: float | None = None
    uncached_input: float | None = None
    cached_input: float | None = None
    turns_to_completion: float | None = None
    tool_calls: float | None = None
    retrieval_latency_ms: float | None = None
    incorrect_pattern_application: float | None = None
    explicit_correction: float | None = None
    privacy_incident: float | None = None
    completion: float | None = None
    metric_sources: Mapping[str, str] = field(default_factory=dict)
    provenance: tuple[str, ...] = ()
    source: str = "direct_outcome_events"
    contamination: bool = False
    outcome_id: str = ""

    def __post_init__(self) -> None:
        if not self.experiment_id:
            raise ValueError("MEASUREMENT_EXPERIMENT_ID_INVALID")
        session = _hash_identifier(self.session_id_hash, "session_id_hash")
        task = _hash_identifier(self.task_id_hash, "task_id_hash", allow_empty=True)
        if not task:
            task = _hash_identifier(f"{self.experiment_id}:{session}:{self.observed_at}", "task_id_hash")
        exposure = _hash_identifier(self.exposure_id, "exposure_id", allow_empty=True)
        observed = _timestamp(self.observed_at)
        if _number(self.retry_count, "retry_count", allow_none=False) is None:
            raise ValueError("MEASUREMENT_RETRY_COUNT_INVALID")
        sources = _safe_sources(self.metric_sources)
        for name in _METRIC_NAMES:
            number = _number(getattr(self, name), name)
            if number is not None:
                object.__setattr__(self, name, number)
        completion = _number(self.completion, "completion")
        if completion is not None:
            object.__setattr__(self, "completion", completion)
        provenance = tuple(sorted({_hash_identifier(item, "provenance") for item in self.provenance if str(item)}))
        object.__setattr__(self, "session_id_hash", session)
        object.__setattr__(self, "task_id_hash", task)
        object.__setattr__(self, "exposure_id", exposure)
        object.__setattr__(self, "observed_at", observed)
        object.__setattr__(self, "retry_count", int(float(self.retry_count)))
        object.__setattr__(self, "host_id", _safe_label(self.host_id, "host_id"))
        object.__setattr__(self, "host_instance_hash", _hash_identifier(self.host_instance_hash, "host_instance_hash", allow_empty=True))
        object.__setattr__(self, "model_family", _safe_label(self.model_family, "model_family"))
        object.__setattr__(self, "domain", _safe_label(self.domain, "domain", default=""))
        object.__setattr__(self, "metric_sources", sources)
        object.__setattr__(self, "provenance", provenance)
        object.__setattr__(self, "source", _safe_label(self.source, "source", default="direct_outcome_events"))
        if not self.outcome_id:
            material = {
                "experiment_id": self.experiment_id,
                "session_id_hash": session,
                "task_id_hash": task,
                "exposure_id": exposure,
                "observed_at": observed,
                "metrics": {name: getattr(self, name) for name in _METRIC_NAMES + ("completion",)},
                "metric_sources": sources,
            }
            object.__setattr__(self, "outcome_id", "out_" + stable_hash(material)[:24])
        elif not _ID_RE.fullmatch(self.outcome_id):
            raise ValueError("MEASUREMENT_OUTCOME_ID_INVALID")

    def to_dict(self) -> dict[str, Any]:
        value: dict[str, Any] = {
            "schema_version": 1,
            "outcome_id": self.outcome_id,
            "experiment_id": self.experiment_id,
            "session_id_hash": self.session_id_hash,
            "task_id_hash": self.task_id_hash,
            "exposure_id": self.exposure_id,
            "observed_at": self.observed_at,
            "host_id": self.host_id,
            "host_instance_hash": self.host_instance_hash,
            "model_family": self.model_family,
            "domain": self.domain,
            "retry_count": self.retry_count,
            "metric_sources": dict(self.metric_sources),
            "provenance": list(self.provenance),
            "source": self.source,
            "contamination": bool(self.contamination),
        }
        for name in _METRIC_NAMES + ("completion",):
            number = getattr(self, name)
            if number is not None:
                value[name] = number
                source = self.metric_sources.get(name)
                if source:
                    value[f"{name}_source"] = source
        return value

    @classmethod
    def from_mapping(cls, value: Mapping[str, Any]) -> "OutcomeRecord":
        _reject_raw_mapping(value)
        sources = value.get("metric_sources", {})
        if not isinstance(sources, Mapping):
            sources = {}
        sources = dict(sources)
        for name in _METRIC_NAMES + ("completion",):
            if f"{name}_source" in value:
                sources[name] = value[f"{name}_source"]
        kwargs = {
            name: value.get(name)
            for name in _METRIC_NAMES + ("completion",)
            if name in value
        }
        return cls(
            experiment_id=str(value.get("experiment_id", "")),
            session_id_hash=str(value.get("session_id_hash", value.get("session_id", ""))),
            task_id_hash=str(value.get("task_id_hash", value.get("task_id", ""))),
            exposure_id=str(value.get("exposure_id", "")),
            observed_at=str(value.get("observed_at", "")),
            host_id=str(value.get("host_id", value.get("host", "unknown"))),
            host_instance_hash=str(value.get("host_instance_hash", "")),
            model_family=str(value.get("model_family", "unknown")),
            domain=str(value.get("domain", "")),
            retry_count=value.get("retry_count", 0),
            metric_sources=sources,
            provenance=value.get("provenance", ()),
            source=str(value.get("source", "direct_outcome_events")),
            contamination=bool(value.get("contamination", False)),
            **kwargs,
        )


@contextmanager
def _exclusive_lock(lock_path: Path):
    lock_path.parent.mkdir(parents=True, exist_ok=True)
    stream = lock_path.open("a+b")
    try:
        stream.seek(0)
        if stream.tell() == 0:
            stream.write(b"0")
            stream.flush()
        stream.seek(0)
        if os.name == "nt":
            import msvcrt

            msvcrt.locking(stream.fileno(), msvcrt.LK_LOCK, 1)
        else:
            import fcntl

            fcntl.flock(stream.fileno(), fcntl.LOCK_EX)
        yield
    finally:
        try:
            stream.seek(0)
            if os.name == "nt":
                import msvcrt

                msvcrt.locking(stream.fileno(), msvcrt.LK_UNLCK, 1)
            else:
                import fcntl

                fcntl.flock(stream.fileno(), fcntl.LOCK_UN)
        finally:
            stream.close()


def _append_unique(path: Path, record_id: str, value: Mapping[str, Any]) -> str:
    path.parent.mkdir(parents=True, exist_ok=True)
    lock_path = path.with_name(path.name + ".lock")
    line = json.dumps(dict(value), ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n"
    with _exclusive_lock(lock_path):
        if path.exists():
            try:
                for raw in path.read_text(encoding="utf-8").splitlines():
                    try:
                        item = json.loads(raw)
                    except json.JSONDecodeError:
                        continue
                    if isinstance(item, Mapping) and str(item.get("exposure_id", item.get("outcome_id", ""))) == record_id:
                        return record_id
            except (OSError, UnicodeError):
                raise ValueError("MEASUREMENT_LOG_READ_FAILED")
        with path.open("a", encoding="utf-8", newline="\n") as stream:
            stream.write(line)
            stream.flush()
            os.fsync(stream.fileno())
    return record_id


def record_exposure(record: ExposureRecord, settings: Any) -> str:
    if not isinstance(record, ExposureRecord):
        raise TypeError("MEASUREMENT_EXPOSURE_RECORD_REQUIRED")
    return _append_unique(_measurement_dir(settings) / "exposures.jsonl", record.exposure_id, record.to_dict())


def record_outcome(outcome: OutcomeRecord, settings: Any) -> str:
    if not isinstance(outcome, OutcomeRecord):
        raise TypeError("MEASUREMENT_OUTCOME_RECORD_REQUIRED")
    return _append_unique(_measurement_dir(settings) / "outcomes.jsonl", outcome.outcome_id, outcome.to_dict())


def measurement_paths(settings: Any) -> dict[str, Path]:
    directory = _measurement_dir(settings)
    return {
        "directory": directory,
        "exposures": directory / "exposures.jsonl",
        "outcomes": directory / "outcomes.jsonl",
    }


def read_measurement_records(path: Path, kind: Literal["exposure", "outcome"]) -> tuple[dict[str, Any], ...]:
    result: list[dict[str, Any]] = []
    target = ExposureRecord if kind == "exposure" else OutcomeRecord
    if not Path(path).exists():
        return ()
    try:
        lines = Path(path).read_text(encoding="utf-8").splitlines()
    except (OSError, UnicodeError) as exc:
        raise ValueError("MEASUREMENT_LOG_READ_FAILED") from exc
    for line in lines:
        if not line.strip():
            continue
        try:
            value = json.loads(line)
            if not isinstance(value, Mapping):
                continue
            parsed = target.from_mapping(value)
        except (TypeError, ValueError, json.JSONDecodeError):
            continue
        result.append(parsed.to_dict())
    return tuple(result)
