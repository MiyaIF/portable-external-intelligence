from __future__ import annotations

import hashlib
import json
import math
import random
from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from statistics import NormalDist
from typing import Any, Iterable, Literal, Mapping

from .context import build_context
from .ids import fingerprint
from .measurement_events import ExposureRecord, OutcomeRecord, record_exposure as record_exposure_event
from .retrieve import RetrievalPolicy, RetrievalQuery, rank_patterns


class Variant(str, Enum):
    CONTROL = "control"
    TREATMENT = "treatment"


PRIMARY_METRICS = ("repeated_search", "rework", "failure")
SECONDARY_METRICS = ("uncached_input", "cached_input", "turns_to_completion")
GUARDRAIL_METRICS = ("incorrect_pattern_application", "explicit_correction", "privacy_incident")
_EXCLUDED = {"security", "legal", "medical", "financial-high-stakes"}
_HASH_RE = __import__("re").compile(r"^sha256:[0-9a-f]{12,64}$")
_FULL_HASH_RE = __import__("re").compile(r"^sha256:[0-9a-f]{64}$")
_COMMIT_SHA_RE = __import__("re").compile(r"^[0-9a-f]{40}$")
EFFECT_EVIDENCE_KEYS = frozenset(
    {
        "evidence_type",
        "experiment_id",
        "protocol_hash",
        "subject_commit_sha",
        "evidence_index_sha256",
        "primary_metrics",
        "eligible_units_per_arm",
        "duration_days",
        "power",
        "alpha",
        "metric_provenance",
        "missingness",
        "contamination",
        "causal_report",
        "analysis_sha256",
    }
)
_METRIC_PROVENANCE_KEYS = frozenset({"status", "evidence_sha256"})
_MISSINGNESS_KEYS = frozenset(
    {"status", "missing_metric_count", "missing_outcome_count", "orphan_outcome_count", "duplicate_outcome_count", "invalid_outcome_count"}
)
_CONTAMINATION_KEYS = frozenset(
    {"status", "count", "assignment_drift_count", "protocol_mismatch_count", "post_treatment_exclusion_count"}
)
_CAUSAL_REPORT_KEYS = frozenset({"status", "evidence_sha256"})


@dataclass(frozen=True)
class ExperimentConfig:
    experiment_id: str = "retrieval-v1"
    alpha: float = 0.05
    power_target: float = 0.80
    minimum_detectable_effect: float = 0.20
    minimum_sessions_per_variant: int = 50
    minimum_calendar_days: int = 14
    excluded_domains: tuple[str, ...] = tuple(sorted(_EXCLUDED))
    bootstrap_iterations: int = 1000
    bootstrap_seed: int = 20260825
    protocol_version: int = 1
    protocol_hash: str = ""
    primary_metrics: tuple[str, ...] = PRIMARY_METRICS
    missing_data_policy: str = "remain_missing_never_impute_zero"
    stopping_rule: str = "do_not_stop_based_on_interim_effect"

    def __post_init__(self) -> None:
        if not self.experiment_id or self.alpha <= 0 or self.alpha >= 1:
            raise ValueError("EXPERIMENT_PROTOCOL_INVALID")
        if not 0 < self.power_target <= 1 or self.minimum_sessions_per_variant < 1 or self.minimum_calendar_days < 1:
            raise ValueError("EXPERIMENT_PROTOCOL_INVALID")
        if self.bootstrap_iterations < 100:
            raise ValueError("EXPERIMENT_BOOTSTRAP_ITERATIONS_INVALID")
        if not self.primary_metrics:
            raise ValueError("EXPERIMENT_PRIMARY_METRIC_REQUIRED")
        computed = protocol_hash_for(self)
        if self.protocol_hash and self.protocol_hash != computed:
            raise ValueError("EXPERIMENT_PROTOCOL_HASH_INVALID")
        object.__setattr__(self, "protocol_hash", computed)
        object.__setattr__(self, "excluded_domains", tuple(sorted({str(value).casefold() for value in self.excluded_domains})))
        object.__setattr__(self, "primary_metrics", tuple(str(value) for value in self.primary_metrics))

    @classmethod
    def defaults(cls) -> "ExperimentConfig":
        return cls()

    @classmethod
    def from_mapping(cls, value: Mapping[str, Any]) -> "ExperimentConfig":
        if not isinstance(value, Mapping):
            raise ValueError("EXPERIMENT_PROTOCOL_INVALID")
        eligibility = value.get("eligibility", {})
        metrics = value.get("metrics", {})
        criteria = value.get("criteria", {})
        excluded = value.get(
            "excluded_domains",
            eligibility.get("excluded_domains", tuple(sorted(_EXCLUDED))) if isinstance(eligibility, Mapping) else tuple(sorted(_EXCLUDED)),
        )
        primary = value.get("primary_metrics", metrics.get("primary", PRIMARY_METRICS) if isinstance(metrics, Mapping) else PRIMARY_METRICS)
        return cls(
            experiment_id=str(value.get("experiment_id", "retrieval-v1")),
            alpha=float(value.get("alpha", criteria.get("alpha", 0.05) if isinstance(criteria, Mapping) else 0.05)),
            power_target=float(value.get("power_target", criteria.get("power", 0.80) if isinstance(criteria, Mapping) else 0.80)),
            minimum_detectable_effect=float(value.get("minimum_detectable_effect", criteria.get("mde", 0.20) if isinstance(criteria, Mapping) else 0.20)),
            minimum_sessions_per_variant=int(value.get("minimum_sessions_per_variant", criteria.get("minimum_per_arm", 50) if isinstance(criteria, Mapping) else 50)),
            minimum_calendar_days=int(value.get("minimum_calendar_days", criteria.get("calendar_days", 14) if isinstance(criteria, Mapping) else 14)),
            excluded_domains=tuple(str(item) for item in excluded),
            bootstrap_iterations=int(value.get("bootstrap_iterations", 1000)),
            bootstrap_seed=int(value.get("bootstrap_seed", 20260825)),
            protocol_version=int(value.get("protocol_version", value.get("schema_version", 1))),
            protocol_hash=str(value.get("protocol_hash", "")),
            primary_metrics=tuple(str(item) for item in primary),
            missing_data_policy=str(value.get("missing_data_policy", "remain_missing_never_impute_zero")),
            stopping_rule=str(value.get("stopping_rule", "do_not_stop_based_on_interim_effect")),
        )


def _protocol_material(config: ExperimentConfig) -> dict[str, Any]:
    return {
        "schema_version": config.protocol_version,
        "experiment_id": config.experiment_id,
        "alpha": config.alpha,
        "power_target": config.power_target,
        "minimum_detectable_effect": config.minimum_detectable_effect,
        "minimum_sessions_per_variant": config.minimum_sessions_per_variant,
        "minimum_calendar_days": config.minimum_calendar_days,
        "excluded_domains": list(sorted(config.excluded_domains)),
        "primary_metrics": list(config.primary_metrics),
        "missing_data_policy": config.missing_data_policy,
        "stopping_rule": config.stopping_rule,
    }


def protocol_hash_for(config: ExperimentConfig) -> str:
    material = json.dumps(_protocol_material(config), ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    return "sha256:" + hashlib.sha256(material.encode("utf-8")).hexdigest()


def assign_arm(session_id_hash: str, experiment_id: str) -> Literal["control", "treatment"]:
    value = str(session_id_hash)
    if not _HASH_RE.fullmatch(value):
        value = fingerprint(value)
    digest = hashlib.sha256(f"{experiment_id}\0{value}".encode("utf-8")).digest()
    return "control" if digest[0] < 128 else "treatment"


def _canonical_session_hash(session_id: object) -> str:
    value = str(session_id)
    if _HASH_RE.fullmatch(value):
        return value
    return "sha256:" + hashlib.sha256(value.encode("utf-8", "replace")).hexdigest()


def assign_variant(session_id: str, experiment_id: str) -> Variant:
    # Hook adapters retain a full SHA-256 for session identifiers.  Use the
    # same canonical representation here so pre-assignment and hook-time
    # assignment cannot disagree about the experiment arm.
    session_hash = _canonical_session_hash(session_id)
    return Variant(assign_arm(session_hash, experiment_id))


@dataclass(frozen=True)
class ExposureResult:
    variant: Variant
    candidate_ids: tuple[str, ...]
    exposed_ids: tuple[str, ...]
    additional_context: str
    exposure_id: str = ""
    query_fingerprint: str = ""
    injected_chars: int = 0
    protocol_hash: str = ""


def _append_legacy_exposure(path: Path, record: ExposureRecord) -> str:
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists():
        for line in path.read_text(encoding="utf-8").splitlines():
            try:
                item = json.loads(line)
            except json.JSONDecodeError:
                continue
            if isinstance(item, Mapping) and item.get("exposure_id") == record.exposure_id:
                return record.exposure_id
    with path.open("a", encoding="utf-8", newline="\n") as stream:
        stream.write(json.dumps(record.to_dict(), ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n")
        stream.flush()
    return record.exposure_id


def record_exposure(
    record_path: Path,
    session_id: str,
    experiment_id: str,
    variant: Variant,
    candidate_ids: Iterable[str],
    exposed_ids: Iterable[str],
    observed_at: str,
    eligible: bool = True,
    excluded_domain: str | None = None,
) -> str:
    config = ExperimentConfig(experiment_id=experiment_id)
    exposed = tuple(exposed_ids)
    record = ExposureRecord(
        experiment_id=experiment_id,
        session_id_hash=fingerprint(session_id),
        task_id_hash=fingerprint(f"{session_id}:{observed_at}"),
        query_fingerprint=fingerprint(session_id),
        arm=variant.value,
        candidate_ids=tuple(candidate_ids),
        selected_ids=exposed,
        injected_chars=0 if variant is Variant.CONTROL else sum(len(str(value)) for value in exposed),
        host_id="legacy",
        observed_at=observed_at,
        protocol_hash=config.protocol_hash,
        domain=excluded_domain or "",
        eligible=eligible,
    )
    return _append_legacy_exposure(Path(record_path), record)


def prepare_exposure(
    session_id: str,
    experiment_id: str,
    prompt: str,
    patterns: Iterable[Mapping[str, Any]],
    *,
    cwd_fingerprint: str = "",
    domain: str = "",
    record_path: Path | None = None,
    observed_at: str = "2026-08-25T00:00:00+00:00",
    settings: Any | None = None,
    config: ExperimentConfig | None = None,
    host_id: str = "unknown",
    host_family: str = "",
    model_family: str = "unknown",
    task_id_hash: str = "",
    retrieval_latency_ms: int = 0,
) -> ExposureResult:
    experiment = config or ExperimentConfig(experiment_id=experiment_id)
    if experiment.experiment_id != experiment_id:
        raise ValueError("EXPERIMENT_ID_MISMATCH")
    session_hash = _canonical_session_hash(session_id)
    variant = Variant(assign_arm(session_hash, experiment_id))
    eligible = domain.casefold() not in set(experiment.excluded_domains)
    hits = (
        rank_patterns(
            RetrievalQuery(
                prompt=prompt,
                cwd_fingerprint=cwd_fingerprint,
                domain=domain,
                now_utc=observed_at,
                host_id=host_id,
                host_family=host_family,
            ),
            patterns,
            RetrievalPolicy.defaults(),
        )
        if eligible
        else []
    )
    candidate_ids = tuple(hit.pattern_id for hit in hits)
    exposed_ids = candidate_ids if variant is Variant.TREATMENT else ()
    context = build_context(hits, 5000) if variant is Variant.TREATMENT else ""
    record = ExposureRecord(
        experiment_id=experiment_id,
        session_id_hash=fingerprint(session_id),
        task_id_hash=task_id_hash or fingerprint(f"{session_id}:{observed_at}:{domain}"),
        query_fingerprint=fingerprint(prompt),
        arm=variant.value,
        candidate_ids=candidate_ids,
        selected_ids=exposed_ids,
        injected_chars=len(context),
        retrieval_latency_ms=retrieval_latency_ms,
        host_id=host_id,
        observed_at=observed_at,
        protocol_hash=experiment.protocol_hash,
        domain=domain,
        eligible=eligible,
        shadow_retrieval=True,
        context_injected=bool(context),
    )
    if settings is not None:
        record_exposure_event(record, settings)
    if record_path is not None:
        _append_legacy_exposure(Path(record_path), record)
    return ExposureResult(
        variant,
        candidate_ids,
        exposed_ids,
        context,
        record.exposure_id,
        record.query_fingerprint,
        record.injected_chars,
        experiment.protocol_hash,
    )


def _parse_date(value: object) -> datetime | None:
    try:
        parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except (TypeError, ValueError):
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)


def _as_mapping(value: Mapping[str, Any] | ExposureRecord | OutcomeRecord) -> Mapping[str, Any]:
    if isinstance(value, ExposureRecord) or isinstance(value, OutcomeRecord):
        return value.to_dict()
    if isinstance(value, Mapping):
        return value
    raise ValueError("EXPERIMENT_RECORD_INVALID")


def _normalise_exposure(row: Mapping[str, Any]) -> tuple[ExposureRecord | None, str | None]:
    try:
        return ExposureRecord.from_mapping(row), None
    except (TypeError, ValueError):
        return None, "INVALID_EXPOSURE"


def _normalise_outcome(row: Mapping[str, Any]) -> tuple[OutcomeRecord | None, str | None]:
    try:
        return OutcomeRecord.from_mapping(row), None
    except (TypeError, ValueError):
        return None, "INVALID_OUTCOME"


def _metric_value(row: Mapping[str, Any], metric: str) -> tuple[float | None, str | None]:
    value = row.get(metric)
    if value is None:
        return None, None
    sources = row.get("metric_sources", {})
    source = row.get(f"{metric}_source")
    if source is None and isinstance(sources, Mapping):
        source = sources.get(metric)
    if source is None or not str(source).strip() or str(source).casefold() in {"unknown", "unverified"}:
        return None, "METRIC_PROVENANCE_UNKNOWN"
    try:
        number = float(value)
    except (TypeError, ValueError):
        return None, "METRIC_VALUE_INVALID"
    if not math.isfinite(number) or number < 0:
        return None, "METRIC_VALUE_INVALID"
    return number, None


def _metric_values(outcomes: Iterable[Mapping[str, Any]], metric: str) -> dict[str, float]:
    values: dict[str, float] = {}
    for row in outcomes:
        session_id = str(row.get("session_id_hash", row.get("session_id", "")))
        value, reason = _metric_value(row, metric)
        if not session_id or value is None or reason is not None:
            continue
        values.setdefault(session_id, value)
    return values


def _bootstrap(
    values_control: list[float],
    values_treatment: list[float],
    seed: int,
    iterations: int,
) -> tuple[float, float, float | None, float | None]:
    if not values_control or not values_treatment:
        return (float("nan"), float("nan"), None, None)
    control_mean = sum(values_control) / len(values_control)
    treatment_mean = sum(values_treatment) / len(values_treatment)
    absolute = treatment_mean - control_mean
    rng = random.Random(seed)
    samples: list[float] = []
    for _ in range(iterations):
        control = [values_control[rng.randrange(len(values_control))] for _ in values_control]
        treatment = [values_treatment[rng.randrange(len(values_treatment))] for _ in values_treatment]
        samples.append(sum(treatment) / len(treatment) - sum(control) / len(control))
    samples.sort()
    low = samples[max(0, int(iterations * 0.025))]
    high = samples[min(len(samples) - 1, int(iterations * 0.975))]
    return absolute, treatment_mean, low, high


def _estimate_power(control: list[float], treatment: list[float], config: ExperimentConfig) -> float:
    if not control or not treatment:
        return 0.0

    def variance(values: list[float]) -> float:
        mean = sum(values) / len(values)
        return sum((value - mean) ** 2 for value in values) / max(1, len(values) - 1)

    standard_error = math.sqrt(variance(control) / len(control) + variance(treatment) / len(treatment))
    if standard_error == 0:
        return 1.0
    effect_z = abs(config.minimum_detectable_effect) / standard_error
    critical = NormalDist().inv_cdf(1 - config.alpha / 2)
    return min(
        1.0,
        max(0.0, NormalDist().cdf(effect_z - critical) + NormalDist().cdf(-effect_z - critical)),
    )


def _record_reason(exclusions: list[dict[str, str]], identifier: str, reason: str) -> None:
    exclusions.append({"record_id_hash": fingerprint(identifier), "reason": reason})


def summarize_experiment(
    exposures: Iterable[Mapping[str, Any] | ExposureRecord],
    outcomes: Iterable[Mapping[str, Any] | OutcomeRecord],
    config: ExperimentConfig | Mapping[str, Any] | Path,
) -> dict[str, Any]:
    if isinstance(config, Path):
        try:
            config = ExperimentConfig.from_mapping(json.loads(config.read_text(encoding="utf-8")))
        except (OSError, UnicodeError, json.JSONDecodeError, ValueError) as exc:
            raise ValueError("EXPERIMENT_PROTOCOL_READ_FAILED") from exc
    elif isinstance(config, Mapping):
        config = ExperimentConfig.from_mapping(config)
    if not isinstance(config, ExperimentConfig):
        raise ValueError("EXPERIMENT_PROTOCOL_REQUIRED")

    exposure_rows = [_as_mapping(value) for value in exposures]
    outcome_rows = [_as_mapping(value) for value in outcomes]
    exclusions: list[dict[str, str]] = []
    valid: dict[str, ExposureRecord] = {}
    key_seen: set[tuple[str, str]] = set()
    assignment_drift = 0
    protocol_mismatch = 0
    protocol_missing = 0
    contamination = 0
    post_treatment_exclusion = 0
    for raw in exposure_rows:
        record, error = _normalise_exposure(raw)
        if record is None:
            _record_reason(exclusions, str(raw.get("experiment_id", "")), error or "INVALID_EXPOSURE")
            continue
        key = (record.session_id_hash, record.task_id_hash)
        if record.experiment_id != config.experiment_id:
            _record_reason(exclusions, record.exposure_id, "EXPERIMENT_ID_MISMATCH")
            continue
        if key in key_seen or record.exposure_id in valid:
            _record_reason(exclusions, record.exposure_id, "DUPLICATE_EXPOSURE")
            continue
        key_seen.add(key)
        if not record.protocol_hash:
            protocol_missing += 1
        elif record.protocol_hash != config.protocol_hash:
            protocol_mismatch += 1
        expected = assign_arm(record.session_id_hash, config.experiment_id)
        if record.arm != expected:
            assignment_drift += 1
        if record.contamination or (
            record.arm == "control"
            and (record.selected_ids or record.injected_chars or record.context_injected)
        ):
            contamination += 1
        if bool(raw.get("post_treatment_excluded", False)):
            post_treatment_exclusion += 1
        excluded_domain = record.domain.casefold() in set(config.excluded_domains)
        if not record.eligible or excluded_domain:
            _record_reason(exclusions, record.exposure_id, "EXCLUDED_DOMAIN")
            continue
        if (
            record.protocol_hash != config.protocol_hash
            or record.arm != expected
            or record.contamination
            or bool(raw.get("post_treatment_excluded", False))
        ):
            _record_reason(exclusions, record.exposure_id, "EXPERIMENT_AUDIT_FAILURE")
            continue
        valid[record.exposure_id] = record

    linked: dict[str, OutcomeRecord] = {}
    orphan_outcomes = 0
    duplicate_outcomes = 0
    invalid_outcomes = 0
    by_key = {(record.session_id_hash, record.task_id_hash): exposure_id for exposure_id, record in valid.items()}
    for raw in outcome_rows:
        record, error = _normalise_outcome(raw)
        if record is None:
            invalid_outcomes += 1
            _record_reason(exclusions, str(raw.get("experiment_id", "")), error or "INVALID_OUTCOME")
            continue
        if record.experiment_id != config.experiment_id:
            orphan_outcomes += 1
            continue
        exposure_id = record.exposure_id if record.exposure_id in valid else by_key.get((record.session_id_hash, record.task_id_hash))
        if not exposure_id:
            orphan_outcomes += 1
            continue
        if exposure_id in linked:
            duplicate_outcomes += 1
            continue
        linked[exposure_id] = record

    missing_outcomes = len(valid) - len(linked)
    metrics: dict[str, Any] = {}
    missing_metric_names: list[str] = []
    unknown_provenance: list[str] = []
    metric_samples: dict[str, tuple[list[float], list[float]]] = {}
    for metric in PRIMARY_METRICS + SECONDARY_METRICS + GUARDRAIL_METRICS:
        control: list[float] = []
        treatment: list[float] = []
        metric_missing = 0
        metric_unknown = 0
        for exposure_id, exposure in valid.items():
            outcome = linked.get(exposure_id)
            if outcome is None:
                metric_missing += 1
                continue
            value, reason = _metric_value(outcome.to_dict(), metric)
            if reason is not None:
                if reason == "METRIC_PROVENANCE_UNKNOWN":
                    metric_unknown += 1
                else:
                    metric_missing += 1
                continue
            if value is None:
                metric_missing += 1
            elif exposure.arm == "control":
                control.append(value)
            else:
                treatment.append(value)
        if not control or not treatment:
            metrics[metric] = {
                "status": "MISSING",
                "control_n": len(control),
                "treatment_n": len(treatment),
                "missing_n": metric_missing,
                "unknown_provenance_n": metric_unknown,
                "provenance_status": "unknown" if metric_unknown else "verified" if not metric_missing else "missing",
            }
            missing_metric_names.append(metric)
        else:
            absolute, treatment_mean, low, high = _bootstrap(
                control,
                treatment,
                config.bootstrap_seed + len(metric),
                config.bootstrap_iterations,
            )
            control_mean = sum(control) / len(control)
            metrics[metric] = {
                "status": "AVAILABLE",
                "control_n": len(control),
                "treatment_n": len(treatment),
                "missing_n": metric_missing,
                "unknown_provenance_n": metric_unknown,
                "control_mean": control_mean,
                "treatment_mean": treatment_mean,
                "absolute_difference": absolute,
                "relative_difference": absolute / control_mean if control_mean else None,
                "ci95_absolute_difference": [low, high],
                "provenance_status": "unknown" if metric_unknown else "verified",
            }
            metric_samples[metric] = (control, treatment)
            if metric_unknown:
                unknown_provenance.extend([metric] * metric_unknown)

    dates = [parsed for record in valid.values() if (parsed := _parse_date(record.observed_at)) is not None]
    calendar_days = (max(dates) - min(dates)).days if dates else 0
    counts = {
        Variant.CONTROL.value: sum(1 for record in valid.values() if record.arm == Variant.CONTROL.value),
        Variant.TREATMENT.value: sum(1 for record in valid.values() if record.arm == Variant.TREATMENT.value),
    }
    power_values = [
        _estimate_power(*metric_samples[metric], config)
        for metric in config.primary_metrics
        if metric in metric_samples
    ]
    estimated_power = min(power_values, default=0.0)
    blocking_reasons: list[str] = []
    if counts["control"] < config.minimum_sessions_per_variant or counts["treatment"] < config.minimum_sessions_per_variant:
        blocking_reasons.append("SAMPLE_BELOW_MINIMUM")
    if calendar_days < config.minimum_calendar_days:
        blocking_reasons.append("CALENDAR_DAYS_BELOW_MINIMUM")
    if protocol_missing or protocol_mismatch:
        blocking_reasons.append("PROTOCOL_HASH_INVALID_OR_MISSING")
    if assignment_drift:
        blocking_reasons.append("ASSIGNMENT_DRIFT")
    if contamination:
        blocking_reasons.append("CONTAMINATION")
    if post_treatment_exclusion:
        blocking_reasons.append("POST_TREATMENT_EXCLUSION")
    if missing_outcomes or orphan_outcomes or duplicate_outcomes or invalid_outcomes:
        blocking_reasons.append("OUTCOME_LINKAGE_INCOMPLETE")
    unavailable_primary = [
        metric for metric in config.primary_metrics if metrics.get(metric, {}).get("status") != "AVAILABLE"
    ]
    if unavailable_primary:
        blocking_reasons.append("PRIMARY_METRIC_MISSING")
    if any(metrics.get(metric, {}).get("unknown_provenance_n", 0) for metric in config.primary_metrics):
        blocking_reasons.append("METRIC_PROVENANCE_UNKNOWN")
    if estimated_power < config.power_target:
        blocking_reasons.append("POWER_BELOW_TARGET")
    conclusion = "CAUSAL_EFFECT_NOT_IDENTIFIED" if blocking_reasons else "CAUSAL_EFFECT_ESTIMATED"
    effect_validated = conclusion == "CAUSAL_EFFECT_ESTIMATED"
    return {
        "experiment_id": config.experiment_id,
        "protocol_hash": config.protocol_hash,
        "conclusion": conclusion,
        "effect_validated": effect_validated,
        "decision": "DO_NOT_CLAIM_CAUSAL_EFFECT" if not effect_validated else "REVIEW_EFFECT_WITH_PRE_REGISTERED_RULE",
        "configuration": {
            "protocol_version": config.protocol_version,
            "primary_metrics": list(config.primary_metrics),
            "alpha": config.alpha,
            "power_target": config.power_target,
            "minimum_detectable_effect": config.minimum_detectable_effect,
            "minimum_sessions_per_variant": config.minimum_sessions_per_variant,
            "minimum_calendar_days": config.minimum_calendar_days,
            "bootstrap_seed": config.bootstrap_seed,
            "eligibility": "one eligible session/task assigned before outcome",
            "exclusions": list(config.excluded_domains),
            "missing_data_policy": config.missing_data_policy,
            "stopping_rule": config.stopping_rule,
        },
        "sample": {
            "eligible_sessions": len(valid),
            "variant_counts": counts,
            "calendar_days": calendar_days,
            "exclusions": exclusions,
        },
        "primary_metrics": {name: metrics.get(name, {"status": "MISSING"}) for name in PRIMARY_METRICS},
        "secondary_metrics": {
            name: {
                **metrics.get(name, {"status": "MISSING"}),
                "association_only": name in {"uncached_input", "cached_input"} and not effect_validated,
            }
            for name in SECONDARY_METRICS
        },
        "guardrails": {name: metrics.get(name, {"status": "MISSING"}) for name in GUARDRAIL_METRICS},
        "missing_data": {
            "metrics": missing_metric_names,
            "outcomes_missing": missing_outcomes,
            "orphan_outcomes": orphan_outcomes,
            "duplicate_outcomes": duplicate_outcomes,
            "invalid_outcomes": invalid_outcomes,
            "no_zero_imputation": True,
        },
        "audit": {
            "assignment_drift_count": assignment_drift,
            "contamination_count": contamination,
            "protocol_missing_count": protocol_missing,
            "protocol_mismatch_count": protocol_mismatch,
            "post_treatment_exclusion_count": post_treatment_exclusion,
            "unknown_metric_provenance": sorted(set(unknown_provenance)),
            "blocking_reasons": blocking_reasons,
        },
        "external_article_reference": {
            "status": "excluded_from_user_baseline",
            "source_kind": "external_article_copy",
            "values_ingested": False,
        },
        "verified_local_facts": {
            "eligible_sessions": len(valid),
            "linked_outcomes": len(linked),
            "protocol_hash": config.protocol_hash,
        },
        "inference": {
            "causal_claim_allowed": effect_validated,
            "cache_quota_association": "causal_only_after_exposure_linkage" if effect_validated else "descriptive_only",
        },
        "unknown": {
            "requires_more_data": not effect_validated,
            "blocking_reasons": blocking_reasons,
        },
        "estimated_power": estimated_power,
    }


def _effect_digest(value: Mapping[str, Any]) -> str:
    material = json.dumps(dict(value), ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    return "sha256:" + hashlib.sha256(material.encode("utf-8")).hexdigest()


def build_effect_evidence(
    summary: Mapping[str, Any],
    *,
    subject_commit_sha: str,
    evidence_index_sha256: str,
) -> dict[str, Any]:
    """Convert an analyzed experiment into a path-free, hash-bound gate record."""

    if not isinstance(summary, Mapping):
        raise ValueError("EFFECT_SUMMARY_REQUIRED")
    configuration = summary.get("configuration")
    sample = summary.get("sample")
    audit = summary.get("audit")
    primary = summary.get("primary_metrics")
    missing = summary.get("missing_data")
    if not isinstance(configuration, Mapping) or not isinstance(sample, Mapping) or not isinstance(audit, Mapping) or not isinstance(primary, Mapping) or not isinstance(missing, Mapping):
        raise ValueError("EFFECT_SUMMARY_SCHEMA_INVALID")
    experiment_id = summary.get("experiment_id")
    protocol_hash = summary.get("protocol_hash")
    if not isinstance(experiment_id, str) or not experiment_id or not isinstance(protocol_hash, str) or not _FULL_HASH_RE.fullmatch(protocol_hash):
        raise ValueError("EFFECT_PROTOCOL_EVIDENCE_INVALID")
    if not isinstance(subject_commit_sha, str) or not _COMMIT_SHA_RE.fullmatch(subject_commit_sha):
        raise ValueError("EFFECT_SUBJECT_INVALID")
    if not isinstance(evidence_index_sha256, str) or not _FULL_HASH_RE.fullmatch(evidence_index_sha256):
        raise ValueError("EFFECT_EVIDENCE_INDEX_INVALID")
    counts = sample.get("variant_counts")
    if not isinstance(counts, Mapping):
        raise ValueError("EFFECT_SAMPLE_INVALID")
    try:
        eligible_units_per_arm = min(int(counts[Variant.CONTROL.value]), int(counts[Variant.TREATMENT.value]))
        duration_days = int(sample.get("calendar_days", 0))
        power = float(summary.get("estimated_power", 0.0))
        alpha = float(configuration.get("alpha"))
    except (KeyError, TypeError, ValueError) as exc:
        raise ValueError("EFFECT_SAMPLE_INVALID") from exc
    primary_metrics = configuration.get("primary_metrics")
    if not isinstance(primary_metrics, list) or not primary_metrics or any(not isinstance(item, str) or not item for item in primary_metrics):
        raise ValueError("EFFECT_PRIMARY_METRICS_INVALID")

    metric_provenance: dict[str, dict[str, str]] = {}
    for metric in primary_metrics:
        row = primary.get(metric)
        if not isinstance(row, Mapping):
            row = {"status": "MISSING", "provenance_status": "missing"}
        source_material = {
            "metric": metric,
            "status": row.get("status"),
            "provenance_status": row.get("provenance_status"),
            "control_n": row.get("control_n", 0),
            "treatment_n": row.get("treatment_n", 0),
            "unknown_provenance_n": row.get("unknown_provenance_n", 0),
        }
        metric_provenance[metric] = {
            "status": "verified" if row.get("status") == "AVAILABLE" and row.get("provenance_status") == "verified" else "unverified",
            "evidence_sha256": _effect_digest(source_material),
        }

    missingness_counts = {
        "missing_metric_count": len(missing.get("metrics", [])) if isinstance(missing.get("metrics"), list) else 1,
        "missing_outcome_count": int(missing.get("outcomes_missing", 0) or 0),
        "orphan_outcome_count": int(missing.get("orphan_outcomes", 0) or 0),
        "duplicate_outcome_count": int(missing.get("duplicate_outcomes", 0) or 0),
        "invalid_outcome_count": int(missing.get("invalid_outcomes", 0) or 0),
    }
    missingness = {
        "status": "complete" if not any(missingness_counts.values()) else "incomplete",
        **missingness_counts,
    }
    contamination_counts = {
        "count": int(audit.get("contamination_count", 0) or 0),
        "assignment_drift_count": int(audit.get("assignment_drift_count", 0) or 0),
        "protocol_mismatch_count": int(audit.get("protocol_mismatch_count", 0) or 0),
        "post_treatment_exclusion_count": int(audit.get("post_treatment_exclusion_count", 0) or 0),
    }
    contamination = {
        "status": "clean" if not any(contamination_counts.values()) else "contaminated",
        **contamination_counts,
    }
    causal_report = {
        "status": str(summary.get("conclusion", "CAUSAL_EFFECT_NOT_IDENTIFIED")),
        "evidence_sha256": _effect_digest(
            {
                "experiment_id": experiment_id,
                "protocol_hash": protocol_hash,
                "subject_commit_sha": subject_commit_sha,
                "evidence_index_sha256": evidence_index_sha256,
                "conclusion": summary.get("conclusion"),
                "decision": summary.get("decision"),
            }
        ),
    }
    value: dict[str, Any] = {
        "evidence_type": "ab_effect",
        "experiment_id": experiment_id,
        "protocol_hash": protocol_hash,
        "subject_commit_sha": subject_commit_sha,
        "evidence_index_sha256": evidence_index_sha256,
        "primary_metrics": list(primary_metrics),
        "eligible_units_per_arm": eligible_units_per_arm,
        "duration_days": duration_days,
        "power": power,
        "alpha": alpha,
        "metric_provenance": metric_provenance,
        "missingness": missingness,
        "contamination": contamination,
        "causal_report": causal_report,
    }
    value["analysis_sha256"] = _effect_digest(value)
    return value


def validate_effect_evidence(
    value: Mapping[str, Any],
    *,
    expected_subject_commit_sha: str | None = None,
    expected_evidence_index_sha256: str | None = None,
) -> bool:
    """Validate the preregistered A/B evidence gate without trusting flags."""

    if not isinstance(value, Mapping) or set(value) != EFFECT_EVIDENCE_KEYS:
        raise ValueError("EFFECT_EVIDENCE_SCHEMA_INVALID")
    if value.get("evidence_type") != "ab_effect":
        raise ValueError("EFFECT_EVIDENCE_TYPE_INVALID")
    if not isinstance(value.get("experiment_id"), str) or not value["experiment_id"]:
        raise ValueError("EFFECT_EXPERIMENT_ID_INVALID")
    if not isinstance(value.get("subject_commit_sha"), str) or not _COMMIT_SHA_RE.fullmatch(value["subject_commit_sha"]):
        raise ValueError("EFFECT_SUBJECT_INVALID")
    for key in ("protocol_hash", "evidence_index_sha256", "analysis_sha256"):
        if not isinstance(value.get(key), str) or not _FULL_HASH_RE.fullmatch(value[key]):
            raise ValueError("EFFECT_HASH_INVALID:" + key)
    if expected_subject_commit_sha is not None:
        if not isinstance(expected_subject_commit_sha, str) or not _COMMIT_SHA_RE.fullmatch(expected_subject_commit_sha):
            raise ValueError("EFFECT_EXPECTED_SUBJECT_INVALID")
        if value["subject_commit_sha"] != expected_subject_commit_sha:
            raise ValueError("EFFECT_SUBJECT_MISMATCH")
    if expected_evidence_index_sha256 is not None:
        if not isinstance(expected_evidence_index_sha256, str) or not _FULL_HASH_RE.fullmatch(expected_evidence_index_sha256):
            raise ValueError("EFFECT_EXPECTED_EVIDENCE_INDEX_INVALID")
        if value["evidence_index_sha256"] != expected_evidence_index_sha256:
            raise ValueError("EFFECT_EVIDENCE_INDEX_MISMATCH")
    primary_metrics = value.get("primary_metrics")
    if not isinstance(primary_metrics, list) or not primary_metrics or len(set(primary_metrics)) != len(primary_metrics) or any(not isinstance(item, str) or not item for item in primary_metrics):
        raise ValueError("EFFECT_PRIMARY_METRICS_INVALID")
    try:
        eligible = int(value.get("eligible_units_per_arm"))
        duration = int(value.get("duration_days"))
        power = float(value.get("power"))
        alpha = float(value.get("alpha"))
    except (TypeError, ValueError) as exc:
        raise ValueError("EFFECT_NUMERIC_FIELDS_INVALID") from exc
    if eligible < 50:
        raise ValueError("EFFECT_SAMPLE_BELOW_MINIMUM")
    if duration < 14:
        raise ValueError("EFFECT_DURATION_BELOW_MINIMUM")
    if not math.isfinite(power) or power < 0.80:
        raise ValueError("EFFECT_POWER_BELOW_TARGET")
    if not math.isfinite(alpha) or not 0 < alpha <= 0.05:
        raise ValueError("EFFECT_ALPHA_INVALID")

    provenance = value.get("metric_provenance")
    if not isinstance(provenance, Mapping) or set(provenance) != set(primary_metrics):
        raise ValueError("EFFECT_METRIC_PROVENANCE_INVALID")
    for metric in primary_metrics:
        row = provenance[metric]
        if not isinstance(row, Mapping) or set(row) != _METRIC_PROVENANCE_KEYS or row.get("status") != "verified" or not isinstance(row.get("evidence_sha256"), str) or not _FULL_HASH_RE.fullmatch(row["evidence_sha256"]):
            raise ValueError("EFFECT_METRIC_PROVENANCE_INVALID:" + metric)

    missingness = value.get("missingness")
    if not isinstance(missingness, Mapping) or set(missingness) != _MISSINGNESS_KEYS or missingness.get("status") != "complete":
        raise ValueError("EFFECT_MISSINGNESS_INVALID")
    contamination = value.get("contamination")
    if not isinstance(contamination, Mapping) or set(contamination) != _CONTAMINATION_KEYS or contamination.get("status") != "clean":
        raise ValueError("EFFECT_CONTAMINATION_INVALID")
    for group in (missingness, contamination):
        for key, count in group.items():
            if key == "status":
                continue
            if type(count) is not int or count != 0:
                raise ValueError("EFFECT_AUDIT_COUNT_INVALID")
    report = value.get("causal_report")
    if not isinstance(report, Mapping) or set(report) != _CAUSAL_REPORT_KEYS or report.get("status") != "CAUSAL_EFFECT_ESTIMATED" or not isinstance(report.get("evidence_sha256"), str) or not _FULL_HASH_RE.fullmatch(report["evidence_sha256"]):
        raise ValueError("EFFECT_CAUSAL_REPORT_INVALID")
    basis = {key: value[key] for key in sorted(EFFECT_EVIDENCE_KEYS - {"analysis_sha256"})}
    if value["analysis_sha256"] != _effect_digest(basis):
        raise ValueError("EFFECT_ANALYSIS_HASH_MISMATCH")
    return True


def render_experiment_report(summary: Mapping[str, Any]) -> str:
    configuration = summary.get("configuration", {})
    sample = summary.get("sample", {})
    sections = [
        ("Verified local facts", summary.get("verified_local_facts", {})),
        ("Inference", summary.get("inference", {})),
        ("Unknown", summary.get("unknown", {})),
        ("External article reference", summary.get("external_article_reference", {})),
        ("Experiment configuration", configuration),
        ("Sample and exclusions", sample),
        ("Primary metrics", summary.get("primary_metrics", {})),
        ("Secondary metrics", summary.get("secondary_metrics", {})),
        ("Guardrails", summary.get("guardrails", {})),
        ("Missing data", summary.get("missing_data", {})),
        ("Causal conclusion", {"status": summary.get("conclusion"), "estimated_power": summary.get("estimated_power")}),
        ("Decision", {"decision": summary.get("decision")}),
    ]
    output: list[str] = []
    for title, value in sections:
        output.extend(
            [
                f"## {title}",
                "",
                "\x60\x60\x60json",
                json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2),
                "\x60\x60\x60",
                "",
            ]
        )
    return "\n".join(output).rstrip() + "\n"
