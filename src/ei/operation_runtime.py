"""Cooperative runtime budgets and read-only automatic-operation snapshots.

Filesystem calls cannot be preempted. Deadlines prevent starting additional
work; they do not promise a hard wall-clock bound on a synchronous OS call.
"""
from __future__ import annotations

import json
import hashlib
import os
import re
import time
from dataclasses import asdict, replace
from datetime import datetime, timedelta
from pathlib import Path

from .operation_health import HealthInput, HealthIssue, evaluate_health
from .safe_fs import assert_safe_target, safe_atomic_write, safe_ensure_directory


# Keep the existing 50 ms lock-wait allowance available for an uninvoked
# cancellation or settlement. This is an admission margin inside the original
# deadline, not a grace period or a guarantee that filesystem work will fit.
_NOTIFICATION_FINISH_RESERVE_MS = 50


class OperationBudget:
    def __init__(self, max_ms: int, *, deadline: float | None = None):
        if type(max_ms) is not int or max_ms < 0:
            raise ValueError("OPERATION_BUDGET_INVALID")
        self.deadline = min(time.monotonic() + max_ms / 1000, deadline) if deadline is not None else time.monotonic() + max_ms / 1000

    def remaining_ms(self) -> int:
        return max(0, int((self.deadline - time.monotonic()) * 1000))

    def check(self) -> None:
        if self.remaining_ms() <= 0:
            raise TimeoutError("OPERATION_BUDGET_EXHAUSTED")


def _read_json(path: Path, *, max_bytes: int = 262144, budget: OperationBudget | None = None):
    if budget is not None:
        budget.check()
    assert_safe_target(path.parent, path, allow_missing=True, expected_type="file")
    if not path.exists():
        return None
    from .index import _read_projection_bytes
    raw = _read_projection_bytes(path, budget=budget, maximum=max_bytes)
    if budget is not None:
        budget.check()
    value = json.loads(raw)
    if not isinstance(value, dict):
        raise ValueError("OPERATION_CACHE_INVALID")
    return value


def _canonical_capture_path(value, budget):
    from .safe_fs import assert_no_reparse_components
    budget.check()
    path = Path(value)
    if not path.is_absolute():
        raise ValueError("CAPTURE_NAMESPACE_UNKNOWN")
    assert_no_reparse_components(path)
    return os.path.normcase(str(path.resolve()))


def capture_namespace(settings, host_id, *, budget):
    """Validated installation namespace shared by Hook, Skill and sources.

    Paths are only hash inputs and are not returned or written to receipts.
    Matching a namespace does not establish record equality or coverage.
    """
    from .install_manifest import validate_install_manifest
    from .host_profiles import PUBLIC_HOST_IDS, host_profile_hash, build_host_profile
    from .ids import fingerprint
    try:
        document = _read_json(Path(settings.paths.install_manifest_path), budget=budget)
        if document is None:
            return None
        manifest = validate_install_manifest(document)
        budget.check()
        if manifest["status"] != "INSTALLED" or host_id not in manifest["work_hosts"]:
            return None
        for manifest_name, settings_name in (("engine_root", "engine_root"), ("knowledge_root", "personal_knowledge_root"), ("runtime_root", "runtime_root")):
            if _canonical_capture_path(manifest[manifest_name], budget) != _canonical_capture_path(getattr(settings.paths, settings_name), budget):
                return None
        record = manifest["hosts"][host_id]
        spec = settings.hosts.get(host_id)
        if spec is None:
            return None
        home = Path(_canonical_capture_path(record["home"], budget))
        if host_id in PUBLIC_HOST_IDS:
            catalog = _read_json(Path(settings.paths.engine_root) / "config" / "hosts.json", budget=budget)
            relative = catalog["hosts"][host_id]
            hook, context = relative["hook_config_path"], relative["global_context_path"]
            if any(not isinstance(value, str) or Path(value).is_absolute() or ".." in Path(value).parts for value in (hook, context)):
                return None
            bound_hook, bound_context = home / hook, home / context
        else:
            profile = _read_json(Path(settings.paths.runtime_root) / record["profile_path"], budget=budget)
            if host_profile_hash(profile) != record["profile_hash"]:
                return None
            bound = build_host_profile(profile, home)
            bound_hook, bound_context = bound.hook_config_path, bound.global_context_path
        for expected, actual, persisted in ((bound_hook, spec.hook_config_path, record["hook_config_path"]), (bound_context, spec.global_context_path, record["context_path"])):
            canonical = _canonical_capture_path(expected, budget)
            if canonical != _canonical_capture_path(actual, budget) or canonical != _canonical_capture_path(persisted, budget):
                return None
        skill = _canonical_capture_path(record["skill_root"], budget)
        if skill not in {_canonical_capture_path(path, budget) for path in spec.skill_roots}:
            return None
        budget.check()
        return (fingerprint({"domain": "ei-capture-instance-v1", "host_id": host_id, "host_home": str(home)}),
                fingerprint({"domain": "ei-capture-personal-store-v1", "personal_root": _canonical_capture_path(settings.paths.personal_knowledge_root, budget)}))
    except TimeoutError:
        raise
    except (OSError, ValueError, TypeError, KeyError, AttributeError, RuntimeError):
        return None


def trusted_capture_identity(settings, host_id, session_hash, turn_hash, record_hash, *, budget):
    from .capture_contract import CaptureIdentity, capture_key
    namespace = capture_namespace(settings, host_id, budget=budget)
    if namespace is None:
        return None
    identity = CaptureIdentity(host_id, *namespace, session_hash, turn_hash, record_hash)
    capture_key(identity)
    return identity


def _ttl(settings):
    interval = getattr(settings, "scheduler_interval_minutes", 30)
    if type(interval) is not int or interval <= 0:
        raise ValueError("OPERATION_INTERVAL_INVALID")
    return min(3600, interval * 60)


def settings_binding(settings):
    """Nonsecret identity only; no candidate, credentials, or command output."""
    organizer = getattr(settings, "organizer", None)
    value = {"roots": [str(getattr(settings.paths, name)) for name in
        ("engine_root", "personal_knowledge_root", "runtime_root", "spool_dir", "queue_dir")],
        "organizer": {name: getattr(organizer, name, None) for name in ("status", "provider_id", "host_id")},
        "interval_seconds": getattr(settings, "scheduler_interval_minutes", 30) * 60}
    return "sha256:" + hashlib.sha256(json.dumps(value, sort_keys=True).encode()).hexdigest()


def _stat_binding(settings, names, *, budget=None):
    """Bounded no-follow metadata binding, not authentication or custody."""
    if not isinstance(names, (list, tuple)) or len(names) > 600:
        raise ValueError("OPERATION_BINDING_INVALID")
    root = Path(settings.paths.runtime_dir)
    rows = {}
    for name in names:
        if budget is not None:
            budget.check()
        if not isinstance(name, str) or not re.fullmatch(r"[A-Za-z0-9_.\-/]{1,200}", name) or ".." in name.split("/") or name.startswith("/"):
            raise ValueError("OPERATION_BINDING_INVALID")
        path = root / name
        assert_safe_target(root, path, allow_missing=True)
        try:
            info = path.stat(follow_symlinks=False)
            rows[name] = [info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns]
        except FileNotFoundError:
            rows[name] = None
    return rows


def _fields(snapshot):
    value = asdict(snapshot)
    for name in ("oldest_pending_at", "earliest_expiry", "last_progress_at", "last_attempt_at", "closeout_earliest_expiry"):
        value[name] = value[name].isoformat() if value[name] else None
    return value


def write_operation_snapshot(settings, snapshot, *, now, budget, custody_binding=None):
    """Persist trusted producer evidence. A count without its binding is unknown."""
    budget.check()
    if not isinstance(snapshot, HealthInput) or now.tzinfo is None or now.utcoffset() is None:
        raise ValueError("OPERATION_CACHE_INVALID")
    if custody_binding is None:
        snapshot = replace(snapshot, pending_count=None, pending_bytes=None, pending_count_status="UNKNOWN",
            closeout_pending_count=None, closeout_pending_bytes=None, closeout_pending_status="UNKNOWN",
            closeout_earliest_expiry=None, closeout_unknown_count=max(1, snapshot.closeout_unknown_count))
    value = {"schema_version": 2, "binding": settings_binding(settings), "generated_at": now.isoformat(),
        "expires_at": (now + timedelta(seconds=_ttl(settings))).isoformat(),
        "custody_binding": custody_binding, "snapshot": _fields(snapshot)}
    raw = json.dumps(value, ensure_ascii=True, sort_keys=True).encode("utf-8")
    if len(raw) > 262144:
        raise ValueError("OPERATION_CACHE_TOO_LARGE")
    budget.check()
    root = Path(settings.paths.runtime_dir)
    safe_ensure_directory(root)
    budget.check()
    safe_atomic_write(root, root / "operation-health.json", raw)
    return snapshot


def _closeout_inventory(settings, *, budget, recovery):
    """Read bounded closeout metadata under its shared ledger lock.

    The returned names are added to the operation-cache custody binding. No
    candidate text or recovery payload is exposed in the health snapshot.
    """
    from .closeout_association import _capture_lock
    from .closeout_store import CloseoutStore, _encoded

    root = Path(settings.paths.runtime_dir)
    relative_root = "state/closeout-associations"
    names = ["state", relative_root, f"{relative_root}/index.json", f"{relative_root}/cursor.json"]
    try:
        with _capture_lock(settings, budget):
            store = CloseoutStore(settings, budget=budget)
            store_root, active, _, records = store._inventory()
            names.extend(f"{relative_root}/{record_id}.json" for record_id in active)
            under_lock = _stat_binding(settings, names, budget=budget)
        count = len(active)
        byte_count = sum(len(_encoded(record)) for record in records.values())
        expiries = []
        for record in records.values():
            budget.check()
            expires = datetime.fromisoformat(str(record["expires_at"]).replace("Z", "+00:00"))
            if expires.tzinfo is None or expires.utcoffset() is None:
                raise ValueError("CLOSEOUT_INDEX_UNKNOWN")
            expiries.append(expires)

        unknown_count = 0
        if not isinstance(recovery, dict) or recovery.get("reason_code") != "CLOSEOUT_RECOVERY_COMPLETE":
            unknown_count = max(1, count)
        else:
            rows = recovery.get("results")
            if not isinstance(rows, list):
                unknown_count = max(1, count)
            else:
                by_id = {row.get("record_id"): row for row in rows if isinstance(row, dict)}
                for record_id in active:
                    row = by_id.get(record_id)
                    if row is None or row.get("association") != "COMMITTED":
                        unknown_count += 1
        return {
            "count": count,
            "bytes": byte_count,
            "earliest_expiry": min(expiries) if expiries else None,
            "unknown_count": unknown_count,
            "status": "COMPLETE",
            "names": names,
            "under_lock": under_lock,
        }
    except TimeoutError:
        raise
    except Exception:
        return {
            "count": None,
            "bytes": None,
            "earliest_expiry": None,
            "unknown_count": 1,
            "status": "UNKNOWN",
            "names": names,
            "under_lock": None,
        }


def collect_operation_snapshot(settings, *, now, budget, max_records=64, pending=None,
                               provider_state=None, scheduler=None, last_progress_at=None, last_attempt_at=None,
                               closeout_recovery=None):
    """Authenticate a rotating bounded sample. Reservations are admission only.

    COMPLETE is possible only when this one page covers every queue reservation
    and every pending reservation, and its index and target bindings did not
    change. History larger than a page remains useful PARTIAL evidence.
    """
    from . import queue, spool
    from .runtime_catalog import RuntimeCatalog, lookup
    from .capture_contract import pending_policy
    from .operation_health import STORAGE_CODES
    if type(max_records) is not int or not 1 <= max_records <= 64:
        raise ValueError("OPERATION_PAGE_LIMIT_INVALID")
    policy = pending_policy(_read_json(Path(settings.capture_policy_path), max_bytes=65536, budget=budget) or {})
    count = size = authenticated_pending = 0
    oldest = expiry = None
    reserved_count = reserved_bytes = queue_total = None
    code = None
    binding = None
    complete = False
    pending = pending or {}
    scheduler = scheduler or {"requested": False, "missed_eligible_runs": None}
    provider_state = provider_state or {}
    root = Path(settings.paths.runtime_dir)
    names = set()
    rows = []
    closeout = _closeout_inventory(settings, budget=budget, recovery=closeout_recovery)
    names.update(closeout["names"])
    try:
        budget.check()
        queue_root, spool_root = queue._root(settings), spool._root(settings)
        # Migration retains its durable cursor. No all-history enumeration.
        queue_catalog = queue._catalog(queue_root, budget)
        budget.check()
        safe_ensure_directory(spool_root)
        budget.check()
        lock = spool._acquire(spool_root, budget=budget)
        try:
            spool_catalog = spool._catalog(spool_root, budget)
            inventory = spool._inventory(spool_catalog, settings, None, budget)
            reserved_count, reserved_bytes = spool_catalog.capacity("pending", budget=budget)
            reserved_bytes += spool_catalog.capacity("validated-result", budget=budget)[1]
        finally:
            spool._release(spool_root, lock)
        queue_total = queue_catalog.capacity("queue", budget=budget)[0]
        # A small complete inventory starts at the beginning; a large one
        # rotates diagnostic samples. This cursor never acknowledges custody.
        page = queue_catalog.page("operation-health-full" if queue_total <= max_records else "operation-health",
                                  limit=max_records, budget=budget, advance=queue_total > max_records)
        for base in (queue_root, spool_root):
            names.update(str(path.relative_to(root)).replace("\\", "/") for path in (base, base / "managed", base / ".runtime-catalog.sqlite"))
        for path in page.paths:
            budget.check()
            names.add(path.relative_to(root).as_posix())
            names.add(path.parent.relative_to(root).as_posix())
            item = queue.read_queue_item(path.stem, settings, budget=budget)
            if item.payload_ref is not None:
                target = lookup(spool_root, item.payload_ref.spool_id, budget=budget)
                names.add(target.relative_to(root).as_posix())
                names.add(target.parent.relative_to(root).as_posix())
            rows.append(item)
        before = _stat_binding(settings, sorted(names), budget=budget)
        authenticated_spools = set()
        for item in rows:
            budget.check()
            if item.payload_ref is None:
                continue
            ref = item.payload_ref
            if item.state in {queue.QueueState.DONE, queue.QueueState.NO_DISCARDED}:
                continue
            try:
                if ref.purpose == "pending" and not item.capture_id:
                    raise ValueError("PENDING_STORAGE_UNAVAILABLE")
                spool.read_spool(ref, settings, now=now, expected_capture_id=item.capture_id if ref.purpose == "pending" else None, budget=budget)
                if ref.spool_id in authenticated_spools:
                    continue
                authenticated_spools.add(ref.spool_id)
                count += 1
                authenticated_pending += ref.purpose == "pending"
                target = lookup(spool_root, ref.spool_id, budget=budget)
                size += target.stat().st_size
                created = datetime.fromisoformat(ref.created_at.replace("Z", "+00:00"))
                expires = datetime.fromisoformat(ref.expires_at.replace("Z", "+00:00"))
                oldest, expiry = min(oldest or created, created), min(expiry or expires, expires)
            except TimeoutError:
                raise
            except (OSError, ValueError, RuntimeError) as exc:
                code = str(exc) if str(exc) in STORAGE_CODES else "PENDING_STORAGE_UNAVAILABLE"
        after = _stat_binding(settings, sorted(names), budget=budget)
        closeout_bound = closeout["under_lock"] is not None and all(
            before.get(name) == row and after.get(name) == row
            for name, row in closeout["under_lock"].items()
        )
        if not closeout_bound:
            closeout.update(count=None, bytes=None, earliest_expiry=None, unknown_count=max(1, closeout["unknown_count"]), status="UNKNOWN")
        if before == after:
            binding = after
            complete = page.complete and inventory.complete and len(rows) == queue_total and authenticated_pending == reserved_count and code is None
        else:
            count = size = 0
            oldest = expiry = None
            code = code or "RUNTIME_ENTRY_CHANGED"
    except TimeoutError:
        # No count survives an incomplete binding. Fault evidence remains.
        binding = None
        closeout.update(count=None, bytes=None, earliest_expiry=None, unknown_count=max(1, closeout["unknown_count"]), status="UNKNOWN")
    except (OSError, ValueError, RuntimeError) as exc:
        code = str(exc) if str(exc) in STORAGE_CODES else "PENDING_STORAGE_UNAVAILABLE"
        closeout.update(count=None, bytes=None, earliest_expiry=None, unknown_count=max(1, closeout["unknown_count"]), status="UNKNOWN")
    pending_codes = [pending.get("reason_code")]
    for row in pending.get("processed", ()):
        if isinstance(row, dict):
            pending_codes.extend((row.get("reason_code"), row.get("cleanup_code")))
    # Specific authenticated page faults survive an unavailable count sample.
    code = next((item for item in pending_codes if item in STORAGE_CODES), code)
    status = "COMPLETE" if complete else "PARTIAL" if binding is not None else "UNKNOWN"
    provider_code = provider_state.get("reason_code")
    if provider_code in {None, "READY", "AUTH_VERIFIED", "CONFIG_CHANGED_RETRY"}:
        provider_code = None
    snapshot = HealthInput(pending_count=count if status != "UNKNOWN" else None,
        pending_bytes=size if status != "UNKNOWN" else None, pending_count_status=status,
        max_items=policy.max_items, max_bytes=policy.max_bytes, reserved_count=reserved_count,
        reserved_bytes=reserved_bytes, oldest_pending_at=oldest if status != "UNKNOWN" else None,
        earliest_expiry=expiry if status != "UNKNOWN" else None, storage_code=code,
        closeout_pending_count=closeout["count"], closeout_pending_bytes=closeout["bytes"],
        closeout_pending_status=closeout["status"], closeout_earliest_expiry=closeout["earliest_expiry"],
        closeout_unknown_count=closeout["unknown_count"],
        provider_id=provider_state.get("provider_id", ""), provider_code=provider_code,
        provider_needs_action=provider_state.get("needs_action", False),
        scheduler_requested=scheduler["requested"], missed_eligible_runs=scheduler["missed_eligible_runs"],
        last_progress_at=last_progress_at, last_attempt_at=last_attempt_at,
        expired_capture_ids=tuple(pending.get("expired_capture_ids", ())),
        cleanup_failed_capture_ids=tuple(pending.get("cleanup_failed_capture_ids", ())))
    return snapshot, binding


def _snapshot(settings, *, now: datetime, budget: OperationBudget | None = None):
    empty = HealthInput(scheduler_requested=False, pending_count=None, pending_bytes=None, pending_count_status="UNKNOWN")
    try:
        value = _read_json(Path(settings.paths.runtime_dir) / "operation-health.json", budget=budget)
        if value is None or set(value) != {"schema_version", "binding", "generated_at", "expires_at", "custody_binding", "snapshot"} or type(value["schema_version"]) is not int or value["schema_version"] != 2:
            return empty, "UNKNOWN"
        if value["binding"] != settings_binding(settings):
            return empty, "UNKNOWN"
        generated, expires = (datetime.fromisoformat(value[key]) for key in ("generated_at", "expires_at"))
        if any(item.tzinfo is None or item.utcoffset() is None for item in (generated, expires, now)) or not generated <= now < expires or expires - generated != timedelta(seconds=_ttl(settings)):
            return empty, "UNKNOWN"
        fields = value["snapshot"]
        if not isinstance(fields, dict) or set(fields) != set(HealthInput.__dataclass_fields__):
            return empty, "UNKNOWN"
        fields = dict(fields)
        if any(not isinstance(fields[name], str) for name in ("host_id", "provider_id", "storage_component_id", "pending_count_status")):
            return empty, "UNKNOWN"
        if fields["provider_code"] is not None and not isinstance(fields["provider_code"], str):
            return empty, "UNKNOWN"
        if fields["provider_code"] in {"READY", "AUTH_VERIFIED", "CONFIG_CHANGED_RETRY"}:
            fields["provider_code"] = None
        for name in ("oldest_pending_at", "earliest_expiry", "last_progress_at", "last_attempt_at", "closeout_earliest_expiry"):
            if fields[name] is not None:
                fields[name] = datetime.fromisoformat(fields[name])
        for name in ("source_missing_ids", "expired_capture_ids", "cleanup_failed_capture_ids"):
            if not isinstance(fields[name], list):
                return empty, "UNKNOWN"
            for identifier in fields[name]:
                if budget is not None:
                    budget.check()
                if not isinstance(identifier, str) or not identifier:
                    return empty, "UNKNOWN"
            fields[name] = tuple(fields[name])
        snapshot = HealthInput(**fields)
        binding = value["custody_binding"]
        try:
            valid_rows = isinstance(binding, dict) and bool(binding) and all(row is None or isinstance(row, list) and len(row) == 5 and all(type(number) is int and number >= 0 for number in row) for row in binding.values())
            if not valid_rows or _stat_binding(settings, list(binding), budget=budget) != binding:
                snapshot = replace(snapshot, pending_count=None, pending_bytes=None, pending_count_status="UNKNOWN",
                                   reserved_count=None, reserved_bytes=None, oldest_pending_at=None, earliest_expiry=None,
                                   closeout_pending_count=None, closeout_pending_bytes=None, closeout_pending_status="UNKNOWN",
                                   closeout_earliest_expiry=None, closeout_unknown_count=max(1, snapshot.closeout_unknown_count))
        except (OSError, ValueError, RuntimeError):
            snapshot = replace(snapshot, pending_count=None, pending_bytes=None, pending_count_status="UNKNOWN",
                               reserved_count=None, reserved_bytes=None, oldest_pending_at=None, earliest_expiry=None,
                               closeout_pending_count=None, closeout_pending_bytes=None, closeout_pending_status="UNKNOWN",
                               closeout_earliest_expiry=None, closeout_unknown_count=max(1, snapshot.closeout_unknown_count))
        return snapshot, "KNOWN"
    except (OSError, ValueError, TypeError, KeyError, RuntimeError):
        return empty, "UNKNOWN"


def operation_snapshot(settings, *, now: datetime, budget=None) -> HealthInput:
    """Read only a bounded cache; missing evidence is exposed by operation_status."""
    return _snapshot(settings, now=now, budget=budget)[0]


def last_maintenance_activity(settings, *, now, budget=None):
    """Historical timestamps are not refreshed custody or current health proof."""
    unknown = {"last_attempt_at": None, "last_progress_at": None}
    try:
        health = _read_json(Path(settings.paths.runtime_dir) / "health.json", budget=budget) or {}
        value = health.get("operation", {})
        if type(value.get("schema_version")) is not int or value["schema_version"] != 1 or value.get("binding") != settings_binding(settings):
            return unknown
        result = {}
        for key in unknown:
            raw = value.get(key)
            parsed = datetime.fromisoformat(raw) if isinstance(raw, str) else None
            if raw is not None and (parsed is None or parsed.tzinfo is None or parsed.utcoffset() is None or parsed > now):
                return unknown
            result[key] = parsed
        if result["last_progress_at"] is not None and (result["last_attempt_at"] is None or result["last_progress_at"] > result["last_attempt_at"]):
            return unknown
        return result
    except TimeoutError:
        raise
    except (OSError, ValueError, TypeError, KeyError, AttributeError):
        return unknown


def operation_status(settings, *, now: datetime, budget=None) -> dict:
    from .incidents import inspect_incidents
    from .task_scheduler import inspect_scheduler_opportunities
    budget = budget if budget is not None else OperationBudget(5000)
    snapshot, status = _snapshot(settings, now=now, budget=budget)
    scheduler = inspect_scheduler_opportunities(settings, now=now, budget=budget, read_only=True)
    snapshot = replace(snapshot, scheduler_requested=scheduler["requested"], missed_eligible_runs=scheduler["missed_eligible_runs"])
    fields = _fields(snapshot)
    activity = last_maintenance_activity(settings, now=now, budget=budget)
    return {"snapshot_status": status, "snapshot": fields,
            **{name: value.isoformat() if value else None for name, value in activity.items()},
            "incidents": inspect_incidents(settings, budget=budget), "notification_policy": notification_policy(settings, budget=budget),
            "scheduler": scheduler, "cli_notification": "UNVERIFIED",
            "issues": [item.reason_code for item in evaluate_health(snapshot, now=now)],
            "detection_limit": "NO_DETECTION_WHILE_BOTH_HOOK_AND_SCHEDULER_STOPPED"}


def service_cli_start(settings, *, now, session_hash=None, budget=None):
    """Independent startup observer; never extends custody-cache freshness."""
    from .task_scheduler import inspect_scheduler_opportunities
    budget = budget if budget is not None else OperationBudget(200)
    try:
        scheduler = inspect_scheduler_opportunities(settings, now=now, budget=budget)
        return service_operation(settings, now=now, channel="cli", session_hash=session_hash,
                                 budget=budget, scheduler=scheduler)
    except TimeoutError:
        return operation_result((), 0, "OPERATION_BUDGET_EXHAUSTED")
    except Exception:
        return operation_result((), 0, "OPERATION_STATE_UNAVAILABLE")


def operation_result(issues, notifications_sent, reason_code="OK"):
    return {"issues": [item.reason_code for item in issues],
            "notifications_sent": notifications_sent, "reason_code": reason_code}


def notification_policy(settings, *, budget=None) -> dict:
    """Read Task 9's policy without treating test consent as routine enablement."""
    unknown = {"status": "UNKNOWN", "enabled": False, "channel": None}
    try:
        value = _read_json(Path(settings.paths.runtime_dir) / "automatic-operation.json", max_bytes=65536, budget=budget)
        if value is None or set(value) != {"schema_version", "settings", "evidence"} or type(value["schema_version"]) is not int or value["schema_version"] != 1:
            return unknown
        config = value["settings"]
        if not isinstance(config, dict) or set(config) != {"notifications", "initial_test"} or not isinstance(value["evidence"], dict):
            return unknown
        notifications, tests = config["notifications"], config["initial_test"]
        if not isinstance(notifications, dict) or set(notifications) != {"enabled", "channel"} or type(notifications["enabled"]) is not bool or notifications["channel"] != "os":
            return unknown
        if not isinstance(tests, dict) or set(tests) != {"allow_model_test", "allow_notification_test"} or any(type(item) is not bool for item in tests.values()):
            return unknown
        return {"status": "KNOWN", **notifications}
    except (OSError, ValueError, TypeError, KeyError, RuntimeError):
        return unknown


def _notify(settings, identifier, *, now, budget):
    from .incidents import abort_notification, claim_notification, settle_notification
    from .notifications.base import DeliveryResult, render_notification, send_native_notification

    budget.check()
    if budget.remaining_ms() <= _NOTIFICATION_FINISH_RESERVE_MS:
        return False  # Do not create a lease when even its margin is absent.
    lease = claim_notification(settings, identifier, channel="os", session_hash=None, now=now,
                               lock_timeout_seconds=min(0.05, budget.remaining_ms() / 1000), budget=budget)
    if lease is None:
        return False
    remaining_ms = budget.remaining_ms()
    if remaining_ms > _NOTIFICATION_FINISH_RESERVE_MS:
        message = render_notification(lease.reason_code, lease.pending_count, recovered=lease.recovered,
                                      pending_count_status=lease.pending_count_status)
        remaining_ms = budget.remaining_ms()
    if remaining_ms <= _NOTIFICATION_FINISH_RESERVE_MS:
        # Both branches are positively uninvoked. Once fully expired, leave
        # UNKNOWN; do not start a fresh cache read merely to cancel the lease.
        if remaining_ms > 0:
            abort_notification(settings, lease, lock_timeout_seconds=0, budget=budget)
        return False
    try:
        result = send_native_notification(message, timeout_seconds=min(2.0,
            (remaining_ms - _NOTIFICATION_FINISH_RESERVE_MS) / 1000))
    except Exception:
        return False  # Invocation happened; delivery remains UNKNOWN.
    if not isinstance(result, DeliveryResult) or budget.remaining_ms() <= 0:
        return False
    settled = settle_notification(settings, lease, result, now=now, budget=budget,
                                  lock_timeout_seconds=min(0.05, budget.remaining_ms() / 1000))
    return settled and result.status == "SENT"


def service_operation(settings, *, now: datetime, channel: str,
                      session_hash: str | None = None, max_ms: int = 200, budget=None,
                      verified_resolutions=(), scheduler=None, additional_issues=()) -> dict:
    if not isinstance(additional_issues, tuple) or any(
        not isinstance(item, HealthIssue) for item in additional_issues
    ):
        raise ValueError("OPERATION_ADDITIONAL_ISSUES_INVALID")
    budget = budget if budget is not None else OperationBudget(max_ms)
    if budget.remaining_ms() <= 0:
        return operation_result((), 0, "OPERATION_BUDGET_EXHAUSTED")
    snapshot, status = _snapshot(settings, now=now, budget=budget)
    if scheduler is not None:
        snapshot = replace(snapshot, scheduler_requested=scheduler["requested"], missed_eligible_runs=scheduler["missed_eligible_runs"])
    issues = (*evaluate_health(snapshot, now=now), *additional_issues)
    sent = 0
    try:
        from .incidents import inspect_incidents, notification_due, update_incidents
        budget.check()
        selection = _read_json(Path(settings.paths.install_manifest_path), budget=budget) or {}
        explicitly_disabled = selection.get("scheduler_requested") is False
        if explicitly_disabled:
            snapshot = replace(snapshot, scheduler_requested=False, missed_eligible_runs=0)
            issues = (*evaluate_health(snapshot, now=now), *additional_issues)
        if scheduler is not None and scheduler.get("reason_code") == "SCHEDULER_EXECUTION_RESUMED":
            from .incidents import incident_id
            verified_resolutions = (*verified_resolutions, incident_id("SCHEDULER_STOPPED", snapshot.host_id or "scheduler"))
        if issues or verified_resolutions:
            incidents = update_incidents(settings, issues, now=now, budget=budget, verified_resolutions=verified_resolutions)
        else:
            incidents = inspect_incidents(settings, budget=budget)["incidents"]
        policy = notification_policy(settings, budget=budget)
        if policy["enabled"]:
            for incident in incidents:
                budget.check()
                if explicitly_disabled and incident["reason_code"] == "SCHEDULER_STOPPED":
                    continue
                if notification_due(incident, channel="os", session_hash=None, now=now, budget=budget):
                    sent += _notify(settings, incident["incident_id"], now=now, budget=budget)
                    break  # At most one external attempt per hook/maintenance.
        return operation_result(issues, sent, "OK" if status == "KNOWN" else "OPERATION_SNAPSHOT_UNKNOWN")
    except TimeoutError:
        return operation_result(issues, sent, "OPERATION_BUDGET_EXHAUSTED")
    except (OSError, ValueError, TypeError, RuntimeError):
        return operation_result(issues, sent, "OPERATION_STATE_UNAVAILABLE")
