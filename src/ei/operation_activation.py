from __future__ import annotations

from collections.abc import Mapping
from datetime import datetime, timezone
import hashlib
import json
import os
import platform
from pathlib import Path
import re
import stat
from copy import deepcopy
from typing import Any

from .notifications.base import DeliveryResult, NotificationMessage, send_native_notification
from .safe_fs import SafeFilesystemError, assert_safe_target, safe_atomic_write, safe_ensure_directory


_OPERATION_STATE_NAME = "automatic-operation.json"
_MAX_OPERATION_STATE_BYTES = 65536
_SHA256_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
_HOST_ID_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{0,63}$")
_STATUS_VALUES = {"VERIFIED", "UNVERIFIED"}
_HOST_FIELDS = {
    "binding", "hook", "accumulation", "recall", "host_version",
    "engine_code_sha256", "binding_sha256", "os_family", "os_version",
    "channel", "tested_at", "observation", "candidate_ref_sha256",
    "event_ref_sha256", "recall_ref_sha256",
}
_SCHEDULER_FIELDS = {
    "run", "monitor", "engine_code_sha256", "binding_sha256", "os_family",
    "os_version", "tested_at", "observation",
}
_NOTIFICATION_FIELDS = {
    "send", "display", "channel", "os_family", "os_version", "tested_at",
    "observation", "test_ref_sha256",
}
_OBSERVATIONS = {
    "HOST_RECEIPT", "SYNTHETIC_END_TO_END", "ISOLATION_UNAVAILABLE",
    "AUTH_OR_TRUST_REQUIRED", "NOT_RUN", "SCHEDULER_RUN_OBSERVED",
    "SCHEDULER_MONITOR_UNSUPPORTED", "OS_SEND_ACCEPTED",
    "USER_CONFIRMED_DISPLAY", "OS_DENIED", "OS_UNAVAILABLE", "OS_FAILED",
}


def _digest(raw: bytes) -> str:
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def _read_local_document(root: Path, path: Path, *, max_bytes: int) -> dict[str, Any] | None:
    if not (root.exists() or root.is_symlink()) or not (path.exists() or path.is_symlink()):
        return None
    try:
        assert_safe_target(root.parent, root, allow_missing=False, expected_type="dir")
        assert_safe_target(root, path, allow_missing=False, expected_type="file")
        flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(path, flags)
        with os.fdopen(descriptor, "rb") as stream:
            before = os.fstat(stream.fileno())
            if not stat.S_ISREG(before.st_mode) or before.st_size > max_bytes:
                return None
            raw = stream.read(max_bytes + 1)
            after = os.fstat(stream.fileno())
        current = path.stat(follow_symlinks=False)
        identity = lambda item: (item.st_dev, item.st_ino, item.st_size, item.st_mtime_ns)
        if len(raw) > max_bytes or identity(before) != identity(after) or identity(after) != identity(current):
            return None
        value = json.loads(raw.decode("utf-8"), object_pairs_hook=_parse_object,
                           parse_constant=lambda _item: (_ for _ in ()).throw(ValueError("JSON_CONSTANT_INVALID")))
    except (OSError, UnicodeError, ValueError, TypeError, json.JSONDecodeError, SafeFilesystemError):
        return None
    return value if isinstance(value, dict) else None


def _read_install_manifest(settings: Any) -> dict[str, Any] | None:
    runtime = Path(settings.paths.runtime_root)
    path = Path(settings.paths.install_manifest_path)
    document = _read_local_document(runtime, path, max_bytes=1_048_576)
    if not isinstance(document, dict) or type(document.get("scheduler_requested")) is not bool:
        return None
    work_hosts = document.get("work_hosts")
    if not isinstance(work_hosts, list) or any(not isinstance(host, str) or not _HOST_ID_RE.fullmatch(host) for host in work_hosts):
        return None
    return document


def _engine_code_digest(settings: Any) -> str:
    source = Path(settings.paths.engine_root) / "src" / "ei"
    digest = hashlib.sha256()
    if not source.is_dir() or source.is_symlink():
        return _digest(b"")
    files = sorted(path for path in source.rglob("*.py") if path.is_file() and not path.is_symlink())
    if len(files) > 4096:
        raise ValueError("ENGINE_CODE_HASH_LIMIT")
    total = 0
    for path in files:
        assert_safe_target(source, path, allow_missing=False, expected_type="file")
        raw = path.read_bytes()
        total += len(raw)
        if total > 64 * 1024 * 1024:
            raise ValueError("ENGINE_CODE_HASH_LIMIT")
        digest.update(path.relative_to(source).as_posix().encode("utf-8"))
        digest.update(b"\0")
        digest.update(len(raw).to_bytes(8, "big"))
        digest.update(hashlib.sha256(raw).digest())
    return "sha256:" + digest.hexdigest()


def _file_digest(path: object) -> str | None:
    if not isinstance(path, (Path, str)):
        return None
    target = Path(path)
    if not (target.exists() or target.is_symlink()) or target.is_symlink() or not target.is_file():
        return None
    try:
        raw = target.read_bytes()
    except OSError:
        return None
    if len(raw) > 8 * 1024 * 1024:
        return None
    return _digest(raw)


def _binding_digest(settings: Any, host_id: str, static_checks: Mapping[str, Any] | None = None) -> str:
    spec = getattr(settings, "hosts", {}).get(host_id) if isinstance(getattr(settings, "hosts", {}), Mapping) else None
    material = {
        "host_id": host_id,
        "host_family": getattr(spec, "host_family", ""),
        "adapter_id": getattr(spec, "adapter_id", ""),
        "profile_hash": getattr(spec, "profile_hash", None),
        "hook_config_sha256": _file_digest(getattr(spec, "hook_config_path", None)),
        "global_context_sha256": _file_digest(getattr(spec, "global_context_path", None)),
        "template_sha256": static_checks.get("template_hash") if isinstance(static_checks, Mapping) else None,
    }
    return _digest(json.dumps(material, ensure_ascii=True, sort_keys=True, separators=(",", ":")).encode("utf-8"))


def _configured_work_hosts(settings: Any) -> tuple[str, ...]:
    manifest = _read_install_manifest(settings)
    if not isinstance(manifest, Mapping):
        return ()
    return tuple(manifest["work_hosts"])


def _invoke_isolated_host_test(settings: Any, host_id: str) -> dict[str, Any]:
    """Run the bounded native driver when available; never substitute a host or home.

    The native driver contract is intentionally fail-closed until its isolated
    CLI/auth/trust boundary is available. Existing receipts are recorded
    independently below and are never promoted to synthetic end-to-end proof.
    """
    del settings, host_id
    return {"status": "UNVERIFIED", "reason_code": "ISOLATION_UNAVAILABLE", "observation": "ISOLATION_UNAVAILABLE"}


def _write_operation_document(settings: Any, document: dict[str, Any]) -> str | None:
    root, path = _operation_state_path(settings)
    raw = json.dumps(document, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
    if len(raw) > _MAX_OPERATION_STATE_BYTES or not _valid_operation_document(document):
        return "OPERATION_STATE_INVALID"
    try:
        safe_ensure_directory(root)
        safe_atomic_write(root, path, raw, mode=0o600)
    except (OSError, TypeError, ValueError, SafeFilesystemError):
        return "OPERATION_STATE_WRITE_FAILED"
    return None


def _os_identity() -> tuple[str, str]:
    family = platform.system() or "unknown"
    version = platform.release() or "unknown"
    return family[:128], version[:128]


def verify_operation(
    settings: Any,
    *,
    allow_model_test: bool,
    allow_notification_test: bool,
    confirmed_notification_seen: bool = False,
) -> dict[str, Any]:
    """Collect bounded evidence, keeping consent, API acceptance, and display separate."""
    if type(allow_model_test) is not bool or type(allow_notification_test) is not bool or type(confirmed_notification_seen) is not bool:
        raise TypeError("OPERATION_CONSENT_BOOLEAN_REQUIRED")
    document, error = ensure_operation_state(settings)
    if document is None:
        return {
            "automatic_operation": "UNVERIFIED",
            "notification_send": "NOT_ATTEMPTED",
            "reason_codes": [error or "OPERATION_STATE_INVALID"],
            "evidence": {},
        }
    state = deepcopy(document)
    prior = deepcopy(state["evidence"])
    if allow_model_test:
        state["settings"]["initial_test"]["allow_model_test"] = True
    if allow_notification_test:
        state["settings"]["initial_test"]["allow_notification_test"] = True

    now = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    os_family, os_version = _os_identity()
    reason_codes: list[str] = []
    notification_send = "NOT_ATTEMPTED"
    try:
        engine_hash = _engine_code_digest(settings)
    except (OSError, SafeFilesystemError, ValueError):
        engine_hash = _digest(b"")
        reason_codes.append("ENGINE_CODE_HASH_UNAVAILABLE")

    manifest = _read_install_manifest(settings)
    scheduler_requested = manifest.get("scheduler_requested") if isinstance(manifest, Mapping) else None
    work_hosts = _configured_work_hosts(settings)
    current_binding: dict[str, Any] = {
        "engine_code_sha256": engine_hash,
        "os_family": os_family,
        "os_version": os_version,
        "notification_channel": "os",
        "scheduler_binding_sha256": _digest(json.dumps({"engine": engine_hash, "os": os_family, "version": os_version}, sort_keys=True).encode("utf-8")),
        "hosts": {},
    }
    certifications: dict[str, tuple[bool, str, str, Mapping[str, Any]]] = {}
    try:
        from .certification import certify_host
        for host_id in work_hosts:
            try:
                result = certify_host(host_id, host_id, "real", settings, allow_version_probe=False)
                receipt = result.receipt
                status = "VERIFIED" if result.status == "PASSED" and result.real_evidence else "UNVERIFIED"
                version = str(receipt.get("host_version", "unknown")) or "unknown"
                static = {}
                try:
                    from .canary import read_hook_status
                    hook_status = read_hook_status(host_id, host_id, settings, persist=False)
                    static = hook_status.static_checks
                except (OSError, TypeError, ValueError):
                    reason_codes.append("HOOK_STATIC_CHECK_UNAVAILABLE")
                binding_hash = _binding_digest(settings, host_id, static)
                certifications[host_id] = (static.get("valid") is True, status, version, static)
                current_binding["hosts"][host_id] = {"binding_sha256": binding_hash, "host_version": version, "channel": "work-cli"}
            except (OSError, TypeError, ValueError, KeyError):
                version = "unknown"
                binding_hash = _binding_digest(settings, host_id)
                certifications[host_id] = (False, "UNVERIFIED", version, {})
                current_binding["hosts"][host_id] = {"binding_sha256": binding_hash, "host_version": version, "channel": "work-cli"}
    except ImportError:
        reason_codes.append("HOST_CERTIFICATION_UNAVAILABLE")

    evidence = invalidate_operation_evidence(prior, current_binding)
    host_rows = evidence.setdefault("hosts", {})
    if not work_hosts:
        reason_codes.append("WORK_HOSTS_UNAVAILABLE")
    for host_id in work_hosts:
        static_valid, hook_status, host_version, static = certifications.get(host_id, (False, "UNVERIFIED", "unknown", {}))
        current = current_binding["hosts"][host_id]
        row = host_rows.get(host_id)
        if not isinstance(row, dict):
            row = {
                "binding": "UNVERIFIED", "hook": "UNVERIFIED", "accumulation": "UNVERIFIED", "recall": "UNVERIFIED",
            }
            host_rows[host_id] = row
        retained_end_to_end = (
            row.get("observation") == "SYNTHETIC_END_TO_END"
            and row.get("accumulation") == "VERIFIED"
            and row.get("recall") == "VERIFIED"
            and row.get("binding_sha256") == current["binding_sha256"]
            and row.get("host_version") == host_version
            and row.get("engine_code_sha256") == engine_hash
            and row.get("os_family") == os_family
            and row.get("os_version") == os_version
        )
        row.update({
            "binding": "VERIFIED" if static_valid else "UNVERIFIED",
            "hook": "VERIFIED" if hook_status == "VERIFIED" else "UNVERIFIED",
            "host_version": host_version,
            "engine_code_sha256": engine_hash,
            "binding_sha256": current["binding_sha256"],
            "os_family": os_family,
            "os_version": os_version,
            "channel": "work-cli",
        })
        if not retained_end_to_end:
            row["tested_at"] = now
            row["observation"] = "HOST_RECEIPT" if hook_status == "VERIFIED" else "NOT_RUN"
        if hook_status != "VERIFIED":
            row["accumulation"] = "UNVERIFIED"
            row["recall"] = "UNVERIFIED"
            for key in ("candidate_ref_sha256", "event_ref_sha256", "recall_ref_sha256"):
                row.pop(key, None)
        if allow_model_test and hook_status == "VERIFIED" and not retained_end_to_end:
            result = _invoke_isolated_host_test(settings, host_id)
            if result.get("status") == "VERIFIED" and all(_valid_hash(result.get(key)) for key in ("candidate_ref_sha256", "event_ref_sha256", "recall_ref_sha256")):
                row.update({key: result[key] for key in ("candidate_ref_sha256", "event_ref_sha256", "recall_ref_sha256")})
                row.update({key: "VERIFIED" for key in ("binding", "hook", "accumulation", "recall")})
                row["observation"] = "SYNTHETIC_END_TO_END"
            else:
                row["accumulation"] = "UNVERIFIED"
                row["recall"] = "UNVERIFIED"
                row["observation"] = str(result.get("observation") or "ISOLATION_UNAVAILABLE")
                reason_codes.append(str(result.get("reason_code") or "HOST_OPERATION_TEST_UNVERIFIED"))
        elif allow_model_test and hook_status != "VERIFIED":
            reason_codes.append("AUTH_OR_TRUST_REQUIRED")
        elif retained_end_to_end:
            reason_codes.append("SYNTHETIC_END_TO_END_EVIDENCE_RETAINED")
        elif not retained_end_to_end:
            reason_codes.append("OPERATION_TEST_CONSENT_REQUIRED")

    if scheduler_requested is True:
        previous_scheduler = evidence.get("scheduler") if isinstance(evidence.get("scheduler"), dict) else {}
        scheduler = dict(previous_scheduler)
        if not scheduler or scheduler.get("engine_code_sha256") != engine_hash or scheduler.get("binding_sha256") != current_binding["scheduler_binding_sha256"]:
            scheduler = {"run": "UNVERIFIED", "monitor": "UNVERIFIED"}
        scheduler.update({
            "run": scheduler.get("run", "UNVERIFIED"),
            "monitor": scheduler.get("monitor", "UNVERIFIED"),
            "engine_code_sha256": engine_hash,
            "binding_sha256": current_binding["scheduler_binding_sha256"],
            "os_family": os_family,
            "os_version": os_version,
            "tested_at": now,
            "observation": "SCHEDULER_MONITOR_UNSUPPORTED" if scheduler.get("monitor") != "VERIFIED" else "SCHEDULER_RUN_OBSERVED",
        })
        evidence["scheduler"] = scheduler
        if scheduler.get("monitor") != "VERIFIED":
            reason_codes.append("SCHEDULER_MONITOR_UNSUPPORTED")
    elif scheduler_requested is False:
        evidence.pop("scheduler", None)
    else:
        reason_codes.append("SCHEDULER_SELECTION_UNAVAILABLE")

    notification = evidence.get("notification") if isinstance(evidence.get("notification"), dict) else None
    if confirmed_notification_seen and notification and notification.get("send") == "SENT":
        notification["display"] = "VERIFIED"
        notification["observation"] = "USER_CONFIRMED_DISPLAY"
        notification["tested_at"] = now
        evidence["notification"] = notification
    elif notification and notification.get("display") == "VERIFIED":
        reason_codes.append("NOTIFICATION_DISPLAY_EVIDENCE_RETAINED")
    elif allow_notification_test:
        if state["settings"]["notifications"]["enabled"] is not True:
            reason_codes.append("NOTIFICATIONS_DISABLED")
        elif notification and notification.get("send") == "SENT" and notification.get("display") == "UNVERIFIED":
            # Await an explicit display confirmation; do not send repeatedly.
            reason_codes.append("NOTIFICATION_DISPLAY_CONFIRMATION_REQUIRED")
        else:
            test_title = "External Intelligence setup test"
            test_body = "If this notification appeared, return to setup and confirm it was visible."
            try:
                delivery = send_native_notification(NotificationMessage(test_title, test_body), timeout_seconds=2.0)
            except Exception:
                delivery = DeliveryResult("FAILED", "OS_FAILED")
            send_status = delivery.status if isinstance(delivery, DeliveryResult) else "FAILED"
            notification_send = send_status
            observed = {
                "SENT": "OS_SEND_ACCEPTED", "DENIED": "OS_DENIED",
                "UNAVAILABLE": "OS_UNAVAILABLE", "FAILED": "OS_FAILED",
            }[send_status]
            test_ref = _digest((test_title + "\0" + test_body).encode("utf-8"))
            notification = {
                "send": send_status,
                "display": "UNVERIFIED",
                "channel": "os",
                "os_family": os_family,
                "os_version": os_version,
                "tested_at": now,
                "observation": observed,
                "test_ref_sha256": test_ref,
            }
            evidence["notification"] = notification
            if send_status != "SENT":
                reason_codes.append("NOTIFICATION_TEST_" + send_status)
            else:
                reason_codes.append("NOTIFICATION_DISPLAY_CONFIRMATION_REQUIRED")
    else:
        reason_codes.append("OPERATION_TEST_CONSENT_REQUIRED")

    state["evidence"] = evidence
    write_error = _write_operation_document(settings, state)
    if write_error:
        reason_codes.append(write_error)
    summary = {
        "scheduler_requested": scheduler_requested,
        "hosts": evidence.get("hosts", {}),
        "scheduler_run": evidence.get("scheduler", {}).get("run") if isinstance(evidence.get("scheduler"), Mapping) else "UNVERIFIED",
        "scheduler_monitor": evidence.get("scheduler", {}).get("monitor") if isinstance(evidence.get("scheduler"), Mapping) else "UNVERIFIED",
        "notification_display": evidence.get("notification", {}).get("display") if isinstance(evidence.get("notification"), Mapping) else "UNVERIFIED",
    }
    readiness = activation_readiness(summary)
    return {
        "automatic_operation": readiness,
        "notification_send": notification_send,
        "reason_codes": list(dict.fromkeys(reason_codes)),
        "evidence": evidence,
    }

def activation_readiness(evidence: dict[str, Any]) -> str:
    if not isinstance(evidence, Mapping):
        return "UNVERIFIED"
    requested = evidence.get("scheduler_requested")
    if requested is False:
        return "DISABLED"
    if type(requested) is not bool:
        return "UNVERIFIED"

    if "hosts" in evidence:
        hosts = evidence.get("hosts")
        if not isinstance(hosts, Mapping) or not hosts:
            return "UNVERIFIED"
        host_fields = ("binding", "hook", "accumulation", "recall")
        if any(
            not isinstance(row, Mapping)
            or any(row.get(field) != "VERIFIED" for field in host_fields)
            for row in hosts.values()
        ):
            return "UNVERIFIED"
        fields = ("scheduler_run", "scheduler_monitor", "notification_display")
    else:
        fields = (
            "binding", "hook", "accumulation", "recall", "scheduler_run",
            "scheduler_monitor", "notification_display",
        )
    return "VERIFIED" if all(evidence.get(field) == "VERIFIED" for field in fields) else "UNVERIFIED"


def _operation_state_path(settings: Any) -> tuple[Path, Path]:
    root = Path(settings.paths.runtime_root)
    return root, root / _OPERATION_STATE_NAME


def _parse_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("OPERATION_STATE_DUPLICATE_KEY")
        result[key] = value
    return result


def _read_operation_document(settings: Any) -> tuple[dict[str, Any] | None, str | None]:
    root, path = _operation_state_path(settings)
    if not root.exists() and not root.is_symlink():
        return None, "OPERATION_STATE_MISSING"
    try:
        assert_safe_target(root.parent, root, allow_missing=False, expected_type="dir")
        assert_safe_target(root, path, allow_missing=True)
        if not (path.exists() or path.is_symlink()):
            return None, "OPERATION_STATE_MISSING"
        assert_safe_target(root, path, allow_missing=False, expected_type="file")
        flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(path, flags)
        with os.fdopen(descriptor, "rb") as stream:
            before = os.fstat(stream.fileno())
            if not stat.S_ISREG(before.st_mode) or before.st_size > _MAX_OPERATION_STATE_BYTES:
                return None, "OPERATION_STATE_INVALID"
            raw = stream.read(_MAX_OPERATION_STATE_BYTES + 1)
            after = os.fstat(stream.fileno())
        current = path.stat(follow_symlinks=False)
        identity = lambda item: (item.st_dev, item.st_ino, item.st_size, item.st_mtime_ns)
        if len(raw) > _MAX_OPERATION_STATE_BYTES or identity(before) != identity(after) or identity(after) != identity(current):
            return None, "OPERATION_STATE_INVALID"
        value = json.loads(raw.decode("utf-8"), object_pairs_hook=_parse_object,
                           parse_constant=lambda _item: (_ for _ in ()).throw(ValueError("OPERATION_STATE_INVALID")))
    except (OSError, UnicodeError, ValueError, TypeError, json.JSONDecodeError, SafeFilesystemError):
        return None, "OPERATION_STATE_INVALID"
    if not _valid_operation_document(value):
        return None, "OPERATION_STATE_INVALID"
    return value, None


def _safe_text(value: object, *, maximum: int = 128) -> bool:
    return (
        isinstance(value, str)
        and 0 < len(value) <= maximum
        and "\x00" not in value
        and "\n" not in value
        and "\r" not in value
        and not value.startswith(("/", "\\"))
        and not re.match(r"^[A-Za-z]:[\\/]", value)
    )


def _valid_time(value: object) -> bool:
    if not _safe_text(value):
        return False
    try:
        parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError:
        return False
    return parsed.tzinfo is not None


def _valid_hash(value: object) -> bool:
    return isinstance(value, str) and _SHA256_RE.fullmatch(value) is not None


def _valid_host_evidence(value: object) -> bool:
    if not isinstance(value, dict) or set(value) - _HOST_FIELDS:
        return False
    required = {
        "binding", "hook", "accumulation", "recall", "host_version",
        "engine_code_sha256", "binding_sha256", "os_family", "os_version",
        "channel", "tested_at", "observation",
    }
    if not required.issubset(value):
        return False
    if any(value.get(field) not in _STATUS_VALUES for field in ("binding", "hook", "accumulation", "recall")):
        return False
    if any(not _valid_hash(value.get(field)) for field in ("engine_code_sha256", "binding_sha256")):
        return False
    if any(not _safe_text(value.get(field)) for field in ("host_version", "os_family", "os_version")):
        return False
    if value.get("channel") != "work-cli" or not _valid_time(value.get("tested_at")) or value.get("observation") not in _OBSERVATIONS:
        return False
    reference_fields = ("candidate_ref_sha256", "event_ref_sha256", "recall_ref_sha256")
    if any(field in value and not _valid_hash(value[field]) for field in reference_fields):
        return False
    if value.get("accumulation") == "VERIFIED" and not all(field in value for field in reference_fields):
        return False
    if value.get("recall") == "VERIFIED" and not all(field in value for field in reference_fields):
        return False
    return True


def _valid_scheduler_evidence(value: object) -> bool:
    if not isinstance(value, dict) or set(value) - _SCHEDULER_FIELDS:
        return False
    required = {"run", "monitor", "engine_code_sha256", "binding_sha256", "os_family", "os_version", "tested_at", "observation"}
    return (
        required.issubset(value)
        and value.get("run") in _STATUS_VALUES
        and value.get("monitor") in _STATUS_VALUES
        and _valid_hash(value.get("engine_code_sha256"))
        and _valid_hash(value.get("binding_sha256"))
        and _safe_text(value.get("os_family"))
        and _safe_text(value.get("os_version"))
        and _valid_time(value.get("tested_at"))
        and value.get("observation") in _OBSERVATIONS
    )


def _valid_notification_evidence(value: object) -> bool:
    if not isinstance(value, dict) or set(value) - _NOTIFICATION_FIELDS:
        return False
    required = {"send", "display", "channel", "os_family", "os_version", "tested_at", "observation"}
    send_values = {"SENT", "UNVERIFIED", "DENIED", "UNAVAILABLE", "FAILED"}
    if not required.issubset(value):
        return False
    if value.get("send") not in send_values or value.get("display") not in _STATUS_VALUES or value.get("channel") != "os":
        return False
    if any(not _safe_text(value.get(field)) for field in ("os_family", "os_version")):
        return False
    if not _valid_time(value.get("tested_at")) or value.get("observation") not in _OBSERVATIONS:
        return False
    if "test_ref_sha256" in value and not _valid_hash(value["test_ref_sha256"]):
        return False
    if value.get("display") == "VERIFIED" and (value.get("send") != "SENT" or value.get("observation") != "USER_CONFIRMED_DISPLAY"):
        return False
    return True


def _valid_operation_document(value: object) -> bool:
    if not isinstance(value, dict) or set(value) != {"schema_version", "settings", "evidence"}:
        return False
    if type(value.get("schema_version")) is not int or value["schema_version"] != 1:
        return False
    settings = value.get("settings")
    if not isinstance(settings, dict) or set(settings) != {"notifications", "initial_test"}:
        return False
    notifications = settings.get("notifications")
    initial_test = settings.get("initial_test")
    if not isinstance(notifications, dict) or set(notifications) != {"enabled", "channel"}:
        return False
    if type(notifications.get("enabled")) is not bool or notifications.get("channel") != "os":
        return False
    if not isinstance(initial_test, dict) or set(initial_test) != {"allow_model_test", "allow_notification_test"}:
        return False
    if any(type(initial_test.get(key)) is not bool for key in initial_test):
        return False
    evidence = value.get("evidence")
    if not isinstance(evidence, dict) or set(evidence) - {"hosts", "scheduler", "notification"}:
        return False
    hosts = evidence.get("hosts", {})
    if not isinstance(hosts, dict) or any(not isinstance(host, str) or not _HOST_ID_RE.fullmatch(host) or not _valid_host_evidence(row) for host, row in hosts.items()):
        return False
    if "scheduler" in evidence and not _valid_scheduler_evidence(evidence["scheduler"]):
        return False
    if "notification" in evidence and not _valid_notification_evidence(evidence["notification"]):
        return False
    return True


def load_operation_evidence(settings: Any) -> dict[str, Any]:
    """Return only a validated, body-free evidence object; invalid state stays unverified."""
    document, _reason = _read_operation_document(settings)
    return dict(document.get("evidence", {})) if document is not None else {}


def ensure_operation_state(settings: Any) -> tuple[dict[str, Any] | None, str | None]:
    """Create safe defaults only when absent; never replace existing user state."""
    current, reason = _read_operation_document(settings)
    if current is not None:
        return current, None
    if reason != "OPERATION_STATE_MISSING":
        return None, reason
    root, path = _operation_state_path(settings)
    value = {
        "schema_version": 1,
        "settings": {
            "notifications": {"enabled": True, "channel": "os"},
            "initial_test": {"allow_model_test": False, "allow_notification_test": False},
        },
        "evidence": {},
    }
    try:
        safe_ensure_directory(root)
        raw = json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
        if len(raw) > _MAX_OPERATION_STATE_BYTES:
            return None, "OPERATION_STATE_INVALID"
        safe_atomic_write(root, path, raw, mode=0o600)
    except (OSError, TypeError, ValueError, SafeFilesystemError):
        return None, "OPERATION_STATE_WRITE_FAILED"
    return value, None


def invalidate_operation_evidence(evidence: dict[str, Any], current_binding: dict[str, Any]) -> dict[str, Any]:
    """Invalidate only receipts whose recorded Host, engine, OS, or channel changed."""
    if not isinstance(evidence, Mapping) or not isinstance(current_binding, Mapping):
        return {}
    result = deepcopy(dict(evidence))
    current_hosts = current_binding.get("hosts")
    saved_hosts = result.get("hosts")
    if isinstance(saved_hosts, dict) and isinstance(current_hosts, Mapping):
        for host_id in tuple(saved_hosts):
            current = current_hosts.get(host_id)
            if not isinstance(current, Mapping):
                del saved_hosts[host_id]
                continue
            previous = saved_hosts[host_id]
            if not isinstance(previous, dict):
                del saved_hosts[host_id]
                continue
            invalidated: set[str] = set()
            if "binding_sha256" in current and previous.get("binding_sha256") != current.get("binding_sha256"):
                invalidated.update(("binding", "hook", "accumulation", "recall"))
            if "host_version" in current and previous.get("host_version") != current.get("host_version"):
                invalidated.update(("hook", "accumulation", "recall"))
            if "channel" in current and previous.get("channel") != current.get("channel"):
                invalidated.update(("hook", "accumulation", "recall"))
            if "engine_code_sha256" in current_binding and previous.get("engine_code_sha256") != current_binding.get("engine_code_sha256"):
                invalidated.update(("hook", "accumulation", "recall"))
            if "os_family" in current_binding and previous.get("os_family") != current_binding.get("os_family"):
                invalidated.update(("hook", "accumulation", "recall"))
            if "os_version" in current_binding and previous.get("os_version") != current_binding.get("os_version"):
                invalidated.update(("hook", "accumulation", "recall"))
            for field in invalidated:
                previous[field] = "UNVERIFIED"

    scheduler = result.get("scheduler")
    if isinstance(scheduler, dict):
        if "engine_code_sha256" in current_binding and scheduler.get("engine_code_sha256") != current_binding.get("engine_code_sha256"):
            scheduler["run"] = "UNVERIFIED"
        if "scheduler_binding_sha256" in current_binding and scheduler.get("binding_sha256") != current_binding.get("scheduler_binding_sha256"):
            scheduler["run"] = "UNVERIFIED"
        if "os_family" in current_binding and scheduler.get("os_family") != current_binding.get("os_family"):
            scheduler["run"] = "UNVERIFIED"
            scheduler["monitor"] = "UNVERIFIED"
        elif "os_version" in current_binding and scheduler.get("os_version") != current_binding.get("os_version"):
            scheduler["monitor"] = "UNVERIFIED"

    notification = result.get("notification")
    if isinstance(notification, dict):
        if "notification_channel" in current_binding and notification.get("channel") != current_binding.get("notification_channel"):
            notification["send"] = "UNVERIFIED"
            notification["display"] = "UNVERIFIED"
        if "os_family" in current_binding and notification.get("os_family") != current_binding.get("os_family"):
            notification["send"] = "UNVERIFIED"
            notification["display"] = "UNVERIFIED"
        if "os_version" in current_binding and notification.get("os_version") != current_binding.get("os_version"):
            notification["send"] = "UNVERIFIED"
            notification["display"] = "UNVERIFIED"
    return result
