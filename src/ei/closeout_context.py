"""Trusted Host context binding for bounded, multi-turn closeout."""

from __future__ import annotations

import json
import re
import copy
from dataclasses import asdict, dataclass, field, replace
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Mapping

from .capture_contract import CaptureIdentity, CaptureReceipt, capture_key
from .capture_ledger import (
    CaptureLedgerError,
    _acquire,
    _release,
    _root as _capture_root,
    read_receipt,
)
from .config import HostSpec
from .hooks.base import NormalizedHookEvent
from .hooks import registry
from .ids import fingerprint
from .journal import validate_schema
from .operation_runtime import OperationBudget, capture_namespace
from .safe_fs import SafeFilesystemError, assert_safe_target, safe_atomic_write, safe_ensure_directory


_HASH_RE = re.compile(r"sha256:[0-9a-f]{64}")
_HOST_ID_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:@-]{0,159}")
_BINDING_MAX_BYTES = 16 * 1024
_MAX_TARGETS = 64
_MAX_CLOSEOUT_PROOFS = 8


@dataclass(frozen=True)
class CloseoutScope:
    cwd_hash: str
    domain_hash: str

    @property
    def fingerprint(self) -> str:
        return fingerprint(
            {
                "domain": "ei-closeout-work-scope-v1",
                "cwd_hash": self.cwd_hash,
                "domain_hash": self.domain_hash,
            }
        )


@dataclass(frozen=True)
class CloseoutContext:
    identity: CaptureIdentity
    target_ids: tuple[str, ...]
    scope: CloseoutScope


@dataclass(frozen=True)
class ContextValidation:
    context: CloseoutContext | None
    target_binding_digest: str | None
    reason_code: str
    _adapter_control: Mapping[str, Any] | None = field(default=None, init=False, repr=False, compare=False)

    @property
    def valid(self) -> bool:
        return (
            self.context is not None
            and self.target_binding_digest is not None
            and self.reason_code == "OK"
        )


class CloseoutContextError(RuntimeError):
    """A fixed-code closeout storage failure; never includes a path or payload."""

    def __init__(self, reason_code: str):
        self.reason_code = reason_code
        super().__init__(reason_code)


def _is_hash(value: Any) -> bool:
    return isinstance(value, str) and _HASH_RE.fullmatch(value) is not None


def _identity_is_valid(identity: Any, *, closeout_record: bool) -> bool:
    if not isinstance(identity, CaptureIdentity):
        return False
    if not isinstance(identity.host_id, str) or _HOST_ID_RE.fullmatch(identity.host_id) is None:
        return False
    if not _is_hash(identity.instance_hash) or not _is_hash(identity.store_id):
        return False
    if not _is_hash(identity.session_hash) or not _is_hash(identity.record_hash):
        return False
    if closeout_record:
        return identity.turn_hash is None
    return _is_hash(identity.turn_hash)


def _scope_is_valid(scope: Any) -> bool:
    return isinstance(scope, CloseoutScope) and _is_hash(scope.cwd_hash) and _is_hash(scope.domain_hash)


def _identity_value(identity: CaptureIdentity) -> dict[str, Any]:
    return asdict(identity)


def _spec_for(settings: Any, host_id: str) -> HostSpec | None:
    hosts = getattr(settings, "hosts", None)
    spec = hosts.get(host_id) if isinstance(hosts, Mapping) else None
    if isinstance(spec, HostSpec) and spec.host_id == host_id:
        return spec
    return None


def _adapter_for(settings: Any, host_id: str):
    try:
        adapter = registry.get_adapter(host_id, settings)
    except (TypeError, ValueError):
        return None
    if getattr(adapter, "host_id", None) != host_id:
        return None
    if getattr(adapter, "supports_closeout_context", False) is not True:
        return None
    return adapter


def _capture_identity_for_event(settings: Any, event: NormalizedHookEvent, budget: OperationBudget) -> bool:
    identity = event.capture_identity
    if not _identity_is_valid(identity, closeout_record=False) or identity.host_id != event.host_id:
        return False
    if identity.session_hash != event.session_id_hash or identity.turn_hash != event.turn_id_hash:
        return False
    namespace = capture_namespace(settings, event.host_id, budget=budget)
    return namespace is not None and (identity.instance_hash, identity.store_id) == namespace


def _binding_root(capture_root: Path, *, create: bool) -> Path | None:
    target = capture_root / "target-bindings"
    if create:
        root = safe_ensure_directory(target, mode=0o700)
        return assert_safe_target(capture_root, root, allow_missing=False, expected_type="dir")
    safe = assert_safe_target(capture_root, target, allow_missing=True)
    if not safe.exists():
        return None
    return assert_safe_target(capture_root, safe, allow_missing=False, expected_type="dir")


def _binding_path(capture_root: Path, capture_id: str, *, create_root: bool) -> Path | None:
    if not _is_hash(capture_id):
        raise ValueError("CLOSEOUT_CONTEXT_INVALID")
    root = _binding_root(capture_root, create=create_root)
    if root is None:
        return None
    path = root / f"{capture_id.removeprefix('sha256:')}.json"
    return assert_safe_target(root, path, allow_missing=True)


def _read_binding(capture_root: Path, capture_id: str, *, budget: OperationBudget) -> dict[str, Any] | None:
    budget.check()
    path = _binding_path(capture_root, capture_id, create_root=False)
    if path is None or (not path.exists() and not path.is_symlink()):
        return None
    try:
        safe_path = assert_safe_target(path.parent, path, allow_missing=False, expected_type="file")
        with safe_path.open("rb") as stream:
            raw = stream.read(_BINDING_MAX_BYTES + 1)
        budget.check()
        if len(raw) > _BINDING_MAX_BYTES:
            raise ValueError("CLOSEOUT_TARGET_CONFLICT")
        value = json.loads(raw.decode("utf-8", errors="strict"))
        if not isinstance(value, Mapping):
            raise ValueError("CLOSEOUT_TARGET_CONFLICT")
        validate_schema("closeout-target-binding", value)
        return dict(value)
    except TimeoutError:
        raise
    except Exception as exc:
        raise CloseoutContextError("CLOSEOUT_TARGET_CONFLICT") from exc


def _write_binding_closeout_proof(
    settings: Any,
    capture_id: str,
    proof: Mapping[str, str],
    *,
    now: datetime,
    budget: OperationBudget,
) -> Mapping[str, Any]:
    """Merge one compact association reference while the capture lock is held."""
    root = _capture_root(settings)
    binding = _read_binding(root, capture_id, budget=budget)
    if binding is None:
        raise CloseoutContextError("CLOSEOUT_TARGET_UNKNOWN")
    proof_value = {
        "record_id": proof.get("record_id"),
        "target_set_hash": proof.get("target_set_hash"),
        "content_hash": proof.get("content_hash"),
        "binding_digest": proof.get("binding_digest"),
        "result_digest": proof.get("result_digest"),
    }
    records = list(binding.get("closeout_proofs", ()))
    matches = [item for item in records if item.get("record_id") == proof_value["record_id"]]
    if matches:
        if matches[0] != proof_value:
            raise CloseoutContextError("CLOSEOUT_PROOF_CONFLICT")
        return binding
    if len(records) >= _MAX_CLOSEOUT_PROOFS:
        raise CloseoutContextError("CLOSEOUT_PROOF_CAPACITY")
    records.append(proof_value)
    records.sort(key=lambda item: str(item.get("record_id", "")))
    updated = dict(binding)
    updated["closeout_proofs"] = records
    if not isinstance(now, datetime) or now.tzinfo is None:
        raise CloseoutContextError("CLOSEOUT_CONTEXT_INVALID")
    updated["updated_at"] = now.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")
    validate_schema("closeout-target-binding", updated)
    encoded = (json.dumps(updated, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")
    if len(encoded) > _BINDING_MAX_BYTES:
        raise CloseoutContextError("CLOSEOUT_PROOF_CAPACITY")
    path = _binding_path(root, capture_id, create_root=False)
    if path is None:
        raise CloseoutContextError("CLOSEOUT_TARGET_UNKNOWN")
    budget.check()
    safe_atomic_write(path.parent, path, encoded, mode=0o600)
    persisted = _read_binding(root, capture_id, budget=budget)
    if persisted is None or persisted.get("closeout_proofs") != records:
        raise CloseoutContextError("CLOSEOUT_TARGET_CONFLICT")
    return persisted


def _binding_semantics(value: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "capture_id": value["capture_id"],
        "identity": dict(value["identity"]),
        "scope_hash": value["scope_hash"],
    }


def _issue_validation(
    context: CloseoutContext,
    binding_digest: str,
    control: Mapping[str, Any],
) -> ContextValidation:
    validation = ContextValidation(context, binding_digest, "OK")
    try:
        copied = copy.deepcopy(dict(control))
    except Exception:
        copied = None
    object.__setattr__(validation, "_adapter_control", copied)
    return validation


def _revalidate_context_under_lock(
    settings: Any,
    validation: ContextValidation,
    *,
    budget: OperationBudget,
) -> str | None:
    """Recheck adapter-produced context and current bindings while locked."""
    budget.check()
    if not isinstance(validation, ContextValidation) or not validation.valid:
        return "CLOSEOUT_CONTEXT_UNVERIFIED"
    context = validation.context
    if context is None or not isinstance(validation._adapter_control, Mapping):
        return "CLOSEOUT_CONTEXT_UNVERIFIED"
    reason = _validate_context_shape(context)
    if reason is not None:
        return reason
    adapter = _adapter_for(settings, context.identity.host_id)
    spec = _spec_for(settings, context.identity.host_id)
    if adapter is None or spec is None or not callable(getattr(adapter, "closeout_context", None)):
        return "CLOSEOUT_CONTEXT_UNVERIFIED"
    try:
        current_context = adapter.closeout_context(validation._adapter_control, spec)
    except TimeoutError:
        raise
    except Exception:
        return "CLOSEOUT_CONTEXT_UNVERIFIED"
    if _validate_context_shape(current_context) is not None:
        return "CLOSEOUT_CONTEXT_UNVERIFIED"
    if current_context.target_ids != tuple(sorted(current_context.target_ids)):
        current_context = replace(current_context, target_ids=tuple(sorted(current_context.target_ids)))
    if current_context != context:
        return "CLOSEOUT_CONTEXT_UNVERIFIED"
    namespace = capture_namespace(settings, context.identity.host_id, budget=budget)
    if namespace is None or (context.identity.instance_hash, context.identity.store_id) != namespace:
        return "CLOSEOUT_NAMESPACE_MISMATCH"
    root = _capture_root(settings)
    bindings: list[Mapping[str, Any]] = []
    try:
        for target_id in context.target_ids:
            budget.check()
            binding = _read_binding(root, target_id, budget=budget)
            if binding is None:
                return "CLOSEOUT_TARGET_UNKNOWN"
            target_identity = _validate_binding_identity(binding, target_id)
            if (
                target_identity.host_id != context.identity.host_id
                or target_identity.instance_hash != context.identity.instance_hash
                or target_identity.store_id != context.identity.store_id
            ):
                return "CLOSEOUT_NAMESPACE_MISMATCH"
            if target_identity.session_hash != context.identity.session_hash or binding["scope_hash"] != context.scope.fingerprint:
                return "CLOSEOUT_SCOPE_MISMATCH"
            receipt = read_receipt(settings, target_id, budget=budget)
            if not _receipt_is_usable(receipt, target_id):
                return "CLOSEOUT_TARGET_UNKNOWN"
            bindings.append(binding)
        digest = _semantic_binding_digest(bindings)
        if digest != validation.target_binding_digest:
            return "CLOSEOUT_TARGET_CONFLICT"
        return None
    except TimeoutError:
        raise
    except CloseoutContextError as exc:
        return exc.reason_code
    except (OSError, RuntimeError, TypeError, ValueError, SafeFilesystemError, CaptureLedgerError):
        return "CLOSEOUT_TARGET_CONFLICT"


def _revalidate_persisted_context_under_lock(
    settings: Any,
    context: CloseoutContext,
    expected_binding_digest: str,
    *,
    budget: OperationBudget,
) -> str | None:
    """Validate a context reconstructed only from a stored association record."""
    budget.check()
    reason = _validate_context_shape(context)
    if reason is not None:
        return reason
    adapter = _adapter_for(settings, context.identity.host_id)
    spec = _spec_for(settings, context.identity.host_id)
    if adapter is None or spec is None or not callable(getattr(adapter, "closeout_context", None)):
        return "CLOSEOUT_CONTEXT_UNVERIFIED"
    namespace = capture_namespace(settings, context.identity.host_id, budget=budget)
    if namespace is None or (context.identity.instance_hash, context.identity.store_id) != namespace:
        return "CLOSEOUT_NAMESPACE_MISMATCH"
    root = _capture_root(settings)
    bindings: list[Mapping[str, Any]] = []
    try:
        for target_id in context.target_ids:
            budget.check()
            binding = _read_binding(root, target_id, budget=budget)
            if binding is None:
                return "CLOSEOUT_TARGET_UNKNOWN"
            target_identity = _validate_binding_identity(binding, target_id)
            if (
                target_identity.host_id != context.identity.host_id
                or target_identity.instance_hash != context.identity.instance_hash
                or target_identity.store_id != context.identity.store_id
            ):
                return "CLOSEOUT_NAMESPACE_MISMATCH"
            if target_identity.session_hash != context.identity.session_hash or binding["scope_hash"] != context.scope.fingerprint:
                return "CLOSEOUT_SCOPE_MISMATCH"
            receipt = read_receipt(settings, target_id, budget=budget)
            if not _receipt_is_usable(receipt, target_id):
                return "CLOSEOUT_TARGET_UNKNOWN"
            bindings.append(binding)
        if _semantic_binding_digest(bindings) != expected_binding_digest:
            return "CLOSEOUT_TARGET_CONFLICT"
        return None
    except TimeoutError:
        raise
    except CloseoutContextError as exc:
        return exc.reason_code
    except (OSError, RuntimeError, TypeError, ValueError, SafeFilesystemError, CaptureLedgerError):
        return "CLOSEOUT_TARGET_CONFLICT"


def _binding_document(capture_id: str, identity: CaptureIdentity, scope: CloseoutScope, now: datetime) -> dict[str, Any]:
    if not isinstance(now, datetime) or now.tzinfo is None or now.utcoffset() != timezone.utc.utcoffset(now):
        raise ValueError("CLOSEOUT_CONTEXT_INVALID")
    value = {
        "schema_version": 1,
        "capture_id": capture_id,
        "identity": _identity_value(identity),
        "scope_hash": scope.fingerprint,
        "updated_at": now.astimezone(timezone.utc).isoformat().replace("+00:00", "Z"),
        "closeout_proofs": [],
    }
    validate_schema("closeout-target-binding", value)
    encoded = (json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")
    if len(encoded) > _BINDING_MAX_BYTES:
        raise ValueError("CLOSEOUT_TARGET_CONFLICT")
    return value


def _receipt_is_usable(receipt: CaptureReceipt | None, capture_id: str) -> bool:
    if receipt is None or receipt.capture_id != capture_id:
        return False
    if receipt.state in {"UNKNOWN", "UNAVAILABLE"} or receipt.reason_code == "PENDING_EXPIRED":
        return False
    return receipt.state in {"WAITING", "SECURED", "EVALUATED_NONE"} and capture_id in receipt.covered_target_ids


def register_adapter_target(
    settings: Any,
    event: NormalizedHookEvent,
    *,
    now: datetime,
    budget: OperationBudget,
) -> bool:
    """Persist a target binding only when its registered adapter proves the scope."""
    budget.check()
    if not isinstance(event, NormalizedHookEvent) or event.normalized_event_name != "turn.stop":
        return False
    adapter = _adapter_for(settings, event.host_id)
    spec = _spec_for(settings, event.host_id)
    if adapter is None or spec is None or not callable(getattr(adapter, "capture_work_scope", None)):
        return False
    identity = event.capture_identity
    capture_id = None
    try:
        if _identity_is_valid(identity, closeout_record=False) and identity.host_id == event.host_id:
            capture_id = capture_key(identity)
    except (TypeError, ValueError):
        return False
    if capture_id is None or not _is_hash(event.cwd_hash) or not _is_hash(event.work_domain_hash):
        return False
    if not _capture_identity_for_event(settings, event, budget):
        return False
    try:
        scope = adapter.capture_work_scope(event, spec)
    except TimeoutError:
        raise
    except Exception:
        return False
    if not _scope_is_valid(scope) or scope.cwd_hash != event.cwd_hash or scope.domain_hash != event.work_domain_hash:
        return False

    try:
        root = _capture_root(settings)
        descriptor = _acquire(root, budget=budget)
        try:
            budget.check()
            receipt = read_receipt(settings, capture_id, budget=budget)
            if not _receipt_is_usable(receipt, capture_id):
                return False
            proposed = _binding_document(capture_id, identity, scope, now)
            existing = _read_binding(root, capture_id, budget=budget)
            if existing is not None:
                if _binding_semantics(existing) != _binding_semantics(proposed):
                    raise CloseoutContextError("CLOSEOUT_TARGET_CONFLICT")
                return True
            path = _binding_path(root, capture_id, create_root=True)
            assert path is not None
            encoded = (json.dumps(proposed, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")
            budget.check()
            safe_atomic_write(path.parent, path, encoded, mode=0o600)
            persisted = _read_binding(root, capture_id, budget=budget)
            if persisted is None or _binding_semantics(persisted) != _binding_semantics(proposed):
                raise CloseoutContextError("CLOSEOUT_TARGET_CONFLICT")
            return True
        finally:
            _release(root, descriptor)
    except TimeoutError:
        raise
    except CloseoutContextError:
        raise
    except (OSError, RuntimeError, TypeError, ValueError, SafeFilesystemError, CaptureLedgerError) as exc:
        raise CloseoutContextError("CLOSEOUT_TARGET_CONFLICT") from exc


def _invalid(reason: str) -> ContextValidation:
    return ContextValidation(None, None, reason)


def _validate_context_shape(context: Any) -> str | None:
    if not isinstance(context, CloseoutContext):
        return "CLOSEOUT_CONTEXT_INVALID"
    if not _identity_is_valid(context.identity, closeout_record=True) or not _scope_is_valid(context.scope):
        return "CLOSEOUT_CONTEXT_INVALID"
    if not isinstance(context.target_ids, tuple) or not 1 <= len(context.target_ids) <= _MAX_TARGETS:
        return "CLOSEOUT_CONTEXT_INVALID"
    if any(not _is_hash(target_id) for target_id in context.target_ids):
        return "CLOSEOUT_CONTEXT_INVALID"
    if len(set(context.target_ids)) != len(context.target_ids):
        return "CLOSEOUT_CONTEXT_INVALID"
    return None


def _validate_binding_identity(value: Mapping[str, Any], target_id: str) -> CaptureIdentity:
    identity_value = value["identity"]
    if not isinstance(identity_value, Mapping):
        raise CloseoutContextError("CLOSEOUT_TARGET_CONFLICT")
    try:
        identity = CaptureIdentity(**dict(identity_value))
    except (TypeError, ValueError) as exc:
        raise CloseoutContextError("CLOSEOUT_TARGET_CONFLICT") from exc
    if not _identity_is_valid(identity, closeout_record=False) or capture_key(identity) != target_id:
        raise CloseoutContextError("CLOSEOUT_TARGET_CONFLICT")
    if value.get("capture_id") != target_id:
        raise CloseoutContextError("CLOSEOUT_TARGET_CONFLICT")
    return identity


def _semantic_binding_digest(bindings: list[Mapping[str, Any]]) -> str:
    semantic = sorted((_binding_semantics(item) for item in bindings), key=lambda item: item["capture_id"])
    return fingerprint(semantic)


def validate_adapter_context(
    settings: Any,
    host_id: str,
    control: Mapping[str, Any],
    *,
    budget: OperationBudget,
) -> ContextValidation:
    """Validate only the context returned by the registered Host adapter."""
    budget.check()
    if not isinstance(control, Mapping):
        return _invalid("CLOSEOUT_CONTEXT_INVALID")
    adapter = _adapter_for(settings, host_id)
    spec = _spec_for(settings, host_id)
    if adapter is None or spec is None or not callable(getattr(adapter, "closeout_context", None)):
        return _invalid("CLOSEOUT_CONTEXT_UNVERIFIED")
    try:
        context = adapter.closeout_context(control, spec)
    except TimeoutError:
        raise
    except Exception:
        return _invalid("CLOSEOUT_CONTEXT_UNVERIFIED")
    if context is None:
        return _invalid("CLOSEOUT_CONTEXT_UNVERIFIED")
    reason = _validate_context_shape(context)
    if reason is not None:
        return _invalid(reason)
    if context.target_ids != tuple(sorted(context.target_ids)):
        context = replace(context, target_ids=tuple(sorted(context.target_ids)))
    if context.identity.host_id != host_id:
        return _invalid("CLOSEOUT_NAMESPACE_MISMATCH")
    namespace = capture_namespace(settings, host_id, budget=budget)
    if namespace is None or (context.identity.instance_hash, context.identity.store_id) != namespace:
        return _invalid("CLOSEOUT_NAMESPACE_MISMATCH")

    try:
        root = _capture_root(settings)
        descriptor = _acquire(root, budget=budget)
    except TimeoutError:
        raise
    except (OSError, RuntimeError, ValueError) as exc:
        raise CloseoutContextError("CLOSEOUT_TARGET_CONFLICT") from exc
    bindings: list[Mapping[str, Any]] = []
    try:
        for target_id in context.target_ids:
            budget.check()
            binding = _read_binding(root, target_id, budget=budget)
            if binding is None:
                return _invalid("CLOSEOUT_TARGET_UNKNOWN")
            target_identity = _validate_binding_identity(binding, target_id)
            if (
                target_identity.host_id != context.identity.host_id
                or target_identity.instance_hash != context.identity.instance_hash
                or target_identity.store_id != context.identity.store_id
            ):
                return _invalid("CLOSEOUT_NAMESPACE_MISMATCH")
            if target_identity.session_hash != context.identity.session_hash or binding["scope_hash"] != context.scope.fingerprint:
                return _invalid("CLOSEOUT_SCOPE_MISMATCH")
            receipt = read_receipt(settings, target_id, budget=budget)
            if receipt is None:
                return _invalid("CLOSEOUT_TARGET_UNKNOWN")
            if receipt.state in {"UNKNOWN", "UNAVAILABLE"} or receipt.reason_code == "PENDING_EXPIRED":
                return _invalid("CLOSEOUT_TARGET_UNKNOWN")
            if receipt.capture_id != target_id or target_id not in receipt.covered_target_ids:
                return _invalid("CLOSEOUT_TARGET_CONFLICT")
            bindings.append(binding)
        budget.check()
        return _issue_validation(context, _semantic_binding_digest(bindings), control)
    except TimeoutError:
        raise
    except CloseoutContextError as exc:
        return _invalid(exc.reason_code)
    except (OSError, RuntimeError, TypeError, ValueError, SafeFilesystemError, CaptureLedgerError):
        return _invalid("CLOSEOUT_TARGET_CONFLICT")
    finally:
        _release(root, descriptor)


__all__ = [
    "CloseoutContext",
    "CloseoutContextError",
    "CloseoutScope",
    "ContextValidation",
    "register_adapter_target",
    "validate_adapter_context",
]
