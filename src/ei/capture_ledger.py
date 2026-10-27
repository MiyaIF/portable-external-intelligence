from __future__ import annotations

import json
import os
import secrets
import time
from dataclasses import replace
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Mapping

from .capture_contract import CloseoutProofRef, CaptureIdentity, CaptureReceipt, capture_key
from .journal import validate_schema
from .safe_fs import SafeFilesystemError, assert_safe_target, safe_atomic_write, safe_ensure_directory, safe_unlink


class CaptureLedgerError(RuntimeError):
    """Raised when a capture receipt cannot be safely read or updated."""


def _root(settings: Any) -> Path:
    runtime = safe_ensure_directory(Path(settings.paths.runtime_dir))
    assert_safe_target(runtime, runtime, allow_root=True, allow_missing=False, expected_type="dir")
    state = safe_ensure_directory(runtime / "state")
    assert_safe_target(runtime, state, allow_missing=False, expected_type="dir")
    root = safe_ensure_directory(state / "capture", mode=0o700)
    return assert_safe_target(runtime, root, allow_missing=False, expected_type="dir")


def _path(root: Path, capture_id: str) -> Path:
    if not isinstance(capture_id, str) or not capture_id.startswith("sha256:"):
        raise ValueError("CAPTURE_ID_INVALID")
    digest = capture_id.removeprefix("sha256:")
    if len(digest) != 64 or any(character not in "0123456789abcdef" for character in digest):
        raise ValueError("CAPTURE_ID_INVALID")
    return assert_safe_target(root, root / f"{digest}.json", allow_missing=True)


def _lock_path(root: Path) -> Path:
    return assert_safe_target(root, root / ".capture.lock", allow_missing=True)


def _wait_for_lock(started: float, delay: float, budget=None) -> None:
    if budget is not None:
        budget.check()
        delay = min(delay, budget.remaining_ms() / 1000)
    if time.monotonic() - started >= 5:
        raise CaptureLedgerError("CAPTURE_LOCK_TIMEOUT")
    time.sleep(delay)


def _acquire(root: Path, *, budget=None) -> int:
    if budget is not None:
        budget.check()
    lock = _lock_path(root)
    started = time.monotonic()
    while True:
        if budget is not None:
            budget.check()
        try:
            return os.open(str(lock), os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        except PermissionError as exc:
            raise CaptureLedgerError("CAPTURE_LOCK_PERMISSION_DENIED") from exc
        except FileExistsError:
            try:
                if time.time() - lock.stat().st_mtime > 120:
                    safe_unlink(root, lock, allow_missing=True)
                    _wait_for_lock(started, 0, budget)
                    continue
            except FileNotFoundError:
                _wait_for_lock(started, 0.001, budget)
                continue
            except PermissionError as exc:
                raise CaptureLedgerError("CAPTURE_LOCK_PERMISSION_DENIED") from exc
            except OSError:
                _wait_for_lock(started, 0.01, budget)
                continue
            _wait_for_lock(started, 0.01, budget)


def _release(root: Path, descriptor: int) -> None:
    os.close(descriptor)
    safe_unlink(root, _lock_path(root), allow_missing=True)


def _serialize(receipt: CaptureReceipt) -> dict[str, Any]:
    value = {
        "capture_id": receipt.capture_id,
        "state": receipt.state,
        "candidate_ids": list(receipt.candidate_ids),
        "covered_target_ids": list(receipt.covered_target_ids),
        "reason_code": receipt.reason_code,
        "updated_at": receipt.updated_at.astimezone(timezone.utc).isoformat().replace("+00:00", "Z"),
        "candidate_hashes": [list(pair) for pair in receipt.candidate_hashes],
        "closeout_proofs": [
            {
                "record_id": proof.record_id,
                "target_set_hash": proof.target_set_hash,
                "content_hash": proof.content_hash,
                "binding_digest": proof.binding_digest,
                "result_digest": proof.result_digest,
            }
            for proof in receipt.closeout_proofs
        ],
    }
    validate_schema("capture-receipt", value)
    return value


def _deserialize(value: Mapping[str, Any]) -> CaptureReceipt:
    validate_schema("capture-receipt", value)
    timestamp = datetime.fromisoformat(str(value["updated_at"]).replace("Z", "+00:00"))
    return CaptureReceipt(
        capture_id=str(value["capture_id"]),
        state=str(value["state"]),  # type: ignore[arg-type]
        candidate_ids=tuple(str(item) for item in value["candidate_ids"]),
        covered_target_ids=tuple(str(item) for item in value["covered_target_ids"]),
        reason_code=str(value["reason_code"]),
        updated_at=timestamp,
        candidate_hashes=tuple((str(pair[0]), str(pair[1])) for pair in value.get("candidate_hashes", ())),
        closeout_proofs=tuple(CloseoutProofRef(**dict(proof)) for proof in value.get("closeout_proofs", ())),
    )


def _read_path(root: Path, path: Path, *, budget=None) -> CaptureReceipt:
    if budget is not None:
        budget.check()
    safe_path = assert_safe_target(root, path, allow_missing=False, expected_type="file")
    try:
        if budget is None:
            raw = safe_path.read_bytes()
        else:
            with safe_path.open("rb") as stream:
                raw = stream.read(2097153)
            if len(raw) > 2097152:
                raise CaptureLedgerError("CAPTURE_RECEIPT_TOO_LARGE")
            budget.check()
        value = json.loads(raw.decode("utf-8", errors="strict"))
        if not isinstance(value, Mapping):
            raise ValueError("CAPTURE_RECEIPT_NOT_OBJECT")
        receipt = _deserialize(value)
        if _path(root, receipt.capture_id) != safe_path:
            raise ValueError("CAPTURE_RECEIPT_PATH_MISMATCH")
        return receipt
    except TimeoutError:
        raise
    except (OSError, UnicodeError, json.JSONDecodeError, KeyError, TypeError, ValueError) as exc:
        raise CaptureLedgerError("CAPTURE_RECEIPT_CORRUPT") from exc


def _write_path(root: Path, path: Path, encoded: bytes, *, budget=None) -> None:
    for attempt in range(5):
        if budget is not None:
            budget.check()
        try:
            safe_atomic_write(root, path, encoded, mode=0o600)
            return
        except SafeFilesystemError as exc:
            if exc.code != "SAFE_REPLACE_FAILED" or attempt == 4:
                raise
            if budget is not None:
                budget.check()
            delay = 0.01 * (attempt + 1)
            time.sleep(min(delay, budget.remaining_ms() / 1000) if budget is not None else delay)


def merge_receipt(old: CaptureReceipt, new: CaptureReceipt) -> CaptureReceipt:
    if old.capture_id != new.capture_id:
        raise ValueError("CAPTURE_ID_CONFLICT")
    if old.state == "UNKNOWN":
        return old
    hashes = dict(old.candidate_hashes)
    for candidate_id, content_hash in new.candidate_hashes:
        previous = hashes.get(candidate_id)
        if previous is not None and previous != content_hash:
            raise ValueError("CAPTURE_CONTENT_CONFLICT")
        hashes[candidate_id] = content_hash
    candidates = tuple(sorted(set(old.candidate_ids) | set(new.candidate_ids)))
    covered = tuple(sorted(set(old.covered_target_ids) | set(new.covered_target_ids)))
    candidate_hashes = tuple(sorted(hashes.items()))
    proofs = {proof.record_id: proof for proof in old.closeout_proofs}
    for proof in new.closeout_proofs:
        previous = proofs.get(proof.record_id)
        if previous is not None and previous != proof:
            raise ValueError("CAPTURE_CLOSEOUT_PROOF_CONFLICT")
        proofs[proof.record_id] = proof
    closeout_proofs = tuple(proofs[key] for key in sorted(proofs))
    if old.reason_code == "PENDING_EXPIRED" or new.reason_code == "PENDING_EXPIRED":
        return replace(
            old,
            state="UNAVAILABLE",
            reason_code="PENDING_EXPIRED",
            candidate_ids=candidates,
            covered_target_ids=covered,
            updated_at=max(old.updated_at, new.updated_at),
            candidate_hashes=candidate_hashes,
            closeout_proofs=tuple(old.closeout_proofs),
        )
    state = "SECURED" if candidates else old.state if new.state == "WAITING" else new.state
    return replace(
        new,
        state=state,
        candidate_ids=candidates,
        covered_target_ids=covered,
        updated_at=max(old.updated_at, new.updated_at),
        candidate_hashes=candidate_hashes,
        closeout_proofs=closeout_proofs,
    )


def record_receipt(settings: Any, receipt: CaptureReceipt, *, budget=None) -> CaptureReceipt:
    if budget is not None:
        budget.check()
    _serialize(receipt)
    root = _root(settings)
    descriptor = _acquire(root, budget=budget)
    try:
        return _record_receipt_locked(root, receipt, budget=budget)
    finally:
        _release(root, descriptor)


def _record_receipt_locked(root: Path, receipt: CaptureReceipt, *, budget=None) -> CaptureReceipt:
    """Caller must own root's capture lock; never reacquires it."""
    if budget is not None:
        budget.check()
    _serialize(receipt)
    path = _path(root, receipt.capture_id)
    merged = merge_receipt(_read_path(root, path, budget=budget), receipt) if path.exists() else receipt
    encoded = (json.dumps(_serialize(merged), ensure_ascii=False, sort_keys=True, indent=2) + "\n").encode("utf-8")
    if budget is not None:
        budget.check()
    _write_path(root, path, encoded, budget=budget)
    return merged


def register_target(settings: Any, identity: CaptureIdentity | None, *, now: datetime, budget=None) -> CaptureReceipt:
    capture_id = capture_key(identity) if identity is not None else None
    if capture_id is None:
        receipt = CaptureReceipt(
            capture_id="sha256:" + secrets.token_hex(32),
            state="UNKNOWN",
            candidate_ids=(),
            covered_target_ids=(),
            reason_code="LEGACY_EVIDENCE_UNKNOWN",
            updated_at=now,
        )
    else:
        receipt = CaptureReceipt(
            capture_id=capture_id,
            state="WAITING",
            candidate_ids=(),
            covered_target_ids=(capture_id,),
            reason_code="CAPTURE_WAITING",
            updated_at=now,
        )
    return record_receipt(settings, receipt, budget=budget)


def read_receipt(settings: Any, capture_id: str, *, budget=None) -> CaptureReceipt | None:
    if budget is not None:
        budget.check()
    root = _root(settings)
    path = _path(root, capture_id)
    if not path.exists():
        return None
    return _read_path(root, path, budget=budget)


def list_receipts(settings: Any) -> tuple[CaptureReceipt, ...]:
    root = _root(settings)
    receipts: list[CaptureReceipt] = []
    for path in sorted(root.glob("*.json")):
        safe_path = assert_safe_target(root, path, allow_missing=False, expected_type="file")
        receipts.append(_read_path(root, safe_path))
    return tuple(receipts)


__all__ = [
    "CaptureLedgerError",
    "list_receipts",
    "merge_receipt",
    "read_receipt",
    "record_receipt",
    "register_target",
]
