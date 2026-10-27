from __future__ import annotations

import math
import re
import sys
import time
from dataclasses import dataclass
from datetime import datetime
from typing import Any


@dataclass(frozen=True)
class NotificationMessage:
    title: str
    body: str

    def __post_init__(self):
        for value in (self.title, self.body):
            if not isinstance(value, str) or not value or len(value) > 2048 or "\x00" in value:
                raise ValueError("NOTIFICATION_MESSAGE_INVALID")


@dataclass(frozen=True)
class DeliveryResult:
    """SENT means OS acceptance, never verified screen display."""

    status: str
    reason_code: str
    delivery_id: str | None = None

    def __post_init__(self):
        if self.status not in {"SENT", "UNAVAILABLE", "DENIED", "FAILED"}:
            raise ValueError("NOTIFICATION_STATUS_INVALID")
        if self.reason_code not in {
            "OS_ACCEPTED", "OS_UNAVAILABLE", "OS_DENIED", "OS_FAILED",
            "OS_TIMEOUT", "OS_RESPONSE_INVALID", "CLI_UNVERIFIED", "BUDGET_EXHAUSTED",
        }:
            raise ValueError("NOTIFICATION_REASON_INVALID")
        if self.delivery_id is not None and (
            not isinstance(self.delivery_id, str)
            or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.:@-]{0,199}", self.delivery_id)
        ):
            raise ValueError("NOTIFICATION_DELIVERY_ID_INVALID")


def render_notification(reason_code: str, pending_count: int | None, *, recovered: bool = False,
                        pending_count_status: str = "COMPLETE") -> NotificationMessage:
    from ..operation_health import STORAGE_CODES, validate_pending_count
    validate_pending_count(pending_count, pending_count_status)
    actions = {
        "AUTH_FAILED": "設定した整理AIに再ログインしてください。",
        "ACCUMULATION_STALLED": "整理処理が停止しています。利用枠と接続を確認してください。",
        "PENDING_LOSS_RISK": "未整理候補の保持期限または容量に近づいています。",
        "SOURCE_UNAVAILABLE": "取得元を利用できず、未取得の内容は保持できていません。",
        "SCHEDULER_STOPPED": "定期処理の停止を検出しました。OSの設定を確認してください。",
        "CLOSEOUT_ASSOCIATION_PENDING": "適用後の関連付けが未完了です。次回の状態確認を待っています。",
        "CLOSEOUT_METADATA_UNKNOWN": "関連付けの状態を確認できません。状態の確認が必要です。",
        "CLOSEOUT_RECOVERY_LOSS": "期限切れの処理を安全に引き継げませんでした。状態確認が必要です。",
    }
    if reason_code in ("CAPACITY_RISK", "EXPIRY_RISK"):
        reason_code = "PENDING_LOSS_RISK"
    action = "整理処理の復旧を確認しました。" if recovered else actions.get(reason_code, "自動蓄積で確認が必要な問題が発生しました。")
    if reason_code in STORAGE_CODES and not recovered and reason_code not in {
        "CLOSEOUT_ASSOCIATION_PENDING", "CLOSEOUT_METADATA_UNKNOWN",
    }:
        action = "保存領域を確認できず、新しい候補の受付を保留しています。保存先を確認してください。"
    count = ("未整理候補の件数は未確認です。" if pending_count_status == "UNKNOWN" else
             f"確認できた範囲の未整理候補: {pending_count}件（総数不明）。" if pending_count_status == "PARTIAL" else
             f"保持済み未整理候補: {pending_count}件。")
    return NotificationMessage("External Intelligence", f"{action} {count}")


def bounded_timeout(timeout_seconds: float) -> float:
    if isinstance(timeout_seconds, bool) or not isinstance(timeout_seconds, (float, int)) or not math.isfinite(timeout_seconds) or timeout_seconds <= 0:
        raise ValueError("NOTIFICATION_TIMEOUT_INVALID")
    return min(float(timeout_seconds), 2.0)


def send_native_notification(message: NotificationMessage, *, timeout_seconds: float = 2.0) -> DeliveryResult:
    timeout = bounded_timeout(timeout_seconds)
    if sys.platform == "win32":
        from .windows import send_notification
    elif sys.platform == "darwin":
        from .macos import send_notification
    elif sys.platform.startswith("linux"):
        from .linux import send_notification
    else:
        return DeliveryResult("UNAVAILABLE", "OS_UNAVAILABLE")
    return send_notification(message, timeout_seconds=timeout)


def deliver_incident(settings: Any, identifier: str, *, now: datetime, timeout_seconds: float = 2.0) -> DeliveryResult | None:
    """Claim/send one due OS notice with a best-effort caller time budget.

    None means no due claim. UNKNOWN survives interruption or failed settlement
    and permits retry after one hour. OS APIs lack crash-safe idempotency;
    exactly-once display is not promised.
    """
    from ..incidents import abort_notification, claim_notification, settle_notification

    deadline = time.monotonic() + bounded_timeout(timeout_seconds)
    lease = claim_notification(settings, identifier, channel="os", session_hash=None, now=now,
                               lock_timeout_seconds=max(0.0, min(0.05, deadline - time.monotonic())))
    if lease is None:
        return None
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        # This branch has positively not invoked an OS adapter. Preserve the
        # previous failure throttle but leave a never-attempted intent due.
        abort_notification(settings, lease, lock_timeout_seconds=0.0)
        return DeliveryResult("FAILED", "BUDGET_EXHAUSTED")
    message = render_notification(lease.reason_code, lease.pending_count, recovered=lease.recovered,
                                  pending_count_status=lease.pending_count_status)
    try:
        result = send_native_notification(message, timeout_seconds=remaining)
        if not isinstance(result, DeliveryResult):
            result = DeliveryResult("FAILED", "OS_RESPONSE_INVALID")
    except Exception:
        result = DeliveryResult("FAILED", "OS_FAILED")
    remaining = deadline - time.monotonic()
    if remaining > 0:
        settle_notification(settings, lease, result, now=now, lock_timeout_seconds=min(0.05, remaining))
    return result
