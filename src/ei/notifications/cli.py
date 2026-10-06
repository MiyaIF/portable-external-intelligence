from __future__ import annotations

from .base import NotificationMessage


def encode_user_notice(host_id: str, message: NotificationMessage, *, verified: bool) -> dict | None:
    """No host has both official field evidence AND observed CLI display yet.

    A caller boolean cannot qualify a host. Never use stderr, additionalContext
    or generated model speech as a user-notice fallback.
    """
    return None
