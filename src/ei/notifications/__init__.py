"""Native notification adapters; acceptance is not screen-display proof."""

from .base import DeliveryResult, NotificationMessage, deliver_incident, render_notification

__all__ = ["DeliveryResult", "NotificationMessage", "deliver_incident", "render_notification"]
