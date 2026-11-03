from __future__ import annotations

import html
import json
import os
import re
import subprocess
import sys
from pathlib import Path

from .base import DeliveryResult, NotificationMessage, bounded_timeout


def send_notification(message: NotificationMessage, *, timeout_seconds: float = 2.0) -> DeliveryResult:
    timeout = bounded_timeout(timeout_seconds)
    executable = "/usr/bin/gdbus"
    if not sys.platform.startswith("linux") or not os.environ.get("DBUS_SESSION_BUS_ADDRESS") or not Path(executable).is_file():
        return DeliveryResult("UNAVAILABLE", "OS_UNAVAILABLE")
    # gdbus parses GVariant arguments even with shell=False; quote text and
    # escape body markup so neither parser interprets it as instructions.
    quote = lambda value: json.dumps(value, ensure_ascii=False)
    argv = [executable, "call", "--session", "--dest", "org.freedesktop.Notifications",
            "--object-path", "/org/freedesktop/Notifications", "--method",
            "org.freedesktop.Notifications.Notify", "--", quote("External Intelligence"),
            "0", quote(""), quote(message.title), quote(html.escape(message.body, quote=False)),
            "[]", "{}", "-1"]
    try:
        result = subprocess.run(argv, shell=False, timeout=timeout, stdin=subprocess.DEVNULL,
                                capture_output=True, text=True, encoding="utf-8", errors="replace", check=False)
    except subprocess.TimeoutExpired:
        return DeliveryResult("FAILED", "OS_TIMEOUT")
    except FileNotFoundError:
        return DeliveryResult("UNAVAILABLE", "OS_UNAVAILABLE")
    except PermissionError:
        return DeliveryResult("DENIED", "OS_DENIED")
    except OSError:
        return DeliveryResult("FAILED", "OS_FAILED")
    if result.returncode == 0:
        match = re.fullmatch(r"\(uint32 ([0-9]{1,10}),\)\s*", result.stdout)
        if match and 0 < int(match[1]) <= 4294967295:
            return DeliveryResult("SENT", "OS_ACCEPTED", match[1])
        return DeliveryResult("FAILED", "OS_RESPONSE_INVALID")
    if "org.freedesktop.DBus.Error.AccessDenied" in result.stderr or "org.freedesktop.DBus.Error.AuthFailed" in result.stderr:
        return DeliveryResult("DENIED", "OS_DENIED")
    if any(code in result.stderr for code in ("org.freedesktop.DBus.Error.ServiceUnknown", "org.freedesktop.DBus.Error.NameHasNoOwner", "org.freedesktop.DBus.Error.NoServer", "org.freedesktop.DBus.Error.Disconnected", "org.freedesktop.DBus.Error.FileNotFound")):
        return DeliveryResult("UNAVAILABLE", "OS_UNAVAILABLE")
    return DeliveryResult("FAILED", "OS_FAILED")
