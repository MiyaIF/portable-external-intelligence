from __future__ import annotations

import subprocess
import sys
from pathlib import Path

from .base import DeliveryResult, NotificationMessage, bounded_timeout


_SCRIPT = 'on run argv\n display notification (item 2 of argv) with title (item 1 of argv)\nend run'


def send_notification(message: NotificationMessage, *, timeout_seconds: float = 2.0) -> DeliveryResult:
    timeout = bounded_timeout(timeout_seconds)
    executable = "/usr/bin/osascript"
    if sys.platform != "darwin" or not Path(executable).is_file():
        return DeliveryResult("UNAVAILABLE", "OS_UNAVAILABLE")
    try:
        result = subprocess.run([executable, "-e", _SCRIPT, "--", message.title, message.body], shell=False,
                                timeout=timeout, stdin=subprocess.DEVNULL, capture_output=True,
                                text=True, encoding="utf-8", errors="replace", check=False)
    except subprocess.TimeoutExpired:
        return DeliveryResult("FAILED", "OS_TIMEOUT")
    except FileNotFoundError:
        return DeliveryResult("UNAVAILABLE", "OS_UNAVAILABLE")
    except PermissionError:
        return DeliveryResult("DENIED", "OS_DENIED")
    except OSError:
        return DeliveryResult("FAILED", "OS_FAILED")
    if result.returncode == 0:
        return DeliveryResult("SENT", "OS_ACCEPTED")
    if "(-1743)" in result.stderr or "(-10004)" in result.stderr:
        return DeliveryResult("DENIED", "OS_DENIED")
    if "(-10810)" in result.stderr:
        return DeliveryResult("UNAVAILABLE", "OS_UNAVAILABLE")
    return DeliveryResult("FAILED", "OS_FAILED")
