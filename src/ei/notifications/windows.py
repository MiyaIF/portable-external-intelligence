from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

from .base import DeliveryResult, NotificationMessage, bounded_timeout


APP_USER_MODEL_ID = "MiyaIF.ExternalIntelligence"
SHORTCUT_NAME = "External Intelligence.lnk"
REGISTRATION_NAME = "notification-registration.json"


def send_notification(message: NotificationMessage, *, timeout_seconds: float = 2.0) -> DeliveryResult:
    timeout = bounded_timeout(timeout_seconds)
    system_root, roaming, local = (os.environ.get(key) for key in ("SystemRoot", "APPDATA", "LOCALAPPDATA"))
    if sys.platform != "win32" or not all((system_root, roaming, local)):
        return DeliveryResult("UNAVAILABLE", "OS_UNAVAILABLE")
    executable = Path(system_root) / "System32" / "WindowsPowerShell" / "v1.0" / "powershell.exe"
    script = Path(__file__).resolve().parents[3] / "scripts" / "notifications" / "windows-toast.ps1"
    shortcut = Path(roaming) / "Microsoft" / "Windows" / "Start Menu" / "Programs" / SHORTCUT_NAME
    registration = Path(local) / "MiyaIF" / "ExternalIntelligence" / REGISTRATION_NAME
    if not all(path.is_file() for path in (executable, script, shortcut, registration)):
        return DeliveryResult("UNAVAILABLE", "OS_UNAVAILABLE")
    try:
        result = subprocess.run([str(executable), "-NoLogo", "-NoProfile", "-NonInteractive",
                                 "-WindowStyle", "Hidden", "-File", str(script)],
                                input=json.dumps({"title": message.title, "body": message.body}, ensure_ascii=False),
                                shell=False, creationflags=0x08000000, timeout=timeout,
                                capture_output=True, text=True, encoding="utf-8", errors="replace", check=False)
    except subprocess.TimeoutExpired:
        return DeliveryResult("FAILED", "OS_TIMEOUT")
    except FileNotFoundError:
        return DeliveryResult("UNAVAILABLE", "OS_UNAVAILABLE")
    except PermissionError:
        return DeliveryResult("DENIED", "OS_DENIED")
    except OSError:
        return DeliveryResult("FAILED", "OS_FAILED")
    if result.returncode != 0:
        if "PSSecurityException" in result.stderr:
            return DeliveryResult("DENIED", "OS_DENIED")
        return DeliveryResult("FAILED", "OS_FAILED")
    status = result.stdout.strip()
    if status in {"SENT", "UNAVAILABLE", "DENIED", "FAILED"}:
        reason = {"SENT": "OS_ACCEPTED", "UNAVAILABLE": "OS_UNAVAILABLE", "DENIED": "OS_DENIED", "FAILED": "OS_FAILED"}[status]
        return DeliveryResult(status, reason)
    return DeliveryResult("FAILED", "OS_RESPONSE_INVALID")
