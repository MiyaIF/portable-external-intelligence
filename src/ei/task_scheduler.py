from __future__ import annotations

import argparse
import getpass
import hashlib
import json
import os
import platform
import shutil
import subprocess
import plistlib
import shlex
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .command_quote import quote_windows_argument, quote_windows_command
from .config import Settings, load_settings
from .safe_fs import absolute_path, SafeFilesystemError, assert_safe_target, safe_atomic_write, safe_ensure_directory, safe_unlink


TASK_NAME = "CodexExternalIntelligenceMaintenance-v1"
SCHEDULER_STATE_NAME = "scheduler-state.json"


@dataclass(frozen=True)
class MaintenanceAction:
    task_name: str
    executable: Path
    argv: tuple[str, ...]
    arguments: str
    working_directory: Path
    log_file: Path
    principal: str
    run_level: str
    execution_time_limit_seconds: int
    multiple_instance_policy: str
    start_when_available: bool
    wake_to_run: bool
    triggers: tuple[str, ...]
    executable_sha256: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "task_name": self.task_name,
            "executable": str(self.executable),
            "argv": list(self.argv),
            "arguments": self.arguments,
            "working_directory": str(self.working_directory),
            "log_file": str(self.log_file),
            "principal": self.principal,
            "run_level": self.run_level,
            "execution_time_limit_seconds": self.execution_time_limit_seconds,
            "multiple_instance_policy": self.multiple_instance_policy,
            "start_when_available": self.start_when_available,
            "wake_to_run": self.wake_to_run,
            "triggers": list(self.triggers),
            "executable_sha256": self.executable_sha256,
        }


def _windows_quote(value: str) -> str:
    return quote_windows_argument(value)


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def current_principal() -> str:
    username = os.environ.get("USERNAME") or getpass.getuser()
    domain = os.environ.get("USERDOMAIN")
    return f"{domain}\\{username}" if domain else username


def resolve_venv_python(settings: Settings, explicit: Path | None = None) -> Path:
    candidates: list[Path] = []
    if explicit is not None:
        candidates.append(Path(explicit))
    candidates.extend((settings.paths.engine_root / ".venv" / "Scripts" / "python.exe", settings.paths.engine_root / ".venv" / "bin" / "python"))
    for candidate in candidates:
        resolved = candidate.expanduser().resolve()
        if resolved.is_file():
            return resolved
    raise FileNotFoundError("SCHEDULER_PYTHON_NOT_FOUND")


def build_maintenance_action(settings: Settings, python_exe: Path | None = None) -> MaintenanceAction:
    if settings.scheduler_task_name != TASK_NAME:
        raise ValueError("SCHEDULER_TASK_NAME_INVALID")
    executable = resolve_venv_python(settings, python_exe)
    log_file = settings.paths.runtime_dir / "logs" / "maintenance.jsonl"
    argv: list[str] = [
        "-m",
        "ei.cli",
        "maintain",
        "--json",
        "--engine-root",
        str(settings.paths.engine_root),
        "--knowledge-root",
        str(settings.paths.knowledge_root),
        "--codex-home",
        str(settings.paths.codex_home),
        "--runtime-root",
        str(settings.paths.runtime_root),
        "--log-file",
        str(log_file),
        "--quiet",
    ]
    if settings.sync_enabled:
        argv.append("--sync")
    arguments = quote_windows_command(argv)
    return MaintenanceAction(
        task_name=TASK_NAME,
        executable=executable,
        argv=tuple(argv),
        arguments=arguments,
        working_directory=settings.paths.engine_root,
        log_file=log_file,
        principal=current_principal(),
        run_level="Limited",
        execution_time_limit_seconds=settings.scheduler_timeout_seconds,
        multiple_instance_policy="IgnoreNew",
        start_when_available=True,
        wake_to_run=False,
        triggers=(f"every_{settings.scheduler_interval_minutes}_minutes",),
        executable_sha256=_sha256_file(executable),
    )



def _interval_minutes(action: MaintenanceAction) -> int:
    for trigger in action.triggers:
        if trigger.startswith("every_") and trigger.endswith("_minutes"):
            try:
                return max(1, int(trigger[len("every_"):-len("_minutes")]))
            except ValueError:
                break
    return 30


def build_launchd_plist(action: MaintenanceAction) -> str:
    """Render a user launch agent with executable and arguments as separate argv values."""
    if not isinstance(action, MaintenanceAction):
        raise TypeError("MAINTENANCE_ACTION_REQUIRED")
    document = {
        "Label": action.task_name,
        "ProgramArguments": [str(action.executable), *action.argv],
        "WorkingDirectory": str(action.working_directory),
        "RunAtLoad": True,
        "StartInterval": _interval_minutes(action) * 60,
        "StandardOutPath": str(action.log_file),
        "StandardErrorPath": str(action.log_file.with_suffix(".err")),
        "ProcessType": "Background",
    }
    return plistlib.dumps(document, fmt=plistlib.FMT_XML, sort_keys=False).decode("utf-8")


def _systemd_exec(action: MaintenanceAction) -> str:
    return shlex.join((str(action.executable), *action.argv))


def build_systemd_user_unit(action: MaintenanceAction, *, timer: bool = False) -> str:
    """Render a systemd --user service or timer without a shell bridge."""
    if not isinstance(action, MaintenanceAction):
        raise TypeError("MAINTENANCE_ACTION_REQUIRED")
    if timer:
        return (
            "[Unit]\n"
            f"Description={action.task_name} timer\n\n"
            "[Timer]\n"
            "OnBootSec=2min\n"
            f"OnUnitActiveSec={_interval_minutes(action)}min\n"
            "Persistent=true\n"
            f"Unit={action.task_name}.service\n\n"
            "[Install]\n"
            "WantedBy=timers.target\n"
        )
    return (
        "[Unit]\n"
        f"Description={action.task_name}\n"
        "After=default.target\n\n"
        "[Service]\n"
        "Type=oneshot\n"
        f"WorkingDirectory={shlex.quote(str(action.working_directory))}\n"
        f"ExecStart={_systemd_exec(action)}\n"
        f"StandardOutput=append:{shlex.quote(str(action.log_file))}\n"
        f"StandardError=append:{shlex.quote(str(action.log_file.with_suffix('.err')))}\n"
    )


def build_systemd_user_timer(action: MaintenanceAction) -> str:
    return build_systemd_user_unit(action, timer=True)

def scheduler_state_path(settings: Settings) -> Path:
    return settings.paths.runtime_dir / SCHEDULER_STATE_NAME


def write_scheduler_state(settings: Settings, action: MaintenanceAction, registered: bool, last_result: int | None = None) -> Path:
    path = scheduler_state_path(settings)
    value = {"schema_version": 1, "registered": registered, "task_name": action.task_name, "registered_at": datetime.now(timezone.utc).isoformat(), "last_registration_result": last_result, "action": action.to_dict()}
    try:
        safe_ensure_directory(path.parent)
        safe_atomic_write(path.parent, path, (json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2) + "\n").encode("utf-8"))
    except SafeFilesystemError as exc:
        raise ValueError(exc.code) from exc
    return path


def remove_scheduler_state(settings: Settings) -> bool:
    """Remove only this engine's scheduler receipt after identity validation."""

    path = scheduler_state_path(settings)
    if not (path.exists() or path.is_symlink()):
        return False
    try:
        assert_safe_target(path.parent, path, allow_missing=False, expected_type="file")
        state = _read_state(settings)
        if state.get("task_name") != TASK_NAME:
            raise ValueError("SCHEDULER_STATE_TASK_MISMATCH")
        return safe_unlink(path.parent, path, allow_missing=True)
    except SafeFilesystemError as exc:
        raise ValueError(exc.code) from exc


def _read_state(settings: Settings) -> dict[str, Any]:
    path = scheduler_state_path(settings)
    if not (path.exists() or path.is_symlink()):
        return {}
    try:
        assert_safe_target(path.parent, path, allow_missing=False, expected_type="file")
        value = json.loads(path.read_text(encoding="utf-8"))
    except SafeFilesystemError as exc:
        raise ValueError(exc.code) from exc
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ValueError("SCHEDULER_STATE_INVALID") from exc
    if not isinstance(value, dict):
        raise ValueError("SCHEDULER_STATE_INVALID")
    return value


def _parse_time(value: object) -> datetime | None:
    text = str(value or "")
    if not text or text.startswith("0001-01-01"):
        return None
    try:
        return datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError:
        return None


def _normalise_platform(platform_name: str | None) -> str:
    return (platform_name or platform.system()).casefold()


def _launch_agents_dir() -> Path:
    configured = os.environ.get("EI_LAUNCH_AGENTS_DIR")
    return absolute_path(configured or (Path.home() / "Library" / "LaunchAgents"))


def _systemd_user_dir() -> Path:
    configured = os.environ.get("EI_SYSTEMD_USER_DIR")
    if configured:
        return absolute_path(configured)
    config_home = os.environ.get("XDG_CONFIG_HOME")
    base = Path(config_home) if config_home else Path.home() / ".config"
    return absolute_path(base / "systemd" / "user")


def _read_scheduler_artifact(root: Path, path: Path) -> tuple[bytes | None, str | None]:
    if not root.is_dir():
        return None, "SCHEDULER_ARTIFACT_DIRECTORY_MISSING"
    try:
        assert_safe_target(root, path, allow_missing=False, expected_type="file")
        return path.read_bytes(), None
    except (OSError, SafeFilesystemError) as exc:
        return None, getattr(exc, "code", type(exc).__name__)


def _sha256_digest(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _recorded_hash(value: object) -> str:
    text = str(value or "").casefold()
    return text[7:] if text.startswith("sha256:") else text


def _expected_action_argv(settings: Settings) -> tuple[str, ...]:
    argv = [
        "-m",
        "ei.cli",
        "maintain",
        "--json",
        "--engine-root",
        str(settings.paths.engine_root),
        "--knowledge-root",
        str(settings.paths.knowledge_root),
        "--codex-home",
        str(settings.paths.codex_home),
        "--runtime-root",
        str(settings.paths.runtime_root),
        "--log-file",
        str(settings.paths.runtime_dir / "logs" / "maintenance.jsonl"),
        "--quiet",
    ]
    if settings.sync_enabled:
        argv.append("--sync")
    return tuple(argv)


def _state_action_checks(settings: Settings, expected: dict[str, Any]) -> tuple[dict[str, bool], list[str] | None, Path | None]:
    raw_executable = expected.get("executable")
    raw_argv = expected.get("argv")
    try:
        expected_executable = absolute_path(raw_executable) if isinstance(raw_executable, str) and raw_executable else None
    except SafeFilesystemError:
        expected_executable = None
    argv = [item for item in raw_argv] if isinstance(raw_argv, list) and all(isinstance(item, str) for item in raw_argv) else None
    full_argv = [str(expected_executable), *argv] if expected_executable is not None and argv is not None else None
    base_argv = list(_expected_action_argv(settings))
    argv_ok = argv is not None and argv == base_argv
    arguments_ok = argv is not None and expected.get("arguments") == quote_windows_command(argv)
    working_directory_ok = False
    if isinstance(expected.get("working_directory"), str):
        try:
            working_directory_ok = absolute_path(str(expected["working_directory"])) == settings.paths.engine_root
        except SafeFilesystemError:
            working_directory_ok = False
    executable_ok = bool(expected_executable and expected_executable.is_file() and not expected_executable.is_symlink())
    executable_hash_ok = False
    if executable_ok:
        try:
            executable_hash_ok = _sha256_file(expected_executable) == _recorded_hash(expected.get("executable_sha256"))
        except OSError:
            executable_hash_ok = False
    checks = {
        "task_name": expected.get("task_name") == TASK_NAME,
        "action_argv": argv_ok,
        "action_arguments": arguments_ok,
        "action_working_directory": working_directory_ok,
        "executable": executable_ok,
        "executable_hash": executable_hash_ok,
        "executable_content_identity": executable_ok and executable_hash_ok,
    }
    return checks, full_argv, expected_executable


def _interval_minutes_from_state(expected: dict[str, Any]) -> int:
    triggers = expected.get("triggers")
    if isinstance(triggers, list):
        for trigger in triggers:
            text = str(trigger)
            if text.startswith("every_") and text.endswith("_minutes"):
                try:
                    return max(1, int(text[len("every_") : -len("_minutes")]))
                except ValueError:
                    break
    return 30


def _unit_value(raw: bytes, section: str, key: str) -> str | None:
    current = ""
    matches: list[str] = []
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        return None
    for line in text.splitlines():
        stripped = line.strip()
        if stripped.startswith("[") and stripped.endswith("]"):
            current = stripped[1:-1]
        elif current == section and stripped.startswith(key + "="):
            matches.append(stripped[len(key) + 1 :])
    return matches[0] if len(matches) == 1 else None


def _unit_argv(value: str | None) -> list[str] | None:
    if value is None:
        return None
    try:
        return shlex.split(value, posix=True)
    except ValueError:
        return None


def _launchd_domain() -> str:
    configured_uid = os.environ.get("EI_LAUNCHD_UID")
    if configured_uid:
        return f"gui/{configured_uid}"
    getuid = getattr(os, "getuid", None)
    return f"gui/{getuid() if callable(getuid) else 0}"


def _inspection_result(
    *,
    platform_name: str,
    checks: dict[str, bool],
    manager_present: bool,
    query_ok: bool,
    artifact_paths: dict[str, str],
    artifact_digests: dict[str, str],
    error_type: str | None = None,
) -> dict[str, Any]:
    identity_keys = tuple(key for key in checks if not key.startswith("manager_"))
    identity_verified = bool(identity_keys) and all(checks[key] for key in identity_keys)
    ok = query_ok and all(checks.values())
    if not query_ok:
        reason_code = "SCHEDULER_QUERY_FAILED"
    elif ok:
        reason_code = "OK"
    else:
        reason_code = "SCHEDULER_CONTRACT_FAILED"
    result: dict[str, Any] = {
        "ok": ok,
        "registered": True,
        "reason_code": reason_code,
        "task_name": TASK_NAME,
        "platform": platform_name,
        "checks": checks,
        "identity_verified": identity_verified,
        "manager_present": manager_present,
        "manager_query_ok": query_ok,
        "artifact_paths": artifact_paths,
        "artifact_digests": artifact_digests,
    }
    if error_type:
        result["error_type"] = error_type
    return result


def inspect_registered_task(
    settings: Settings,
    powershell_exe: str = "powershell.exe",
    *,
    platform_name: str | None = None,
) -> dict[str, Any]:
    state = _read_state(settings)
    if not state.get("registered"):
        return {"ok": True, "registered": False, "reason_code": "NOT_REGISTERED", "required": False, "task_name": TASK_NAME}
    expected = state.get("action")
    if not isinstance(expected, dict):
        return {"ok": False, "registered": True, "reason_code": "SCHEDULER_STATE_ACTION_MISSING", "task_name": TASK_NAME}
    selected_platform = _normalise_platform(platform_name)
    state_checks, expected_argv, expected_executable = _state_action_checks(settings, expected)
    if selected_platform in {"darwin", "mac", "macos"}:
        artifact = _launch_agents_dir() / f"{TASK_NAME}.plist"
        artifact_paths = {"plist": str(artifact)}
        try:
            completed = subprocess.run(
                ["launchctl", "print", f"{_launchd_domain()}/{TASK_NAME}"],
                capture_output=True,
                text=True,
                timeout=20,
                check=False,
            )
        except (OSError, subprocess.SubprocessError) as exc:
            return _inspection_result(platform_name="macos", checks={**state_checks, "manager_status": False, "persisted_artifact": False}, manager_present=False, query_ok=False, artifact_paths=artifact_paths, artifact_digests={}, error_type=type(exc).__name__)
        raw, _ = _read_scheduler_artifact(_launch_agents_dir(), artifact)
        checks = {**state_checks, "manager_status": completed.returncode == 0, "persisted_artifact": raw is not None}
        digests: dict[str, str] = {}
        if raw is not None:
            digests["plist"] = _sha256_digest(raw)
            try:
                document = plistlib.loads(raw)
            except (plistlib.InvalidFileException, ValueError, TypeError):
                document = None
            checks.update(
                {
                    "plist_label": isinstance(document, dict) and document.get("Label") == TASK_NAME,
                    "program_arguments": isinstance(document, dict) and document.get("ProgramArguments") == expected_argv,
                    "argv": isinstance(document, dict) and document.get("ProgramArguments") == expected_argv,
                    "working_directory": isinstance(document, dict) and document.get("WorkingDirectory") == str(settings.paths.engine_root),
                    "plist_content_identity": isinstance(document, dict) and document.get("ProgramArguments") == expected_argv and document.get("WorkingDirectory") == str(settings.paths.engine_root),
                }
            )
        else:
            checks.update({"plist_label": False, "program_arguments": False, "argv": False, "working_directory": False, "plist_content_identity": False})
        return _inspection_result(platform_name="macos", checks=checks, manager_present=completed.returncode == 0, query_ok=True, artifact_paths=artifact_paths, artifact_digests=digests)
    if selected_platform == "linux":
        unit_dir = _systemd_user_dir()
        service = unit_dir / f"{TASK_NAME}.service"
        timer = unit_dir / f"{TASK_NAME}.timer"
        artifact_paths = {"service": str(service), "timer": str(timer)}
        try:
            enabled = subprocess.run(
                ["systemctl", "--user", "is-enabled", f"{TASK_NAME}.timer"],
                capture_output=True,
                text=True,
                timeout=20,
                check=False,
            )
            active = subprocess.run(
                ["systemctl", "--user", "is-active", f"{TASK_NAME}.timer"],
                capture_output=True,
                text=True,
                timeout=20,
                check=False,
            )
        except (OSError, subprocess.SubprocessError) as exc:
            return _inspection_result(platform_name="linux", checks={**state_checks, "manager_enabled": False, "manager_active": False, "persisted_service": False, "persisted_timer": False}, manager_present=False, query_ok=False, artifact_paths=artifact_paths, artifact_digests={}, error_type=type(exc).__name__)
        service_raw, _ = _read_scheduler_artifact(unit_dir, service)
        timer_raw, _ = _read_scheduler_artifact(unit_dir, timer)
        checks = {
            **state_checks,
            "manager_enabled": enabled.returncode == 0,
            "manager_active": active.returncode == 0,
            "persisted_service": service_raw is not None,
            "persisted_timer": timer_raw is not None,
        }
        digests: dict[str, str] = {}
        service_argv = _unit_argv(_unit_value(service_raw, "Service", "ExecStart")) if service_raw is not None else None
        service_working = _unit_argv(_unit_value(service_raw, "Service", "WorkingDirectory")) if service_raw is not None else None
        checks.update(
            {
                "service_argv": service_argv == expected_argv,
                "argv": service_argv == expected_argv,
                "service_executable": bool(service_argv and expected_executable and service_argv[0] == str(expected_executable)),
                "working_directory": service_working == [str(settings.paths.engine_root)],
                "timer_unit": _unit_value(timer_raw, "Timer", "Unit") == f"{TASK_NAME}.service" if timer_raw is not None else False,
                "timer_interval": _unit_value(timer_raw, "Timer", "OnUnitActiveSec") == f"{_interval_minutes_from_state(expected)}min" if timer_raw is not None else False,
                "timer_persistent": str(_unit_value(timer_raw, "Timer", "Persistent")).casefold() == "true" if timer_raw is not None else False,
                "unit_content_identity": service_argv == expected_argv and service_working == [str(settings.paths.engine_root)],
            }
        )
        if service_raw is not None:
            digests["service"] = _sha256_digest(service_raw)
        if timer_raw is not None:
            digests["timer"] = _sha256_digest(timer_raw)
        return _inspection_result(platform_name="linux", checks=checks, manager_present=enabled.returncode == 0 or active.returncode == 0, query_ok=True, artifact_paths=artifact_paths, artifact_digests=digests)
    if selected_platform != "windows":
        return {"ok": False, "registered": True, "reason_code": "SCHEDULER_PLATFORM_UNSUPPORTED", "task_name": TASK_NAME}
    query = (
        "$task=Get-ScheduledTask -TaskName $env:EI_TASK_NAME -ErrorAction Stop;"
        "$info=Get-ScheduledTaskInfo -TaskName $env:EI_TASK_NAME -ErrorAction Stop;"
        "$action=$task.Actions | Select-Object -First 1;"
        "$lastRun=if($info.LastRunTime -and $info.LastRunTime.Year -gt 2000)"
        "{$info.LastRunTime.ToUniversalTime().ToString('o')}else{$null};"
        "$nextRun=if($info.NextRunTime -and $info.NextRunTime.Year -gt 2000)"
        "{$info.NextRunTime.ToUniversalTime().ToString('o')}else{$null};"
        "[pscustomobject]@{TaskName=$task.TaskName;Execute=$action.Execute;"
        "Arguments=$action.Arguments;WorkingDirectory=$action.WorkingDirectory;"
        "UserId=[string]$task.Principal.UserId;RunLevel=[string]$task.Principal.RunLevel;"
        "LastTaskResult=$info.LastTaskResult;LastRunTime=$lastRun;NextRunTime=$nextRun;"
        "State=[string]$task.State} | ConvertTo-Json -Compress"
    )
    environment = os.environ.copy()
    environment["EI_TASK_NAME"] = str(expected.get("task_name", TASK_NAME))
    try:
        completed = subprocess.run([powershell_exe, "-NoProfile", "-Command", query], capture_output=True, text=True, timeout=20, env=environment, check=False)
    except (OSError, subprocess.SubprocessError) as exc:
        return {"ok": False, "registered": True, "reason_code": "SCHEDULER_QUERY_FAILED", "error_type": type(exc).__name__, "task_name": TASK_NAME}
    if completed.returncode != 0:
        return {"ok": False, "registered": True, "reason_code": "SCHEDULED_TASK_NOT_FOUND", "task_name": TASK_NAME, "platform": "windows", "identity_verified": False, "manager_present": False, "manager_query_ok": True, "checks": {**state_checks, "manager_status": False}, "artifact_paths": {}, "artifact_digests": {}}
    try:
        live = json.loads(completed.stdout)
    except json.JSONDecodeError:
        return {"ok": False, "registered": True, "reason_code": "SCHEDULER_QUERY_INVALID", "task_name": TASK_NAME}
    executable = Path(str(live.get("Execute", "")).strip('"')).resolve()
    expected_executable = Path(str(expected.get("executable", ""))).resolve()
    live_arguments = str(live.get("Arguments", ""))
    expected_arguments = str(expected.get("arguments", ""))
    principal = str(live.get("UserId", ""))
    expected_principal = current_principal()
    principal_user = principal.replace("/", "\\").rsplit("\\", 1)[-1].casefold()
    expected_user = expected_principal.replace("/", "\\").rsplit("\\", 1)[-1].casefold()
    principal_ok = bool(principal_user) and principal_user == expected_user
    last_run = _parse_time(live.get("LastRunTime"))
    next_run = _parse_time(live.get("NextRunTime"))
    task_state = str(live.get("State", "")).casefold()
    stale = bool(last_run and (datetime.now(timezone.utc) - last_run.astimezone(timezone.utc)).total_seconds() > settings.scheduler_interval_minutes * 60 * 2 and task_state != "running")
    checks = {
        "task_name": str(live.get("TaskName", "")) == TASK_NAME,
        "executable": executable == expected_executable and executable.is_file(),
        "executable_hash": executable.is_file() and _sha256_file(executable) == str(expected.get("executable_sha256", "")),
        "executable_content_identity": executable.is_file() and _sha256_file(executable) == _recorded_hash(expected.get("executable_sha256")),
        "arguments": live_arguments == expected_arguments and "cmd /c" not in live_arguments.casefold() and "-m" in live_arguments and "ei.cli" in live_arguments and "maintain" in live_arguments and "--json" in live_arguments and str(settings.paths.engine_root) in live_arguments and str(settings.paths.knowledge_root) in live_arguments and str(settings.paths.codex_home) in live_arguments and str(settings.paths.runtime_root) in live_arguments,
        "working_directory": Path(str(live.get("WorkingDirectory", ""))).resolve() == settings.paths.engine_root,
        "principal": principal_ok,
        "run_level": str(live.get("RunLevel", "")).casefold() in {"limited", "leastprivilege"},
        "last_result_present": live.get("LastTaskResult") is not None,
        "last_run_present_or_not_run_yet": last_run is not None or task_state in {"ready", "running", "queued"},
        "next_run_present": next_run is not None,
        "not_stale": not stale,
    }
    identity_keys = ("task_name", "executable", "executable_hash", "executable_content_identity", "arguments", "working_directory", "principal", "run_level")
    return {"ok": all(checks.values()), "registered": True, "reason_code": "OK" if all(checks.values()) else "SCHEDULER_CONTRACT_FAILED", "task_name": TASK_NAME, "platform": "windows", "checks": checks, "identity_verified": all(checks[key] for key in identity_keys), "manager_present": True, "manager_query_ok": True, "artifact_paths": {}, "artifact_digests": {}, "last_task_result": live.get("LastTaskResult"), "last_run_time": live.get("LastRunTime"), "next_run_time": live.get("NextRunTime"), "state": live.get("State")}


def register_scheduler(
    settings: Settings,
    action: MaintenanceAction,
    engine_root: Path,
    *,
    check_only: bool = False,
    platform_name: str | None = None,
) -> dict[str, Any]:
    if not isinstance(settings, Settings) or not isinstance(action, MaintenanceAction):
        raise TypeError("SCHEDULER_ARGUMENT_INVALID")
    engine = Path(engine_root).expanduser().resolve()
    if engine != settings.paths.engine_root or action.working_directory != engine:
        raise ValueError("SCHEDULER_ENGINE_ROOT_MISMATCH")
    selected_platform = (platform_name or platform.system()).casefold()
    if selected_platform == "windows":
        script = engine / "scripts" / "install-scheduled-task.ps1"
        executable = shutil.which("powershell.exe") or "powershell.exe"
        command = [
            executable,
            "-NoProfile",
            "-ExecutionPolicy",
            "Bypass",
            "-File",
            str(script),
            "-RepoPath",
            str(engine),
            "-KnowledgeRoot",
            str(settings.paths.knowledge_root),
            "-CodexHome",
            str(settings.paths.codex_home),
            "-RuntimeRoot",
            str(settings.paths.runtime_root),
            "-PythonExe",
            str(action.executable),
        ]
        normalized_platform = "windows"
    elif selected_platform in {"darwin", "mac", "macos"}:
        script = engine / "scripts" / "install-launchd.sh"
        command = [
            shutil.which("sh") or "/bin/sh",
            str(script),
            "--engine-root",
            str(engine),
            "--knowledge-root",
            str(settings.paths.knowledge_root),
            "--codex-home",
            str(settings.paths.codex_home),
            "--runtime-root",
            str(settings.paths.runtime_root),
            "--python-exe",
            str(action.executable),
        ]
        normalized_platform = "macos"
    elif selected_platform == "linux":
        script = engine / "scripts" / "install-systemd-user.sh"
        command = [
            shutil.which("sh") or "/bin/sh",
            str(script),
            "--engine-root",
            str(engine),
            "--knowledge-root",
            str(settings.paths.knowledge_root),
            "--codex-home",
            str(settings.paths.codex_home),
            "--runtime-root",
            str(settings.paths.runtime_root),
            "--python-exe",
            str(action.executable),
        ]
        normalized_platform = "linux"
    else:
        return {"ok": False, "requested": True, "status": "REGISTRATION_FAILED", "reason_code": "SCHEDULER_PLATFORM_UNSUPPORTED", "registered": False, "retryable": False}
    if not script.is_file() or script.is_symlink():
        return {"ok": False, "requested": True, "status": "REGISTRATION_FAILED", "reason_code": "SCHEDULER_INSTALLER_MISSING", "registered": False, "retryable": False}
    # Re-registration is idempotent when the persisted action identity and
    # the live scheduler identity are both unchanged.  Keep check-only on the
    # explicit verification path below so it never writes a state receipt.
    if not check_only:
        try:
            persisted = _read_state(settings)
        except ValueError:
            persisted = {}
        if persisted.get("registered") is True and persisted.get("action") == action.to_dict():
            verification = inspect_registered_task(settings, platform_name=normalized_platform)
            if verification.get("ok") and verification.get("registered") and verification.get("identity_verified", True):
                return {
                    "ok": True,
                    "requested": True,
                    "status": "ALREADY_CURRENT",
                    "reason_code": "OK",
                    "registered": True,
                    "retryable": False,
                    "state_path": str(scheduler_state_path(settings)),
                    "platform": normalized_platform,
                    "verification": verification,
                    "action": action.to_dict(),
                }
    if check_only:
        command.append("-CheckOnly" if normalized_platform == "windows" else "--check-only")
    try:
        completed = subprocess.run(
            command,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=max(30, int(settings.scheduler_timeout_seconds)),
            check=False,
            shell=False,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        if not check_only:
            write_scheduler_state(settings, action, False)
        return {"ok": False, "requested": True, "status": "REGISTRATION_FAILED", "reason_code": "SCHEDULER_REGISTRATION_FAILED", "registered": False, "retryable": True, "error_type": type(exc).__name__, "platform": normalized_platform}
    if completed.returncode != 0:
        state_path = None if check_only else write_scheduler_state(settings, action, False, completed.returncode)
        return {"ok": False, "requested": True, "status": "REGISTRATION_FAILED", "reason_code": "SCHEDULER_REGISTRATION_FAILED", "registered": False, "retryable": True, "returncode": completed.returncode, "state_path": str(state_path) if state_path else None, "platform": normalized_platform}
    if check_only:
        return {"ok": True, "requested": True, "status": "CHECK_ONLY", "reason_code": "OK", "registered": False, "retryable": False, "platform": normalized_platform, "action": action.to_dict()}
    state_path = write_scheduler_state(settings, action, True, completed.returncode)
    verified = inspect_registered_task(settings, platform_name=normalized_platform)
    if not verified.get("ok") or not verified.get("registered"):
        write_scheduler_state(settings, action, False, completed.returncode)
        return {"ok": False, "requested": True, "status": "VERIFICATION_FAILED", "reason_code": str(verified.get("reason_code") or "SCHEDULER_VERIFICATION_FAILED"), "registered": False, "retryable": True, "state_path": str(state_path), "platform": normalized_platform, "verification": verified}
    return {"ok": True, "requested": True, "status": "REGISTERED", "reason_code": "OK", "registered": True, "retryable": False, "state_path": str(state_path), "platform": normalized_platform, "verification": verified, "action": action.to_dict()}


def _remove_owned_scheduler_file(root: Path, path: Path, digest: str) -> bool:
    try:
        return safe_unlink(root, path, expected_digest="sha256:" + digest, allow_missing=False)
    except SafeFilesystemError as exc:
        raise ValueError(exc.code) from exc


def _windows_unregister_command() -> str:
    return (
        "$task=Get-ScheduledTask -TaskName $env:EI_TASK_NAME -ErrorAction Stop;"
        "$action=$task.Actions | Select-Object -First 1;"
        "if ([string]$action.Execute -ne $env:EI_EXPECTED_EXECUTABLE -or "
        "[string]$action.Arguments -ne $env:EI_EXPECTED_ARGUMENTS -or "
        "[string]$action.WorkingDirectory -ne $env:EI_EXPECTED_WORKING_DIRECTORY) "
        "{ throw 'SCHEDULER_ACTION_MISMATCH' };"
        "$hash=(Get-FileHash -LiteralPath $env:EI_EXPECTED_EXECUTABLE -Algorithm SHA256).Hash.ToLowerInvariant();"
        "if ($hash -ne $env:EI_EXPECTED_HASH) { throw 'SCHEDULER_EXECUTABLE_MISMATCH' };"
        "Unregister-ScheduledTask -TaskName $env:EI_TASK_NAME -Confirm:$false"
    )


def unregister_scheduler(
    settings: Settings,
    action: MaintenanceAction | str | None = None,
    *,
    check_only: bool = False,
    platform_name: str | None = None,
    powershell_exe: str = "powershell.exe",
) -> dict[str, Any]:
    """Unregister the owned scheduler job after verifying its live identity."""

    if not isinstance(settings, Settings):
        raise TypeError("SCHEDULER_ARGUMENT_INVALID")
    if isinstance(action, str) and platform_name is None:
        platform_name = action
        action = None
    if action is not None and not isinstance(action, MaintenanceAction):
        raise TypeError("SCHEDULER_ARGUMENT_INVALID")

    state_path = scheduler_state_path(settings)
    if not (state_path.exists() or state_path.is_symlink()):
        return {
            "ok": True,
            "requested": True,
            "status": "NOT_REGISTERED",
            "reason_code": "NOT_REGISTERED",
            "registered": False,
            "removed": False,
            "job_removed": False,
            "platform": _normalise_platform(platform_name),
        }
    try:
        assert_safe_target(state_path.parent, state_path, allow_missing=False, expected_type="file")
        state_raw = state_path.read_bytes()
        state = json.loads(state_raw.decode("utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError, SafeFilesystemError) as exc:
        return {
            "ok": False,
            "requested": True,
            "status": "UNREGISTER_BLOCKED",
            "reason_code": getattr(exc, "code", "SCHEDULER_STATE_INVALID"),
            "registered": True,
            "removed": False,
            "job_removed": False,
            "platform": _normalise_platform(platform_name),
        }
    if not isinstance(state, dict) or state.get("task_name") != TASK_NAME:
        return {
            "ok": False,
            "requested": True,
            "status": "UNREGISTER_BLOCKED",
            "reason_code": "SCHEDULER_STATE_TASK_MISMATCH",
            "registered": bool(isinstance(state, dict) and state.get("registered")),
            "removed": False,
            "job_removed": False,
            "platform": _normalise_platform(platform_name),
        }
    expected = state.get("action")
    if not isinstance(expected, dict):
        return {
            "ok": False,
            "requested": True,
            "status": "UNREGISTER_BLOCKED",
            "reason_code": "SCHEDULER_STATE_ACTION_MISSING",
            "registered": bool(state.get("registered")),
            "removed": False,
            "job_removed": False,
            "platform": _normalise_platform(platform_name),
        }
    if action is not None and expected != action.to_dict():
        return {
            "ok": False,
            "requested": True,
            "status": "UNREGISTER_BLOCKED",
            "reason_code": "SCHEDULER_IDENTITY_MISMATCH",
            "registered": bool(state.get("registered")),
            "removed": False,
            "job_removed": False,
            "platform": _normalise_platform(platform_name),
        }
    if not state.get("registered"):
        if check_only:
            return {
                "ok": True,
                "requested": True,
                "status": "CHECK_ONLY",
                "reason_code": "OK",
                "registered": False,
                "removed": False,
                "job_removed": False,
                "would_remove": True,
                "platform": _normalise_platform(platform_name),
            }
        try:
            removed = _remove_owned_scheduler_file(state_path.parent, state_path, _sha256_digest(state_raw))
        except ValueError as exc:
            return {
                "ok": False,
                "requested": True,
                "status": "UNREGISTER_BLOCKED",
                "reason_code": str(exc),
                "registered": False,
                "removed": False,
                "job_removed": False,
                "platform": _normalise_platform(platform_name),
            }
        return {
            "ok": True,
            "requested": True,
            "status": "UNREGISTERED",
            "reason_code": "OK",
            "registered": False,
            "removed": removed,
            "job_removed": False,
            "state_path": str(state_path),
            "platform": _normalise_platform(platform_name),
        }

    selected_platform = _normalise_platform(platform_name)
    verification = inspect_registered_task(settings, powershell_exe, platform_name=selected_platform)
    query_ok = verification.get("manager_query_ok") is True
    manager_present = verification.get("manager_present") is True
    identity_verified = verification.get("identity_verified") is True
    absent_windows_task = selected_platform == "windows" and verification.get("reason_code") == "SCHEDULED_TASK_NOT_FOUND" and query_ok
    if selected_platform not in {"windows", "darwin", "mac", "macos", "linux"}:
        return {"ok": False, "requested": True, "status": "UNREGISTER_BLOCKED", "reason_code": "SCHEDULER_PLATFORM_UNSUPPORTED", "registered": True, "removed": False, "job_removed": False, "platform": selected_platform, "verification": verification}
    if not query_ok or (not identity_verified and not absent_windows_task):
        return {
            "ok": False,
            "requested": True,
            "status": "UNREGISTER_BLOCKED",
            "reason_code": "SCHEDULER_IDENTITY_MISMATCH" if query_ok else "SCHEDULER_QUERY_FAILED",
            "registered": True,
            "removed": False,
            "job_removed": False,
            "platform": "macos" if selected_platform in {"darwin", "mac", "macos"} else selected_platform,
            "verification": verification,
        }
    normalized_platform = "macos" if selected_platform in {"darwin", "mac", "macos"} else selected_platform
    if check_only:
        return {
            "ok": True,
            "requested": True,
            "status": "CHECK_ONLY",
            "reason_code": "OK",
            "registered": True,
            "removed": False,
            "job_removed": False,
            "would_remove": True,
            "platform": normalized_platform,
            "verification": verification,
        }

    if manager_present:
        if normalized_platform == "macos":
            command = ["launchctl", "bootout", f"{_launchd_domain()}/{TASK_NAME}"]
            environment = None
        elif normalized_platform == "linux":
            command = ["systemctl", "--user", "disable", "--now", f"{TASK_NAME}.timer"]
            environment = None
        else:
            expected_executable = absolute_path(str(expected.get("executable", "")))
            command = [powershell_exe, "-NoProfile", "-Command", _windows_unregister_command()]
            environment = os.environ.copy()
            environment.update(
                {
                    "EI_TASK_NAME": TASK_NAME,
                    "EI_EXPECTED_EXECUTABLE": str(expected_executable),
                    "EI_EXPECTED_ARGUMENTS": str(expected.get("arguments", "")),
                    "EI_EXPECTED_WORKING_DIRECTORY": str(settings.paths.engine_root),
                    "EI_EXPECTED_HASH": _recorded_hash(expected.get("executable_sha256")),
                }
            )
        try:
            completed = subprocess.run(command, capture_output=True, text=True, timeout=20, env=environment, check=False, shell=False)
        except (OSError, subprocess.SubprocessError) as exc:
            return {"ok": False, "requested": True, "status": "UNREGISTER_FAILED", "reason_code": "SCHEDULER_UNREGISTER_FAILED", "registered": True, "removed": False, "job_removed": False, "platform": normalized_platform, "error_type": type(exc).__name__, "verification": verification}
        if completed.returncode != 0:
            return {"ok": False, "requested": True, "status": "UNREGISTER_FAILED", "reason_code": "SCHEDULER_UNREGISTER_FAILED", "registered": True, "removed": False, "job_removed": False, "platform": normalized_platform, "returncode": completed.returncode, "verification": verification}

    removed_artifacts: list[str] = []
    try:
        for name, raw_path in verification.get("artifact_paths", {}).items():
            digest = verification.get("artifact_digests", {}).get(name)
            if not isinstance(raw_path, str) or not isinstance(digest, str):
                raise ValueError("SCHEDULER_ARTIFACT_IDENTITY_MISSING")
            artifact = absolute_path(raw_path)
            root = artifact.parent
            if _remove_owned_scheduler_file(root, artifact, digest):
                removed_artifacts.append(str(artifact))
        state_removed = _remove_owned_scheduler_file(state_path.parent, state_path, _sha256_digest(state_raw))
    except (OSError, ValueError, SafeFilesystemError) as exc:
        return {"ok": False, "requested": True, "status": "UNREGISTER_FAILED", "reason_code": str(getattr(exc, "code", exc)), "registered": True, "removed": bool(removed_artifacts), "job_removed": manager_present, "platform": normalized_platform, "removed_artifacts": removed_artifacts, "verification": verification}
    return {
        "ok": True,
        "requested": True,
        "status": "UNREGISTERED",
        "reason_code": "OK",
        "registered": False,
        "removed": state_removed or bool(removed_artifacts),
        "job_removed": manager_present,
        "state_path": str(state_path),
        "removed_artifacts": removed_artifacts,
        "platform": normalized_platform,
        "verification": verification,
    }


def _main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo-root")
    parser.add_argument("--engine-root")
    parser.add_argument("--knowledge-root")
    parser.add_argument("--codex-home", required=True)
    parser.add_argument("--runtime-root")
    parser.add_argument("--python-exe")
    parser.add_argument("--json", action="store_true")
    parser.add_argument("--write-state", action="store_true")
    parser.add_argument("--registered", action="store_true")
    parser.add_argument("--last-result", type=int)
    args = parser.parse_args()
    if not args.engine_root and not args.repo_root:
        raise SystemExit("ENGINE_ROOT_REQUIRED")
    if args.engine_root or args.knowledge_root:
        settings = load_settings(
            engine_root=Path(args.engine_root or args.repo_root),
            knowledge_root=Path(args.knowledge_root) if args.knowledge_root else None,
            codex_home=Path(args.codex_home),
            runtime_root=Path(args.runtime_root) if args.runtime_root else None,
        )
    else:
        settings = load_settings(Path(args.repo_root), Path(args.codex_home), runtime_root=Path(args.runtime_root) if args.runtime_root else None)
    action = build_maintenance_action(settings, Path(args.python_exe) if args.python_exe else None)
    result = action.to_dict()
    if args.write_state:
        result["state_path"] = str(write_scheduler_state(settings, action, args.registered, args.last_result))
    if args.json:
        print(json.dumps(result, ensure_ascii=False, sort_keys=True, indent=2))
    else:
        print(result)
    return 0


if __name__ == "__main__":
    raise SystemExit(_main())

__all__ = ["MaintenanceAction", "TASK_NAME", "SCHEDULER_STATE_NAME", "build_maintenance_action", "build_launchd_plist", "build_systemd_user_unit", "build_systemd_user_timer", "scheduler_state_path", "write_scheduler_state", "remove_scheduler_state", "inspect_registered_task", "register_scheduler", "unregister_scheduler"]
