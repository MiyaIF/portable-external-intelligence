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
import re
import time
import ctypes
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
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


def _sha256_file(path: Path, *, budget=None) -> str:
    if budget is not None:
        from .safe_fs import _file_digest
        return _file_digest(path, budget=budget).removeprefix("sha256:")
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
        interval = _interval_minutes(action)
        # systemd's usec_t is uint64; UINT64_MAX is its infinity sentinel.
        if interval > ((2**64 - 2) // (120 * 1_000_000)):
            raise ValueError("SCHEDULER_INTERVAL_OUT_OF_RANGE")
        return (
            "[Unit]\n"
            f"Description={action.task_name} timer\n\n"
            "[Timer]\n"
            "OnBootSec=2min\n"
            f"OnUnitActiveSec={interval}min\n"
            f"OnUnitActiveSec={2 * interval}min\n"
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


def _maintenance_action_from_record(value: object) -> MaintenanceAction | None:
    required = {
        "task_name", "executable", "argv", "arguments", "working_directory", "log_file",
        "principal", "run_level", "execution_time_limit_seconds", "multiple_instance_policy",
        "start_when_available", "wake_to_run", "triggers", "executable_sha256",
    }
    if not isinstance(value, dict) or set(value) != required:
        return None
    if any(not isinstance(value.get(key), str) for key in (
        "task_name", "executable", "arguments", "working_directory", "log_file", "principal",
        "run_level", "multiple_instance_policy", "executable_sha256",
    )):
        return None
    if not isinstance(value.get("argv"), list) or not all(isinstance(item, str) for item in value["argv"]):
        return None
    if not isinstance(value.get("triggers"), list) or not all(isinstance(item, str) for item in value["triggers"]):
        return None
    if type(value.get("start_when_available")) is not bool or type(value.get("wake_to_run")) is not bool:
        return None
    if type(value.get("execution_time_limit_seconds")) is not int:
        return None
    return MaintenanceAction(
        task_name=value["task_name"], executable=Path(value["executable"]), argv=tuple(value["argv"]),
        arguments=value["arguments"], working_directory=Path(value["working_directory"]),
        log_file=Path(value["log_file"]), principal=value["principal"], run_level=value["run_level"],
        execution_time_limit_seconds=value["execution_time_limit_seconds"],
        multiple_instance_policy=value["multiple_instance_policy"],
        start_when_available=value["start_when_available"], wake_to_run=value["wake_to_run"],
        triggers=tuple(value["triggers"]), executable_sha256=value["executable_sha256"],
    )


def _legacy_systemd_user_timer(action: MaintenanceAction) -> str:
    lines = build_systemd_user_timer(action).splitlines()
    timers = [index for index, line in enumerate(lines) if line.startswith("OnUnitActiveSec=")]
    if len(timers) != 2:
        raise ValueError("SCHEDULER_TIMER_RENDER_INVALID")
    del lines[timers[1]]
    return "\n".join(lines) + "\n"


def _systemd_artifacts_are_owned(settings: Settings, current_action: MaintenanceAction) -> bool:
    """Only replace unit files matching this engine's recorded generated definition."""
    unit_dir = _systemd_user_dir()
    service = unit_dir / f"{TASK_NAME}.service"
    timer = unit_dir / f"{TASK_NAME}.timer"
    present = (service.exists() or service.is_symlink(), timer.exists() or timer.is_symlink())
    if not any(present):
        return True
    try:
        state = _read_state(settings)
    except ValueError:
        return False
    previous = _maintenance_action_from_record(state.get("action"))
    if state.get("task_name") != TASK_NAME or previous is None or previous.working_directory != current_action.working_directory:
        return False
    service_raw, service_error = _read_scheduler_artifact(unit_dir, service)
    timer_raw, timer_error = _read_scheduler_artifact(unit_dir, timer)
    if service_error not in {None, "SCHEDULER_ARTIFACT_DIRECTORY_MISSING"} or timer_error not in {None, "SCHEDULER_ARTIFACT_DIRECTORY_MISSING"}:
        return False
    if service_raw is not None and service_raw != build_systemd_user_unit(previous).encode("utf-8"):
        return False
    if timer_raw is not None:
        current_timer = build_systemd_user_timer(previous).encode("utf-8")
        legacy_timer = _legacy_systemd_user_timer(previous).encode("utf-8")
        if timer_raw not in {current_timer, legacy_timer}:
            return False
    # A service artifact must be present unless its recorded scheduler state
    # describes a failed first registration that this explicit setup can retry.
    if service_raw is None and state.get("registered") is True:
        return False
    if timer_raw is None and state.get("registered") is True:
        return False
    return True

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


def _state_action_checks(settings: Settings, expected: dict[str, Any], *, budget=None) -> tuple[dict[str, bool], list[str] | None, Path | None]:
    if budget is not None:
        budget.check()
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
            executable_hash_ok = _sha256_file(expected_executable, budget=budget) == _recorded_hash(expected.get("executable_sha256"))
        except TimeoutError:
            raise
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


def _scheduler_query(argv, budget, *, env=None):
    budget.check()
    result = subprocess.run(argv, capture_output=True, text=True, encoding="utf-8", errors="strict",
        stdin=subprocess.DEVNULL, timeout=min(2.0, budget.remaining_ms() / 1000), env=env, check=False)
    budget.check()
    if len(result.stdout.encode("utf-8")) > 262144 or len(result.stderr.encode("utf-8")) > 65536:
        raise ValueError("SCHEDULER_QUERY_LIMIT")
    return result


def _scheduler_clocks(selected, budget):
    """Continuous (includes sleep) and awake counters in microseconds."""
    budget.check()
    if selected == "linux":
        from .index import _read_projection_bytes
        boot = _read_projection_bytes(Path("/proc/sys/kernel/random/boot_id"), budget=budget, maximum=128).decode().strip()
        return boot, time.clock_gettime_ns(time.CLOCK_BOOTTIME) // 1000, time.clock_gettime_ns(time.CLOCK_MONOTONIC) // 1000
    if selected == "macos":
        boot = _scheduler_query(["sysctl", "-n", "kern.boottime"], budget).stdout.strip()
        class Timebase(ctypes.Structure):
            _fields_ = [("numer", ctypes.c_uint32), ("denom", ctypes.c_uint32)]
        library = ctypes.CDLL("/usr/lib/libSystem.B.dylib")
        base = Timebase()
        if library.mach_timebase_info(ctypes.byref(base)) != 0 or not base.denom:
            raise ValueError("SCHEDULER_CLOCK_UNAVAILABLE")
        library.mach_absolute_time.restype = library.mach_continuous_time.restype = ctypes.c_uint64
        return boot, library.mach_continuous_time() * base.numer // base.denom // 1000, library.mach_absolute_time() * base.numer // base.denom // 1000
    if selected == "windows":
        kernel = ctypes.WinDLL("kernel32", use_last_error=True)
        kernel.GetTickCount64.restype = ctypes.c_uint64
        awake = ctypes.c_uint64()
        if not kernel.QueryUnbiasedInterruptTime(ctypes.byref(awake)):
            raise ValueError("SCHEDULER_CLOCK_UNAVAILABLE")
        return None, kernel.GetTickCount64() * 1000, awake.value // 10
    raise ValueError("SCHEDULER_QUERY_UNSUPPORTED")


def _bus_properties(unit, interface, fields, budget):
    prefix = ["busctl", "--user", "--allow-interactive-authorization=no", "--auto-start=no"]
    located = _scheduler_query([*prefix, "call", "org.freedesktop.systemd1", "/org/freedesktop/systemd1", "org.freedesktop.systemd1.Manager", "GetUnit", "s", unit], budget)
    tokens = shlex.split(located.stdout)
    if located.returncode != 0 or len(tokens) != 2 or tokens[0] != "o" or not tokens[1].startswith("/org/freedesktop/systemd1/unit/"):
        raise ValueError("SCHEDULER_QUERY_UNSUPPORTED")
    queried = _scheduler_query([*prefix, "--json=short", "get-property", "org.freedesktop.systemd1", tokens[1], "org.freedesktop.systemd1." + interface, *fields], budget)
    rows = [json.loads(line) for line in queried.stdout.splitlines() if line.strip()]
    if queried.returncode != 0 or len(rows) != len(fields) or any(not isinstance(row, dict) or set(row) != {"type", "data"} for row in rows):
        raise ValueError("SCHEDULER_QUERY_UNSUPPORTED")
    signatures = {"TimersMonotonic": "a(stt)", "TimersCalendar": "a(sst)", "AccuracyUSec": "t", "RandomizedDelayUSec": "t",
        "WakeSystem": "b", "LastTriggerUSecMonotonic": "t", "InvocationID": "ay", "ActiveState": "s", "UnitFileState": "s",
        "NeedDaemonReload": "b", "Conditions": "a(sbbsi)", "Asserts": "a(sbbsi)", "FragmentPath": "s", "DropInPaths": "as",
        "InactiveExitTimestampMonotonic": "t", "Job": "(uo)", "ExecStart": "a(sasbttttuii)", "ExecCondition": "a(sasbttttuii)",
        "WorkingDirectory": "s", "Result": "s"}
    for name, row in zip(fields, rows, strict=True):
        budget.check()
        signature, value = signatures[name], row["data"]
        if row["type"] != signature or (signature == "t" and (type(value) is not int or not 0 <= value < 2**64)) or (signature == "b" and type(value) is not bool) or (signature == "s" and not isinstance(value, str)) or (signature[0] in {"a", "("} and not isinstance(value, list)):
            raise ValueError("SCHEDULER_QUERY_INVALID")
    return dict(zip(fields, (row["data"] for row in rows), strict=True))


def _native_scheduler_sample(settings, *, now, budget):
    from .operation_runtime import _read_json
    from .index import _read_projection_bytes
    state = _read_json(scheduler_state_path(settings), budget=budget) or {}
    expected = state.get("action")
    if state.get("registered") is not True or not isinstance(expected, dict):
        raise ValueError("SCHEDULER_NOT_REGISTERED")
    checks, argv, _ = _state_action_checks(settings, expected, budget=budget)
    selected = _normalise_platform(None)
    selected = "macos" if selected in {"darwin", "mac", "macos"} else selected
    boot, continuous, awake = _scheduler_clocks(selected, budget)
    native = {"platform": selected, "identity_verified": all(checks.values()), "registered": False,
        "enabled": False, "running": False, "conditions_verified": False, "generation": None,
        "boot_id": boot, "monotonic_us": continuous, "awake_us": awake, "observed_at": now.isoformat(), "next_run_at": None}
    if selected == "linux":
        unit_dir = _systemd_user_dir()
        service_raw = _read_projection_bytes(unit_dir / f"{TASK_NAME}.service", budget=budget, maximum=65536)
        timer_raw = _read_projection_bytes(unit_dir / f"{TASK_NAME}.timer", budget=budget, maximum=65536)
        timer = _bus_properties(f"{TASK_NAME}.timer", "Timer", ["TimersMonotonic", "TimersCalendar", "AccuracyUSec", "RandomizedDelayUSec", "WakeSystem", "LastTriggerUSecMonotonic"], budget)
        tu = _bus_properties(f"{TASK_NAME}.timer", "Unit", ["InvocationID", "ActiveState", "UnitFileState", "NeedDaemonReload", "Conditions", "Asserts", "FragmentPath", "DropInPaths"], budget)
        su = _bus_properties(f"{TASK_NAME}.service", "Unit", ["InactiveExitTimestampMonotonic", "ActiveState", "NeedDaemonReload", "Conditions", "Asserts", "FragmentPath", "DropInPaths", "Job"], budget)
        service = _bus_properties(f"{TASK_NAME}.service", "Service", ["ExecStart", "ExecCondition", "WorkingDirectory", "Result"], budget)
        executable = service["ExecStart"]
        definition = hashlib.sha256(service_raw + b"\0" + timer_raw).hexdigest()
        identity = (native["identity_verified"] and isinstance(executable, list) and len(executable) == 1 and
            isinstance(executable[0], list) and len(executable[0]) >= 2 and executable[0][1] == argv and
            service["WorkingDirectory"] == str(settings.paths.engine_root) and
            _unit_argv(_unit_value(service_raw, "Service", "ExecStart")) == argv and
            _unit_value(timer_raw, "Timer", "Unit") == f"{TASK_NAME}.service" and
            _unit_values(timer_raw, "Timer", "OnUnitActiveSec") in ([f"{settings.scheduler_interval_minutes}min"], [f"{settings.scheduler_interval_minutes}min", f"{2 * settings.scheduler_interval_minutes}min"]) and
            tu["FragmentPath"] == str(unit_dir / f"{TASK_NAME}.timer") and su["FragmentPath"] == str(unit_dir / f"{TASK_NAME}.service"))
        invocation = tu["InvocationID"]
        generation = bytes(invocation).hex() if isinstance(invocation, list) and len(invocation) == 16 and all(type(item) is int and 0 <= item <= 255 for item in invocation) and any(invocation) else None
        conditions = (all(row["NeedDaemonReload"] is False and row["Conditions"] == [] and row["Asserts"] == [] and row["DropInPaths"] == [] for row in (tu, su)) and
            timer["TimersCalendar"] == [] and timer["WakeSystem"] is False and service["ExecCondition"] == [] and service["Result"] == "success" and
            isinstance(su["Job"], list) and len(su["Job"]) == 2 and type(su["Job"][0]) is int and su["Job"][0] == 0 and tu["ActiveState"] == "active")
        native.update(identity_verified=bool(identity), registered=True, enabled=tu["UnitFileState"] == "enabled",
            running=su["ActiveState"] in {"active", "activating", "deactivating", "reloading"}, conditions_verified=conditions,
            generation=generation, definition_hash=definition, activation_us=max(su["InactiveExitTimestampMonotonic"], timer["LastTriggerUSecMonotonic"]),
            service_activation_us=su["InactiveExitTimestampMonotonic"], last_trigger_us=timer["LastTriggerUSecMonotonic"],
            timers=timer["TimersMonotonic"], accuracy_us=timer["AccuracyUSec"], random_delay_us=timer["RandomizedDelayUSec"], last_exit=service["Result"])
        due = [row[2] for row in native["timers"] if isinstance(row, list) and len(row) == 3 and type(row[2]) is int and row[2] > awake]
        if due:
            native["next_run_at"] = (now + timedelta(microseconds=min(due) - awake)).isoformat()
        return native
    if selected == "macos":
        path = _launch_agents_dir() / f"{TASK_NAME}.plist"
        raw = _read_projection_bytes(path, budget=budget, maximum=65536)
        plist = plistlib.loads(raw)
        result = _scheduler_query(["launchctl", "print", f"{_launchd_domain()}/{TASK_NAME}"], budget)
        if result.returncode != 0:
            raise ValueError("SCHEDULER_QUERY_UNSUPPORTED")
        def field(name):
            match = re.search(r"^\s*" + re.escape(name) + r"\s*=\s*([^\r\n]+)$", result.stdout, re.MULTILINE)
            return match.group(1).strip() if match else None
        last_exit, runs = field("last exit code"), field("runs")
        native.update(identity_verified=bool(native["identity_verified"] and plist.get("Label") == TASK_NAME and plist.get("ProgramArguments") == argv and plist.get("WorkingDirectory") == str(settings.paths.engine_root)),
            registered=True, enabled=None, plist_disabled=plist.get("Disabled", False), running=field("state") == "running",
            definition_hash=hashlib.sha256(raw).hexdigest(), last_exit=int(last_exit) if last_exit and re.fullmatch(r"-?\d+", last_exit) else None,
            runs=int(runs) if runs and runs.isdigit() else None)
        return native
    if selected == "windows":
        query = ("$ErrorActionPreference='Stop';$t=Get-ScheduledTask -TaskName $env:EI_TASK_NAME;"
            "$i=Get-ScheduledTaskInfo -TaskName $env:EI_TASK_NAME;"
            "$s=New-Object -ComObject Schedule.Service;$s.Connect();$r=$s.GetFolder('\\').GetTask($env:EI_TASK_NAME);"
            "[pscustomobject]@{xml=(Export-ScheduledTask -TaskName $env:EI_TASK_NAME);enabled=$t.Settings.Enabled;state=[string]$t.State;"
            "last_exit=$i.LastTaskResult;last_run=$i.LastRunTime.ToUniversalTime().ToString('o');next_run=$i.NextRunTime.ToUniversalTime().ToString('o');"
            "native_missed_runs=$r.NumberOfMissedRuns;boot=(Get-CimInstance Win32_OperatingSystem).LastBootUpTime.ToUniversalTime().ToString('o')}|ConvertTo-Json -Compress")
        environment = {**os.environ, "EI_TASK_NAME": TASK_NAME}
        result = _scheduler_query([shutil.which("powershell.exe") or "powershell.exe", "-NoProfile", "-NonInteractive", "-Command", query], budget, env=environment)
        if result.returncode != 0:
            raise ValueError("SCHEDULER_QUERY_UNSUPPORTED")
        value = json.loads(result.stdout)
        import xml.etree.ElementTree as ET
        xml = value["xml"]
        if not isinstance(xml, str) or "<!DOCTYPE" in xml or "<!ENTITY" in xml:
            raise ValueError("SCHEDULER_QUERY_INVALID")
        root = ET.fromstring(xml)
        ns = {"t": "http://schemas.microsoft.com/windows/2004/02/mit/task"}
        actions = root.findall("t:Actions/t:Exec", ns)
        identity = len(actions) == 1 and all(actions[0].findtext("t:" + key, namespaces=ns) == expected[attribute] for key, attribute in (("Command", "executable"), ("Arguments", "arguments"), ("WorkingDirectory", "working_directory")))
        native.update(identity_verified=bool(native["identity_verified"] and identity), registered=True, enabled=value.get("enabled") is True,
            running=value.get("state") == "Running", boot_id=value.get("boot"), definition_hash=hashlib.sha256(xml.encode()).hexdigest(),
            last_exit=value.get("last_exit"), last_run_at=value.get("last_run"), next_run_at=value.get("next_run"), native_missed_runs=value.get("native_missed_runs"),
            conditions={**{key: root.findtext("t:Settings/t:" + key, namespaces=ns) for key in ("DisallowStartIfOnBatteries", "StopIfGoingOnBatteries", "RunOnlyIfIdle", "RunOnlyIfNetworkAvailable", "StartWhenAvailable", "WakeToRun")},
                "LogonType": root.findtext("t:Principals/t:Principal/t:LogonType", namespaces=ns)})
        return native
    raise ValueError("SCHEDULER_QUERY_UNSUPPORTED")


def _linux_opportunities(previous, current, settings):
    """Two actual armed points, never elapsed/interval or a missed-run counter."""
    unknown = (None, "SCHEDULER_OPPORTUNITY_EVIDENCE_UNAVAILABLE", False)
    if not isinstance(previous, dict):
        return None, "SCHEDULER_BASELINE_REQUIRED", False
    for row in (previous, current):
        if any(row.get(key) is not True for key in ("identity_verified", "registered", "enabled", "conditions_verified")) or row.get("running") is not False:
            return unknown
        if any(type(row.get(key)) is not int or row[key] < 0 for key in ("monotonic_us", "awake_us", "activation_us", "accuracy_us", "random_delay_us")):
            return unknown
    for key in ("boot_id", "generation", "definition_hash"):
        if not current.get(key) and key not in {"random_delay_us", "accuracy_us"} or previous.get(key) != current.get(key):
            return unknown
    old_time, new_time = _parse_time(previous.get("observed_at")), _parse_time(current.get("observed_at"))
    if old_time is None or new_time is None or old_time.utcoffset() is None or new_time.utcoffset() is None:
        return unknown
    continuous = current["monotonic_us"] - previous["monotonic_us"]
    awake = current["awake_us"] - previous["awake_us"]
    wall = int((new_time - old_time).total_seconds() * 1_000_000)
    if min(continuous, awake, wall) < 0 or abs(continuous - awake) > 2_000_000 or abs(wall - continuous) > 2_000_000:
        return unknown
    # A freshly re-armed schedule alone is not recovery. Require a distinct
    # native timer trigger and a successful target activation after it.
    fields = ("last_trigger_us", "service_activation_us")
    if all(type(row.get(key)) is int and 0 <= row[key] < 2**64 - 1 for row in (previous, current) for key in fields):
        if (current["last_exit"] == "success" if "last_exit" in current else False) and previous["last_trigger_us"] < current["last_trigger_us"] <= current["service_activation_us"] <= current["awake_us"] and previous["service_activation_us"] < current["service_activation_us"]:
            return 0, "SCHEDULER_EXECUTION_RESUMED", False
    for key in ("activation_us", "timers", "accuracy_us", "random_delay_us"):
        if previous.get(key) != current.get(key):
            return unknown
    interval = settings.scheduler_interval_minutes * 60 * 1_000_000
    timers = current.get("timers")
    if not isinstance(timers, list) or len(timers) > 16 or interval <= 0 or interval * 2 >= 2**64 - 1:
        return unknown
    points = []
    for row in timers:
        if not isinstance(row, list) or len(row) != 3 or row[0] != "OnUnitActiveUSec":
            continue
        offset, due = row[1:]
        if type(offset) is not int or type(due) is not int or due != current["activation_us"] + offset or due >= 2**64 - 1:
            return unknown
        points.append((offset, due))
    if sorted(offset for offset, _ in points) != [interval, 2 * interval]:
        return None, "SCHEDULER_SECOND_OPPORTUNITY_UNAVAILABLE", True
    if any(due <= previous["awake_us"] for _, due in points):
        return unknown
    allowance = current["accuracy_us"] + current["random_delay_us"]
    missed = sum(current["awake_us"] > due + allowance for _, due in points)
    return missed, "SCHEDULER_MISSED_OPPORTUNITIES" if missed else "SCHEDULER_OPPORTUNITIES_PENDING", True


def inspect_scheduler_opportunities(settings: Settings, *, now: datetime, budget=None, read_only=False) -> dict:
    from .operation_runtime import OperationBudget, _read_json, settings_binding
    budget = budget if budget is not None else OperationBudget(5000)
    result = {"requested": False, "missed_eligible_runs": None, "next_run_at": None, "reason_code": "SCHEDULER_SELECTION_UNKNOWN", "native": {}}
    try:
        budget.check()
        manifest = _read_json(Path(settings.paths.install_manifest_path), budget=budget) or {}
        requested = manifest.get("scheduler_requested")
        if type(requested) is not bool:
            return result
        result["requested"] = requested
        if not requested:
            return {**result, "missed_eligible_runs": 0, "reason_code": "SCHEDULER_EXPLICITLY_DISABLED"}
        native = _native_scheduler_sample(settings, now=now, budget=budget)
        result.update(native=native, next_run_at=native.get("next_run_at"))
        if native.get("platform") == "macos":
            return {**result, "reason_code": "SCHEDULER_GENERATION_EVIDENCE_UNAVAILABLE"}
        if native.get("platform") == "windows":
            return {**result, "reason_code": "SCHEDULER_OPPORTUNITY_EVIDENCE_UNAVAILABLE"}
        if native.get("platform") != "linux":
            return {**result, "reason_code": "SCHEDULER_QUERY_UNSUPPORTED"}
        path = Path(settings.paths.runtime_root) / "scheduler-opportunities.json"
        stored = _read_json(path, budget=budget)
        previous = stored.get("sample") if isinstance(stored, dict) and set(stored) == {"schema_version", "binding", "sample"} and type(stored["schema_version"]) is int and stored["schema_version"] == 1 and stored["binding"] == settings_binding(settings) else None
        count, reason, retain = _linux_opportunities(previous, native, settings)
        result.update(missed_eligible_runs=count, reason_code=reason)
        if not read_only and not retain:
            value = {"schema_version": 1, "binding": settings_binding(settings), "sample": native}
            raw = json.dumps(value, ensure_ascii=True, sort_keys=True).encode()
            if len(raw) > 262144:
                raise ValueError("SCHEDULER_QUERY_LIMIT")
            budget.check()
            safe_ensure_directory(path.parent)
            budget.check()
            safe_atomic_write(path.parent, path, raw)
        return result
    except TimeoutError:
        return {**result, "reason_code": "SCHEDULER_BUDGET_EXHAUSTED"}
    except (OSError, ValueError, TypeError, KeyError, AttributeError, OverflowError, subprocess.SubprocessError):
        return {**result, "reason_code": "SCHEDULER_QUERY_UNSUPPORTED"}


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
    matches = _unit_values(raw, section, key)
    return matches[0] if len(matches) == 1 else None


def _unit_values(raw: bytes, section: str, key: str) -> list[str]:
    current = ""
    matches: list[str] = []
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        return []
    for line in text.splitlines():
        stripped = line.strip()
        if stripped.startswith("[") and stripped.endswith("]"):
            current = stripped[1:-1]
        elif current == section and stripped.startswith(key + "="):
            matches.append(stripped[len(key) + 1 :])
    return matches


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
        recorded_action = _maintenance_action_from_record(expected)
        service_definition_ok = service_raw is not None and recorded_action is not None and service_raw == build_systemd_user_unit(recorded_action).encode("utf-8")
        timer_definition_ok = timer_raw is not None and recorded_action is not None and timer_raw == build_systemd_user_timer(recorded_action).encode("utf-8")
        checks.update(
            {
                "service_argv": service_argv == expected_argv,
                "argv": service_argv == expected_argv,
                "service_executable": bool(service_argv and expected_executable and service_argv[0] == str(expected_executable)),
                "working_directory": service_working == [str(settings.paths.engine_root)],
                "timer_unit": _unit_value(timer_raw, "Timer", "Unit") == f"{TASK_NAME}.service" if timer_raw is not None else False,
                "timer_interval": _unit_values(timer_raw, "Timer", "OnUnitActiveSec") == [f"{_interval_minutes_from_state(expected)}min", f"{2 * _interval_minutes_from_state(expected)}min"] if timer_raw is not None else False,
                "timer_persistent": str(_unit_value(timer_raw, "Timer", "Persistent")).casefold() == "true" if timer_raw is not None else False,
                "service_generated_definition": service_definition_ok,
                "timer_generated_definition": timer_definition_ok,
                "unit_content_identity": service_argv == expected_argv and service_working == [str(settings.paths.engine_root)] and service_definition_ok,
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
        "State=[string]$task.State;Enabled=$task.Settings.Enabled} | ConvertTo-Json -Compress"
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
        "manager_enabled": live.get("Enabled") is True and task_state in {"ready", "running", "queued"},
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
    if normalized_platform == "linux" and not check_only and not _systemd_artifacts_are_owned(settings, action):
        return {"ok": False, "requested": True, "status": "REGISTRATION_BLOCKED", "reason_code": "SCHEDULER_ARTIFACT_CONFLICT", "registered": False, "retryable": False, "platform": normalized_platform}
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
        if normalized_platform == "windows" and "PSSecurityException" in str(completed.stderr):
            state_path = None if check_only else write_scheduler_state(settings, action, False, completed.returncode)
            return {"ok": False, "requested": True, "status": "REGISTRATION_DENIED", "reason_code": "SCHEDULER_REGISTRATION_DENIED", "registered": False, "retryable": False, "error_type": "PSSecurityException", "state_path": str(state_path) if state_path else None, "platform": normalized_platform}
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
