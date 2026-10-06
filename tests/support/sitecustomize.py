"""Opt-in, test-only isolation for the Windows notification process boundary."""

from __future__ import annotations

import os
import sys
_ENABLED = "EI_TEST_NOTIFICATION_ISOLATION"
_BOOTSTRAP_IMPORT_FAILURE = "EI_TEST_NOTIFICATION_BOOTSTRAP_IMPORT_FAILURE"
_INITIAL_IMPORT_FAILURE = "EI_TEST_NOTIFICATION_INITIAL_IMPORT_FAILURE"
_BOOTSTRAP_FAILURE = "EI_TEST_NOTIFICATION_BOOTSTRAP_FAILURE"

try:
    if os.environ.get(_ENABLED) == "1" and os.environ.get(_INITIAL_IMPORT_FAILURE) == "1" and len(sys.argv) > 1:
        sys.modules.pop("shutil", None)

        class _FailShutilImport:
            def find_spec(self, fullname, *args, **kwargs):
                if fullname == "shutil":
                    raise OSError(10106, "injected initial sitecustomize import failure")
                return None

        sys.meta_path.insert(0, _FailShutilImport())
    import shutil
    import stat
    import venv
    if os.environ.get(_ENABLED) == "1" and os.environ.get(_BOOTSTRAP_IMPORT_FAILURE) == "1" and len(sys.argv) > 1:
        class _FailUnittestMockImport:
            def find_spec(self, fullname, *args, **kwargs):
                if fullname == "unittest.mock":
                    raise OSError(10106, "injected early test-bootstrap import failure")
                return None

        sys.meta_path.insert(0, _FailUnittestMockImport())
        import unittest.mock
    import hashlib
    import json
    from pathlib import Path
    import re
    import subprocess
    import tempfile
    from typing import Any
except BaseException as exc:
    if os.environ.get(_ENABLED) == "1":
        error_code = getattr(exc, "errno", None)
        detail = f":{error_code}" if type(error_code) is int else ""
        sys.stderr.write(f"NOTIFICATION_TEST_BOOTSTRAP_FAILED{detail}\n")
        sys.stderr.flush()
        raise SystemExit(125) from exc
    raise


_ROOT = "EI_TEST_NOTIFICATION_ROOT"
_TARGET = "EI_TEST_NOTIFICATION_TARGET"
_PRIVATE_SYSTEM_ROOT = "EI_TEST_NOTIFICATION_PRIVATE_SYSTEM_ROOT"
_HELPER_ROOT = "EI_TEST_NOTIFICATION_HELPER_ROOT"
_SUPPORT = "EI_TEST_NOTIFICATION_SUPPORT"
_REAL_PYTHON = "EI_TEST_REAL_PYTHON"
_ALLOW_HELPER = "EI_TEST_NOTIFICATION_ALLOW_HELPER"
_HELPER_NAME = "register-windows-notification.ps1"
_APP_ID = "MiyaIF.ExternalIntelligence"
_FAKE_SHORTCUT = b"owned test-only shortcut fixture\n"
_INERT_POWERSHELL = b"inert test-only powershell sentinel"
_REPOSITORY = Path(__file__).resolve().parents[2]


def is_powershell_execution_policy_refusal(*output_parts: str | bytes | None) -> bool:
    """Recognize only PowerShell's specific unsigned-script policy diagnostics."""
    text = "\n".join(
        part.decode("utf-8", errors="replace") if isinstance(part, bytes) else (part or "")
        for part in output_parts
    ).replace("\x00", "").casefold()
    compact = "".join(character for character in text if not character.isspace())
    policy_help = "about_execution_policies" in compact
    english_policy_message = "runningscriptsisdisabled" in compact and policy_help
    has_fqid = "fullyqualifiederrorid" in compact
    has_policy_exception = any(
        marker in compact
        for marker in ("unauthorizedaccess", "pssecurityexception", "authorizationmanagercheckfailed")
    )
    return english_policy_message or (policy_help and has_fqid and has_policy_exception)


def _arg_text(value: Any) -> str:
    try:
        return os.fsdecode(os.fspath(value))
    except TypeError:
        return str(value)


def _path_key(value: str | os.PathLike[str]) -> str:
    return os.path.normcase(os.path.abspath(os.fspath(value)))


def _helper_script() -> Path:
    return Path(os.environ.get(_HELPER_ROOT, _REPOSITORY)) / "scripts" / "notifications" / _HELPER_NAME


def _validate_private_system_root() -> None:
    root_value = os.environ.get(_ROOT)
    private_value = os.environ.get(_PRIVATE_SYSTEM_ROOT)
    target_value = os.environ.get(_TARGET)
    system_value = os.environ.get("SystemRoot")
    if not all((root_value, private_value, target_value, system_value)):
        raise RuntimeError("private SystemRoot fixture is incomplete")
    root = Path(root_value).resolve(strict=True)
    expected_private = (root / "Windows").resolve(strict=True)
    private = Path(private_value).resolve(strict=True)
    actual_system = Path(system_value).resolve(strict=True)
    expected_target = expected_private / "System32" / "WindowsPowerShell" / "v1.0" / "powershell.exe"
    target = Path(target_value).resolve(strict=True)
    if private != expected_private or actual_system != expected_private or target != expected_target.resolve(strict=True):
        raise RuntimeError("private SystemRoot fixture does not match its owned root")
    paths = (
        root,
        expected_private,
        expected_private / "System32",
        expected_private / "System32" / "WindowsPowerShell",
        expected_private / "System32" / "WindowsPowerShell" / "v1.0",
        expected_target,
    )
    for path in paths:
        info = path.lstat()
        if stat.S_ISLNK(info.st_mode) or getattr(info, "st_file_attributes", 0) & 0x400:
            raise RuntimeError("private SystemRoot fixture contains a reparse point")
    if not expected_target.is_file() or expected_target.read_bytes() != _INERT_POWERSHELL:
        raise RuntimeError("private SystemRoot helper is not the inert fixture")


def _looks_like_notification_helper(command: Any) -> bool:
    if isinstance(command, (str, bytes, os.PathLike)):
        return _HELPER_NAME.casefold() in _arg_text(command).casefold()
    if not isinstance(command, (tuple, list)):
        return False
    arguments = [_arg_text(item) for item in command]
    if any(Path(item).name.casefold() == _HELPER_NAME.casefold() for item in arguments):
        return True
    return any(item.casefold() == "-action" for item in arguments) and any(
        item.casefold() == "-target" for item in arguments
    ) and any(Path(item).name.casefold() == "powershell.exe" for item in arguments)


def _invalid(detail: str) -> AssertionError:
    return AssertionError(f"NOTIFICATION_TEST_UNEXPECTED_HELPER_ARGV: {detail}")


def _unexpected_helper_call() -> AssertionError:
    sys.stderr.write("NOTIFICATION_TEST_UNEXPECTED_HELPER_CALL\n")
    sys.stderr.flush()
    return AssertionError("NOTIFICATION_TEST_UNEXPECTED_HELPER_CALL")


def _command_items(command: Any) -> list[str]:
    if isinstance(command, (str, bytes, os.PathLike)):
        return [_arg_text(command)]
    if isinstance(command, (tuple, list)):
        return [_arg_text(item) for item in command]
    return []


def _is_powershell_executable(value: str) -> bool:
    name = value.strip().strip('"\'')
    name = name.replace("\\", "/").rsplit("/", 1)[-1].casefold()
    return name in {"powershell", "powershell.exe", "pwsh", "pwsh.exe"}


def _powershell_command_text(command: Any, executable: Any, shell: bool) -> str | None:
    items = _command_items(command)
    executable_text = _arg_text(executable) if executable is not None else ""
    if executable_text and _is_powershell_executable(executable_text):
        return " ".join(items)
    if items and _is_powershell_executable(items[0]):
        return " ".join(items[1:])
    if not items:
        return None

    # Shell wrappers are inspected only for an embedded PowerShell executable;
    # ordinary Python/Git commands remain delegated unchanged.
    wrapper_names = {"cmd", "cmd.exe", "sh", "sh.exe", "bash", "bash.exe", "dash"}
    first = items[0].replace("\\", "/").rsplit("/", 1)[-1].casefold()
    joined = " ".join(items)
    if shell or first in wrapper_names:
        if re.search(
            r"(?i)(?:^|[\s\"'])[^\s\"']*(?:\\|/)?(?:powershell|pwsh)(?:\.exe)?(?=$|[\s\"'])",
            joined,
        ):
            return joined
    return None


def _reject_powershell_policy_changes(command: Any, *, executable: Any = None, shell: bool = False) -> None:
    text = _powershell_command_text(command, executable, shell)
    if text is None:
        return
    normalized = text.replace("`", "")
    if re.search(r"(?i)(?:^|[\s\"'])[-/](?:executionpolicy|ep)(?=$|[\s:=\"'])", normalized):
        raise AssertionError("TEST_ONLY_POWERSHELL_POLICY_CHANGE_BLOCKED")
    if re.search(
        r"(?i)(?<![\w-])(?:set-executionpolicy|set-executionpolic|set-executionpoli|set-executionpol|set-execpolicy|set-ep|sep)(?![\w-])",
        normalized,
    ):
        raise AssertionError("TEST_ONLY_POWERSHELL_POLICY_CHANGE_BLOCKED")


def _validate_helper_call(command: Any, kwargs: dict[str, Any]) -> tuple[str, str, dict[str, str], dict[str, str]]:
    if not isinstance(command, (tuple, list)) or not command or any(not isinstance(item, str) for item in command):
        raise _invalid("argv must be a string sequence")
    root = os.environ.get(_ROOT)
    system_root = os.environ.get("SystemRoot")
    target = os.environ.get(_TARGET)
    if not root or not system_root or not target:
        raise _invalid("isolation roots or expected target are missing")
    expected_executable = Path(system_root) / "System32" / "WindowsPowerShell" / "v1.0" / "powershell.exe"
    expected_script = _helper_script()
    prefix = [
        str(expected_executable), "-NoLogo", "-NoProfile", "-NonInteractive", "-WindowStyle", "Hidden",
        "-File", str(expected_script), "-Action",
    ]
    argv = list(command)
    if argv[:len(prefix)] != prefix:
        raise _invalid("fixed executable or helper arguments differ")
    try:
        action_index = len(prefix)
        action = argv[action_index]
        if action not in {"Register", "Verify", "Unregister"} or argv[action_index + 1] != "-Target":
            raise _invalid("action or target switch is invalid")
        supplied_target = argv[action_index + 2]
    except IndexError as exc:
        raise _invalid("action or target is incomplete") from exc
    if _path_key(supplied_target) != _path_key(target):
        raise AssertionError("NOTIFICATION_TEST_UNEXPECTED_TARGET")
    tail = argv[action_index + 3:]
    options: dict[str, str] = {}
    if len(tail) % 2:
        raise _invalid("optional hash arguments are unpaired")
    for name, value in zip(tail[::2], tail[1::2]):
        if name not in {"-ExpectedShortcutSha256", "-ExpectedRegistrationSha256"} or name in options:
            raise _invalid("unknown or duplicate optional argument")
        if len(value) != 64 or any(char not in "0123456789abcdef" for char in value):
            raise _invalid("optional hash is malformed")
        options[name] = value
    expected_kwargs = {
        "shell": False,
        "creationflags": 0x08000000 if os.name == "nt" else 0,
        "timeout": 15,
        "capture_output": True,
        "text": True,
        "encoding": "utf-8",
        "errors": "replace",
        "check": False,
    }
    if kwargs != expected_kwargs:
        raise _invalid("process options differ from the fixed contract")
    paths = {
        "shortcut": str(Path(os.environ["APPDATA"]) / "Microsoft" / "Windows" / "Start Menu" / "Programs" / "External Intelligence.lnk"),
        "registration": str(Path(os.environ["LOCALAPPDATA"]) / "MiyaIF" / "ExternalIntelligence" / "notification-registration.json"),
        "root": root,
    }
    root_key = _path_key(root)
    if any(_path_key(value) != root_key and not _path_key(value).startswith(root_key + os.sep) for value in paths.values()):
        raise _invalid("derived artifacts are outside the owned temporary root")
    return action, supplied_target, paths, options


def _record_bytes(shortcut_hash: str, target: str) -> bytes:
    return json.dumps({
        "schema_version": 1,
        "app_id": _APP_ID,
        "shortcut_sha256": shortcut_hash,
        "target": target,
    }, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _fake_helper_result(command: Any, action: str, target: str, paths: dict[str, str], options: dict[str, str]) -> subprocess.CompletedProcess[str]:
    shortcut = Path(paths["shortcut"])
    registration = Path(paths["registration"])
    shortcut_hash = hashlib.sha256(_FAKE_SHORTCUT).hexdigest()
    record = _record_bytes(shortcut_hash, target)
    record_hash = hashlib.sha256(record).hexdigest()
    status = "UNAVAILABLE"
    verified = False
    reason_code = "TEST_FIXTURE_STATE_INVALID"

    if action == "Register":
        if not shortcut.exists() and not registration.exists():
            shortcut.parent.mkdir(parents=True, exist_ok=True)
            registration.parent.mkdir(parents=True, exist_ok=True)
            shortcut.write_bytes(_FAKE_SHORTCUT)
            registration.write_bytes(record)
            status, verified, reason_code = "REGISTERED", True, "TEST_FIXTURE_REGISTERED"
        elif shortcut.is_file() and registration.is_file() and shortcut.read_bytes() == _FAKE_SHORTCUT and registration.read_bytes() == record:
            status, verified, reason_code = "CURRENT", True, "TEST_FIXTURE_CURRENT"
        else:
            status, reason_code = "CONFLICT", "TEST_FIXTURE_CONFLICT"
    elif action == "Verify":
        hashes_match = (
            options.get("-ExpectedShortcutSha256", shortcut_hash) == shortcut_hash
            and options.get("-ExpectedRegistrationSha256", record_hash) == record_hash
        )
        if hashes_match and shortcut.is_file() and registration.is_file() and shortcut.read_bytes() == _FAKE_SHORTCUT and registration.read_bytes() == record:
            status, verified, reason_code = "CURRENT", True, "TEST_FIXTURE_CURRENT"
        else:
            status, reason_code = "UNAVAILABLE", "TEST_FIXTURE_MISSING"
    else:
        if not shortcut.exists() and not registration.exists():
            status, verified, reason_code = "REMOVED", True, "TEST_FIXTURE_ALREADY_ABSENT"
        elif (
            options.get("-ExpectedShortcutSha256", shortcut_hash) == shortcut_hash
            and options.get("-ExpectedRegistrationSha256", record_hash) == record_hash
            and shortcut.is_file()
            and registration.is_file()
            and shortcut.read_bytes() == _FAKE_SHORTCUT
            and registration.read_bytes() == record
        ):
            shortcut.unlink()
            registration.unlink()
            status, verified, reason_code = "REMOVED", True, "TEST_FIXTURE_REMOVED"
        else:
            status, reason_code = "CONFLICT", "TEST_FIXTURE_CONFLICT"
    response = {
        "status": status,
        "verified": verified,
        "target": target,
        "shortcut_sha256": shortcut_hash,
        "registration_sha256": record_hash,
        "reason_code": reason_code,
    }
    return subprocess.CompletedProcess(command, 0, stdout=json.dumps(response, separators=(",", ":")), stderr="")


def _install_guard() -> None:
    current_run = subprocess.run
    if not getattr(current_run, "_ei_notification_isolation", False):
        def guarded_run(*popenargs: Any, **kwargs: Any) -> Any:
            command = popenargs[0] if popenargs else kwargs.get("args")
            _reject_powershell_policy_changes(
                command,
                executable=kwargs.get("executable"),
                shell=bool(kwargs.get("shell", False)),
            )
            if not _looks_like_notification_helper(command):
                return current_run(*popenargs, **kwargs)
            if len(popenargs) != 1 or "args" in kwargs:
                raise _invalid("unexpected subprocess.run calling convention")
            action, target, paths, options = _validate_helper_call(command, kwargs)
            if os.environ.get(_ALLOW_HELPER) != "1":
                raise _unexpected_helper_call()
            return _fake_helper_result(command, action, target, paths, options)

        guarded_run._ei_notification_isolation = True  # type: ignore[attr-defined]
        subprocess.run = guarded_run  # type: ignore[assignment]

    current_popen = subprocess.Popen
    if getattr(current_popen, "_ei_notification_isolation", False):
        return

    if isinstance(current_popen, type):
        class GuardedPopen(current_popen):  # type: ignore[misc, valid-type]
            _ei_notification_isolation = True

            def __new__(cls, *popenargs: Any, **kwargs: Any) -> Any:
                command = popenargs[0] if popenargs else kwargs.get("args")
                _reject_powershell_policy_changes(
                    command,
                    executable=kwargs.get("executable"),
                    shell=bool(kwargs.get("shell", False)),
                )
                if _looks_like_notification_helper(command):
                    raise _unexpected_helper_call()
                parent_new = getattr(current_popen, "__new__", object.__new__)
                if parent_new is object.__new__:
                    return object.__new__(cls)
                return parent_new(cls, *popenargs, **kwargs)

            def __init__(self, *popenargs: Any, **kwargs: Any) -> None:
                super().__init__(*popenargs, **kwargs)

        GuardedPopen.__name__ = getattr(current_popen, "__name__", "Popen")
        GuardedPopen.__qualname__ = getattr(current_popen, "__qualname__", "Popen")
        subprocess.Popen = GuardedPopen  # type: ignore[assignment]
    else:
        def guarded_popen(*popenargs: Any, **kwargs: Any) -> Any:
            command = popenargs[0] if popenargs else kwargs.get("args")
            _reject_powershell_policy_changes(
                command,
                executable=kwargs.get("executable"),
                shell=bool(kwargs.get("shell", False)),
            )
            if _looks_like_notification_helper(command):
                raise _unexpected_helper_call()
            return current_popen(*popenargs, **kwargs)

        guarded_popen._ei_notification_isolation = True  # type: ignore[attr-defined]
        subprocess.Popen = guarded_popen  # type: ignore[assignment]


class NotificationIsolation:
    """Own temporary Windows profile roots and fake only the fixed helper process."""

    _ENVIRONMENT = (
        _ENABLED, _ROOT, _TARGET, _PRIVATE_SYSTEM_ROOT, _HELPER_ROOT,
        _ALLOW_HELPER, "SystemRoot", "APPDATA", "LOCALAPPDATA",
    )

    def __init__(self, expected_target: str | os.PathLike[str] | None = None) -> None:
        self.expected_target = os.fspath(expected_target) if expected_target is not None else None
        self._saved_environment: dict[str, str | None] = {}
        self._temporary: tempfile.TemporaryDirectory[str] | None = None
        self._previous_run: Any = None
        self._previous_popen: Any = None
        self.root: Path | None = None

    def __enter__(self) -> "NotificationIsolation":
        from unittest.mock import patch

        self._temporary = tempfile.TemporaryDirectory(prefix="ei-notification-test-")
        self.root = Path(self._temporary.name).resolve()
        self._saved_environment = {name: os.environ.get(name) for name in self._ENVIRONMENT}
        windows = self.root / "Windows"
        executable = windows / "System32" / "WindowsPowerShell" / "v1.0" / "powershell.exe"
        executable.parent.mkdir(parents=True)
        executable.write_bytes(b"inert test-only powershell sentinel")
        self.expected_target = self.expected_target or os.fspath(executable)
        os.environ.update({
            _ENABLED: "1",
            _ROOT: str(self.root),
            _TARGET: self.expected_target,
            _PRIVATE_SYSTEM_ROOT: str(windows),
            _HELPER_ROOT: str(_REPOSITORY),
            _ALLOW_HELPER: "0",
            "SystemRoot": str(windows),
            "APPDATA": str(self.root / "Roaming"),
            "LOCALAPPDATA": str(self.root / "Local"),
        })
        self._previous_run = subprocess.run
        self._previous_popen = subprocess.Popen
        _install_guard()
        import ei.installer

        self._installer_patch = patch.object(
            ei.installer,
            "_run_windows_notification_registration",
            self._fake_engine_helper,
        )
        self._installer_patch.start()
        return self

    def _fake_engine_helper(
        self,
        action: str,
        target: str | os.PathLike[str],
        *,
        expected_shortcut_sha256: str | None = None,
        expected_registration_sha256: str | None = None,
    ) -> dict[str, Any]:
        if action not in {"register", "verify", "unregister"}:
            raise AssertionError("NOTIFICATION_TEST_UNEXPECTED_HELPER_ARGV: unknown action")
        command = [
            str(Path(os.environ["SystemRoot"]) / "System32" / "WindowsPowerShell" / "v1.0" / "powershell.exe"),
            "-NoLogo", "-NoProfile", "-NonInteractive", "-WindowStyle", "Hidden", "-File", str(_helper_script()),
            "-Action", {"register": "Register", "verify": "Verify", "unregister": "Unregister"}[action],
            "-Target", os.fspath(target),
        ]
        if expected_shortcut_sha256 is not None:
            command.extend(("-ExpectedShortcutSha256", expected_shortcut_sha256))
        if expected_registration_sha256 is not None:
            command.extend(("-ExpectedRegistrationSha256", expected_registration_sha256))
        kwargs = {
            "shell": False,
            "creationflags": 0x08000000 if os.name == "nt" else 0,
            "timeout": 15,
            "capture_output": True,
            "text": True,
            "encoding": "utf-8",
            "errors": "replace",
            "check": False,
        }
        checked_action, checked_target, paths, options = _validate_helper_call(command, kwargs)
        if os.environ.get(_ALLOW_HELPER) != "1":
            raise _unexpected_helper_call()
        completed = _fake_helper_result(command, checked_action, checked_target, paths, options)
        return json.loads(completed.stdout)

    def allow_notification_helper(self) -> None:
        os.environ[_ALLOW_HELPER] = "1"

    def reject_notification_helper(self) -> None:
        os.environ[_ALLOW_HELPER] = "0"

    def __exit__(self, exc_type: Any, exc: Any, traceback: Any) -> bool:
        self._installer_patch.stop()
        subprocess.run = self._previous_run
        subprocess.Popen = self._previous_popen
        for name, value in self._saved_environment.items():
            if value is None:
                os.environ.pop(name, None)
            else:
                os.environ[name] = value
        if self._temporary is not None:
            self._temporary.cleanup()
        return False


if os.environ.get(_ENABLED) == "1":
    try:
        if os.environ.get(_PRIVATE_SYSTEM_ROOT):
            _validate_private_system_root()
        if os.environ.get(_BOOTSTRAP_FAILURE) == "1" and len(sys.argv) > 1:
            raise RuntimeError("requested test bootstrap failure")
        _install_guard()
    except BaseException as exc:
        sys.stderr.write("NOTIFICATION_TEST_BOOTSTRAP_FAILED\n")
        sys.stderr.flush()
        raise SystemExit(125) from exc


class NotificationIsolationMixin:
    """Install a per-test owned fixture for direct installer lifecycle calls."""

    def setUp(self) -> None:
        super().setUp()  # type: ignore[misc]
        self.notification_isolation = NotificationIsolation()
        self.notification_isolation.__enter__()
        self.addCleanup(self.notification_isolation.__exit__, None, None, None)

    def notification_child_environment(
        self,
        *,
        engine_root: str | os.PathLike[str] | None = None,
        target: str | os.PathLike[str] | None = None,
        allow_notification_helper: bool = False,
    ) -> dict[str, str]:
        isolation = self.notification_isolation
        if isolation.root is None or isolation.expected_target is None:
            raise RuntimeError("notification isolation fixture is not active")
        engine = Path(engine_root or _REPOSITORY).resolve()
        environment = dict(os.environ)
        environment.update({
            _ENABLED: "1",
            _ROOT: str(isolation.root),
            _TARGET: os.fspath(target or isolation.expected_target),
            _PRIVATE_SYSTEM_ROOT: os.environ[_PRIVATE_SYSTEM_ROOT],
            _HELPER_ROOT: str(engine),
            _SUPPORT: str(_REPOSITORY / "tests" / "support"),
            _REAL_PYTHON: sys.executable,
            "SystemRoot": os.environ["SystemRoot"],
            "APPDATA": os.environ["APPDATA"],
            "LOCALAPPDATA": os.environ["LOCALAPPDATA"],
            _ALLOW_HELPER: "1" if allow_notification_helper else "0",
        })
        paths = [str(_REPOSITORY / "tests" / "support"), str(engine / "src")]
        if environment.get("PYTHONPATH"):
            paths.append(environment["PYTHONPATH"])
        environment["PYTHONPATH"] = os.pathsep.join(paths)
        return environment

    def isolated_python_executable(self) -> Path:
        """Create a disposable interpreter whose sitecustomize also loads with -I."""
        isolation = self.notification_isolation
        if isolation.root is None:
            raise RuntimeError("notification isolation fixture is not active")
        environment_root = isolation.root / "isolated-python-environment"
        venv.EnvBuilder(with_pip=False, clear=False).create(environment_root)
        if os.name == "nt":
            executable = environment_root / "Scripts" / "python.exe"
            site_packages = environment_root / "Lib" / "site-packages"
        else:
            executable = environment_root / "bin" / "python"
            site_packages = environment_root / "lib" / f"python{sys.version_info.major}.{sys.version_info.minor}" / "site-packages"
        if not executable.is_file() or not site_packages.is_dir():
            raise RuntimeError("isolated Python environment layout is unsupported")
        shutil.copyfile(_REPOSITORY / "tests" / "support" / "sitecustomize.py", site_packages / "sitecustomize.py")
        return executable

    def powershell_python_shim(self) -> Path:
        root = self.notification_isolation.root
        if root is None:
            raise RuntimeError("notification isolation fixture is not active")
        path = root / "isolated-python-test-shim.ps1"
        source = r'''param()
$ErrorActionPreference = 'Stop'
$arguments = @($args)
$shimPath = [IO.Path]::GetFullPath([string]$MyInvocation.MyCommand.Path)
$probe = 'import sys,venv,ensurepip; sys.exit(1) if sys.version_info < (3,11) else None; print(sys.executable)'
$bootstrap = "import runpy,sys;source=sys.argv.pop(1);sys.path.insert(0,source);runpy.run_module('ei.installer',run_name='__main__')"
function Get-EiPrivateSystemRoot {
  $root = [IO.Path]::GetFullPath([string]$env:EI_TEST_NOTIFICATION_ROOT)
  $privateRoot = [IO.Path]::GetFullPath([string]$env:EI_TEST_NOTIFICATION_PRIVATE_SYSTEM_ROOT)
  $expectedRoot = [IO.Path]::GetFullPath((Join-Path $root 'Windows'))
  if (-not [string]::Equals($privateRoot, $expectedRoot, [StringComparison]::OrdinalIgnoreCase)) { throw 'private root mismatch' }
  $target = [IO.Path]::GetFullPath([string]$env:EI_TEST_NOTIFICATION_TARGET)
  $sentinel = [IO.Path]::GetFullPath((Join-Path $privateRoot 'System32/WindowsPowerShell/v1.0/powershell.exe'))
  if (-not [string]::Equals($target, $sentinel, [StringComparison]::OrdinalIgnoreCase)) { throw 'private target mismatch' }
  $checkedPaths = @(
    $root,
    $privateRoot,
    (Join-Path $privateRoot 'System32'),
    (Join-Path $privateRoot 'System32/WindowsPowerShell'),
    (Join-Path $privateRoot 'System32/WindowsPowerShell/v1.0'),
    $sentinel
  )
  foreach ($path in $checkedPaths) {
    $item = Get-Item -Force -LiteralPath $path -ErrorAction Stop
    if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { throw 'private fixture contains a reparse point' }
  }
  if (-not $item.PSIsContainer -and [IO.File]::ReadAllText($sentinel, [Text.Encoding]::ASCII) -ne 'inert test-only powershell sentinel') { throw 'private helper is not inert' }
  return $privateRoot
}
function Get-EiRealPython {
  if ([string]::IsNullOrWhiteSpace([string]$env:EI_TEST_REAL_PYTHON)) { return $null }
  try {
    $realPython = [IO.Path]::GetFullPath([string]$env:EI_TEST_REAL_PYTHON)
    $item = Get-Item -Force -LiteralPath $realPython -ErrorAction Stop
    if ($item.PSIsContainer -or -not (Test-Path -LiteralPath $realPython -PathType Leaf) -or (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0)) { return $null }
    return $realPython
  } catch {
    return $null
  }
}
function Test-EiSetupArguments {
  if ($arguments.Count -lt 10 -or $arguments.Count -gt 96 -or $arguments[0] -ne '-I' -or $arguments[1] -ne '-B' -or $arguments[2] -ne '-X' -or $arguments[3] -ne 'utf8' -or $arguments[4] -ne '-c' -or $arguments[5] -ne $bootstrap -or -not (Test-Path -LiteralPath ([string]$arguments[6]) -PathType Container) -or ([IO.Path]::GetFileName([string]$arguments[6]) -ne 'src') -or $arguments[7] -ne '--setup') { return $false }
  $valueOptions = @('--python-exe', '--privacy-profile', '--skill-mode', '--repo', '--engine-root', '--knowledge-mode', '--knowledge-root', '--personal-knowledge-root', '--team-knowledge-root', '--team-member-id', '--runtime-root', '--github-repository', '--github-executable', '--remote-name', '--branch', '--confirm-github-create', '--hosts', '--host-home', '--providers', '--organizer-provider', '--organizer-host')
  $repeatableValueOptions = @('--hosts', '--host-home', '--providers')
  $switchOptions = @('--no-team-knowledge', '--sync', '--no-sync', '--experiment', '--scheduler', '--no-scheduler', '--check-only', '--verify-operation', '--allow-model-test', '--allow-notification-test', '--non-interactive', '--accept-plan', '--skip-venv', '--json')
  $seen = @{}
  for ($index = 8; $index -lt $arguments.Count; $index++) {
    $option = [string]$arguments[$index]
    if ($valueOptions -contains $option) {
      if ($index + 1 -ge $arguments.Count -or [string]::IsNullOrWhiteSpace([string]$arguments[$index + 1]) -or ([string]$arguments[$index + 1]).StartsWith('--')) { return $false }
      if ($seen.ContainsKey($option) -and $repeatableValueOptions -notcontains $option) { return $false }
      $value = [string]$arguments[$index + 1]
      if ($option -eq '--python-exe' -and -not [string]::Equals($value, $shimPath, [StringComparison]::OrdinalIgnoreCase)) { return $false }
      $seen[$option] = $true
      $index++
    } elseif ($switchOptions -contains $option) {
      if ($seen.ContainsKey($option)) { return $false }
      $seen[$option] = $true
    } else {
      return $false
    }
  }
  $setupCount = @($arguments[7..($arguments.Count - 1)] | Where-Object { $_ -eq '--setup' }).Count
  $pythonCount = @($arguments[7..($arguments.Count - 1)] | Where-Object { $_ -eq '--python-exe' }).Count
  $hasRepository = $seen.ContainsKey('--repo') -xor $seen.ContainsKey('--engine-root')
  return $setupCount -eq 1 -and $pythonCount -eq 1 -and $seen.ContainsKey('--privacy-profile') -and $seen.ContainsKey('--skill-mode') -and $hasRepository -and -not ($seen.ContainsKey('--sync') -and $seen.ContainsKey('--no-sync')) -and -not ($seen.ContainsKey('--scheduler') -and $seen.ContainsKey('--no-scheduler'))
}
function Write-EiArgumentTrace {
  param([object[]]$RawArguments, [object[]]$ForwardedArguments)
  if ([string]::IsNullOrWhiteSpace([string]$env:EI_TEST_PYTHON_SHIM_TRACE)) { return $true }
  try {
    $root = [IO.Path]::GetFullPath([string]$env:EI_TEST_NOTIFICATION_ROOT)
    $trace = [IO.Path]::GetFullPath([string]$env:EI_TEST_PYTHON_SHIM_TRACE)
    if (-not [string]::Equals([IO.Path]::GetDirectoryName($trace), $root, [StringComparison]::OrdinalIgnoreCase)) { return $false }
    $json = @{rawArguments=@($RawArguments); forwardedArguments=@($ForwardedArguments)} | ConvertTo-Json -Depth 4 -Compress
    $bytes = [Text.Encoding]::UTF8.GetBytes($json)
    if ($bytes.Length -gt 16384) { return $false }
    $stream = [IO.File]::Open($trace, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::None)
    try { $stream.Write($bytes, 0, $bytes.Length) } finally { $stream.Dispose() }
    return $true
  } catch {
    return $false
  }
}
function Test-EiUninstallArguments {
  if ($arguments.Count -lt 8 -or $arguments[0] -ne '-B' -or $arguments[1] -ne '-m' -or $arguments[2] -ne 'ei.installer' -or $arguments[3] -ne '--uninstall') { return $false }
  $valueOptions = @('--manifest', '--python-exe', '--confirm-manifest-sha256')
  $switchOptions = @('--restore-config-backup', '--remove-runtime-cache', '--remove-runtime', '--remove-venv', '--keep-skills', '--no-scheduled-task', '--force', '--check-only', '--json')
  $seen = @{}
  for ($index = 4; $index -lt $arguments.Count; $index++) {
    $option = [string]$arguments[$index]
    if ($valueOptions -contains $option) {
      if ($seen.ContainsKey($option) -or $index + 1 -ge $arguments.Count -or [string]::IsNullOrWhiteSpace([string]$arguments[$index + 1]) -or ([string]$arguments[$index + 1]).StartsWith('--')) { return $false }
      $seen[$option] = $true
      $index++
    } elseif ($switchOptions -contains $option) {
      if ($seen.ContainsKey($option)) { return $false }
      $seen[$option] = $true
    } else {
      return $false
    }
  }
  $pythonIndex = [Array]::IndexOf([string[]]$arguments, '--python-exe')
  return $seen.ContainsKey('--manifest') -and $seen.ContainsKey('--python-exe') -and [string]::Equals([string]$arguments[$pythonIndex + 1], $shimPath, [StringComparison]::OrdinalIgnoreCase)
}
if ($arguments.Count -eq 4 -and $arguments[0] -eq '-I' -and $arguments[1] -eq '-B' -and $arguments[2] -eq '-c' -and $arguments[3] -eq $probe) {
  $realPython = Get-EiRealPython
  if ([string]::IsNullOrWhiteSpace([string]$realPython)) {
    [Console]::Error.WriteLine('EI_TEST_PYTHON_SHIM_REAL_PYTHON_INVALID')
    $global:LASTEXITCODE = 125
    if ($MyInvocation.ScriptName) { return }
    exit 125
  }
  $outerSystemRoot = $env:SystemRoot
  $probeOutput = @()
  $probeExit = 125
  try {
    $env:SystemRoot = Get-EiPrivateSystemRoot
    $probeOutput = & $realPython @arguments 2>&1
    $probeExit = $LASTEXITCODE
  } catch {
    [Console]::Error.WriteLine('EI_TEST_PYTHON_SHIM_PRIVATE_SYSTEMROOT_INVALID')
  } finally {
    $env:SystemRoot = $outerSystemRoot
  }
  if ($probeExit -ne 0) {
    foreach ($line in $probeOutput) { [Console]::Error.WriteLine([string]$line) }
    $global:LASTEXITCODE = $probeExit
    if ($MyInvocation.ScriptName) { return }
    exit $probeExit
  }
  Write-Output $MyInvocation.MyCommand.Path
  $global:LASTEXITCODE = 0
  return
}
if (Test-EiSetupArguments) {
  $realPython = Get-EiRealPython
  if ([string]::IsNullOrWhiteSpace([string]$realPython)) {
    [Console]::Error.WriteLine('EI_TEST_PYTHON_SHIM_REAL_PYTHON_INVALID')
    $global:LASTEXITCODE = 125
    if ($MyInvocation.ScriptName) { return }
    exit 125
  }
  $preload = 'import os,sys;sys.path.insert(0,os.environ["EI_TEST_NOTIFICATION_SUPPORT"]);import sitecustomize;exec(sys.argv.pop(1))'
  $rawCliArguments = @($arguments[6..($arguments.Count - 1)])
  $mappedCliArguments = @($rawCliArguments)
  $pythonIndex = [Array]::IndexOf([string[]]$mappedCliArguments, '--python-exe')
  $mappedCliArguments[$pythonIndex + 1] = $realPython
  $forward = @('-I', '-B', '-X', 'utf8', '-c', $preload, $bootstrap) + $mappedCliArguments
  if (-not (Write-EiArgumentTrace -RawArguments $arguments -ForwardedArguments $forward)) {
    [Console]::Error.WriteLine('EI_TEST_PYTHON_SHIM_TRACE_INVALID')
    $global:LASTEXITCODE = 125
    if ($MyInvocation.ScriptName) { return }
    exit 125
  }
  $outerSystemRoot = $env:SystemRoot
  $childExit = 125
  try {
    $env:SystemRoot = Get-EiPrivateSystemRoot
    & $realPython @forward
    $childExit = $LASTEXITCODE
  } catch {
    [Console]::Error.WriteLine('EI_TEST_PYTHON_SHIM_PRIVATE_SYSTEMROOT_INVALID')
  } finally {
    $env:SystemRoot = $outerSystemRoot
  }
  $global:LASTEXITCODE = $childExit
  return
}
if (Test-EiUninstallArguments) {
  $realPython = Get-EiRealPython
  if ([string]::IsNullOrWhiteSpace([string]$realPython)) {
    [Console]::Error.WriteLine('EI_TEST_PYTHON_SHIM_REAL_PYTHON_INVALID')
    $global:LASTEXITCODE = 125
    if ($MyInvocation.ScriptName) { return }
    exit 125
  }
  $forward = @($arguments)
  $pythonIndex = [Array]::IndexOf([string[]]$forward, '--python-exe')
  $forward[$pythonIndex + 1] = $realPython
  if (-not (Write-EiArgumentTrace -RawArguments $arguments -ForwardedArguments $forward)) {
    [Console]::Error.WriteLine('EI_TEST_PYTHON_SHIM_TRACE_INVALID')
    $global:LASTEXITCODE = 125
    if ($MyInvocation.ScriptName) { return }
    exit 125
  }
  $outerSystemRoot = $env:SystemRoot
  $childExit = 125
  try {
    $env:SystemRoot = Get-EiPrivateSystemRoot
    & $realPython @forward
    $childExit = $LASTEXITCODE
  } catch {
    [Console]::Error.WriteLine('EI_TEST_PYTHON_SHIM_PRIVATE_SYSTEMROOT_INVALID')
  } finally {
    $env:SystemRoot = $outerSystemRoot
  }
  $global:LASTEXITCODE = $childExit
  if ($MyInvocation.ScriptName) { return }
  exit $childExit
}
[Console]::Error.WriteLine('EI_TEST_PYTHON_SHIM_ARGV_INVALID')
$global:LASTEXITCODE = 64
if ($MyInvocation.ScriptName) { return }
exit 64
'''
        path.write_text(source, encoding="utf-8", newline="\n")
        return path

    def shell_python_shim(self) -> Path:
        root = self.notification_isolation.root
        if root is None:
            raise RuntimeError("notification isolation fixture is not active")
        path = root / "isolated-python-test-shim.sh"
        source = '''#!/usr/bin/env bash
set -u
probe='import sys,venv,ensurepip; sys.exit(1) if sys.version_info < (3,11) else None; print(sys.executable)'
bootstrap='import runpy,sys;source=sys.argv.pop(1);sys.path.insert(0,source);runpy.run_module("ei.installer",run_name="__main__")'
real_python="$EI_TEST_REAL_PYTHON"
case "$real_python" in [A-Za-z]:\\*) real_python="$(cygpath -u "$real_python")" ;; esac
if [[ $# -eq 4 && "$1" == "-I" && "$2" == "-B" && "$3" == "-c" && "$4" == "$probe" ]]; then
  if "$real_python" "$@" >/dev/null; then
    if command -v cygpath >/dev/null 2>&1; then printf '%s\\n' "$(cygpath -u "$0")"; else printf '%s\\n' "$0"; fi
    exit 0
  else
    exit $?
  fi
fi
if [[ $# -ge 8 && "$1" == "-I" && "$2" == "-B" && "$3" == "-X" && "$4" == "utf8" && "$5" == "-c" && "$6" == "$bootstrap" && -d "$7" && "${7##*/}" == "src" ]]; then
  has_setup=0
  for argument in "${@:8}"; do [[ "$argument" == "--setup" ]] && has_setup=$((has_setup + 1)); done
  [[ $has_setup -eq 1 ]] || { printf '%s\\n' 'EI_TEST_PYTHON_SHIM_ARGV_INVALID' >&2; exit 64; }
  shift 6
  preload='import os,sys;sys.path.insert(0,os.environ["EI_TEST_NOTIFICATION_SUPPORT"]);import sitecustomize;exec(sys.argv.pop(1))'
  exec "$real_python" -I -B -X utf8 -c "$preload" "$bootstrap" "$@"
fi
printf '%s\\n' 'EI_TEST_PYTHON_SHIM_ARGV_INVALID' >&2
exit 64
'''
        path.write_text(source, encoding="utf-8", newline="\n")
        path.chmod(0o755)
        return path
