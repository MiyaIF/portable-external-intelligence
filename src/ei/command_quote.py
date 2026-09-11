"""Portable argv construction and shell-string quoting for host integrations.

Hook vendors expose command hooks as strings, even though the engine itself
always works with an argument vector.  Keeping construction here prevents
callers from interpolating executable or root paths into shell syntax.
"""

from __future__ import annotations

import os
import shlex
import subprocess
from pathlib import Path
from typing import Iterable, Sequence


class CommandQuoteError(ValueError):
    """Raised when an executable or command argument cannot be rendered safely."""


_MODULE_BOOTSTRAP = (
    "import runpy,sys;"
    "source=sys.argv.pop(1);"
    "module=sys.argv.pop(1);"
    "sys.path.insert(0,source);"
    "runpy.run_module(module,run_name='__main__')"
)
_SCRIPT_BOOTSTRAP = (
    "import os,runpy,sys;"
    "script=sys.argv.pop(1);"
    "sys.path.insert(0,os.path.dirname(script));"
    "runpy.run_path(script,run_name='__main__')"
)


def _validated_argv(argv: Iterable[str]) -> tuple[str, ...]:
    if isinstance(argv, (str, bytes)):
        raise CommandQuoteError("COMMAND_ARGV_REQUIRED")
    values = tuple(argv)
    if not values:
        raise CommandQuoteError("COMMAND_ARGV_EMPTY")
    for value in values:
        if not isinstance(value, str) or not value:
            raise CommandQuoteError("COMMAND_ARGUMENT_INVALID")
        if "\x00" in value or any(ord(char) < 0x20 and char not in "\t" for char in value):
            raise CommandQuoteError("COMMAND_ARGUMENT_CONTROL_CHARACTER")
    return values


def _path_value(value: str | os.PathLike[str]) -> str:
    raw = os.fspath(value)
    if isinstance(raw, bytes):
        raise CommandQuoteError("COMMAND_PATH_TEXT_REQUIRED")
    if not raw:
        raise CommandQuoteError("COMMAND_PATH_REQUIRED")
    return raw


def _trusted_module_argv(
    executable: str | os.PathLike[str],
    engine_root: str | os.PathLike[str],
    module: str,
) -> list[str]:
    engine = Path(_path_value(engine_root)).expanduser()
    return [
        _path_value(executable),
        "-I",
        "-B",
        "-X",
        "utf8",
        "-c",
        _MODULE_BOOTSTRAP,
        str(engine / "src"),
        module,
    ]


def build_hook_argv(
    executable: str | os.PathLike[str],
    *,
    host_id: str,
    engine_root: str | os.PathLike[str],
    personal_knowledge_root: str | os.PathLike[str] | None = None,
    team_knowledge_root: str | os.PathLike[str] | None = None,
    runtime_root: str | os.PathLike[str] | None = None,
    host_home: str | os.PathLike[str] | None = None,
    knowledge_root: str | os.PathLike[str] | None = None,
) -> tuple[str, ...]:
    """Build the common hook entrypoint argv without a shell bridge."""

    if not isinstance(host_id, str) or not host_id:
        raise CommandQuoteError("COMMAND_HOST_ID_REQUIRED")
    if personal_knowledge_root is not None and knowledge_root is not None:
        if os.path.normcase(os.path.abspath(os.fspath(personal_knowledge_root))) != os.path.normcase(os.path.abspath(os.fspath(knowledge_root))):
            raise CommandQuoteError("COMMAND_PERSONAL_ROOT_CONFLICT")
    legacy_personal = personal_knowledge_root is None and knowledge_root is not None
    personal = personal_knowledge_root if personal_knowledge_root is not None else knowledge_root
    if personal is None:
        raise CommandQuoteError("COMMAND_PERSONAL_ROOT_REQUIRED")
    if runtime_root is None:
        raise CommandQuoteError("COMMAND_RUNTIME_ROOT_REQUIRED")
    values = [
        *_trusted_module_argv(executable, engine_root, "ei.hook_entry"),
        "--host-id",
        host_id,
        "--engine-root",
        _path_value(engine_root),
        "--knowledge-root" if legacy_personal else "--personal-knowledge-root",
        _path_value(personal),
    ]
    if team_knowledge_root is not None:
        values.extend(("--team-knowledge-root", _path_value(team_knowledge_root)))
    values.extend(
        (
            "--runtime-root",
            _path_value(runtime_root),
        )
    )
    if host_home is not None:
        values.extend(("--codex-home", _path_value(host_home)))
    return _validated_argv(values)


def build_observe_argv(
    executable: str | os.PathLike[str],
    *,
    engine_root: str | os.PathLike[str] | None = None,
    knowledge_root: str | os.PathLike[str] | None = None,
    runtime_root: str | os.PathLike[str] | None = None,
) -> tuple[str, ...]:
    """Build the fallback observation command used by managed context files."""

    roots = (engine_root, knowledge_root, runtime_root)
    if any(value is not None for value in roots):
        if any(value is None for value in roots):
            raise CommandQuoteError("COMMAND_ROOTS_INCOMPLETE")
        values = [
            *_trusted_module_argv(executable, engine_root, "ei.cli"),
            "observe",
            "--stdin-json",
            "--json",
        ]
        values.extend(
            (
                "--engine-root",
                _path_value(engine_root),
                "--knowledge-root",
                _path_value(knowledge_root),
                "--runtime-root",
                _path_value(runtime_root),
            )
        )
    else:
        values = [
            _path_value(executable),
            "-I",
            "-B",
            "-X",
            "utf8",
            "-m",
            "ei.cli",
            "observe",
            "--stdin-json",
            "--json",
        ]
    return _validated_argv(values)


def build_skill_launcher_argv(
    executable: str | os.PathLike[str],
    *,
    skill_destination: str | os.PathLike[str],
    engine_root: str | os.PathLike[str],
    runtime_root: str | os.PathLike[str],
) -> tuple[str, ...]:
    """Build the only supported Skill entry command.

    The first Python process is isolated before any Skill module or caller
    supplied ``PYTHONPATH`` can be imported.
    """

    launcher = Path(_path_value(skill_destination)) / "scripts" / "launcher.py"
    return _validated_argv(
        (
            _path_value(executable),
            "-I",
            "-B",
            "-X",
            "utf8",
            "-c",
            _SCRIPT_BOOTSTRAP,
            str(launcher),
            "--engine-root",
            _path_value(engine_root),
            "--runtime-root",
            _path_value(runtime_root),
        )
    )


def quote_windows_argument(value: str) -> str:
    """Quote one argument using Python's Windows argv/CreateProcess rules."""

    return subprocess.list2cmdline([_validated_argv((value,))[0]])


def quote_posix_argument(value: str) -> str:
    """Quote one argument for a POSIX shell command field."""

    return shlex.quote(_validated_argv((value,))[0])


def quote_windows_command(argv: Sequence[str]) -> str:
    """Render an argv vector for a Windows command-line hook field."""

    return subprocess.list2cmdline(_validated_argv(argv))


def quote_posix_command(argv: Sequence[str]) -> str:
    """Render an argv vector for a POSIX shell command field."""

    return shlex.join(_validated_argv(argv))


def quote_command(argv: Sequence[str], *, platform: str | None = None) -> str:
    """Render a command for ``windows`` or ``posix`` deterministically."""

    selected = (platform or ("windows" if os.name == "nt" else "posix")).casefold()
    if selected in {"windows", "win32", "nt"}:
        return quote_windows_command(argv)
    if selected in {"posix", "linux", "darwin", "macos", "unix"}:
        return quote_posix_command(argv)
    raise CommandQuoteError("COMMAND_PLATFORM_UNSUPPORTED")


__all__ = [
    "CommandQuoteError",
    "build_hook_argv",
    "build_observe_argv",
    "build_skill_launcher_argv",
    "quote_command",
    "quote_posix_argument",
    "quote_posix_command",
    "quote_windows_argument",
    "quote_windows_command",
]
