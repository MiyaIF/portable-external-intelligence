#!/usr/bin/env sh
set -eu

engine_root="${EI_ENGINE_ROOT:-${EI_REPO_ROOT:-$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)}}"
codex_home="${EI_CODEX_HOME:-$HOME/.codex}"
runtime_root="${EI_RUNTIME_ROOT:-$codex_home/external-intelligence}"
knowledge_root="${EI_KNOWLEDGE_ROOT:-$codex_home/external-intelligence-knowledge}"
python_exe="${EI_PYTHON_EXE:-}"
check_only=0

while [ "$#" -gt 0 ]; do
  case "$1" in
    --repo|--engine-root) [ "$#" -ge 2 ] || { echo "ARGUMENT_VALUE_REQUIRED" >&2; exit 2; }; engine_root=$2; shift 2 ;;
    --codex-home) [ "$#" -ge 2 ] || { echo "ARGUMENT_VALUE_REQUIRED" >&2; exit 2; }; codex_home=$2; shift 2 ;;
    --runtime-root) [ "$#" -ge 2 ] || { echo "ARGUMENT_VALUE_REQUIRED" >&2; exit 2; }; runtime_root=$2; shift 2 ;;
    --knowledge-root) [ "$#" -ge 2 ] || { echo "ARGUMENT_VALUE_REQUIRED" >&2; exit 2; }; knowledge_root=$2; shift 2 ;;
    --python-exe) [ "$#" -ge 2 ] || { echo "ARGUMENT_VALUE_REQUIRED" >&2; exit 2; }; python_exe=$2; shift 2 ;;
    --check-only) check_only=1; shift ;;
    *) echo "ARGUMENT_UNKNOWN:$1" >&2; exit 2 ;;
  esac
done

engine_root="$(CDPATH= cd -- "$engine_root" && pwd)"
codex_home="$(CDPATH= cd -- "$(dirname -- "$codex_home")" && pwd)/$(basename -- "$codex_home")"
runtime_root="$(CDPATH= cd -- "$(dirname -- "$runtime_root")" && pwd)/$(basename -- "$runtime_root")"
knowledge_root="$(CDPATH= cd -- "$(dirname -- "$knowledge_root")" && pwd)/$(basename -- "$knowledge_root")"
[ -d "$engine_root/src" ] || { echo "ENGINE_ROOT_INVALID" >&2; exit 2; }
if [ -z "$python_exe" ]; then
  python_exe="$(command -v python3 || command -v python || true)"
fi
[ -n "$python_exe" ] || { echo "PYTHON_NOT_FOUND" >&2; exit 2; }
case "$python_exe" in
  */*) ;;
  *) python_exe="$(command -v "$python_exe")" ;;
esac

export PYTHONPATH="$engine_root/src${PYTHONPATH:+:$PYTHONPATH}"
rendered="$("$python_exe" -B -m ei.task_scheduler --engine-root "$engine_root" --knowledge-root "$knowledge_root" --codex-home "$codex_home" --runtime-root "$runtime_root" --python-exe "$python_exe" --json)"
if [ "$check_only" -eq 1 ]; then
  printf '%s\n' "$rendered"
  exit 0
fi

unit_dir="${EI_SYSTEMD_USER_DIR:-${XDG_CONFIG_HOME:-$HOME/.config}/systemd/user}"
mkdir -p "$unit_dir"
"$python_exe" -B -c '
from pathlib import Path
import sys
from ei.config import load_settings
from ei.task_scheduler import build_maintenance_action, build_systemd_user_timer, build_systemd_user_unit
engine, knowledge, home, runtime, python, service, timer = map(Path, sys.argv[1:8])
settings = load_settings(engine_root=engine, knowledge_root=knowledge, codex_home=home, runtime_root=runtime)
action = build_maintenance_action(settings, python)
Path(service).write_text(build_systemd_user_unit(action), encoding="utf-8", newline="\n")
Path(timer).write_text(build_systemd_user_timer(action), encoding="utf-8", newline="\n")
' "$engine_root" "$knowledge_root" "$codex_home" "$runtime_root" "$python_exe" "$unit_dir/CodexExternalIntelligenceMaintenance-v1.service" "$unit_dir/CodexExternalIntelligenceMaintenance-v1.timer"

systemctl --user daemon-reload
systemctl --user enable --now CodexExternalIntelligenceMaintenance-v1.timer
"$python_exe" -B -m ei.task_scheduler --engine-root "$engine_root" --knowledge-root "$knowledge_root" --codex-home "$codex_home" --runtime-root "$runtime_root" --python-exe "$python_exe" --json --write-state --registered
printf '%s\n' "Registered systemd user timer CodexExternalIntelligenceMaintenance-v1.timer."
