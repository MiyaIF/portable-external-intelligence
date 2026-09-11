#!/usr/bin/env sh
set -eu
repo=""
engine_root=""
knowledge_root=""
codex_home=""
runtime_root=""
python_exe=""
strict=0
json_mode=0
while [ "$#" -gt 0 ]; do
  case "$1" in
    --repo|--repo-path) repo=$2; shift 2 ;;
    --engine-root) engine_root=$2; shift 2 ;;
    --knowledge-root) knowledge_root=$2; shift 2 ;;
    --codex-home) codex_home=$2; shift 2 ;;
    --runtime-root) runtime_root=$2; shift 2 ;;
    --python-exe) python_exe=$2; shift 2 ;;
    --strict) strict=1; shift ;;
    --json) json_mode=1; shift ;;
    *) echo "unknown option: $1" >&2; exit 2 ;;
  esac
done
repo="${repo:-${EI_REPO_ROOT:-$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)}}"
python_exe="${python_exe:-${EI_PYTHON_EXE:-$(command -v python3 || command -v python || true)}}"
[ -n "$python_exe" ] || { echo "PYTHON_NOT_FOUND" >&2; exit 2; }
set -- -B -m ei.doctor --repo-root "$repo"
[ -n "$engine_root" ] && set -- "$@" --engine-root "$engine_root"
[ -n "$knowledge_root" ] && set -- "$@" --knowledge-root "$knowledge_root"
[ -n "$codex_home" ] && set -- "$@" --codex-home "$codex_home"
[ -n "$runtime_root" ] && set -- "$@" --runtime-root "$runtime_root"
[ "$strict" -eq 1 ] && set -- "$@" --strict
[ "$json_mode" -eq 1 ] && set -- "$@" --json
PYTHONPATH="$repo/src${PYTHONPATH:+:$PYTHONPATH}" PYTHONDONTWRITEBYTECODE=1 "$python_exe" "$@"
