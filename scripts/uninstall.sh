#!/usr/bin/env sh
set -eu

# Default uninstall removes owned integration artifacts only.  Knowledge
# events, shared member shards, outbox, and writer identity remain; callers
# must opt into --remove-runtime-cache or --remove-runtime explicitly.

manifest=""
python_exe=""
confirm_manifest_sha256=""
restore=0
remove_cache=0
remove_runtime=0
remove_venv=0
keep_skills=0
force=0
check_only=0
json_mode=0
no_scheduler=0

while [ "$#" -gt 0 ]; do
  case "$1" in
    --manifest|--manifest-path) manifest=$2; shift 2 ;;
    --python-exe) python_exe=$2; shift 2 ;;
    --confirm-manifest-sha256) confirm_manifest_sha256=$2; shift 2 ;;
    --restore-config-backup) restore=1; shift ;;
    --remove-runtime-cache) remove_cache=1; shift ;;
    --remove-runtime) remove_runtime=1; shift ;;
    --remove-venv) remove_venv=1; shift ;;
    --keep-skills) keep_skills=1; shift ;;
    --force) force=1; shift ;;
    --check-only) check_only=1; shift ;;
    --no-scheduled-task) no_scheduler=1; shift ;;
    --json) json_mode=1; shift ;;
    *) echo "unknown option: $1" >&2; exit 2 ;;
  esac
done

[ -n "$manifest" ] || { echo "MANIFEST_REQUIRED" >&2; exit 2; }
if [ -z "$python_exe" ]; then
  python_exe="${EI_PYTHON_EXE:-$(command -v python3 || command -v python || true)}"
fi
[ -n "$python_exe" ] || { echo "PYTHON_NOT_FOUND" >&2; exit 2; }
[ "$check_only" -eq 1 ] || [ -n "$confirm_manifest_sha256" ] || { echo "UNINSTALL_CONFIRMATION_REQUIRED" >&2; exit 2; }
repo="$("$python_exe" -c 'import json,sys; print(json.load(open(sys.argv[1], encoding="utf-8"))["repo_root"])' "$manifest")"
[ -d "$repo/src" ] || { echo "REPO_ROOT_INVALID" >&2; exit 2; }

set -- -B -m ei.installer --uninstall --manifest "$manifest" --python-exe "$python_exe"
[ -z "$confirm_manifest_sha256" ] || set -- "$@" --confirm-manifest-sha256 "$confirm_manifest_sha256"
[ "$restore" -eq 1 ] && set -- "$@" --restore-config-backup
[ "$remove_cache" -eq 1 ] && set -- "$@" --remove-runtime-cache
[ "$remove_runtime" -eq 1 ] && set -- "$@" --remove-runtime
[ "$remove_venv" -eq 1 ] && set -- "$@" --remove-venv
[ "$keep_skills" -eq 1 ] && set -- "$@" --keep-skills
[ "$force" -eq 1 ] && set -- "$@" --force
[ "$check_only" -eq 1 ] && set -- "$@" --check-only
[ "$json_mode" -eq 1 ] && set -- "$@" --json
[ "$no_scheduler" -eq 1 ] && set -- "$@" --no-scheduled-task

PYTHONPATH="$repo/src${PYTHONPATH:+:$PYTHONPATH}" PYTHONDONTWRITEBYTECODE=1 "$python_exe" "$@"
