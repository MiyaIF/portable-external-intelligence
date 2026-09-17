#!/usr/bin/env sh
set -eu

repo=""
engine_root=""
knowledge_root=""
personal_knowledge_root=""
team_knowledge_root=""
team_member_id=""
no_team_knowledge=0
runtime_root=""
manifest=""
python_exe=""
hosts=""
host_homes=""
check_only=0
non_interactive=0
json_mode=0

while [ "$#" -gt 0 ]; do
  case "$1" in
    --repo) repo=$2; shift 2 ;;
    --engine-root) engine_root=$2; shift 2 ;;
    --knowledge-root) knowledge_root=$2; shift 2 ;;
    --personal-knowledge-root) personal_knowledge_root=$2; shift 2 ;;
    --team-knowledge-root) team_knowledge_root=$2; shift 2 ;;
    --team-member-id) team_member_id=$2; shift 2 ;;
    --no-team-knowledge) no_team_knowledge=1; shift ;;
    --runtime-root) runtime_root=$2; shift 2 ;;
    --manifest|--manifest-path) manifest=$2; shift 2 ;;
    --python-exe) python_exe=$2; shift 2 ;;
    --hosts) hosts="${hosts}${hosts:+,}$2"; shift 2 ;;
    --host-home) host_homes="${host_homes}${host_homes:+,}$2"; shift 2 ;;
    --check-only) check_only=1; shift ;;
    --non-interactive) non_interactive=1; shift ;;
    --json) json_mode=1; shift ;;
    *) echo "unknown option: $1" >&2; exit 2 ;;
  esac
done

if [ -n "$manifest" ] && { [ -n "$engine_root" ] || [ -n "$knowledge_root" ] || [ -n "$personal_knowledge_root" ] || [ -n "$team_knowledge_root" ] || [ -n "$team_member_id" ] || [ "$no_team_knowledge" -eq 1 ]; }; then
  echo "ROOT_OPTIONS_CONFLICT_WITH_MANIFEST" >&2
  exit 2
fi
[ -z "$knowledge_root" ] || [ -z "$personal_knowledge_root" ] || { echo "PERSONAL_KNOWLEDGE_ROOT_CONFLICT" >&2; exit 2; }
[ -z "$team_member_id" ] || [ -n "$team_knowledge_root" ] || { echo "TEAM_KNOWLEDGE_ROOT_REQUIRED" >&2; exit 2; }

if [ -z "$python_exe" ]; then
  python_exe="${EI_PYTHON_EXE:-$(command -v python3 || command -v python || true)}"
fi
[ -n "$python_exe" ] || { echo "PYTHON_NOT_FOUND" >&2; exit 2; }

manifest_mode=0
if [ -n "$manifest" ]; then
  manifest_mode=1
  [ -f "$manifest" ] || { echo "MANIFEST_NOT_FOUND" >&2; exit 2; }
  repo="$("$python_exe" -c 'import json,sys; print(json.load(open(sys.argv[1], encoding="utf-8"))["repo_root"])' "$manifest")"
else
  repo="${repo:-${EI_REPO_ROOT:-$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)}}"
fi
[ -d "$repo/src" ] || { echo "REPO_ROOT_INVALID" >&2; exit 2; }

set -- -B -m ei.installer --update --python-exe "$python_exe"
if [ "$manifest_mode" -eq 1 ]; then
  set -- "$@" --manifest "$manifest"
elif [ -n "$engine_root" ]; then
  set -- "$@" --engine-root "$engine_root"
else
  set -- "$@" --repo "$repo"
fi
if [ -n "$knowledge_root" ]; then
  [ "$manifest_mode" -eq 0 ] || { echo "KNOWLEDGE_ROOT_CONFLICTS_WITH_MANIFEST" >&2; exit 2; }
  [ -n "$engine_root" ] || { echo "ENGINE_ROOT_REQUIRED" >&2; exit 2; }
  set -- "$@" --knowledge-root "$knowledge_root"
fi
[ -n "$personal_knowledge_root" ] && set -- "$@" --personal-knowledge-root "$personal_knowledge_root"
[ -n "$team_knowledge_root" ] && set -- "$@" --team-knowledge-root "$team_knowledge_root"
[ -n "$team_member_id" ] && set -- "$@" --team-member-id "$team_member_id"
[ "$no_team_knowledge" -eq 1 ] && set -- "$@" --no-team-knowledge
[ -n "$runtime_root" ] && set -- "$@" --runtime-root "$runtime_root"
[ -n "$hosts" ] && set -- "$@" --hosts "$hosts"
[ -n "$host_homes" ] && set -- "$@" --host-home "$host_homes"
[ "$check_only" -eq 1 ] && set -- "$@" --check-only
[ "$non_interactive" -eq 1 ] && set -- "$@" --non-interactive
[ "$json_mode" -eq 1 ] && set -- "$@" --json

PYTHONPATH="$repo/src${PYTHONPATH:+:$PYTHONPATH}" PYTHONDONTWRITEBYTECODE=1 "$python_exe" "$@"
