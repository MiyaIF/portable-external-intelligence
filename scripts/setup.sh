#!/usr/bin/env sh
set -eu

repo="${EI_REPO_ROOT:-$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)}"
engine_root=""
knowledge_mode=""
knowledge_root=""
personal_knowledge_root=""
team_knowledge_root=""
team_member_id=""
no_team_knowledge=0
runtime_root=""
github_repository=""
github_executable="gh"
remote_name="origin"
branch="main"
confirm_github_create=""
hosts=""
host_homes=""
providers=""
organizer_provider=""
organizer_host=""
privacy_profile="private-reusable"
python_exe="${EI_PYTHON_EXE:-}"
skill_mode="copy"
sync_enabled=0
sync_disabled=0
experiment=0
scheduler=0
check_only=0
non_interactive=0
accept_plan=0
skip_venv=0
json_mode=0

while [ "$#" -gt 0 ]; do
  case "$1" in
    --repo) repo=$2; shift 2 ;;
    --engine-root) engine_root=$2; shift 2 ;;
    --knowledge-mode) knowledge_mode=$2; shift 2 ;;
    --knowledge-root) knowledge_root=$2; shift 2 ;;
    --personal-knowledge-root) personal_knowledge_root=$2; shift 2 ;;
    --team-knowledge-root) team_knowledge_root=$2; shift 2 ;;
    --team-member-id) team_member_id=$2; shift 2 ;;
    --no-team-knowledge) no_team_knowledge=1; shift ;;
    --runtime-root) runtime_root=$2; shift 2 ;;
    --github-repository) github_repository=$2; shift 2 ;;
    --github-executable) github_executable=$2; shift 2 ;;
    --remote-name) remote_name=$2; shift 2 ;;
    --branch) branch=$2; shift 2 ;;
    --confirm-github-create) confirm_github_create=$2; shift 2 ;;
    --hosts) hosts="${hosts}${hosts:+,}$2"; shift 2 ;;
    --host-home) host_homes="${host_homes}${host_homes:+,}$2"; shift 2 ;;
    --providers) providers="${providers}${providers:+,}$2"; shift 2 ;;
    --organizer-provider) organizer_provider=$2; shift 2 ;;
    --organizer-host) organizer_host=$2; shift 2 ;;
    --privacy-profile) privacy_profile=$2; shift 2 ;;
    --python-exe) python_exe=$2; shift 2 ;;
    --skill-mode) skill_mode=$2; shift 2 ;;
    --sync) sync_enabled=1; shift ;;
    --no-sync) sync_disabled=1; shift ;;
    --experiment) experiment=1; shift ;;
    --scheduler) scheduler=1; shift ;;
    --check-only) check_only=1; shift ;;
    --non-interactive) non_interactive=1; shift ;;
    --accept-plan) accept_plan=1; shift ;;
    --skip-venv) skip_venv=1; shift ;;
    --json) json_mode=1; shift ;;
    *) echo "unknown option: $1" >&2; exit 2 ;;
  esac
done

if [ "$sync_enabled" -eq 1 ] && [ "$sync_disabled" -eq 1 ]; then
  echo "SYNC_SELECTION_CONFLICT" >&2
  exit 2
fi
if [ -n "$team_knowledge_root" ] && [ "$no_team_knowledge" -eq 1 ]; then
  echo "TEAM_SELECTION_CONFLICT" >&2
  exit 2
fi

if [ -z "$python_exe" ]; then
  python_exe="$(command -v python3 || command -v python || true)"
fi
if [ -z "$python_exe" ]; then
  echo "PYTHON_NOT_FOUND" >&2
  exit 2
fi
case "$python_exe" in
  */*) ;;
  *) python_exe="$(command -v "$python_exe")" ;;
esac

set -- -B -m ei.installer --setup --python-exe "$python_exe" --privacy-profile "$privacy_profile" --skill-mode "$skill_mode"
if [ -n "$engine_root" ]; then
  set -- "$@" --engine-root "$engine_root"
else
  set -- "$@" --repo "$repo"
fi
[ -n "$knowledge_mode" ] && set -- "$@" --knowledge-mode "$knowledge_mode"
[ -n "$knowledge_root" ] && set -- "$@" --knowledge-root "$knowledge_root"
[ -n "$personal_knowledge_root" ] && set -- "$@" --personal-knowledge-root "$personal_knowledge_root"
[ -n "$team_knowledge_root" ] && set -- "$@" --team-knowledge-root "$team_knowledge_root"
[ -n "$team_member_id" ] && set -- "$@" --team-member-id "$team_member_id"
[ "$no_team_knowledge" -eq 1 ] && set -- "$@" --no-team-knowledge
[ -n "$runtime_root" ] && set -- "$@" --runtime-root "$runtime_root"
[ -n "$github_repository" ] && set -- "$@" --github-repository "$github_repository"
[ -n "$github_executable" ] && set -- "$@" --github-executable "$github_executable"
[ -n "$remote_name" ] && set -- "$@" --remote-name "$remote_name"
[ -n "$branch" ] && set -- "$@" --branch "$branch"
[ -n "$confirm_github_create" ] && set -- "$@" --confirm-github-create "$confirm_github_create"
[ -n "$hosts" ] && set -- "$@" --hosts "$hosts"
[ -n "$host_homes" ] && set -- "$@" --host-home "$host_homes"
[ -n "$providers" ] && set -- "$@" --providers "$providers"
[ -n "$organizer_provider" ] && set -- "$@" --organizer-provider "$organizer_provider"
[ -n "$organizer_host" ] && set -- "$@" --organizer-host "$organizer_host"
[ "$sync_enabled" -eq 1 ] && set -- "$@" --sync
[ "$sync_disabled" -eq 1 ] && set -- "$@" --no-sync
[ "$experiment" -eq 1 ] && set -- "$@" --experiment
[ "$scheduler" -eq 1 ] && set -- "$@" --scheduler
[ "$check_only" -eq 1 ] && set -- "$@" --check-only
[ "$non_interactive" -eq 1 ] && set -- "$@" --non-interactive
[ "$accept_plan" -eq 1 ] && set -- "$@" --accept-plan
[ "$skip_venv" -eq 1 ] && set -- "$@" --skip-venv
[ "$json_mode" -eq 1 ] && set -- "$@" --json

PYTHONPATH="$repo/src${PYTHONPATH:+:$PYTHONPATH}" PYTHONDONTWRITEBYTECODE=1 "$python_exe" "$@"
