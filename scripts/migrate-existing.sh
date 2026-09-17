#!/usr/bin/env sh
set -eu

source=""
report=""
inventory=""
repo=""
source_root=""
knowledge_root=""
runtime_root=""
python_exe=""
dry_run=0
apply_plan_hash=""
apply_mode=0
allow_global_source=0
operation=""
plan_path=""
receipt_path=""
verified_backup=""
confirm=0

while [ "$#" -gt 0 ]; do
  case "$1" in
    --source) [ "$#" -ge 2 ] || { echo "SOURCE_REQUIRED" >&2; exit 2; }; source=$2; shift 2 ;;
    --report) [ "$#" -ge 2 ] || { echo "REPORT_REQUIRED" >&2; exit 2; }; report=$2; shift 2 ;;
    --inventory) [ "$#" -ge 2 ] || { echo "INVENTORY_REQUIRED" >&2; exit 2; }; inventory=$2; shift 2 ;;
    --repo|--repo-root) [ "$#" -ge 2 ] || { echo "REPO_REQUIRED" >&2; exit 2; }; repo=$2; shift 2 ;;
    --source-root) [ "$#" -ge 2 ] || { echo "SOURCE_ROOT_REQUIRED" >&2; exit 2; }; source_root=$2; shift 2 ;;
    --knowledge-root) [ "$#" -ge 2 ] || { echo "KNOWLEDGE_ROOT_REQUIRED" >&2; exit 2; }; knowledge_root=$2; shift 2 ;;
    --runtime-root) [ "$#" -ge 2 ] || { echo "RUNTIME_ROOT_REQUIRED" >&2; exit 2; }; runtime_root=$2; shift 2 ;;
    --python-exe) [ "$#" -ge 2 ] || { echo "PYTHON_REQUIRED" >&2; exit 2; }; python_exe=$2; shift 2 ;;
    --dry-run) dry_run=1; shift ;;
    --apply) apply_mode=1; shift ;;
    --expected-plan-hash|--apply-plan-hash) [ "$#" -ge 2 ] || { echo "PLAN_HASH_REQUIRED" >&2; exit 2; }; apply_plan_hash=$2; shift 2 ;;
    --allow-global-source) allow_global_source=1; shift ;;
    --operation) [ "$#" -ge 2 ] || { echo "OPERATION_REQUIRED" >&2; exit 2; }; operation=$2; shift 2 ;;
    --plan|--plan-path) [ "$#" -ge 2 ] || { echo "PLAN_REQUIRED" >&2; exit 2; }; plan_path=$2; shift 2 ;;
    --receipt|--receipt-path) [ "$#" -ge 2 ] || { echo "RECEIPT_REQUIRED" >&2; exit 2; }; receipt_path=$2; shift 2 ;;
    --verified-backup) [ "$#" -ge 2 ] || { echo "BACKUP_REQUIRED" >&2; exit 2; }; verified_backup=$2; shift 2 ;;
    --confirm) confirm=1; shift ;;
    *) echo "unknown option: $1" >&2; exit 2 ;;
  esac
done

repo="${repo:-${EI_REPO_ROOT:-$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)}}"
[ -d "$repo/src" ] || { echo "REPO_ROOT_INVALID" >&2; exit 2; }
python_exe="${python_exe:-${EI_PYTHON_EXE:-$(command -v python3 || command -v python || true)}}"
[ -n "$python_exe" ] || { echo "PYTHON_NOT_FOUND" >&2; exit 2; }

if [ -n "$operation" ]; then
  [ -n "$runtime_root" ] || { echo "RUNTIME_ROOT_REQUIRED" >&2; exit 2; }
  [ "$operation" = "rollback" ] || [ -n "$knowledge_root" ] || { echo "KNOWLEDGE_ROOT_REQUIRED" >&2; exit 2; }
  case "$operation" in
    inspect)
      source_root="${source_root:-$repo}"
      set -- -B -m ei.cli migration inspect --repo "$source_root" --knowledge-root "$knowledge_root" --runtime-root "$runtime_root" ;;
    apply|cleanup)
      [ -n "$plan_path" ] || { echo "PLAN_REQUIRED" >&2; exit 2; }
      [ -n "$apply_plan_hash" ] || { echo "PLAN_HASH_REQUIRED" >&2; exit 2; }
      set -- -B -m ei.cli migration "$operation" --plan "$plan_path" --confirm-plan-hash "$apply_plan_hash"
      if [ "$operation" = "cleanup" ]; then
        [ -n "$verified_backup" ] || { echo "BACKUP_REQUIRED" >&2; exit 2; }
        set -- "$@" --verified-backup "$verified_backup"
      fi ;;
    rollback)
      [ -n "$receipt_path" ] || { echo "RECEIPT_REQUIRED" >&2; exit 2; }
      [ -n "$apply_plan_hash" ] || { echo "PLAN_HASH_REQUIRED" >&2; exit 2; }
      set -- -B -m ei.cli migration rollback --receipt "$receipt_path" --confirm-plan-hash "$apply_plan_hash" ;;
    inspect-recovery)
      set -- -B -m ei.cli migration inspect-recovery --knowledge-root "$knowledge_root" --runtime-root "$runtime_root" ;;
    recover-staging)
      [ -n "$apply_plan_hash" ] || { echo "PLAN_HASH_REQUIRED" >&2; exit 2; }
      set -- -B -m ei.cli migration recover-staging --knowledge-root "$knowledge_root" --runtime-root "$runtime_root" --plan-hash "$apply_plan_hash"
      [ "$confirm" -eq 1 ] && set -- "$@" --confirm ;;
    *) echo "OPERATION_INVALID" >&2; exit 2 ;;
  esac
  [ -n "$report" ] && set -- "$@" --output "$report"
  set -- "$@" --json
  PYTHONPATH="${repo}/src${PYTHONPATH:+:$PYTHONPATH}" PYTHONDONTWRITEBYTECODE=1 "$python_exe" "$@"
  exit $?
fi

[ -n "$source" ] || { echo "SOURCE_REQUIRED" >&2; exit 2; }
[ -n "$report" ] || { echo "REPORT_REQUIRED" >&2; exit 2; }
if [ "$dry_run" -eq "$apply_mode" ] && [ -z "$apply_plan_hash" ]; then
  echo "CHOOSE_DRY_RUN_OR_APPLY" >&2
  exit 2
fi
if [ -n "$apply_plan_hash" ]; then
  apply_mode=1
fi

set -- -B -m ei.cli migrate-existing --source "$source" --report "$report" --repo-root "$repo"
[ -n "$runtime_root" ] && set -- "$@" --runtime-root "$runtime_root"
[ -n "$inventory" ] && set -- "$@" --inventory "$inventory"
[ "$dry_run" -eq 1 ] && set -- "$@" --dry-run
[ "$apply_mode" -eq 1 ] && set -- "$@" --apply
[ -n "$apply_plan_hash" ] && set -- "$@" --apply-plan-hash "$apply_plan_hash"
[ "$allow_global_source" -eq 1 ] && set -- "$@" --allow-global-source

PYTHONPATH="${repo}/src${PYTHONPATH:+:$PYTHONPATH}" PYTHONDONTWRITEBYTECODE=1 "$python_exe" "$@"
