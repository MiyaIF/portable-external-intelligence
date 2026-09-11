#!/usr/bin/env sh
set -eu

engine_root=""
knowledge_root=""
host_id=""
instance_id=""
mode="real"
runtime_root=""
host_home=""
output=""
os_profile=""
python_exe="${PYTHON_EXE:-python3}"

while [ "$#" -gt 0 ]; do
  case "$1" in
    --repo|--engine-root) [ "$#" -ge 2 ] || { printf '%s\n' "CERTIFICATION_ENGINE_ROOT_REQUIRED" >&2; exit 2; }; engine_root=$2; shift 2 ;;
    --knowledge-root) [ "$#" -ge 2 ] || { printf '%s\n' "CERTIFICATION_KNOWLEDGE_ROOT_REQUIRED" >&2; exit 2; }; knowledge_root=$2; shift 2 ;;
    --host) host_id=$2; shift 2 ;;
    --instance) instance_id=$2; shift 2 ;;
    --mode) mode=$2; shift 2 ;;
    --runtime-root) runtime_root=$2; shift 2 ;;
    --host-home) host_home=$2; shift 2 ;;
    --output) output=$2; shift 2 ;;
    --os-profile) os_profile=$2; shift 2 ;;
    --python-exe) python_exe=$2; shift 2 ;;
    *) printf '%s\n' "CERTIFICATION_ARGUMENT_INVALID" >&2; exit 2 ;;
  esac
done

[ -n "$engine_root" ] || { printf '%s\n' "CERTIFICATION_ENGINE_ROOT_REQUIRED" >&2; exit 2; }
[ -n "$knowledge_root" ] || { printf '%s\n' "CERTIFICATION_KNOWLEDGE_ROOT_REQUIRED" >&2; exit 2; }
[ -n "$runtime_root" ] || { printf '%s\n' "CERTIFICATION_RUNTIME_ROOT_REQUIRED" >&2; exit 2; }
[ -n "$host_id" ] || { printf '%s\n' "CERTIFICATION_HOST_REQUIRED" >&2; exit 2; }
[ -n "$instance_id" ] || { printf '%s\n' "CERTIFICATION_INSTANCE_REQUIRED" >&2; exit 2; }
[ -d "$engine_root/src" ] || { printf '%s\n' "ENGINE_ROOT_INVALID" >&2; exit 2; }
export PYTHONPATH="$engine_root/src${PYTHONPATH:+:$PYTHONPATH}"

set -- -B -m ei.cli certify-host --engine-root "$engine_root" --knowledge-root "$knowledge_root" --runtime-root "$runtime_root" --host "$host_id" --instance "$instance_id" --mode "$mode" --json
[ -n "$host_home" ] && set -- "$@" --host-home "$host_home"
[ -n "$output" ] && set -- "$@" --output "$output"
[ -n "$os_profile" ] && set -- "$@" --os-profile "$os_profile"
exec "$python_exe" "$@"
