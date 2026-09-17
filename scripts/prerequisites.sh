#!/usr/bin/env sh
# Sourced by setup.sh before any Python process. All progress goes to stderr.
ei_python_location() {
  command -v "$1"
}

ei_probe_python() {
  ei_boot_python_location=$(ei_python_location "$1") || return 1
  # Apple's Python shim can open the CLT installer just like its Git shim.
  if [ "$(uname -s)" = Darwin ] && [ "$ei_boot_python_location" = /usr/bin/python3 ]; then
    ei_macos_run xcode-select -p >/dev/null 2>&1 || return 1
  fi
  "$1" -I -B -c 'import sys,venv,ensurepip; sys.exit(1) if sys.version_info < (3,11) else None; print(sys.executable)' 2>/dev/null
}

ei_find_python() {
  if [ -n "$1" ]; then
    ei_probe_python "$1"
    return $?
  fi
  for ei_boot_candidate in python3 python3.13 python; do
    if ei_probe_python "$ei_boot_candidate"; then return 0; fi
  done
  if [ "$(uname -s)" = Darwin ]; then
    # The .pkg changes the next shell's PATH, not the already-running setup.
    for ei_boot_candidate in /usr/local/bin/python3 /Library/Frameworks/Python.framework/Versions/3.13/bin/python3.13; do
      if ei_probe_python "$ei_boot_candidate"; then return 0; fi
    done
  fi
  return 1
}

ei_git_available() {
  command -v git >/dev/null 2>&1 || return 1
  # On macOS /usr/bin/git can launch an installation dialog. Do not trigger
  # that during a read-only prerequisite check without prior consent.
  if [ "$(uname -s)" = Darwin ] && [ "$(command -v git)" = /usr/bin/git ]; then
    xcode-select -p >/dev/null 2>&1 || return 1
  fi
  git --version >/dev/null 2>&1
}

ei_dependency_manager() {
  case "$(uname -s)" in
    Darwin) printf '%s\n' macos-native ;;
    Linux)
      if command -v apt-get >/dev/null 2>&1; then printf '%s\n' apt-get
      elif command -v dnf >/dev/null 2>&1; then printf '%s\n' dnf
      else return 1; fi ;;
    *) return 1 ;;
  esac
}

ei_is_interactive() {
  [ "${ei_boot_noninteractive:-0}" != 1 ] && [ -t 0 ]
}

ei_macos_run() {
  # Do not resolve security checks or installers through a caller-controlled PATH.
  case "$1" in
    xcode-select|curl|shasum|open) /usr/bin/"$@" ;;
    pkgutil|spctl) /usr/sbin/"$@" ;;
    *) return 2 ;;
  esac
}

ei_macos_tools_available() {
  for ei_mac_tool in /usr/bin/xcode-select /usr/bin/curl /usr/bin/shasum /usr/bin/open /usr/sbin/pkgutil /usr/sbin/spctl; do
    [ -x "$ei_mac_tool" ] || return 1
  done
}

ei_wait_macos_install() {
  printf '%s' '導入画面で完了を確認してから Enter（中断する場合は q）: ' >&2
  IFS= read -r ei_mac_answer || return 1
  [ -z "$ei_mac_answer" ]
}

ei_install_macos_python() (
  # Subshell scopes temporary-file cleanup; never delete recursively.
  # Pin both version and SHA-256 from the official release page. Updating this
  # pin requires a source review, not parsing/executing a moving download URL.
  # https://www.python.org/downloads/release/python-31315/
  ei_mac_url='https://www.python.org/ftp/python/3.13.15/python-3.13.15-macos11.pkg'
  ei_mac_sha256='3b7eaf7f29825f796e8267024435540ddf1f17fc9a97ad58095daa7a75bfdcd3' # pragma: allowlist secret - public installer integrity digest from the release page above
  ei_is_interactive || return 2
  ei_macos_tools_available || { printf '%s\n' PREREQUISITE_NATIVE_TOOLS_UNAVAILABLE >&2; return 2; }
  ei_mac_tmp=$(mktemp -d "${TMPDIR:-/tmp}/ei-prerequisites.XXXXXXXX") || return 2
  ei_mac_pkg="$ei_mac_tmp/python.pkg"
  ei_mac_gui_pending=0
  trap 'if [ "$ei_mac_gui_pending" = 1 ]; then printf "PREREQUISITE_PACKAGE_RETAINED: Installerの終了を確認できないため保持しました: %s\n" "$ei_mac_pkg" >&2; else rm -f -- "$ei_mac_pkg"; rmdir -- "$ei_mac_tmp"; fi' 0
  trap 'exit 130' INT
  trap 'exit 143' TERM
  ei_macos_run curl --disable --fail --silent --show-error --proto '=https' --tlsv1.2 --connect-timeout 20 --max-time 300 --output "$ei_mac_pkg" "$ei_mac_url" || return 2
  ei_mac_digest=$(ei_macos_run shasum -a 256 "$ei_mac_pkg") || return 2
  if [ "${ei_mac_digest%% *}" != "$ei_mac_sha256" ]; then
    printf '%s\n' PREREQUISITE_PACKAGE_HASH_MISMATCH >&2; return 2
  fi
  ei_macos_run pkgutil --check-signature "$ei_mac_pkg" >&2 || return 2
  ei_macos_run spctl --assess --type install "$ei_mac_pkg" >&2 || return 2
  printf '%s\n' 'Python公式インストーラーを開きます。表示される導入内容・利用規約・管理者確認を確認してください。' >&2
  printf '%s\n' '完了後は公式手順の Install Certificates.command も実行してください。setupはこれらの確認を代理承認しません。' >&2
  printf '%s\n' 'インストーラーを終了するとsetupに戻ります。起動・待機が中断された場合は、一時パッケージを保持して場所を表示します。' >&2
  ei_mac_gui_pending=1
  ei_macos_run open -W -n "$ei_mac_pkg" || return 2
  ei_mac_gui_pending=0
  ei_wait_macos_install || return 2
)

ei_install_macos_dependencies() {
  if ! ei_is_interactive; then
    printf '%s\n' 'PREREQUISITE_INTERACTIVE_REQUIRED: macOSの導入画面は利用者の確認が必要です。対話端末でsetupを再実行するか、https://git-scm.com/install/mac と https://www.python.org/downloads/macos/ から事前導入してください。' >&2
    return 2
  fi
  # Validate the whole plan before starting any OS action.
  for ei_mac_package in "$@"; do
    case "$ei_mac_package" in git|python3) ;; *) return 2 ;; esac
  done
  for ei_mac_package in "$@"; do
    case "$ei_mac_package" in
      git)
        ei_macos_run xcode-select --install || return 2
        ei_wait_macos_install || return 2
        if ! ei_git_available; then
          printf '%s\n' 'PREREQUISITE_POSTCHECK_FAILED: Gitの導入はまだ確認できません。Appleの導入画面を確認してsetupを再実行してください。' >&2
          return 2
        fi ;;
      python3) ei_install_macos_python || return 2 ;;
    esac
  done
}

ei_install_dependencies() {
  ei_boot_manager=$1
  shift
  case "$ei_boot_manager" in
    macos-native) ei_install_macos_dependencies "$@" ;;
    apt-get|dnf)
      if [ "$ei_boot_manager" = apt-get ]; then set -- --no-remove -y "$@"; else set -- -y "$@"; fi
      if [ "$(id -u)" = 0 ]; then "$ei_boot_manager" install "$@"
      elif command -v sudo >/dev/null 2>&1; then
        if [ "${ei_boot_noninteractive:-0}" = 1 ]; then sudo -n "$ei_boot_manager" install "$@"
        else sudo "$ei_boot_manager" install "$@"; fi
      else return 1; fi ;;
    *) return 1 ;;
  esac
}

ei_ensure_prerequisites() {
  # requested Python, non-interactive, check-only, explicit installation consent
  ei_boot_requested=$1
  ei_boot_noninteractive=$2
  ei_boot_check=$3
  ei_boot_consent=$4
  ei_boot_python=$(ei_find_python "$ei_boot_requested") || ei_boot_python=''
  if [ -n "$ei_boot_requested" ] && [ -z "$ei_boot_python" ]; then
    printf '%s\n' 'PYTHON_OVERRIDE_UNUSABLE: 指定Pythonを確認してください。' >&2
    return 2
  fi
  ei_boot_git_missing=0
  ei_git_available || ei_boot_git_missing=1
  if [ "$ei_boot_git_missing" = 0 ] && [ -n "$ei_boot_python" ]; then printf '%s\n' "$ei_boot_python"; return 0; fi
  printf '%s\n' 'Git または Python 3.11以降（venv/ensurepipを含む）が不足しています。' >&2
  if [ "$ei_boot_check" = 1 ]; then printf '%s\n' PREREQUISITE_CHECK_ONLY_MISSING >&2; return 2; fi
  ei_boot_manager=$(ei_dependency_manager) || ei_boot_manager=''
  if [ -z "$ei_boot_manager" ]; then
    printf '%s\n' 'PREREQUISITE_MANAGER_UNAVAILABLE: https://git-scm.com/install/ と https://www.python.org/downloads/ の手動手順で導入し、setupを再実行してください。' >&2
    return 2
  fi
  set --
  [ "$ei_boot_git_missing" = 0 ] || set -- "$@" git
  if [ -z "$ei_boot_python" ]; then
    case "$ei_boot_manager" in
      macos-native) set -- "$@" python3 ;;
      apt-get) set -- "$@" python3 python3-venv ;;
      dnf) set -- "$@" python3 ;;
    esac
  fi
  printf '導入方法: %s / パッケージ: %s\n' "$ei_boot_manager" "$*" >&2
  printf '%s\n' '管理者権限や利用規約の確認が必要な場合があります。既存ソフトは削除しません。' >&2
  if [ "$ei_boot_manager" = macos-native ]; then
    if [ "$ei_boot_git_missing" = 1 ]; then
      printf '%s\n' 'GitはAppleのCommand Line Toolsで導入します。Git以外のコンパイラ・SDKなども含まれます。Xcode本体やHomebrewは導入しません。' >&2
    fi
    if [ -z "$ei_boot_python" ]; then
      printf '%s\n' 'Pythonはpython.org公式のPython 3.13.15パッケージを取得・検証し、macOSのインストーラーで導入します。' >&2
    fi
  fi
  if [ "$ei_boot_consent" != 1 ]; then
    if ! ei_is_interactive; then
      printf '%s\n' PREREQUISITE_CONSENT_REQUIRED >&2; return 2
    fi
    printf '%s' '不足ソフトをインストールして続行しますか？ [y/N]: ' >&2
    IFS= read -r ei_boot_answer || ei_boot_answer=''
    case "$ei_boot_answer" in y|Y|yes|YES) ;; *) printf '%s\n' PREREQUISITE_INSTALL_DECLINED >&2; return 2 ;; esac
  fi
  if ! ei_install_dependencies "$ei_boot_manager" "$@" >&2; then
    printf '%s\n' PREREQUISITE_INSTALL_FAILED >&2; return 2
  fi
  hash -r 2>/dev/null || true
  ei_boot_python=$(ei_find_python "$ei_boot_requested") || ei_boot_python=''
  if ! ei_git_available || [ -z "$ei_boot_python" ]; then
    printf '%s\n' 'PREREQUISITE_POSTCHECK_FAILED: 新しいターミナルでsetupを再実行してください。' >&2
    return 2
  fi
  printf '%s\n' "$ei_boot_python"
}
