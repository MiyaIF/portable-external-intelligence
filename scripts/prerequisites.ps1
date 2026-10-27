# Native bootstrap: this file must work before Python is installed.
function Find-EiPython {
  param([string]$Requested)
  $candidates = @()
  if ($Requested) {
    $candidates = @((Resolve-Path -LiteralPath $Requested -ErrorAction Stop).Path)
  } else {
    foreach ($name in @('python3.exe', 'python.exe')) {
      $command = Get-Command $name -CommandType Application -ErrorAction SilentlyContinue | Select-Object -First 1
      if ($command -and $command.Source -notlike '*\Microsoft\WindowsApps\*') { $candidates += $command.Source }
    }
    $launcher = Get-Command py.exe -CommandType Application -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($launcher) {
      # Listing does not ask the Python install manager to download a runtime.
      try {
        $listed = & $launcher.Source -0p 2>$null
        if ($LASTEXITCODE -eq 0) {
          foreach ($line in $listed) {
            if ($line -match '([A-Za-z]:\\.+?python(?:[0-9.]+)?\.exe)\s*\*?\s*$') { $candidates += $Matches[1] }
          }
        }
      } catch {}
    }
  }
  foreach ($candidate in ($candidates | Select-Object -Unique)) {
    try {
      $resolved = & $candidate -I -B -c 'import sys,venv,ensurepip; sys.exit(1) if sys.version_info < (3,11) else None; print(sys.executable)' 2>$null
      if ($LASTEXITCODE -eq 0 -and $resolved -and (Test-Path -LiteralPath ([string]$resolved).Trim() -PathType Leaf)) {
        return ([string]$resolved).Trim()
      }
    } catch {}
  }
  if ($Requested) { throw 'PYTHON_OVERRIDE_UNUSABLE' }
  return $null
}

function Test-EiGit {
  $command = Get-Command git.exe -CommandType Application -ErrorAction SilentlyContinue | Select-Object -First 1
  if (-not $command) { return $false }
  try {
    $null = & $command.Source --version 2>$null
    return ($LASTEXITCODE -eq 0)
  } catch { return $false }
}

function Get-EiDependencyManager {
  $command = Get-Command winget.exe -CommandType Application -ErrorAction SilentlyContinue | Select-Object -First 1
  if ($command) { return $command.Source }
  return $null
}

function Invoke-EiDependencyInstall {
  param([string]$Manager, [string]$PackageId, [switch]$NonInteractive)
  if ($PackageId -notin @('Git.Git', 'Python.Python.3.13')) { throw 'PREREQUISITE_PACKAGE_INVALID' }
  $installArgs = @('install', '--id', $PackageId, '--exact', '--source', 'winget', '--no-upgrade')
  if ($NonInteractive) { $installArgs += '--disable-interactivity' }
  # Do not bypass EULAs, installer hashes, UAC, security scans, or reboot consent.
  & $Manager @installArgs 2>&1 | ForEach-Object { [Console]::Error.WriteLine([string]$_) }
  if ($LASTEXITCODE -ne 0) { throw 'PREREQUISITE_INSTALL_FAILED' }
}

function Resolve-EiPrerequisites {
  param([string]$PythonExe, [switch]$NonInteractive, [switch]$CheckOnly, [switch]$InstallPrerequisites)
  $python = Find-EiPython $PythonExe
  $packages = @()
  if (-not (Test-EiGit)) { $packages += 'Git.Git' }
  if (-not $python) { $packages += 'Python.Python.3.13' }
  if ($packages.Count -eq 0) { return $python }
  [Console]::Error.WriteLine('必要なソフトが不足しています: ' + ($packages -join ', '))
  [Console]::Error.WriteLine('WinGetの指定パッケージを導入します。管理者確認・利用規約の確認が出る場合があります。既存ソフトを削除しません。')
  if ($CheckOnly) { throw 'PREREQUISITE_CHECK_ONLY_MISSING' }
  $manager = Get-EiDependencyManager
  if (-not $manager) {
    [Console]::Error.WriteLine('手動で https://git-scm.com/install/windows と https://www.python.org/downloads/windows/ から導入し、setupを再実行してください。')
    throw 'PREREQUISITE_MANAGER_UNAVAILABLE'
  }
  if (-not $InstallPrerequisites) {
    if ($NonInteractive -or [Console]::IsInputRedirected) { throw 'PREREQUISITE_CONSENT_REQUIRED' }
    $answer = Read-Host '不足ソフトをインストールして続行しますか？ [y/N]'
    if ($answer.Trim().ToLowerInvariant() -notin @('y', 'yes')) { throw 'PREREQUISITE_INSTALL_DECLINED' }
  }
  foreach ($package in $packages) { Invoke-EiDependencyInstall -Manager $manager -PackageId $package -NonInteractive:$NonInteractive }
  # Refresh only this process; do not persist PATH changes ourselves.
  $env:PATH = (@($env:PATH, [Environment]::GetEnvironmentVariable('Path', 'Machine'), [Environment]::GetEnvironmentVariable('Path', 'User')) | Where-Object { $_ }) -join ';'
  $python = Find-EiPython $PythonExe
  if (-not (Test-EiGit) -or -not $python) {
    [Console]::Error.WriteLine('導入後の確認ができませんでした。新しいターミナルからsetupを再実行してください。')
    throw 'PREREQUISITE_POSTCHECK_FAILED'
  }
  return $python
}
