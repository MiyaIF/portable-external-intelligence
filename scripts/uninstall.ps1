param(
  [Parameter(Mandatory=$true)][string]$ManifestPath,
  [string]$PythonExe,
  [string]$ConfirmManifestSha256,
  [switch]$RestoreConfigBackup,
  [switch]$RemoveRuntimeCache,
  [switch]$RemoveRuntime,
  [switch]$RemoveVenv,
  [switch]$KeepSkills,
  [switch]$Force,
  [switch]$CheckOnly,
  [switch]$NoScheduledTask,
  [switch]$Json
)
$ErrorActionPreference = "Stop"
# The installer removes only owned integration artifacts.  Personal/team
# events, shared member shards, outbox, and writer identity are retained by
# default; -RemoveRuntimeCache is the explicit team-cache cleanup switch.
$manifestFile = (Resolve-Path -LiteralPath $ManifestPath -ErrorAction Stop).Path
$manifestData = Get-Content -Raw -Encoding UTF8 -LiteralPath $manifestFile | ConvertFrom-Json
if (-not $PythonExe -and $manifestData.python_exe -and (Test-Path -LiteralPath ([string]$manifestData.python_exe) -PathType Leaf)) { $PythonExe = [string]$manifestData.python_exe }
if (-not $PythonExe) { $PythonExe = (Get-Command python.exe -ErrorAction SilentlyContinue).Source }
if (-not $PythonExe) { $PythonExe = (Get-Command py.exe -ErrorAction SilentlyContinue).Source }
if (-not $PythonExe) { throw "PYTHON_NOT_FOUND" }
if (-not $CheckOnly -and -not $ConfirmManifestSha256) { throw "UNINSTALL_CONFIRMATION_REQUIRED" }
$repoPath = (Resolve-Path -LiteralPath ([string]$manifestData.repo_root) -ErrorAction Stop).Path
$runtimePath = [IO.Path]::GetFullPath([string]$manifestData.runtime_root)
$oldPythonPath = $env:PYTHONPATH
$env:PYTHONPATH = (Join-Path $repoPath "src") + $(if ($oldPythonPath) { ";" + $oldPythonPath } else { "" })
$args = @("-B", "-m", "ei.installer", "--uninstall", "--manifest", $manifestFile, "--python-exe", $PythonExe)
if ($ConfirmManifestSha256) { $args += @("--confirm-manifest-sha256", $ConfirmManifestSha256) }
if ($RestoreConfigBackup) { $args += "--restore-config-backup" }
if ($RemoveRuntimeCache) { $args += "--remove-runtime-cache" }
if ($RemoveRuntime) { $args += "--remove-runtime" }
if ($RemoveVenv) { $args += "--remove-venv" }
if ($KeepSkills) { $args += "--keep-skills" }
if ($NoScheduledTask) { $args += "--no-scheduled-task" }
if ($Force) { $args += "--force" }
if ($CheckOnly) { $args += "--check-only" }
if ($Json) { $args += "--json" }
& $PythonExe @args
exit $LASTEXITCODE
