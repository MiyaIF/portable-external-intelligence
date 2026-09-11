param(
  [string]$RepoPath = (Join-Path $PSScriptRoot ".."),
  [string]$CodexHome,
  [string]$RuntimeRoot,
  [string]$PythonExe,
  [switch]$CheckOnly,
  [string]$TaskName = "CodexExternalIntelligenceMaintenance-v1"
)
$ErrorActionPreference = "Stop"
if ($TaskName -ne "CodexExternalIntelligenceMaintenance-v1") { throw "SCHEDULER_TASK_NAME_INVALID" }
$repo = (Resolve-Path -LiteralPath $RepoPath -ErrorAction Stop).Path
if (-not $CodexHome) {
  if ($env:CODEX_HOME) { $CodexHome = $env:CODEX_HOME }
  else { $CodexHome = Join-Path $env:USERPROFILE ".codex" }
}
$taskHome = [IO.Path]::GetFullPath($CodexHome)
if (-not $RuntimeRoot) { $RuntimeRoot = Join-Path $taskHome "external-intelligence" }
$runtimeRoot = [IO.Path]::GetFullPath($RuntimeRoot)
if (-not $PythonExe) { $PythonExe = Join-Path $repo ".venv\Scripts\python.exe" }
$python = (Resolve-Path -LiteralPath $PythonExe -ErrorAction Stop).Path
$oldPythonPath = $env:PYTHONPATH
$env:PYTHONPATH = (Join-Path $repo "src") + $(if ($oldPythonPath) { ";$oldPythonPath" } else { "" })
$statePath = Join-Path $runtimeRoot "scheduler-state.json"
if (-not (Test-Path -LiteralPath $statePath -PathType Leaf)) { Write-Output "No managed scheduler state exists."; exit 0 }
$state = Get-Content -Raw -Encoding UTF8 -LiteralPath $statePath | ConvertFrom-Json
if (-not $state.registered) { Write-Output "Managed scheduler is already absent."; exit 0 }
$task = Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
if (-not $task) { throw "SCHEDULED_TASK_NOT_FOUND" }
$expected = $state.action
$liveAction = $task.Actions | Select-Object -First 1
if ([string]$liveAction.Execute -ne [string]$expected.executable -or [string]$liveAction.Arguments -ne [string]$expected.arguments -or [string]$liveAction.WorkingDirectory -ne [string]$expected.working_directory) {
  throw "SCHEDULER_ACTION_MISMATCH"
}
if ($CheckOnly) { [pscustomobject]@{ task_name = $TaskName; action_verified = $true; would_remove = $true } | ConvertTo-Json -Compress; exit 0 }
Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false
& $python -B -m ei.task_scheduler --repo-root $repo --codex-home $taskHome --runtime-root $runtimeRoot --python-exe $python --json --write-state
if ($LASTEXITCODE -ne 0) { throw "Scheduler state write failed with exit code $LASTEXITCODE" }
Write-Output "Removed managed scheduled task $TaskName after action verification."
