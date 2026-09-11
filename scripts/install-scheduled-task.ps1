param(
  [string]$RepoPath = (Join-Path $PSScriptRoot ".."),
  [string]$CodexHome,
  [string]$KnowledgeRoot,
  [string]$RuntimeRoot,
  [string]$PythonExe,
  [switch]$CheckOnly,
  [string]$TaskName = "CodexExternalIntelligenceMaintenance-v1"
)
$ErrorActionPreference = "Stop"
$utf8NoBom = New-Object System.Text.UTF8Encoding($false)
[Console]::OutputEncoding = $utf8NoBom
$OutputEncoding = $utf8NoBom
$env:PYTHONIOENCODING = "utf-8"
$env:PYTHONUTF8 = "1"

function Resolve-Python {
  param([string]$Requested, [string]$Repo)
  if ($Requested) { return (Resolve-Path -LiteralPath $Requested -ErrorAction Stop).Path }
  $candidate = Join-Path $Repo ".venv\Scripts\python.exe"
  if (Test-Path -LiteralPath $candidate -PathType Leaf) { return (Resolve-Path -LiteralPath $candidate).Path }
  throw "SCHEDULER_PYTHON_NOT_FOUND"
}

$repo = (Resolve-Path -LiteralPath $RepoPath -ErrorAction Stop).Path
if (-not $CodexHome) {
  if ($env:CODEX_HOME) { $CodexHome = $env:CODEX_HOME }
  else { $CodexHome = Join-Path $env:USERPROFILE ".codex" }
}
$taskHome = [IO.Path]::GetFullPath($CodexHome)
if (-not $RuntimeRoot) { $RuntimeRoot = Join-Path $taskHome "external-intelligence" }
if (-not $KnowledgeRoot) { $KnowledgeRoot = Join-Path $taskHome "external-intelligence-knowledge" }
$runtimeRoot = [IO.Path]::GetFullPath($RuntimeRoot)
$knowledgeRoot = [IO.Path]::GetFullPath($KnowledgeRoot)
if ($TaskName -ne "CodexExternalIntelligenceMaintenance-v1") { throw "SCHEDULER_TASK_NAME_INVALID" }
$python = Resolve-Python $PythonExe $repo
$oldPythonPath = $env:PYTHONPATH
$env:PYTHONPATH = (Join-Path $repo "src") + $(if ($oldPythonPath) { ";$oldPythonPath" } else { "" })
$rendered = & $python -B -m ei.task_scheduler --engine-root $repo --knowledge-root $knowledgeRoot --codex-home $taskHome --runtime-root $runtimeRoot --python-exe $python --json
if ($LASTEXITCODE -ne 0) { throw "Scheduler action rendering failed with exit code $LASTEXITCODE" }
$definition = $rendered | ConvertFrom-Json

$intervalTrigger = @($definition.triggers) | Where-Object { ([string]$_) -match "^every_\d+_minutes$" } | Select-Object -First 1
$intervalMatch = [regex]::Match(([string]$intervalTrigger), "every_(\d+)_minutes")
$interval = if ($intervalMatch.Success) { [int]$intervalMatch.Groups[1].Value } else { 30 }
$registrationPreview = [ordered]@{
  repetition_interval = ("PT{0}M" -f $interval)
  repetition_duration = "P3650D"
  stop_at_duration_end = $false
  principal_source = "current-user-default"
  logon_type = "Interactive"
  run_level = "Limited"
  trigger_mode = "once-with-repetition"
}
$definition | Add-Member -NotePropertyName "registration_preview" -NotePropertyValue $registrationPreview -Force
if ($CheckOnly) { $definition | ConvertTo-Json -Depth 10; exit 0 }

$action = New-ScheduledTaskAction -Execute ([string]$definition.executable) -Argument ([string]$definition.arguments) -WorkingDirectory ([string]$definition.working_directory)
$repeatingTrigger = New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes(2) -RepetitionInterval (New-TimeSpan -Minutes $interval) -RepetitionDuration (New-TimeSpan -Days 3650)
$repeatingTrigger.Repetition.StopAtDurationEnd = $false
$taskSettings = New-ScheduledTaskSettingsSet -MultipleInstances IgnoreNew -ExecutionTimeLimit (New-TimeSpan -Minutes 10) -StartWhenAvailable
Register-ScheduledTask -TaskName $TaskName -Action $action -Trigger $repeatingTrigger -Settings $taskSettings -Force | Out-Null

& $python -B -m ei.task_scheduler --engine-root $repo --knowledge-root $knowledgeRoot --codex-home $taskHome --runtime-root $runtimeRoot --python-exe $python --json --write-state --registered
if ($LASTEXITCODE -ne 0) { throw "Scheduler state write failed with exit code $LASTEXITCODE" }
Write-Output "Registered user-level scheduled task $TaskName with limited privileges and no wake-to-run."
