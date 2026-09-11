param(
  [string]$Source,
  [string]$Report,
  [string]$Inventory,
  [string]$RepoPath = (Join-Path $PSScriptRoot ".."),
  [string]$SourceRoot,
  [string]$KnowledgeRoot,
  [string]$CodexHome,
  [string]$RuntimeRoot,
  [string]$PythonExe,
  [switch]$DryRun,
  [switch]$Apply,
  [string]$ExpectedPlanHash,
  [switch]$AllowGlobalSource,
  [ValidateSet("inspect","apply","rollback","cleanup","inspect-recovery","recover-staging")][string]$Operation,
  [string]$PlanPath,
  [string]$ReceiptPath,
  [switch]$Confirm
)
$ErrorActionPreference = "Stop"
if (-not $PythonExe) { $PythonExe = Join-Path $env:LOCALAPPDATA "Programs\Python\Python313\python.exe" }
if (-not $CodexHome) { if ($env:CODEX_HOME) { $CodexHome = $env:CODEX_HOME } else { $CodexHome = Join-Path $env:USERPROFILE ".codex" } }
$repo = (Resolve-Path -LiteralPath $RepoPath -ErrorAction Stop).Path
$env:PYTHONPATH = (Join-Path $repo "src") + $(if ($env:PYTHONPATH) { ";$env:PYTHONPATH" } else { "" })
$args = @()
if ($Operation) {
  if (-not $RuntimeRoot) { throw "RuntimeRoot is required for root migration" }
  if (-not $KnowledgeRoot -and $Operation -notin @("rollback")) { throw "KnowledgeRoot is required for root migration" }
  $args = @("-B", "-m", "ei.cli", "migration", $Operation)
  if ($Operation -eq "inspect") {
    $sourceValue = if ($SourceRoot) { $SourceRoot } else { $repo }
    $args += @("--repo", $sourceValue, "--knowledge-root", $KnowledgeRoot, "--runtime-root", $RuntimeRoot)
    if ($PlanPath) { $args += @("--plan-output", $PlanPath) }
  } elseif ($Operation -eq "apply" -or $Operation -eq "cleanup") {
    if (-not $PlanPath) { throw "PlanPath is required" }
    if (-not $ExpectedPlanHash) { throw "ExpectedPlanHash is required" }
    $args += @("--plan", $PlanPath, "--confirm-plan-hash", $ExpectedPlanHash)
    if ($Operation -eq "cleanup") {
      if (-not $VerifiedBackup) { throw "VerifiedBackup is required" }
      $args += @("--verified-backup", $VerifiedBackup)
    }
  } elseif ($Operation -eq "rollback") {
    if (-not $ReceiptPath) { throw "ReceiptPath is required" }
    if (-not $ExpectedPlanHash) { throw "ExpectedPlanHash is required" }
    $args += @("--receipt", $ReceiptPath, "--confirm-plan-hash", $ExpectedPlanHash)
  } else {
    $args += @("--knowledge-root", $KnowledgeRoot, "--runtime-root", $RuntimeRoot)
    if (-not $ExpectedPlanHash) { throw "ExpectedPlanHash is required" }
    $args += @("--plan-hash", $ExpectedPlanHash)
    if ($Confirm) { $args += "--confirm" }
  }
  if ($Report) { $args += @("--output", $Report) }
  $args += "--json"
  & $PythonExe @args
  exit $LASTEXITCODE
}
if (-not $Source -or -not $Report) { throw "Source and Report are required for legacy source ingestion" }
if ($DryRun -eq $Apply -and -not $ExpectedPlanHash) { throw "Choose exactly one of -DryRun or -Apply" }
$args = @("-B", "-m", "ei.cli", "migrate-existing", "--source", $Source, "--report", $Report, "--repo-root", $repo, "--codex-home", $CodexHome)
if ($RuntimeRoot) { $args += @("--runtime-root", $RuntimeRoot) }
if ($DryRun) { $args += "--dry-run" }
if ($Apply) { $args += "--apply" }
if ($ExpectedPlanHash) { $args += @("--apply-plan-hash", $ExpectedPlanHash) }
if ($Inventory) { $args += @("--inventory", $Inventory) }
if ($AllowGlobalSource) { $args += "--allow-global-source" }
& $PythonExe @args
exit $LASTEXITCODE
