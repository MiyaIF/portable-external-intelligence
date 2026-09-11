param(
  [string]$Repo = (Join-Path $PSScriptRoot ".."),
  [string]$EngineRoot,
  [ValidateSet("local", "github-new", "github-existing")]
  [string]$KnowledgeMode,
  [string]$KnowledgeRoot,
  [string]$PersonalKnowledgeRoot,
  [string]$TeamKnowledgeRoot,
  [string]$TeamMemberId,
  [switch]$NoTeamKnowledge,
  [string]$RuntimeRoot,
  [string]$GitHubRepository,
  [string]$GitHubExecutable = "gh",
  [string]$RemoteName = "origin",
  [string]$Branch = "main",
  [string]$ConfirmGitHubCreate,
  [string[]]$Hosts = @(),
  [string[]]$HostHome = @(),
  [string[]]$Providers = @(),
  [string]$OrganizerProvider,
  [string]$OrganizerHost,
  [string]$PrivacyProfile = "private-reusable",
  [string]$PythonExe,
  [string]$SkillMode = "copy",
  [switch]$Sync,
  [switch]$NoSync,
  [switch]$Experiment,
  [switch]$Scheduler,
  [switch]$CheckOnly,
  [switch]$NonInteractive,
  [switch]$AcceptPlan,
  [switch]$SkipVenv,
  [switch]$Json
)
$ErrorActionPreference = "Stop"
if ($Sync -and $NoSync) { throw "SYNC_SELECTION_CONFLICT" }
if ($TeamKnowledgeRoot -and $NoTeamKnowledge) { throw "TEAM_SELECTION_CONFLICT" }

function Resolve-PythonExecutable {
  param([string]$Requested)
  if ($Requested) {
    $resolved = (Resolve-Path -LiteralPath $Requested -ErrorAction Stop).Path
    & $resolved -c "import sys; raise SystemExit(0 if sys.version_info >= (3,11) else 1)"
    if ($LASTEXITCODE -ne 0) { throw "PYTHON_VERSION_UNSUPPORTED" }
    return $resolved
  }
  foreach ($candidate in @("py.exe", "python.exe", "python3")) {
    try {
      if ($candidate -eq "py.exe") {
        & $candidate -3 -c "import sys; raise SystemExit(0 if sys.version_info >= (3,11) else 1)" 2>$null
        if ($LASTEXITCODE -eq 0) { return ((& $candidate -3 -c "import sys; print(sys.executable)").Trim()) }
      } else {
        & $candidate -c "import sys; raise SystemExit(0 if sys.version_info >= (3,11) else 1)" 2>$null
        if ($LASTEXITCODE -eq 0) { return ((& $candidate -c "import sys; print(sys.executable)").Trim()) }
      }
    } catch {}
  }
  throw "PYTHON_NOT_FOUND"
}

$repoPath = (Resolve-Path -LiteralPath $Repo -ErrorAction Stop).Path
if (-not (Test-Path -LiteralPath (Join-Path $repoPath "src") -PathType Container)) { throw "REPO_ROOT_INVALID" }
$python = Resolve-PythonExecutable $PythonExe
$oldPythonPath = $env:PYTHONPATH
$env:PYTHONPATH = (Join-Path $repoPath "src") + $(if ($oldPythonPath) { ";" + $oldPythonPath } else { "" })
$cli = @("-B", "-m", "ei.installer", "--setup", "--python-exe", $python, "--privacy-profile", $PrivacyProfile, "--skill-mode", $SkillMode)
if ($EngineRoot) { $cli += @("--engine-root", $EngineRoot) } else { $cli += @("--repo", $repoPath) }
if ($KnowledgeMode) { $cli += @("--knowledge-mode", $KnowledgeMode) }
if ($KnowledgeRoot) { $cli += @("--knowledge-root", $KnowledgeRoot) }
if ($PersonalKnowledgeRoot) { $cli += @("--personal-knowledge-root", $PersonalKnowledgeRoot) }
if ($TeamKnowledgeRoot) { $cli += @("--team-knowledge-root", $TeamKnowledgeRoot) }
if ($TeamMemberId) { $cli += @("--team-member-id", $TeamMemberId) }
if ($NoTeamKnowledge) { $cli += "--no-team-knowledge" }
if ($RuntimeRoot) { $cli += @("--runtime-root", $RuntimeRoot) }
if ($GitHubRepository) { $cli += @("--github-repository", $GitHubRepository) }
if ($GitHubExecutable) { $cli += @("--github-executable", $GitHubExecutable) }
if ($RemoteName) { $cli += @("--remote-name", $RemoteName) }
if ($Branch) { $cli += @("--branch", $Branch) }
if ($ConfirmGitHubCreate) { $cli += @("--confirm-github-create", $ConfirmGitHubCreate) }
if ($Hosts.Count -gt 0) { foreach ($item in $Hosts) { $cli += @("--hosts", $item) } }
if ($HostHome.Count -gt 0) { foreach ($item in $HostHome) { $cli += @("--host-home", $item) } }
if ($Providers.Count -gt 0) { foreach ($item in $Providers) { $cli += @("--providers", $item) } }
if ($OrganizerProvider) { $cli += @("--organizer-provider", $OrganizerProvider) }
if ($OrganizerHost) { $cli += @("--organizer-host", $OrganizerHost) }
if ($Sync) { $cli += "--sync" }
if ($NoSync) { $cli += "--no-sync" }
if ($Experiment) { $cli += "--experiment" }
if ($Scheduler) { $cli += "--scheduler" }
if ($CheckOnly) { $cli += "--check-only" }
if ($NonInteractive) { $cli += "--non-interactive" }
if ($AcceptPlan) { $cli += "--accept-plan" }
if ($SkipVenv) { $cli += "--skip-venv" }
if ($Json) { $cli += "--json" }
& $python @cli
$code = $LASTEXITCODE
if ($code -ne 0) { exit $code }
exit 0
