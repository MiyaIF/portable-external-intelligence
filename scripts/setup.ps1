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
  [switch]$NoScheduler,
  [switch]$InstallPrerequisites,
  [switch]$CheckOnly,
  [switch]$NonInteractive,
  [switch]$AcceptPlan,
  [switch]$SkipVenv,
  [switch]$Json
)
$ErrorActionPreference = "Stop"
if ($Sync -and $NoSync) { throw "SYNC_SELECTION_CONFLICT" }
if ($Scheduler -and $NoScheduler) { throw "SCHEDULER_SELECTION_CONFLICT" }
if ($TeamKnowledgeRoot -and $NoTeamKnowledge) { throw "TEAM_SELECTION_CONFLICT" }

$repoPath = (Resolve-Path -LiteralPath $Repo -ErrorAction Stop).Path
if (-not (Test-Path -LiteralPath (Join-Path $repoPath "src") -PathType Container)) { throw "REPO_ROOT_INVALID" }
. (Join-Path $PSScriptRoot 'prerequisites.ps1')
try {
  $python = Resolve-EiPrerequisites -PythonExe $PythonExe -NonInteractive:$NonInteractive -CheckOnly:$CheckOnly -InstallPrerequisites:$InstallPrerequisites
} catch {
  if ($Json) { @{ok=$false; error_code=$_.Exception.Message; stage='prerequisites'} | ConvertTo-Json -Compress }
  else { [Console]::Error.WriteLine($_.Exception.Message) }
  exit 2
}
$bootstrap = 'import runpy,sys;source=sys.argv.pop(1);sys.path.insert(0,source);runpy.run_module(''ei.installer'',run_name=''__main__'')'
$cli = @("-I", "-B", "-X", "utf8", "-c", $bootstrap, (Join-Path $repoPath 'src'), "--setup", "--python-exe", $python, "--privacy-profile", $PrivacyProfile, "--skill-mode", $SkillMode)
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
if ($NoScheduler) { $cli += "--no-scheduler" }
if ($CheckOnly) { $cli += "--check-only" }
if ($NonInteractive) { $cli += "--non-interactive" }
if ($AcceptPlan) { $cli += "--accept-plan" }
if ($SkipVenv) { $cli += "--skip-venv" }
if ($Json) { $cli += "--json" }
& $python @cli
$code = $LASTEXITCODE
if ($code -ne 0) { exit $code }
exit 0
