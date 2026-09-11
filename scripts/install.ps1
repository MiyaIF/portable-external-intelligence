param(
  [string]$RepoPath = (Join-Path $PSScriptRoot ".."),
  [string]$EngineRoot,
  [string]$KnowledgeRoot,
  [string]$PersonalKnowledgeRoot,
  [string]$TeamKnowledgeRoot,
  [string]$TeamMemberId,
  [switch]$NoTeamKnowledge,
  [string]$CodexHome,
  [string]$OrganizerProvider,
  [string]$OrganizerHost,
  [string]$PythonExe,
  [switch]$SkipVenv,
  [switch]$CheckOnly,
  [switch]$NoScheduledTask,
  [switch]$Json
)
$ErrorActionPreference = "Stop"
if ($PersonalKnowledgeRoot -and $KnowledgeRoot) { throw "PERSONAL_KNOWLEDGE_ROOT_CONFLICT" }
if (-not $CodexHome) {
  $CodexHome = if ($env:CODEX_HOME) { $env:CODEX_HOME } else { Join-Path $env:USERPROFILE ".codex" }
}
$repo = (Resolve-Path -LiteralPath $RepoPath -ErrorAction Stop).Path
$setup = Join-Path $PSScriptRoot "setup.ps1"
$runtime = Join-Path ([IO.Path]::GetFullPath($CodexHome)) "external-intelligence"
$knowledge = if ($KnowledgeRoot) { [IO.Path]::GetFullPath($KnowledgeRoot) } else { Join-Path ([IO.Path]::GetFullPath($CodexHome)) "external-intelligence-knowledge" }
$setupArgs = @("-Repo", $repo, "-KnowledgeMode", "local", "-RuntimeRoot", $runtime, "-Hosts", "codex-cli", "-HostHome", ("codex-cli=" + [IO.Path]::GetFullPath($CodexHome)), "-NonInteractive", "-AcceptPlan")
if ($OrganizerProvider) { $setupArgs += @("-OrganizerProvider", $OrganizerProvider) }
if ($OrganizerHost) { $setupArgs += @("-OrganizerHost", $OrganizerHost) }
if ($PersonalKnowledgeRoot) { $setupArgs += @("-PersonalKnowledgeRoot", [IO.Path]::GetFullPath($PersonalKnowledgeRoot)) }
else { $setupArgs += @("-KnowledgeRoot", $knowledge) }
if ($EngineRoot) { $setupArgs += @("-EngineRoot", $EngineRoot) }
if ($TeamKnowledgeRoot) { $setupArgs += @("-TeamKnowledgeRoot", $TeamKnowledgeRoot) }
if ($TeamMemberId) { $setupArgs += @("-TeamMemberId", $TeamMemberId) }
if ($NoTeamKnowledge) { $setupArgs += "-NoTeamKnowledge" }
if ($PythonExe) { $setupArgs += @("-PythonExe", $PythonExe) }
if ($SkipVenv) { $setupArgs += "-SkipVenv" }
if ($CheckOnly) { $setupArgs += "-CheckOnly" }
if ($Json) { $setupArgs += "-Json" }
if (-not $NoScheduledTask -and -not $CheckOnly) { $setupArgs += "-Scheduler" }
& powershell.exe -NoProfile -ExecutionPolicy Bypass -File $setup @setupArgs
exit $LASTEXITCODE
