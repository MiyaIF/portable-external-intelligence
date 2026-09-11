param(
  [string]$Repo = (Join-Path $PSScriptRoot ".."),
  [string]$EngineRoot,
  [string]$KnowledgeRoot,
  [string]$PersonalKnowledgeRoot,
  [string]$TeamKnowledgeRoot,
  [string]$TeamMemberId,
  [switch]$NoTeamKnowledge,
  [string]$RuntimeRoot,
  [string]$ManifestPath,
  [string]$PythonExe,
  [string[]]$Hosts = @(),
  [string[]]$HostHome = @(),
  [switch]$CheckOnly,
  [switch]$NonInteractive,
  [switch]$Json
)
$ErrorActionPreference = "Stop"
if ($ManifestPath -and ($EngineRoot -or $KnowledgeRoot -or $PersonalKnowledgeRoot -or $TeamKnowledgeRoot -or $TeamMemberId -or $NoTeamKnowledge)) { throw "ROOT_OPTIONS_CONFLICT_WITH_MANIFEST" }
if ($KnowledgeRoot -and $PersonalKnowledgeRoot) { throw "PERSONAL_KNOWLEDGE_ROOT_CONFLICT" }
if ($KnowledgeRoot -and -not $EngineRoot) { throw "ENGINE_ROOT_REQUIRED" }
if ($TeamMemberId -and -not $TeamKnowledgeRoot) { throw "TEAM_KNOWLEDGE_ROOT_REQUIRED" }
if (-not $PythonExe) {
  $PythonExe = (Get-Command python.exe -ErrorAction SilentlyContinue).Source
  if (-not $PythonExe) { $PythonExe = (Get-Command py.exe -ErrorAction SilentlyContinue).Source }
}
if (-not $PythonExe) { throw "PYTHON_NOT_FOUND" }
if ($ManifestPath) {
  $manifestFile = (Resolve-Path -LiteralPath $ManifestPath -ErrorAction Stop).Path
  $manifestData = Get-Content -Raw -Encoding UTF8 -LiteralPath $manifestFile | ConvertFrom-Json
  if (-not $manifestData.repo_root) { throw "MANIFEST_REPO_ROOT_MISSING" }
  $repoPath = (Resolve-Path -LiteralPath ([string]$manifestData.repo_root) -ErrorAction Stop).Path
} else {
  $repoPath = (Resolve-Path -LiteralPath $Repo -ErrorAction Stop).Path
}
$oldPythonPath = $env:PYTHONPATH
$env:PYTHONPATH = (Join-Path $repoPath "src") + $(if ($oldPythonPath) { ";" + $oldPythonPath } else { "" })
$args = @("-B", "-m", "ei.installer", "--update", "--python-exe", $PythonExe)
if ($ManifestPath) { $args += @("--manifest", $ManifestPath) } elseif ($EngineRoot) { $args += @("--engine-root", $EngineRoot) } else { $args += @("--repo", $repoPath) }
if ($KnowledgeRoot) { $args += @("--knowledge-root", $KnowledgeRoot) }
if ($PersonalKnowledgeRoot) { $args += @("--personal-knowledge-root", $PersonalKnowledgeRoot) }
if ($TeamKnowledgeRoot) { $args += @("--team-knowledge-root", $TeamKnowledgeRoot) }
if ($TeamMemberId) { $args += @("--team-member-id", $TeamMemberId) }
if ($NoTeamKnowledge) { $args += "--no-team-knowledge" }
if ($RuntimeRoot) { $args += @("--runtime-root", $RuntimeRoot) }
foreach ($item in $Hosts) { $args += @("--hosts", $item) }
foreach ($item in $HostHome) { $args += @("--host-home", $item) }
if ($CheckOnly) { $args += "--check-only" }
if ($NonInteractive) { $args += "--non-interactive" }
if ($Json) { $args += "--json" }
& $PythonExe @args
exit $LASTEXITCODE
