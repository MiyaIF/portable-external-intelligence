param(
  [string]$RepoPath = (Join-Path $PSScriptRoot ".."),
  [string]$EngineRoot,
  [string]$KnowledgeRoot,
  [string]$CodexHome,
  [string]$RuntimeRoot,
  [string]$PythonExe,
  [switch]$Strict,
  [switch]$Json
)
$ErrorActionPreference = "Stop"
$repo = (Resolve-Path -LiteralPath $RepoPath -ErrorAction Stop).Path
if (-not $CodexHome) { $CodexHome = if ($env:CODEX_HOME) { $env:CODEX_HOME } else { Join-Path $env:USERPROFILE ".codex" } }
if (-not $PythonExe) {
  $PythonExe = (Get-Command python.exe -ErrorAction SilentlyContinue).Source
  if (-not $PythonExe) { $PythonExe = (Get-Command py.exe -ErrorAction SilentlyContinue).Source }
}
if (-not $PythonExe) { throw "PYTHON_NOT_FOUND" }
$oldPythonPath = $env:PYTHONPATH
$env:PYTHONPATH = (Join-Path $repo "src") + $(if ($oldPythonPath) { ";" + $oldPythonPath } else { "" })
$args = @("-B", "-m", "ei.doctor", "--repo-root", $repo, "--codex-home", $CodexHome)
if ($EngineRoot) { $args += @("--engine-root", $EngineRoot) }
if ($KnowledgeRoot) { $args += @("--knowledge-root", $KnowledgeRoot) }
if ($RuntimeRoot) { $args += @("--runtime-root", $RuntimeRoot) }
if ($Strict) { $args += "--strict" }
if ($Json) { $args += "--json" }
& $PythonExe @args
exit $LASTEXITCODE
