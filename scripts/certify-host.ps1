[CmdletBinding()]
param(
  [Parameter(Mandatory = $true)][string]$Repo,
  [Parameter(Mandatory = $true)][string]$HostId,
  [Parameter(Mandatory = $true)][string]$InstanceId,
  [ValidateSet("fixture", "real")][string]$Mode = "real",
  [string]$RuntimeRoot,
  [string]$HostHome,
  [string]$Output,
  [string]$OsProfile,
  [string]$PythonExe = "python.exe"
)

$ErrorActionPreference = "Stop"
$repoPath = (Resolve-Path -LiteralPath $Repo -ErrorAction Stop).Path
if (-not (Test-Path -LiteralPath (Join-Path $repoPath "src") -PathType Container)) {
  throw "REPO_ROOT_INVALID"
}
$pythonPath = (Get-Command $PythonExe -ErrorAction Stop).Source
$env:PYTHONPATH = Join-Path $repoPath "src"
$arguments = @("-B", "-m", "ei.cli", "certify-host", "--repo", $repoPath, "--host", $HostId, "--instance", $InstanceId, "--mode", $Mode, "--json")
if ($RuntimeRoot) { $arguments += @("--runtime-root", $RuntimeRoot) }
if ($HostHome) { $arguments += @("--host-home", $HostHome) }
if ($Output) { $arguments += @("--output", $Output) }
if ($OsProfile) { $arguments += @("--os-profile", $OsProfile) }
& $pythonPath @arguments
exit $LASTEXITCODE
