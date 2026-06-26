# Run from the repository root: .\scripts\run_bot.ps1
$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$repoRoot = Split-Path -Parent $scriptDir
$backendRoot = Join-Path $repoRoot "backend"
$pythonExe = Join-Path $backendRoot ".venv\Scripts\python.exe"

$env:PYTHONPATH = $backendRoot
$env:PYTHONUNBUFFERED = "1"

if (-not (Test-Path -LiteralPath $pythonExe)) {
  Write-Error "Backend virtualenv Python not found at $pythonExe"
  exit 1
}

Set-Location $repoRoot
& $pythonExe "bot\main.py"
