# Double-click launcher for Proxy Tester.
# Resolves paths relative to this file, so it works from any working directory.

$ErrorActionPreference = 'Stop'

$scriptPath = Join-Path -Path $PSScriptRoot -ChildPath 'main.py'

if (-not (Test-Path -LiteralPath $scriptPath)) {
    Write-Host "Python entry point not found:" -ForegroundColor Red
    Write-Host $scriptPath
    Read-Host "Press Enter to close"
    exit 1
}

Set-Location -LiteralPath $PSScriptRoot

$py = Get-Command py -ErrorAction SilentlyContinue
$python = Get-Command python -ErrorAction SilentlyContinue

if ($py) {
    & $py.Source -3 $scriptPath @args
} elseif ($python) {
    & $python.Source $scriptPath @args
} else {
    Write-Host "Python was not found. Install Python 3.9+ or add it to PATH." -ForegroundColor Red
    Read-Host "Press Enter to close"
    exit 1
}

$exitCode = $LASTEXITCODE
if ($null -eq $exitCode) {
    $exitCode = 0
}

if ($exitCode -ne 0) {
    Write-Host ""
    Write-Host "Script exited with code $exitCode." -ForegroundColor Yellow
}

Read-Host "Press Enter to close"
exit $exitCode
