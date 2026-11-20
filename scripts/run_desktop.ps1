<#
.SYNOPSIS
    Runs SentinelSOC in the foreground (desktop/dev mode) without installing
    the Windows Service — useful for a first look or for development.

.DESCRIPTION
    Sets up the virtual environment (same first steps as install.ps1) if it
    doesn't exist yet, then runs `python main.py` in the foreground. Press
    Ctrl+C to stop. Does not require an elevated session, but Event Log
    collection will be more limited than when running as the service
    (which runs as SYSTEM) — some logs/events require elevated rights to read.

.EXAMPLE
    .\run_desktop.ps1
#>
$ErrorActionPreference = "Stop"
. (Join-Path $PSScriptRoot "_common.ps1")
$root = Get-ProjectRoot

$venvPython = Get-VenvPython -Root $root
if (-not (Test-Path $venvPython)) {
    Write-Host "No virtual environment yet — setting one up (same as install.ps1's first steps) ..."
    $py = Get-PythonLauncher
    if (-not $py) {
        Write-Error "Python 3.10+ was not found on PATH. Install it from https://www.python.org/downloads/windows/ and re-run."
        exit 1
    }
    $pyArgs = $py.Args
    & $py.Cmd @pyArgs -m venv (Join-Path $root ".venv")
    & $venvPython -m pip install --upgrade pip --quiet
    & $venvPython -m pip install -r (Join-Path $root "requirements.txt")
}

$port = Get-ConfiguredPort -Root $root
Write-Host "Starting SentinelSOC in the foreground — dashboard will be at http://127.0.0.1:$port/" -ForegroundColor Cyan
Write-Host "Press Ctrl+C to stop." -ForegroundColor Cyan

Push-Location $root
try {
    & $venvPython (Join-Path $root "main.py")
} finally {
    Pop-Location
}
