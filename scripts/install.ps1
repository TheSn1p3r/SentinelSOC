<#
.SYNOPSIS
    Installs SentinelSOC as a Windows Service, in place, from this project
    directory.

.DESCRIPTION
    Run this from an elevated PowerShell session, from anywhere — it locates
    the project root itself (the parent of this scripts\ folder). It will:
      1. Create a Python virtual environment (.venv) if one doesn't exist.
      2. Install dependencies from requirements.txt into it.
      3. Create data\, logs\, and quarantine\ folders.
      4. Restrict the project folder's permissions to Administrators + SYSTEM.
      5. Register the SentinelSOC Windows Service (auto-start).
      6. Start the service, unless -StartNow:$false is given.

    Extract/move SentinelSOC to its final location BEFORE running this —
    it installs in place, it does not copy itself to Program Files.

.PARAMETER StartNow
    Start the service immediately after installing. Default: true.

.EXAMPLE
    .\install.ps1
.EXAMPLE
    .\install.ps1 -StartNow $false
#>
param([bool]$StartNow = $true)

$ErrorActionPreference = "Stop"
. (Join-Path $PSScriptRoot "_common.ps1")

Assert-Admin
$root = Get-ProjectRoot

Write-Host "== SentinelSOC installer ==" -ForegroundColor Cyan
Write-Host "Install root: $root"

# --- 1/6: Python ------------------------------------------------------------
$py = Get-PythonLauncher
if (-not $py) {
    Write-Error "Python 3.10+ was not found on PATH. Install it from https://www.python.org/downloads/windows/ (tick 'Add python.exe to PATH' during setup), then re-run this script."
    exit 1
}
Write-Host "Found Python via: $($py.Cmd) $($py.Args -join ' ')"

# --- 2/6: virtual environment + dependencies --------------------------------
$venvPath = Join-Path $root ".venv"
$venvPython = Get-VenvPython -Root $root
if (-not (Test-Path $venvPython)) {
    Write-Host "Creating virtual environment at $venvPath ..."
    $pyArgs = $py.Args
    & $py.Cmd @pyArgs -m venv $venvPath
    if ($LASTEXITCODE -ne 0 -or -not (Test-Path $venvPython)) {
        Write-Error "Failed to create the virtual environment."
        exit 1
    }
} else {
    Write-Host "Virtual environment already exists at $venvPath"
}

Write-Host "Installing dependencies (this can take a minute) ..."
& $venvPython -m pip install --upgrade pip --quiet
& $venvPython -m pip install -r (Join-Path $root "requirements.txt")
if ($LASTEXITCODE -ne 0) {
    Write-Error "pip install failed — see the output above."
    exit 1
}

# --- 3/6: data directories ---------------------------------------------------
foreach ($dir in @("data", "logs", "quarantine")) {
    $p = Join-Path $root $dir
    if (-not (Test-Path $p)) {
        New-Item -ItemType Directory -Path $p | Out-Null
        Write-Host "Created $p"
    }
}

# --- 4/6: restrict permissions ----------------------------------------------
Write-Host "Restricting folder permissions to Administrators and SYSTEM ..."
icacls $root /inheritance:r                                | Out-Null
icacls $root /grant:r "*S-1-5-32-544:(OI)(CI)F"             | Out-Null   # Administrators
icacls $root /grant:r "*S-1-5-18:(OI)(CI)F"                 | Out-Null   # SYSTEM

# --- 5/6: register the service ----------------------------------------------
$serviceScript = Join-Path $root "sentinelsoc\service_win.py"
Write-Host "Registering the SentinelSOC Windows Service ..."
& $venvPython $serviceScript --startup auto install
if ($LASTEXITCODE -ne 0) {
    Write-Error "Service registration failed — see the output above. A common cause is pywin32's post-install step not having run; try: `"$venvPython`" -m pywin32_postinstall -install"
    exit 1
}

# --- 6/6: start it ------------------------------------------------------------
if ($StartNow) {
    Write-Host "Starting the SentinelSOC service ..."
    & $venvPython $serviceScript start
}

$port = Get-ConfiguredPort -Root $root
Write-Host ""
Write-Host "Done." -ForegroundColor Green
Write-Host "Dashboard:      http://127.0.0.1:$port/"
Write-Host "Login key:      config\config.yaml -> api.api_key (auto-generated)"
Write-Host "Manage it with: scripts\service_control.ps1 {start|stop|restart|status}"
Write-Host "Uninstall with: scripts\uninstall.ps1"
