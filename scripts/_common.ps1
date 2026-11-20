# Shared helpers for the SentinelSOC PowerShell scripts.
# This file is dot-sourced by install.ps1 / uninstall.ps1 / service_control.ps1
# / run_desktop.ps1 — it isn't meant to be run directly.

$Script:SentinelSOCServiceName = "SentinelSOC"

function Assert-Admin {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($id)
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)) {
        Write-Error "This script must be run from an elevated (Administrator) PowerShell session. Right-click PowerShell, choose 'Run as Administrator', then re-run this script."
        exit 1
    }
}

function Get-ProjectRoot {
    # This file lives at <root>\scripts\_common.ps1, so its own directory's
    # parent is the project root, regardless of which script dot-sourced it.
    return (Split-Path -Parent $PSScriptRoot)
}

function Get-PythonLauncher {
    <#
    Returns @{ Cmd = <string>; Args = <string[]> } for a usable Python 3
    interpreter (preferring the 'py' launcher, which the official
    python.org installer registers), or $null if none was found.
    #>
    if (Get-Command py -ErrorAction SilentlyContinue) {
        & py -3 --version *> $null
        if ($LASTEXITCODE -eq 0) { return @{ Cmd = 'py'; Args = @('-3') } }
    }
    if (Get-Command python -ErrorAction SilentlyContinue) {
        & python --version *> $null
        if ($LASTEXITCODE -eq 0) { return @{ Cmd = 'python'; Args = @() } }
    }
    return $null
}

function Get-VenvPython {
    param([Parameter(Mandatory = $true)][string]$Root)
    return (Join-Path $Root ".venv\Scripts\python.exe")
}

function Get-ConfiguredPort {
    param([Parameter(Mandatory = $true)][string]$Root, [int]$Default = 8765)
    try {
        $cfgText = Get-Content (Join-Path $Root "config\config.yaml") -Raw -ErrorAction Stop
        if ($cfgText -match '(?m)^\s*port:\s*(\d+)\s*$') { return [int]$Matches[1] }
    } catch {}
    return $Default
}
