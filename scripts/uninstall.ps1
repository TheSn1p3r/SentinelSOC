<#
.SYNOPSIS
    Stops and removes the SentinelSOC Windows Service.

.DESCRIPTION
    By default this leaves data\, logs\, and quarantine\ in place — the
    quarantine folder in particular may still hold samples you want for an
    ongoing investigation. Pass -RemoveData to delete all three as well.

.PARAMETER RemoveData
    Also delete data\, logs\, and quarantine\ (irreversible — quarantined
    files are permanently deleted, not restored first).

.EXAMPLE
    .\uninstall.ps1
.EXAMPLE
    .\uninstall.ps1 -RemoveData
#>
param([switch]$RemoveData)

$ErrorActionPreference = "Stop"
. (Join-Path $PSScriptRoot "_common.ps1")
Assert-Admin

$root = Get-ProjectRoot
$venvPython = Get-VenvPython -Root $root
$serviceScript = Join-Path $root "sentinelsoc\service_win.py"

$svc = Get-Service -Name $Script:SentinelSOCServiceName -ErrorAction SilentlyContinue
if ($svc) {
    if ($svc.Status -ne 'Stopped') {
        Write-Host "Stopping the SentinelSOC service ..."
        Stop-Service $Script:SentinelSOCServiceName -Force
    }
    if (Test-Path $venvPython) {
        Write-Host "Removing the service registration ..."
        & $venvPython $serviceScript remove
    } else {
        Write-Host "Virtual environment not found; removing the service registration via sc.exe instead ..."
        sc.exe delete $Script:SentinelSOCServiceName | Out-Null
    }
    Write-Host "Service removed." -ForegroundColor Green
} else {
    Write-Host "The SentinelSOC service isn't installed; nothing to stop."
}

if ($RemoveData) {
    Write-Warning "Deleting data\, logs\, and quarantine\ — this permanently deletes any quarantined files."
    foreach ($dir in @("data", "logs", "quarantine")) {
        $p = Join-Path $root $dir
        if (Test-Path $p) { Remove-Item -Recurse -Force $p }
    }
    Write-Host "Data removed." -ForegroundColor Green
} else {
    Write-Host "data\, logs\, and quarantine\ were left in place. Re-run with -RemoveData to delete them, or remove the project folder yourself once you've confirmed you don't need anything in quarantine\."
}

Write-Host "Uninstall complete." -ForegroundColor Green
