<#
.SYNOPSIS
    Start, stop, restart, or check the status of the SentinelSOC service.

.EXAMPLE
    .\service_control.ps1 status
.EXAMPLE
    .\service_control.ps1 restart
#>
param(
    [Parameter(Mandatory = $true, Position = 0)]
    [ValidateSet('start', 'stop', 'restart', 'status')]
    [string]$Action
)

$ErrorActionPreference = "Stop"
. (Join-Path $PSScriptRoot "_common.ps1")

$svc = Get-Service -Name $Script:SentinelSOCServiceName -ErrorAction SilentlyContinue
if (-not $svc) {
    Write-Error "The SentinelSOC service is not installed. Run scripts\install.ps1 first."
    exit 1
}

if ($Action -ne 'status') { Assert-Admin }

switch ($Action) {
    'start'   { Start-Service $Script:SentinelSOCServiceName; Write-Host "Started." -ForegroundColor Green }
    'stop'    { Stop-Service $Script:SentinelSOCServiceName -Force; Write-Host "Stopped." -ForegroundColor Yellow }
    'restart' { Restart-Service $Script:SentinelSOCServiceName -Force; Write-Host "Restarted." -ForegroundColor Green }
    'status'  { Get-Service $Script:SentinelSOCServiceName | Format-List Name, DisplayName, Status, StartType }
}
