<#
.SYNOPSIS
  Exporte des journaux Windows utiles à l'investigation.
#>
[CmdletBinding()]
param(
    [string]$OutputDir = ".\evtx-export",
    [string[]]$Logs = @("System", "Application", "Security", "Microsoft-Windows-Sysmon/Operational")
)

New-Item -ItemType Directory -Force -Path $OutputDir | Out-Null

foreach ($log in $Logs) {
    $safeName = $log -replace '[\\/]', '_'
    $out = Join-Path $OutputDir "$safeName.evtx"
    Write-Host "[+] Export $log -> $out" -ForegroundColor Cyan
    try {
        wevtutil epl $log $out
    } catch {
        Write-Warning "Impossible d'exporter $log : $($_.Exception.Message)"
    }
}

Write-Host "[+] Terminé" -ForegroundColor Green
