<#
.SYNOPSIS
  Exporte des événements Sysmon importants en CSV.

.USAGE
  powershell -ExecutionPolicy Bypass -File .\Export-SysmonHunt.ps1 -OutputDir C:\BlueTeam\Reports\Hunts
#>

param(
  [string]$OutputDir = ".\sysmon_exports",
  [int]$MaxEvents = 1000
)

$ErrorActionPreference = "Stop"
New-Item -ItemType Directory -Force -Path $OutputDir | Out-Null

$LogName = "Microsoft-Windows-Sysmon/Operational"
$EventMap = @{
  1  = "creation_processus"
  3  = "connexion_reseau"
  11 = "creation_fichier"
  22 = "requete_dns"
}

foreach ($id in $EventMap.Keys) {
  $nom = $EventMap[$id]
  $sortie = Join-Path $OutputDir "sysmon_${id}_${nom}.csv"

  Write-Host "[+] Export Event ID $id -> $sortie" -ForegroundColor Cyan

  Get-WinEvent -FilterHashtable @{LogName=$LogName; Id=$id} -MaxEvents $MaxEvents |
    Select-Object TimeCreated, Id, ProviderName, MachineName, Message |
    Export-Csv -NoTypeInformation -Encoding UTF8 -Path $sortie
}
