<#
.SYNOPSIS
  Audite les exclusions Microsoft Defender configurées localement.
.DESCRIPTION
  Script défensif SOC/Blue Team. N'applique aucune modification.
#>
[CmdletBinding()]
param(
    [string]$OutputPath = ".\defender-exclusions-audit.txt"
)

Write-Host "[+] Audit des exclusions Microsoft Defender" -ForegroundColor Cyan

$pref = Get-MpPreference
$result = [PSCustomObject]@{
    ExclusionPath      = $pref.ExclusionPath
    ExclusionProcess   = $pref.ExclusionProcess
    ExclusionExtension = $pref.ExclusionExtension
    ExclusionIpAddress = $pref.ExclusionIpAddress
}

$result | Format-List | Tee-Object -FilePath $OutputPath
Write-Host "[+] Rapport écrit : $OutputPath" -ForegroundColor Green
