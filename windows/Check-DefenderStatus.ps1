<#
.SYNOPSIS
  Audit rapide de Microsoft Defender.

.DESCRIPTION
  Affiche les principaux paramètres Defender utiles en triage Blue Team :
  protection temps réel, exclusions, cloud protection et règles ASR.
#>

$ErrorActionPreference = "SilentlyContinue"

Write-Host "=== État Microsoft Defender ===" -ForegroundColor Cyan
Get-MpComputerStatus | Select-Object `
  AMServiceEnabled,
  AntivirusEnabled,
  RealTimeProtectionEnabled,
  BehaviorMonitorEnabled,
  IoavProtectionEnabled,
  AntivirusSignatureLastUpdated,
  NISEngineVersion,
  AMProductVersion | Format-List

Write-Host "`n=== Préférences Defender ===" -ForegroundColor Cyan
$prefs = Get-MpPreference

$prefs | Select-Object `
  DisableRealtimeMonitoring,
  MAPSReporting,
  SubmitSamplesConsent,
  CloudBlockLevel,
  PUAProtection | Format-List

Write-Host "`n=== Exclusions Defender ===" -ForegroundColor Yellow
$prefs | Select-Object ExclusionPath, ExclusionProcess, ExclusionExtension, ExclusionIpAddress | Format-List

Write-Host "`n=== Règles Attack Surface Reduction ===" -ForegroundColor Yellow
$prefs | Select-Object AttackSurfaceReductionRules_Ids, AttackSurfaceReductionRules_Actions | Format-List
