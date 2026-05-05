<#
.SYNOPSIS
  Repère des processus suspects en cours d'exécution.

.DESCRIPTION
  Recherche des processus lancés depuis des chemins suspects ou avec des noms souvent abusés.
#>

$NomsSuspects = @(
  "powershell", "pwsh", "cmd", "wscript", "cscript", "mshta",
  "rundll32", "regsvr32", "certutil", "bitsadmin", "wmic", "schtasks"
)

$CheminsSuspects = @(
  "\AppData\",
  "\Temp\",
  "\Users\Public\",
  "\ProgramData\"
)

Write-Host "=== Triage des processus suspects ===" -ForegroundColor Cyan

Get-CimInstance Win32_Process | ForEach-Object {
  $raisons = @()

  foreach ($nom in $NomsSuspects) {
    if ($_.Name -match [regex]::Escape($nom)) {
      $raisons += "NomSuspect:$nom"
    }
  }

  foreach ($chemin in $CheminsSuspects) {
    if (($_.CommandLine -like "*$chemin*") -or ($_.ExecutablePath -like "*$chemin*")) {
      $raisons += "CheminSuspect:$chemin"
    }
  }

  if ($_.CommandLine -match "-enc|-encodedcommand|downloadstring|iex|invoke-expression") {
    $raisons += "ArgumentPowerShellSuspect"
  }

  if ($raisons.Count -gt 0) {
    [PSCustomObject]@{
      ProcessId       = $_.ProcessId
      ParentProcessId = $_.ParentProcessId
      Nom             = $_.Name
      Chemin          = $_.ExecutablePath
      LigneCommande   = $_.CommandLine
      Raisons         = ($raisons -join ",")
    }
  }
} | Format-Table -AutoSize
