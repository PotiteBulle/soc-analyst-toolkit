# Notes Blue Team Windows

## Objectif

Centraliser des commandes utiles pour l'audit défensif Windows : Defender, Sysmon, journaux d'événements et processus suspects.

## Points à surveiller

- Exclusions Defender inattendues
- Processus lancés depuis `AppData`, `Temp`, `Public`
- PowerShell avec `-EncodedCommand`
- LOLBins : `rundll32`, `regsvr32`, `mshta`, `certutil`, `bitsadmin`
- Sysmon Event ID 1, 3, 11, 22

## Commandes utiles

```powershell
Get-MpComputerStatus
Get-MpPreference | Select-Object ExclusionPath, ExclusionProcess, ExclusionExtension, ExclusionIpAddress
Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" -MaxEvents 20
```
