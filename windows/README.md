# Windows Blue Team

Ce dossier contient des scripts PowerShell orientés Blue Team Windows.

Ils servent à faciliter :

- Le triage local.
- L’audit Microsoft Defender.
- L’export d’événements.
- L’analyse de processus suspects.
- L’investigation Sysmon.

## Scripts

```text
windows/
├── Check-DefenderStatus.ps1
├── defender_exclusions_audit.ps1
├── export_eventlogs.ps1
├── Export-SysmonHunt.ps1
├── Get-SuspiciousProcesses.ps1
└── sysmon_process_hunt.ps1
```

## `Check-DefenderStatus.ps1`

Affiche un état rapide de Microsoft Defender :

- Protection temps réel.
- Signatures.
- Préférences.
- Exclusions.
- Règles ASR.

### Exemple

```powershell
powershell -ExecutionPolicy Bypass -File .\windows\Check-DefenderStatus.ps1
```

## `Get-SuspiciousProcesses.ps1`

Recherche des processus suspects actuellement actifs.

Exemples de signaux :

- PowerShell encodé.
- Processus lancés depuis `AppData` ou `Temp`.
- LOLBins.
- Commandes suspectes.

### Exemple

```powershell
powershell -ExecutionPolicy Bypass -File .\windows\Get-SuspiciousProcesses.ps1
```

## `Export-SysmonHunt.ps1`

Exporte plusieurs Event IDs Sysmon importants en CSV.

Événements ciblés :

- Event ID 1 : création de processus.
- Event ID 3 : connexion réseau.
- Event ID 11 : création de fichier.
- Event ID 22 : requête DNS.

### Exemple

```powershell
powershell -ExecutionPolicy Bypass -File .\windows\Export-SysmonHunt.ps1 -OutputDir C:\BlueTeam\Reports\Hunts
```

## Bonnes pratiques

- Lancer PowerShell en administrateur lorsque nécessaire.
- Ne pas modifier la configuration Defender sans comprendre l’impact.
- Conserver les exports d’événements dans un dossier dédié.
- Documenter les commandes exécutées pendant une investigation.
- Corréler les résultats PowerShell avec les logs Windows et Sysmon.

## Avertissement

Ces scripts sont défensifs. Ils ne doivent pas être utilisés pour contourner des protections, masquer une activité ou modifier un système sans autorisation.
