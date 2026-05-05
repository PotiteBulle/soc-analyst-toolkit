# Logs

Ce dossier contient des scripts destinés à l’analyse de logs dans un contexte SOC / Blue Team.

L’objectif est d’automatiser certaines tâches de triage :

- Extraction d’IOC.
- Détection d’échecs de connexion.
- Recherche de commandes suspectes.
- Analyse d’exports Sysmon ou Windows Event Logs.

## Scripts

```text
logs/
├── extract_iocs_from_logs.py
├── failed_login_analyzer.py
├── suspicious_process_finder.py
├── sysmon_event1_parser.py
└── windows_eventlog_notes.md
```

## `extract_iocs_from_logs.py`

Extrait des IOC depuis un fichier de logs.

Éléments recherchés :

- Adresses IP.
- Domaines.
- URLs.
- Hashes.
- Emails.

### Exemple

```bash
python3 logs/extract_iocs_from_logs.py application.log
```

## `failed_login_analyzer.py`

Analyse les échecs de connexion dans un fichier de logs.

### Exemple

```bash
python3 logs/failed_login_analyzer.py auth.log --threshold 5
```

### Cas d’usage

- Repérer une IP qui tente beaucoup de connexions.
- Repérer un compte ciblé.
- Détecter une tentative de brute force simple.

## `suspicious_process_finder.py`

Recherche des commandes ou processus suspects dans un CSV ou un fichier texte.

Motifs recherchés :

- `powershell -enc`
- `cmd.exe /c`
- `rundll32`
- `regsvr32`
- `mshta`
- `certutil`
- `bitsadmin`
- chemins `AppData`, `Temp`, `Public`
- traces liées à LSASS ou Mimikatz

### Exemple

```bash
python3 logs/suspicious_process_finder.py process-hunt.csv
```

## `sysmon_event1_parser.py`

Parse un export CSV Sysmon Event ID 1 pour générer un résumé des créations de processus.

### Exemple

```bash
python3 logs/sysmon_event1_parser.py sysmon_event1.csv -o rapport_sysmon.md
```

## Bonnes pratiques

- Toujours conserver le fichier brut d’origine.
- Documenter les commandes utilisées.
- Exporter les résultats dans un format lisible.
- Corréler les événements suspects avec d’autres sources.
- Vérifier les faux positifs avant de conclure.

## Sources de logs utiles

- Sysmon
- Windows Security Event Log
- PowerShell Operational Logs
- Defender Logs
- Proxy Logs
- DNS Logs
- Firewall Logs
- EDR Alerts

## Notes

Ces scripts sont volontairement simples. Ils ne remplacent pas un SIEM, mais peuvent aider à comprendre la logique d’un triage SOC et à automatiser des tâches répétitives.
