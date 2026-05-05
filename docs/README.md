# Documentation

Ce dossier contient les notes, checklists, workflows et modèles de rapport associés au dépôt `soc-analyst-toolkit`.

L’objectif est de fournir une documentation claire pour accompagner les scripts et faciliter leur utilisation dans un contexte SOC / Blue Team.

## Contenu

```text
docs/
├── incident-report-template.md
├── ioc-handling-guide.md
├── phishing-analysis-workflow.md
├── soc-triage-checklist.md
├── windows-blue-team-notes.md
└── wireshark-smtp-analysis.md
```

## Fichiers

### `incident-report-template.md`

Modèle de rapport d’incident à remplir pendant ou après une analyse.

Il peut servir à documenter :

- Le contexte.
- Les artefacts observés.
- Les IOC.
- Les actions réalisées.
- Les recommandations.
- Les conclusions.

### `ioc-handling-guide.md`

Guide de manipulation des IOC :

- Extraction.
- Defang/Refang.
- Classification.
- Priorisation.
- Partage sécurisé.

### `phishing-analysis-workflow.md`

Workflow d’analyse phishing :

- Lecture des headers.
- Identification de l’expéditeur.
- Extraction des URLs.
- Analyse des pièces jointes.
- Vérification SPF/DKIM/DMARC.
- Construction d’un rapport.

### `soc-triage-checklist.md`

Checklist rapide pour le triage SOC.

Elle permet de structurer les premières actions lorsqu’une alerte arrive.

### `windows-blue-team-notes.md`

Notes utiles pour l’analyse Windows :

- Defender.
- Sysmon.
- Événements Windows.
- Processus suspects.
- Commandes PowerShell utiles.

### `wireshark-smtp-analysis.md`

Notes pour analyser du trafic SMTP avec Wireshark :

- Filtres utiles.
- Codes SMTP.
- Extraction de pièces jointes.
- Interprétation des réponses 4xx/5xx.

## Utilisation conseillée

Ces documents peuvent être utilisés comme support pendant :

- Des laboratoires.
- Un exercice SOC.
- Une analyse phishing
- Un triage d’alerte
- Une rédaction de rapport.

## Bonnes pratiques

- Garder les rapports factuels.
- Séparer les observations des hypothèses.
- Defanger les IOC dans les documents publics.
- Ne jamais inclure de données sensibles réelles dans un dépôt public.
- Documenter les commandes utilisées pour rendre l’analyse reproductible.

## Exemple de structure de rapport

```md
# Rapport d’incident

## Résumé exécutif

## Chronologie

## Artefacts analysés

## IOC

## Analyse

## Impact potentiel

## Recommandations

## Conclusion
```
