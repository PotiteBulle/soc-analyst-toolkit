# SOC Analyst Toolkit

Collection de scripts défensifs pour l’analyse SOC, le triage phishing, l’extraction d’artefacts, les logs et l’investigation numérique.

## Objectif

Ce dépôt regroupe des outils simples, documentés et utilisables dans un contexte défensif : SOC, Blue Team, DFIR, phishing analysis, labs et entraînement personnel.

## Arborescence

```text
soc-analyst-toolkit/
├── phishing/   # Analyse d'emails, extraction d'URLs, pièces jointes, défang
├── hashing/    # Hash de fichiers et dossiers
├── logs/       # Extraction d'IOC depuis des logs texte
├── network/    # Extraction IP/domaines et filtres Wireshark
├── windows/    # Scripts PowerShell Blue Team Windows
├── yara/       # Helpers et règles YARA défensives
├── docs/       # Workflows et modèles SOC
└── tests/      # Tests unitaires simples
```

## Installation rapide

```bash
git clone https://github.com/PotiteBulle/soc-analyst-toolkit.git
cd soc-analyst-toolkit
python3 -m pip install -r requirements.txt 2>/dev/null || true
```

La majorité des scripts Python n’utilisent que la bibliothèque standard.

## Exemples

Extraire les pièces jointes d’un email `.eml` :

```bash
python3 phishing/extract_eml_attachments.py suspicious.eml -o extracted_attachments
```

Extraire les URLs d’un email :

```bash
python3 phishing/extract_urls_from_eml.py suspicious.eml
```

Hasher un fichier :

```bash
python3 hashing/hash_file.py sample.bin
```

Extraire des IOC depuis un log :

```bash
python3 logs/extract_iocs_from_logs.py suspicious.log -o iocs.json
```

## Usage éthique

Ce dépôt est destiné uniquement à l’analyse défensive, à la formation, aux laboratoires autorisés et à la réponse à incident.

Ne pas exécuter de fichiers suspects sur un système de production. Les scripts sont conçus pour l’analyse statique, le triage défensif et l’investigation numérique.
