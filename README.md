# SOC Analyst Toolkit

Collection de scripts défensifs pour l’analyse SOC, le triage phishing, l’extraction d’artefacts, la gestion d’IOC, l’analyse de logs, l’analyse réseau, l’investigation Windows et les premiers réflexes Blue Team.

Ce dépôt a pour objectif de regrouper des outils simples, lisibles et utiles dans un contexte d’apprentissage SOC Analyst, de lab cybersécurité, de réponse à incident légère et d’analyse défensive.

## Objectifs du dépôt

- Centraliser des scripts pratiques pour l’analyse SOC.
- Automatiser certaines tâches répétitives de triage.
- Faciliter l’extraction d’IOC depuis des emails, logs, fichiers ou PCAP.
- Fournir une base de documentation claire pour progresser en Blue Team.
- Construire progressivement un toolkit personnel utilisable en lab et en environnement autorisé.

## Arborescence

```text
soc-analyst-toolkit/
├── docs/
├── hashing/
├── iocs/
├── logs/
├── network/
├── phishing/
├── samples/
├── tests/
├── windows/
└── yara/
```

## Modules principaux

### `phishing/`

Scripts dédiés à l’analyse d’emails suspects :

- extraction de pièces jointes `.eml`
- extraction d’URLs
- extraction d’IOC
- analyse de headers
- vérification SPF/DKIM/DMARC
- defang/refang d’IOC

### `iocs/`

Outils pour nettoyer, dédupliquer, classer et documenter des indicateurs de compromission.

### `hashing/`

Scripts pour calculer les hashes de fichiers ou de dossiers complets.

### `logs/`

Scripts d’analyse de logs et de détection de motifs suspects.

### `network/`

Outils et notes pour l’analyse réseau, notamment SMTP, DNS et PCAP.

### `windows/`

Scripts PowerShell orientés Blue Team Windows : Defender, Sysmon, processus suspects, export d’événements.

### `yara/`

Aides à la génération et à l’exécution de règles YARA.

### `docs/`

Guides, checklists, workflows et modèles de rapport.

## Prérequis

Les scripts Python sont conçus pour Python 3.10+.

Installation recommandée :

```bash
python3 --version
```

Certains scripts réseau peuvent nécessiter `tshark` :

```bash
tshark --version
```

Les scripts PowerShell doivent être lancés sur Windows avec les droits adaptés selon les actions effectuées.

## Utilisation rapide

Exemple : extraire des pièces jointes depuis un email `.eml`.

```bash
python3 phishing/extract_eml_attachments.py suspicious.eml -o extracted_attachments
```

Exemple : extraire des IOC depuis un email.

```bash
python3 phishing/extract_email_iocs.py suspicious.eml --json rapport_iocs.json
```

Exemple : calculer le SHA256 d’un fichier.

```bash
python3 hashing/hash_file.py sample.bin
```

Exemple : analyser un PCAP SMTP avec `tshark`.

```bash
python3 network/smtp_pcap_helper.py traffic.pcap
```

## Bonnes pratiques

- Ne jamais exécuter une pièce jointe suspecte sur une machine de production.
- Travailler dans une VM ou un lab isolé.
- Ne pas publier de vrais emails, PCAP, logs internes ou données sensibles.
- Defanger les IOC avant de les partager publiquement.
- Vérifier les scripts avant toute utilisation dans un environnement réel.

## Données sensibles et samples

Le dépôt contient un dossier `samples/`, mais celui-ci ne doit pas contenir de malware réel, d’emails sensibles, de PCAP privés ou de données personnelles.

Les fichiers suivants sont ignorés volontairement par `.gitignore` :

```text
*.eml
*.pcap
*.pcapng
extracted_attachments/
output/
samples/*
```

## Roadmap

Idées d’amélioration futures :

- Ajouter un générateur de rapport phishing complet.
- Ajouter un export JSON/CSV standardisé pour tous les scripts.
- Ajouter des tests unitaires supplémentaires.
- Ajouter des exemples factices dans `samples/`.
- Ajouter des workflows SOC orientés TryHackMe / Hack The Box.
- Ajouter des règles Sigma et YARA défensives.
- Ajouter un mode interactif pour certains scripts.

## Usage éthique

Ce dépôt est destiné uniquement à :

- l’analyse défensive
- la formation SOC / Blue Team
- les laboratoires autorisés
- l’investigation numérique
- la réponse à incident
- la recherche personnelle dans un cadre légal.

Il ne doit pas être utilisé pour mener des actions offensives non autorisées, contourner des protections, exécuter des charges malveillantes ou nuire à des systèmes tiers.

## Licence

Ce projet est publié sous licence MIT.