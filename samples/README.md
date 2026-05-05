# Samples

Ce dossier sert uniquement d’emplacement local pour des fichiers de test.

## Attention

Ce dossier ne doit pas contenir de fichiers sensibles dans le dépôt public.

Ne pas publier :

- Malwares.
- Pièces jointes suspectes.
- Emails réels.
- PCAP internes.
- Logs d’entreprise.
- Données personnelles.
- Fichiers confidentiels.

Le `.gitignore` est prévu pour ignorer le contenu de ce dossier tout en conservant ce README.

## Utilisation locale

Tu peux placer temporairement des fichiers de test ici :

```text
samples/
├── test.eml
├── traffic.pcap
├── logs.txt
└── suspicious.bin
```

Puis lancer les scripts depuis la racine du dépôt.

Exemple :

```bash
python3 phishing/extract_email_iocs.py samples/test.eml
```

## Recommandation

Avant chaque commit :

```bash
git status
```

Vérifie qu’aucun fichier sensible n’est en attente d’ajout.
