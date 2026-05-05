# Samples phishing

Ce dossier est prévu pour documenter l’utilisation de samples locaux lors des tests.

## Important

Ne pas publier dans ce dépôt :

- De vrais emails d’entreprise.
- Des emails contenant des données personnelles.
- Des malwares.
- Des pièces jointes réelles suspectes.
- Des fichiers confidentiels.

Le `.gitignore` du dépôt est configuré pour éviter l’ajout accidentel de fichiers `.eml`, `.pcap`, `.pcapng` et du contenu du dossier `samples/`.

## Utilisation recommandée

Pour tester localement les scripts, tu peux placer temporairement tes fichiers ici :

```text
phishing/samples/
├── suspicious.eml
└── README.md
```

Mais seuls les fichiers de documentation doivent être poussés sur GitHub.

## Exemple de test local

```bash
python3 ../extract_eml_attachments.py suspicious.eml -o extracted_attachments
```

## Bonnes pratiques

- Utiliser des exemples factices.
- Anonymiser les données.
- Supprimer les samples avant un commit.
- Vérifier `git status` avant chaque push.
