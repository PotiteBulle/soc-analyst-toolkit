# Hashing

Ce dossier contient des scripts dédiés au calcul de hashes de fichiers.

Les hashes sont essentiels en analyse SOC, DFIR et phishing pour identifier, comparer et rechercher des fichiers suspects dans des plateformes comme VirusTotal, MalwareBazaar, Any.Run ou des rapports internes.

## Scripts

```text
hashing/
├── hash_file.py
└── hash_directory.py
```

## `hash_file.py`

Calcule les hashes d’un fichier unique.

Hashes généralement utiles :

- MD5
- SHA1
- SHA256

### Exemple d’utilisation

```bash
python3 hashing/hash_file.py fichier_suspect.bin
```

### Cas d’usage

- Identifier une pièce jointe suspecte.
- Rechercher un hash dans VirusTotal.
- Comparer deux fichiers.
- Ajouter un hash dans un rapport IOC.

## `hash_directory.py`

Calcule le SHA256 de tous les fichiers d’un dossier.

### Exemple d’utilisation

```bash
python3 hashing/hash_directory.py ./samples
```

Avec export CSV :

```bash
python3 hashing/hash_directory.py ./samples -o hashes.csv
```

### Cas d’usage

- Hasher toutes les pièces jointes extraites d’un email.
- Générer un inventaire de fichiers.
- Comparer un dossier avant/après analyse.
- Documenter les artefacts d’un incident.

## Bonnes pratiques

- Utiliser SHA256 comme hash principal dans les rapports.
- Garder MD5/SHA1 uniquement pour compatibilité avec certains outils.
- Ne pas publier de fichiers suspects dans le dépôt.
- Partager les hashes plutôt que les fichiers lorsque c’est possible.

## Exemple de sortie attendue

```text
fichier.pdf
MD5    : ...
SHA1   : ...
SHA256 : ...
```

## Notes SOC

Un hash seul ne prouve pas qu’un fichier est malveillant. Il doit être corrélé avec :

- Le contexte.
- La source du fichier.
- Le comportement observé.
- Les détections antivirus.
- Les métadonnées.
- Les résultats sandbox.
- Les autres IOC associés.
