# Tests

Ce dossier contient les tests unitaires du dépôt.

Les tests permettent de vérifier que certains scripts continuent de fonctionner après modification.

## Contenu

```text
tests/
├── test_defang_iocs.py
├── test_extract_eml_attachments.py
└── test_ioc_deduplicator.py
```

## Prérequis

Installer `pytest` si nécessaire :

```bash
pip install pytest
```

## Lancer les tests

Depuis la racine du dépôt :

```bash
pytest
```

Ou :

```bash
python -m pytest
```

## Objectifs des tests

- Vérifier les fonctions de defang/refang.
- Vérifier la classification d’IOC.
- Vérifier l’extraction de pièces jointes EML.
- Éviter les régressions lors de l’ajout de nouveaux scripts.

## Bonnes pratiques

- Ajouter un test pour chaque nouvelle fonction importante.
- Utiliser des samples factices.
- Ne jamais utiliser de vrais emails sensibles dans les tests.
- Garder les tests simples et lisibles.
