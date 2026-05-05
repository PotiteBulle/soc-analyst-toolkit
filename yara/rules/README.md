# Règles YARA

Ce dossier contient les règles YARA du toolkit.

## Organisation recommandée

```text
rules/
├── README.md
├── example_rule.yar
├── phishing_attachment.yar
├── suspicious_scripts.yar
└── windows_lolbins.yar
```

## Bonnes pratiques

- Une règle doit avoir un nom clair.
- Ajouter des métadonnées.
- Éviter les conditions trop générales.
- Tester les règles avant publication.
- Documenter les cas d’usage.
- Éviter d’inclure des éléments trop spécifiques à un environnement privé.

## Exemple de section `meta`

```yara
meta:
    description = "Détection de chaînes suspectes dans un script"
    author = "soc-analyst-toolkit"
    date = "2026-01-01"
    confidence = "low"
```

## Note

Une règle YARA n’est pas une preuve absolue. Elle doit être interprétée avec le contexte, les métadonnées, les logs et les autres artefacts disponibles.
