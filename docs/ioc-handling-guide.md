# Guide de manipulation des IOC

## Défanger avant partage

Exemples :

```text
https://evil.example.com -> hxxps://evil[.]example[.]com
user@example.com -> user[@]example[.]com
8.8.8.8 -> 8[.]8[.]8[.]8
```

## Vérifier le contexte

Un IOC seul ne suffit pas toujours. Vérifier :

- Horodatage
- Source
- Direction du trafic
- Processus associé
- Utilisateurices associé

## Stockage

Préférer un format structuré : JSON, CSV ou Markdown.
