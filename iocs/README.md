# IOC Tools

Ce dossier contient des outils pour manipuler des IOC, c’est-à-dire des indicateurs de compromission.

Les IOC peuvent inclure :

- Adresses IP.
- Domaines.
- URLs.
- Hashes.
- Adresses email.
- Chemins de fichiers.
- Noms de processus.
- Clés de registre.

## Scripts

```text
iocs/
├── ioc_deduplicator.py
└── ioc_report_builder.py
```

## `ioc_deduplicator.py`

Nettoie, déduplique et classe une liste d’IOC.

### Fonctionnalités

- Suppression des doublons.
- Refang automatique simple.
- Classification par type.
- Export en fichiers séparés.
- Export JSON.

### Exemple d’utilisation

```bash
python3 iocs/ioc_deduplicator.py iocs.txt -o cleaned_iocs
```

### Sorties générées

```text
cleaned_iocs.json
cleaned_iocs_ips.txt
cleaned_iocs_domaines.txt
cleaned_iocs_urls.txt
cleaned_iocs_hashes.txt
cleaned_iocs_inconnus.txt
```

## `ioc_report_builder.py`

Génère un rapport Markdown depuis une liste d’IOC.

### Exemple d’utilisation

```bash
python3 iocs/ioc_report_builder.py iocs.txt -o rapport_ioc.md
```

### Exemple de rapport

```md
# Rapport IOC

## Résumé

- Adresses IP: 3
- Domaines: 5
- URLs: 2
- Hashes: 1
```

## Bonnes pratiques IOC

- Defanger les IOC avant de les partager publiquement.
- Conserver la source de chaque IOC lorsque c’est possible.
- Distinguer les IOC confirmés des IOC suspects.
- Ne pas considérer un IOC isolé comme une preuve absolue.
- Corréler les IOC avec les logs, les alertes et le contexte métier.

## Defang / Refang

Exemples :

```text
https://evil.com/login  -> hxxps://evil[.]com/login
evil.com               -> evil[.]com
admin@example.com      -> admin[@]example[.]com
```

## Utilisation dans un rapport SOC

Les IOC peuvent être placés dans une section comme :

```md
## IOC observés

| Type | Valeur | Source | Confiance |
|---|---|---|---|
| Domaine | evil[.]com | Email suspect | Moyenne |
| SHA256 | ... | Pièce jointe | Haute |
```
