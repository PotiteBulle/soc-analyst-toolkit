# YARA

Ce dossier contient des aides pour l’utilisation de YARA dans un contexte SOC / Blue Team.

YARA permet de créer des règles pour identifier des fichiers à partir de chaînes, motifs ou structures.

## Contenu

```text
yara/
├── rules/
│   ├── README.md
│   └── example_rule.yar
├── strings_to_yara.py
└── yara_scan_helper.py
```

## `yara_scan_helper.py`

Helper pour lancer un scan YARA sur un fichier ou un dossier.

### Exemple

```bash
python3 yara/yara_scan_helper.py yara/rules/example_rule.yar samples/
```

## `strings_to_yara.py`

Génère une règle YARA simple depuis une liste de chaînes.

### Exemple

```bash
python3 yara/strings_to_yara.py strings.txt --rule suspicious_sample -o suspicious_sample.yar
```

## Dossier `rules/`

Contient les règles YARA.

## Bonnes pratiques

- Donner un nom clair aux règles.
- Ajouter une section `meta`.
- Éviter les règles trop larges.
- Tester les règles sur des fichiers bénins.
- Documenter les faux positifs possibles.
- Ne pas inclure de samples malveillants dans le dépôt.

## Exemple de règle YARA

```yara
rule example_suspicious_strings
{
    meta:
        description = "Exemple de règle YARA"
        author = "soc-analyst-toolkit"

    strings:
        $s1 = "powershell" nocase
        $s2 = "cmd.exe" nocase

    condition:
        any of them
}
```
