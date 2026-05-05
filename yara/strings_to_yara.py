#!/usr/bin/env python3
"""Génère une règle YARA simple depuis une liste de chaînes.

Usage :
    python3 strings_to_yara.py strings.txt --rule suspicious_sample -o suspicious_sample.yar
"""
from __future__ import annotations

import argparse
import re
from pathlib import Path


def nettoyer_chaine(valeur: str) -> str:
    """Nettoie une chaîne pour l'intégrer dans une règle YARA."""
    valeur = valeur.strip().replace("\\", "\\\\").replace('"', '\\"')
    valeur = re.sub(r"[\x00-\x1f\x7f]", "", valeur)
    return valeur


def nom_regle_valide(nom: str) -> str:
    """Transforme un nom arbitraire en nom de règle YARA valide."""
    nom = re.sub(r"\W+", "_", nom)

    if not nom or nom[0].isdigit():
        nom = "rule_" + nom

    return nom


def main() -> None:
    parseur = argparse.ArgumentParser(description="Génère une règle YARA basique depuis des chaînes.")
    parseur.add_argument("strings_file", type=Path, help="Fichier contenant une chaîne par ligne")
    parseur.add_argument("--rule", default="generated_rule", help="Nom de la règle YARA")
    parseur.add_argument("-o", "--output", type=Path, default=Path("generated_rule.yar"), help="Fichier YARA de sortie")
    parseur.add_argument("--min-len", type=int, default=6, help="Longueur minimale des chaînes")
    parseur.add_argument("--max-strings", type=int, default=20, help="Nombre maximal de chaînes")
    args = parseur.parse_args()

    if not args.strings_file.is_file():
        raise SystemExit(f"[!] Fichier introuvable : {args.strings_file}")

    chaines = []

    for ligne in args.strings_file.read_text(errors="replace").splitlines():
        chaine = nettoyer_chaine(ligne)
        if args.min_len <= len(chaine) <= 160:
            chaines.append(chaine)

    chaines = list(dict.fromkeys(chaines))[: args.max_strings]
    nom_regle = nom_regle_valide(args.rule)

    lignes = [
        f"rule {nom_regle}",
        "{",
        "    meta:",
        '        description = "Règle générée depuis des chaînes extraites"',
        '        author = "soc-analyst-toolkit"',
        "",
        "    strings:",
    ]

    for index, chaine in enumerate(chaines, start=1):
        lignes.append(f'        $s{index} = "{chaine}" ascii nocase')

    lignes.extend([
        "",
        "    condition:",
        "        any of them",
        "}",
        "",
    ])

    args.output.write_text("\n".join(lignes), encoding="utf-8")
    print(f"[+] Règle YARA générée : {args.output}")


if __name__ == "__main__":
    main()
