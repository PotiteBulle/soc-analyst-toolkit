#!/usr/bin/env python3
"""Génère un rapport Markdown depuis une liste d'IOC.

Usage :
    python3 ioc_report_builder.py iocs.txt -o rapport_ioc.md
"""
from __future__ import annotations

import argparse
import re
from datetime import datetime, timezone
from pathlib import Path

IP_RE = re.compile(r"^(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)$")
HASH_RE = re.compile(r"^[A-Fa-f0-9]{32}$|^[A-Fa-f0-9]{40}$|^[A-Fa-f0-9]{64}$")
URL_RE = re.compile(r"^https?://", re.IGNORECASE)
DOMAINE_RE = re.compile(r"^(?:[A-Za-z0-9-]+\.)+[A-Za-z]{2,}$")


def refang(valeur: str) -> str:
    return valeur.replace("[.]", ".").replace("hxxp://", "http://").replace("hxxps://", "https://")


def defang(valeur: str) -> str:
    return valeur.replace("https://", "hxxps://").replace("http://", "hxxp://").replace(".", "[.]")


def classer(valeur: str) -> str:
    valeur = refang(valeur.strip())

    if IP_RE.match(valeur):
        return "Adresses IP"
    if HASH_RE.match(valeur):
        return "Hashes"
    if URL_RE.match(valeur):
        return "URLs"
    if DOMAINE_RE.match(valeur):
        return "Domaines"

    return "Autres"


def main() -> None:
    parseur = argparse.ArgumentParser(description="Génère un rapport Markdown d'IOC.")
    parseur.add_argument("input", type=Path, help="Fichier contenant les IOC")
    parseur.add_argument("-o", "--output", type=Path, default=Path("rapport_ioc.md"), help="Rapport Markdown de sortie")
    args = parseur.parse_args()

    categories = {
        "Adresses IP": set(),
        "Domaines": set(),
        "URLs": set(),
        "Hashes": set(),
        "Autres": set(),
    }

    for ligne in args.input.read_text(errors="replace").splitlines():
        valeur = ligne.strip()
        if not valeur or valeur.startswith("#"):
            continue
        categories[classer(valeur)].add(refang(valeur))

    lignes = [
        "# Rapport IOC",
        "",
        f"Date UTC : {datetime.now(timezone.utc).isoformat(timespec='seconds')}",
        "",
        "## Résumé",
        "",
    ]

    for nom, elements in categories.items():
        lignes.append(f"- {nom}: {len(elements)}")

    for nom, elements in categories.items():
        lignes.extend(["", f"## {nom}", ""])
        if not elements:
            lignes.append("_Aucun élément._")
            continue

        for element in sorted(elements):
            lignes.append(f"- `{defang(element)}`")

    args.output.write_text("\n".join(lignes) + "\n", encoding="utf-8")
    print(f"[+] Rapport généré : {args.output}")


if __name__ == "__main__":
    main()
