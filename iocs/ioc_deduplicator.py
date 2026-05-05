#!/usr/bin/env python3
"""Nettoie, déduplique et classe une liste d'IOC.

Usage :
    python3 ioc_deduplicator.py iocs.txt -o cleaned_iocs
"""
from __future__ import annotations

import argparse
import json
import re
from pathlib import Path

IP_RE = re.compile(r"^(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)$")
HASH_RE = re.compile(r"^[A-Fa-f0-9]{32}$|^[A-Fa-f0-9]{40}$|^[A-Fa-f0-9]{64}$")
URL_RE = re.compile(r"^https?://", re.IGNORECASE)
DOMAINE_RE = re.compile(r"^(?:[A-Za-z0-9-]+\.)+[A-Za-z]{2,}$")


def refang(valeur: str) -> str:
    """Normalise un IOC defangé."""
    return valeur.strip().replace("[.]", ".").replace("hxxp://", "http://").replace("hxxps://", "https://")


def classer_ioc(valeur: str) -> str:
    """Classe un IOC selon son type."""
    valeur = refang(valeur)

    if IP_RE.match(valeur):
        return "ips"
    if HASH_RE.match(valeur):
        return "hashes"
    if URL_RE.match(valeur):
        return "urls"
    if DOMAINE_RE.match(valeur):
        return "domaines"

    return "inconnus"


def main() -> None:
    parseur = argparse.ArgumentParser(description="Déduplique et classe une liste d'IOC.")
    parseur.add_argument("input", type=Path, help="Fichier contenant les IOC")
    parseur.add_argument("-o", "--output-prefix", default="cleaned_iocs", help="Préfixe des fichiers de sortie")
    args = parseur.parse_args()

    if not args.input.is_file():
        raise SystemExit(f"[!] Fichier introuvable : {args.input}")

    valeurs_uniques = set()

    for ligne in args.input.read_text(errors="replace").splitlines():
        ligne = ligne.strip()
        if ligne and not ligne.startswith("#"):
            valeurs_uniques.add(refang(ligne))

    categories = {"ips": [], "domaines": [], "urls": [], "hashes": [], "inconnus": []}

    for valeur in sorted(valeurs_uniques):
        categories[classer_ioc(valeur)].append(valeur)

    prefixe = Path(args.output_prefix)
    prefixe.with_suffix(".json").write_text(json.dumps(categories, indent=2), encoding="utf-8")

    for nom, elements in categories.items():
        chemin = Path(f"{prefixe}_{nom}.txt")
        chemin.write_text("\n".join(elements) + ("\n" if elements else ""), encoding="utf-8")
        print(f"{nom}: {len(elements)} élément(s)")

    print(f"[+] Export JSON généré : {prefixe.with_suffix('.json')}")


if __name__ == "__main__":
    main()
