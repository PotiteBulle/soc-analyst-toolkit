#!/usr/bin/env python3
"""Outil simple pour defang/refang des IOC.

Usage :
    python3 url_defanger.py --defang "https://evil.com/login"
    python3 url_defanger.py --refang "hxxps://evil[.]com/login"
"""
from __future__ import annotations

import argparse
import sys


def defang(valeur: str) -> str:
    """Transforme un IOC en version non cliquable."""
    valeur = valeur.replace("https://", "hxxps://").replace("http://", "hxxp://")
    valeur = valeur.replace(".", "[.]").replace("@", "[@]")
    return valeur


def refang(valeur: str) -> str:
    """Restaure un IOC defangé vers sa forme normale."""
    valeur = valeur.replace("hxxps://", "https://").replace("hxxp://", "http://")
    valeur = valeur.replace("[.]", ".").replace("[@]", "@")
    return valeur


def main() -> None:
    parseur = argparse.ArgumentParser(description="Defang/refang des IOC.")
    groupe = parseur.add_mutually_exclusive_group(required=True)
    groupe.add_argument("--defang", action="store_true", help="Rendre les IOC non cliquables")
    groupe.add_argument("--refang", action="store_true", help="Restaurer les IOC")
    parseur.add_argument("valeurs", nargs="*", help="IOC à transformer. Lit stdin si vide.")
    args = parseur.parse_args()

    valeurs = args.valeurs or [ligne.strip() for ligne in sys.stdin if ligne.strip()]
    transformation = defang if args.defang else refang

    for valeur in valeurs:
        print(transformation(valeur))


if __name__ == "__main__":
    main()
