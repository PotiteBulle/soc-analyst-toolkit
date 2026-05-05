#!/usr/bin/env python3
"""Analyse une liste de domaines DNS et repère des noms suspects.

Usage :
    python3 dns_suspicious_domains.py domains.txt
"""
from __future__ import annotations

import argparse
from pathlib import Path

MOTS_CLES = ["login", "verify", "secure", "account", "update", "office", "microsoft", "paypal", "bank", "wallet"]
TLD_SUSPECTS = {".buzz", ".top", ".xyz", ".icu", ".click", ".live", ".cam", ".zip"}


def evaluer_domaine(domaine: str) -> tuple[int, list[str]]:
    """Attribue un score simple à un domaine potentiellement suspect."""
    d = domaine.lower().strip(".")
    score = 0
    raisons = []

    if len(d) > 45:
        score += 2
        raisons.append("domaine_long")

    if d.count(".") >= 3:
        score += 1
        raisons.append("nombreux_sous_domaines")

    for mot in MOTS_CLES:
        if mot in d:
            score += 1
            raisons.append(f"mot_cle:{mot}")

    for tld in TLD_SUSPECTS:
        if d.endswith(tld):
            score += 1
            raisons.append(f"tld:{tld}")

    if any(caractere.isdigit() for caractere in d):
        score += 1
        raisons.append("contient_chiffre")

    return score, raisons


def main() -> None:
    parseur = argparse.ArgumentParser(description="Repère des domaines DNS potentiellement suspects.")
    parseur.add_argument("input", type=Path, help="Fichier contenant un domaine par ligne")
    parseur.add_argument("--min-score", type=int, default=2, help="Score minimal à afficher")
    args = parseur.parse_args()

    if not args.input.is_file():
        raise SystemExit(f"[!] Fichier introuvable : {args.input}")

    for ligne in args.input.read_text(errors="replace").splitlines():
        domaine = ligne.strip()

        if not domaine or domaine.startswith("#"):
            continue

        score, raisons = evaluer_domaine(domaine)

        if score >= args.min_score:
            print(f"{score}\t{domaine}\t{','.join(raisons)}")


if __name__ == "__main__":
    main()
