#!/usr/bin/env python3
"""Recherche des processus ou lignes de commande suspects dans un CSV ou un fichier texte.

Usage :
    python3 suspicious_process_finder.py process-hunt.csv
"""
from __future__ import annotations

import argparse
import csv
import re
from pathlib import Path

MOTIFS_SUSPECTS = [
    r"powershell(.exe)?\s+.*(-enc|-encodedcommand|downloadstring|iex|invoke-expression)",
    r"cmd\.exe\s+/c",
    r"\b(mshta|rundll32|regsvr32|certutil|bitsadmin|wmic|schtasks)\.exe\b",
    r"\\appdata\\|\\temp\\|\\public\\",
    r"vssadmin.*delete.*shadows",
    r"wevtutil.*cl",
    r"mimikatz|sekurlsa|lsass",
]


def motifs_trouves(texte: str) -> list[str]:
    """Retourne les motifs suspects détectés."""
    return [motif for motif in MOTIFS_SUSPECTS if re.search(motif, texte, re.IGNORECASE)]


def lire_lignes(chemin: Path):
    """Lit un CSV ou un fichier texte en générant des dictionnaires."""
    if chemin.suffix.lower() == ".csv":
        with chemin.open(newline="", encoding="utf-8", errors="replace") as fichier:
            yield from csv.DictReader(fichier)
    else:
        for ligne in chemin.read_text(errors="replace").splitlines():
            yield {"ligne": ligne}


def main() -> None:
    parseur = argparse.ArgumentParser(description="Repère des processus suspects dans un fichier.")
    parseur.add_argument("input", type=Path, help="CSV ou fichier texte à analyser")
    args = parseur.parse_args()

    if not args.input.is_file():
        raise SystemExit(f"[!] Fichier introuvable : {args.input}")

    total = 0
    print("# Détections de processus suspects")

    for ligne in lire_lignes(args.input):
        contenu = " ".join(str(valeur) for valeur in ligne.values() if valeur)
        alertes = motifs_trouves(contenu)

        if not alertes:
            continue

        total += 1
        print("\n---")
        print(f"Détection #{total}")
        print(f"Motifs détectés : {', '.join(alertes)}")

        for cle, valeur in ligne.items():
            if valeur:
                print(f"{cle}: {valeur}")

    if total == 0:
        print("Aucun motif suspect détecté.")


if __name__ == "__main__":
    main()
