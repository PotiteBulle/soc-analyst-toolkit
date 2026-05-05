#!/usr/bin/env python3
"""Analyse simple des logs d'échecs de connexion.

Usage :
    python3 failed_login_analyzer.py auth.log --threshold 5
"""
from __future__ import annotations

import argparse
import re
from collections import Counter
from pathlib import Path

IP_RE = re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b")

MOTIFS_UTILISATEUR = [
    re.compile(r"Failed password for (?:invalid user )?(?P<user>[A-Za-z0-9._-]+)", re.IGNORECASE),
    re.compile(r"user(?:name)?[=: ]+(?P<user>[A-Za-z0-9._-]+)", re.IGNORECASE),
]


def extraire_utilisateur(ligne: str) -> str | None:
    """Tente d'extraire un nom d'utilisateur depuis une ligne de log."""
    for motif in MOTIFS_UTILISATEUR:
        resultat = motif.search(ligne)
        if resultat:
            return resultat.group("user")
    return None


def main() -> None:
    parseur = argparse.ArgumentParser(description="Analyse les échecs de connexion dans un fichier de logs.")
    parseur.add_argument("logfile", type=Path, help="Fichier de logs à analyser")
    parseur.add_argument("--threshold", type=int, default=5, help="Seuil d'alerte")
    args = parseur.parse_args()

    if not args.logfile.is_file():
        raise SystemExit(f"[!] Fichier introuvable : {args.logfile}")

    compteur_ips = Counter()
    compteur_utilisateurs = Counter()

    for ligne in args.logfile.read_text(errors="replace").splitlines():
        if not re.search(r"fail|failed|invalid|denied|échec|refus", ligne, re.IGNORECASE):
            continue

        for ip in IP_RE.findall(ligne):
            compteur_ips[ip] += 1

        utilisateur = extraire_utilisateur(ligne)
        if utilisateur:
            compteur_utilisateurs[utilisateur] += 1

    print("# Résumé des échecs de connexion")

    print("\n## Top adresses IP")
    for ip, nombre in compteur_ips.most_common(20):
        alerte = " <-- seuil atteint" if nombre >= args.threshold else ""
        print(f"{nombre:5} {ip}{alerte}")

    print("\n## Top utilisateurs ciblés")
    for utilisateur, nombre in compteur_utilisateurs.most_common(20):
        alerte = " <-- seuil atteint" if nombre >= args.threshold else ""
        print(f"{nombre:5} {utilisateur}{alerte}")


if __name__ == "__main__":
    main()
