#!/usr/bin/env python3
"""Analyse rapide SPF / DKIM / DMARC depuis les headers d'un fichier EML.

Usage :
    python3 email_security_check.py suspicious.eml
"""
from __future__ import annotations

import argparse
import re
from email import policy
from email.parser import BytesParser
from pathlib import Path


def trouver_resultat(texte: str, cle: str) -> str:
    """Recherche un résultat SPF/DKIM/DMARC dans Authentication-Results."""
    motif = rf"\b{re.escape(cle)}=(pass|fail|softfail|neutral|none|temperror|permerror)\b"
    resultat = re.search(motif, texte, re.IGNORECASE)
    return resultat.group(1).lower() if resultat else "non trouvé"


def main() -> None:
    parseur = argparse.ArgumentParser(description="Vérifie SPF/DKIM/DMARC dans un EML.")
    parseur.add_argument("eml", type=Path, help="Fichier .eml à analyser")
    args = parseur.parse_args()

    if not args.eml.is_file():
        raise SystemExit(f"[!] Fichier introuvable : {args.eml}")

    with args.eml.open("rb") as fichier:
        message = BytesParser(policy=policy.default).parse(fichier)

    authentication_results = "\n".join(message.get_all("Authentication-Results", []))
    received_spf = "\n".join(message.get_all("Received-SPF", []))
    texte_analyse = authentication_results + "\n" + received_spf

    print("=== Résumé du message ===")
    print(f"Sujet        : {message.get('Subject', '')}")
    print(f"From         : {message.get('From', '')}")
    print(f"Reply-To     : {message.get('Reply-To', '')}")
    print(f"Return-Path  : {message.get('Return-Path', '')}")

    print("\n=== Résultats d'authentification ===")
    print(f"SPF          : {trouver_resultat(texte_analyse, 'spf')}")
    print(f"DKIM         : {trouver_resultat(texte_analyse, 'dkim')}")
    print(f"DMARC        : {trouver_resultat(texte_analyse, 'dmarc')}")

    print("\n=== Header Authentication-Results ===")
    print(authentication_results or "non trouvé")

    print("\n=== Header Received-SPF ===")
    print(received_spf or "non trouvé")


if __name__ == "__main__":
    main()
