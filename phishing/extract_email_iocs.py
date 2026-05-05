#!/usr/bin/env python3
"""Extrait les IOC principaux depuis un fichier EML.

Éléments extraits :
- URLs
- domaines
- adresses IP
- adresses e-mail
- headers importants
- noms de pièces jointes

Usage :
    python3 extract_email_iocs.py suspicious.eml --json iocs.json
"""
from __future__ import annotations

import argparse
import json
import re
from email import policy
from email.parser import BytesParser
from pathlib import Path
from urllib.parse import urlparse

URL_RE = re.compile(r"""https?://[^\s"'<>)}\]]+""", re.IGNORECASE)
EMAIL_RE = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")
IP_RE = re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b")
DOMAINE_RE = re.compile(r"\b(?:[A-Za-z0-9-]+\.)+[A-Za-z]{2,}\b")

HEADERS_IMPORTANTS = [
    "Subject", "From", "To", "Cc", "Reply-To", "Return-Path", "Sender",
    "Message-ID", "Date", "Authentication-Results", "Received-SPF",
    "DKIM-Signature", "X-Originating-IP", "X-Mailer", "User-Agent",
]


def extraire_corps_texte(message) -> str:
    """Récupère les parties texte et HTML lisibles du message."""
    morceaux = []

    for partie in message.walk():
        if partie.get_content_maintype() == "multipart":
            continue

        if partie.get_content_type() not in {"text/plain", "text/html"}:
            continue

        try:
            morceaux.append(partie.get_content())
        except Exception:
            contenu = partie.get_payload(decode=True)
            if contenu:
                morceaux.append(contenu.decode(errors="replace"))

    return "\n".join(morceaux)


def domaines_depuis_urls(urls: set[str]) -> set[str]:
    """Extrait les domaines à partir des URLs."""
    domaines = set()

    for url in urls:
        hote = urlparse(url).hostname
        if hote:
            domaines.add(hote.lower())

    return domaines


def analyser_eml(eml: Path) -> dict:
    """Analyse un fichier EML et retourne un rapport structuré."""
    with eml.open("rb") as fichier:
        message = BytesParser(policy=policy.default).parse(fichier)

    brut = eml.read_text(errors="replace")
    corps = extraire_corps_texte(message)
    contenu_global = brut + "\n" + corps

    urls = set(URL_RE.findall(contenu_global))
    emails = set(EMAIL_RE.findall(contenu_global))
    ips = set(IP_RE.findall(contenu_global))
    domaines = set(DOMAINE_RE.findall(contenu_global)) | domaines_depuis_urls(urls)

    pieces_jointes = []
    for partie in message.walk():
        nom_fichier = partie.get_filename()
        if nom_fichier:
            pieces_jointes.append({
                "nom_fichier": nom_fichier,
                "type_mime": partie.get_content_type(),
                "disposition": partie.get_content_disposition(),
            })

    headers = {h: message.get_all(h, []) for h in HEADERS_IMPORTANTS if message.get_all(h)}

    return {
        "source": str(eml),
        "headers": headers,
        "pieces_jointes": pieces_jointes,
        "iocs": {
            "urls": sorted(urls),
            "emails": sorted(emails),
            "ips": sorted(ips),
            "domaines": sorted(domaines),
        },
    }


def main() -> None:
    parseur = argparse.ArgumentParser(description="Extrait les IOC d'un fichier EML.")
    parseur.add_argument("eml", type=Path, help="Fichier .eml à analyser")
    parseur.add_argument("--json", type=Path, help="Export JSON optionnel")
    args = parseur.parse_args()

    if not args.eml.is_file():
        raise SystemExit(f"[!] Fichier introuvable : {args.eml}")

    rapport = analyser_eml(args.eml)

    print(f"# Rapport IOC pour {args.eml}")

    print("\n## Headers")
    for nom, valeurs in rapport["headers"].items():
        for valeur in valeurs:
            print(f"{nom}: {valeur}")

    print("\n## Pièces jointes")
    if not rapport["pieces_jointes"]:
        print("_Aucune pièce jointe trouvée._")
    else:
        for item in rapport["pieces_jointes"]:
            print(f"- {item['nom_fichier']} ({item['type_mime']})")

    print("\n## IOC")
    for categorie, valeurs in rapport["iocs"].items():
        print(f"\n### {categorie}")
        if not valeurs:
            print("_Aucun élément trouvé._")
        else:
            for valeur in valeurs:
                print(valeur)

    if args.json:
        args.json.write_text(json.dumps(rapport, indent=2, ensure_ascii=False), encoding="utf-8")
        print(f"\n[+] Export JSON généré : {args.json}")


if __name__ == "__main__":
    main()
