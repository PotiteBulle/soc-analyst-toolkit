#!/usr/bin/env python3
"""Parseur simple d'en-têtes email pour triage phishing."""
from __future__ import annotations

import argparse
from email import policy
from email.parser import BytesParser
from email.utils import getaddresses
from pathlib import Path

INTERESTING_HEADERS = [
    "Subject", "From", "To", "Cc", "Reply-To", "Return-Path", "Sender",
    "Message-ID", "Date", "Authentication-Results", "Received-SPF",
    "DKIM-Signature", "X-Originating-IP", "X-Mailer", "User-Agent",
]


def parse_headers(eml_path: Path) -> None:
    with eml_path.open("rb") as handle:
        msg = BytesParser(policy=policy.default).parse(handle)

    print("# Résumé des en-têtes")
    for header in INTERESTING_HEADERS:
        values = msg.get_all(header, [])
        for value in values:
            print(f"{header}: {value}")

    print("\n# Adresses parsées")
    for header in ["From", "To", "Cc", "Reply-To", "Return-Path", "Sender"]:
        values = msg.get_all(header, [])
        if not values:
            continue
        print(f"[{header}]")
        for name, addr in getaddresses(values):
            print(f"  name={name!r} addr={addr}")

    print("\n# Chaîne Received")
    received = msg.get_all("Received", [])
    for index, value in enumerate(received, start=1):
        print(f"Hop {index}: {value}")


def main() -> None:
    parser = argparse.ArgumentParser(description="Affiche les en-têtes utiles d'un .eml")
    parser.add_argument("eml", type=Path)
    args = parser.parse_args()
    if not args.eml.exists():
        raise SystemExit(f"[!] Fichier introuvable : {args.eml}")
    parse_headers(args.eml)


if __name__ == "__main__":
    main()
