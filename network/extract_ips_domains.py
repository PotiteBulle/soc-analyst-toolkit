#!/usr/bin/env python3
"""Extraction d'IP et domaines depuis stdin ou fichier."""
from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
DOMAIN_RE = re.compile(r"\b(?:[A-Za-z0-9-]+\.)+[A-Za-z]{2,}\b")


def valid_ip(ip: str) -> bool:
    try:
        return all(0 <= int(part) <= 255 for part in ip.split("."))
    except ValueError:
        return False


def main() -> None:
    parser = argparse.ArgumentParser(description="Extrait IP et domaines depuis un texte")
    parser.add_argument("file", nargs="?", type=Path, help="Fichier optionnel. Si absent, lit stdin.")
    parser.add_argument("--defang", action="store_true")
    args = parser.parse_args()

    text = args.file.read_text(errors="replace") if args.file else sys.stdin.read()
    ips = sorted({ip for ip in IP_RE.findall(text) if valid_ip(ip)})
    domains = sorted({d.lower() for d in DOMAIN_RE.findall(text)})

    def fmt(value: str) -> str:
        return value.replace(".", "[.]") if args.defang else value

    print("# IPs")
    for ip in ips:
        print(fmt(ip))
    print("\n# Domains")
    for domain in domains:
        print(fmt(domain))


if __name__ == "__main__":
    main()
