#!/usr/bin/env python3
"""Extraction simple d'IOC depuis des logs texte : IP, domaines, URLs, emails."""
from __future__ import annotations

import argparse
import json
import re
from pathlib import Path

IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
URL_RE = re.compile(r"https?://[^\s\"'<>\)\]}]+", re.IGNORECASE)
EMAIL_RE = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")
DOMAIN_RE = re.compile(r"\b(?:[A-Za-z0-9-]+\.)+[A-Za-z]{2,}\b")


def is_valid_ip(ip: str) -> bool:
    try:
        return all(0 <= int(part) <= 255 for part in ip.split("."))
    except ValueError:
        return False


def extract(text: str) -> dict[str, list[str]]:
    ips = sorted({ip for ip in IP_RE.findall(text) if is_valid_ip(ip)})
    urls = sorted(set(URL_RE.findall(text)))
    emails = sorted(set(EMAIL_RE.findall(text)))
    domains = sorted({d.lower() for d in DOMAIN_RE.findall(text) if not d.replace('.', '').isdigit()})
    return {"ips": ips, "domains": domains, "urls": urls, "emails": emails}


def main() -> None:
    parser = argparse.ArgumentParser(description="Extrait des IOC depuis un fichier log")
    parser.add_argument("logfile", type=Path)
    parser.add_argument("-o", "--output", type=Path, help="Fichier JSON de sortie")
    args = parser.parse_args()

    if not args.logfile.exists():
        raise SystemExit(f"[!] Fichier introuvable : {args.logfile}")

    result = extract(args.logfile.read_text(errors="replace"))
    print(json.dumps(result, indent=2, ensure_ascii=False))
    if args.output:
        args.output.write_text(json.dumps(result, indent=2, ensure_ascii=False), encoding="utf-8")
        print(f"[+] JSON écrit : {args.output}")


if __name__ == "__main__":
    main()
