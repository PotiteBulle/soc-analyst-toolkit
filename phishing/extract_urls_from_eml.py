#!/usr/bin/env python3
"""Extraction d'URLs depuis un fichier .eml, avec option de défang."""
from __future__ import annotations

import argparse
import re
from email import policy
from email.parser import BytesParser
from html import unescape
from pathlib import Path
from urllib.parse import unquote

URL_RE = re.compile(r"https?://[^\s\"'<>\)\]}]+", re.IGNORECASE)


def defang(value: str) -> str:
    return value.replace("http://", "hxxp://").replace("https://", "hxxps://").replace(".", "[.]")


def iter_text_parts(eml_path: Path) -> str:
    with eml_path.open("rb") as handle:
        msg = BytesParser(policy=policy.default).parse(handle)
    chunks: list[str] = []
    for part in msg.walk():
        if part.is_multipart():
            continue
        payload = part.get_payload(decode=True)
        if payload is None:
            continue
        charset = part.get_content_charset() or "utf-8"
        try:
            chunks.append(payload.decode(charset, errors="replace"))
        except LookupError:
            chunks.append(payload.decode("utf-8", errors="replace"))
    return "\n".join(chunks)


def extract_urls(text: str) -> list[str]:
    candidates = URL_RE.findall(unescape(text))
    cleaned = sorted({unquote(url).rstrip(".,;:") for url in candidates})
    return cleaned


def main() -> None:
    parser = argparse.ArgumentParser(description="Extrait les URLs d'un fichier .eml")
    parser.add_argument("eml", type=Path)
    parser.add_argument("--defang", action="store_true", help="Affiche les URLs défangées")
    args = parser.parse_args()

    if not args.eml.exists():
        raise SystemExit(f"[!] Fichier introuvable : {args.eml}")

    for url in extract_urls(iter_text_parts(args.eml)):
        print(defang(url) if args.defang else url)


if __name__ == "__main__":
    main()
