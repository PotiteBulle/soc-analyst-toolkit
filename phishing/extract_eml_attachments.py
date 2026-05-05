#!/usr/bin/env python3
"""Extracteur de pièces jointes depuis un fichier .eml.

Usage:
    python3 extract_eml_attachments.py message.eml -o extracted_attachments
"""
from __future__ import annotations

import argparse
import re
from email import policy
from email.parser import BytesParser
from pathlib import Path


def safe_filename(name: str) -> str:
    name = name.strip().replace("\\", "_").replace("/", "_")
    name = re.sub(r"[\x00-\x1f\x7f]", "_", name)
    return name or "attachment.bin"


def unique_path(output_dir: Path, filename: str) -> Path:
    path = output_dir / filename
    if not path.exists():
        return path
    stem, suffix = path.stem, path.suffix
    index = 1
    while True:
        candidate = output_dir / f"{stem}_{index}{suffix}"
        if not candidate.exists():
            return candidate
        index += 1


def extract_attachments(eml_path: Path, output_dir: Path) -> int:
    output_dir.mkdir(parents=True, exist_ok=True)
    with eml_path.open("rb") as handle:
        msg = BytesParser(policy=policy.default).parse(handle)

    found = 0
    for part in msg.walk():
        filename = part.get_filename()
        disposition = part.get_content_disposition()
        content_type = part.get_content_type()

        if not filename and disposition != "attachment":
            continue
        if not filename:
            filename = f"attachment_{found + 1}.bin"

        payload = part.get_payload(decode=True)
        if payload is None:
            print(f"[!] Impossible de décoder : {filename}")
            continue

        out_path = unique_path(output_dir, safe_filename(filename))
        out_path.write_bytes(payload)
        found += 1
        print(f"[+] Extrait : {out_path}")
        print(f"    Type MIME : {content_type}")
        print(f"    Taille    : {len(payload)} bytes")

    if found == 0:
        print("[!] Aucune pièce jointe trouvée.")
    return found


def main() -> None:
    parser = argparse.ArgumentParser(description="Extrait les pièces jointes d'un fichier .eml")
    parser.add_argument("eml", type=Path, help="Chemin vers le fichier .eml")
    parser.add_argument("-o", "--output", type=Path, default=Path("extracted_attachments"), help="Dossier de sortie")
    args = parser.parse_args()

    if not args.eml.exists():
        raise SystemExit(f"[!] Fichier introuvable : {args.eml}")
    extract_attachments(args.eml, args.output)


if __name__ == "__main__":
    main()
