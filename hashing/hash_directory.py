#!/usr/bin/env python3
"""Calcule les hashes SHA256 de tous les fichiers d'un dossier."""
from __future__ import annotations

import argparse
import csv
import hashlib
from pathlib import Path


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def iter_files(root: Path):
    for path in sorted(root.rglob("*")):
        if path.is_file():
            yield path


def main() -> None:
    parser = argparse.ArgumentParser(description="Hash SHA256 récursif d'un dossier")
    parser.add_argument("directory", type=Path)
    parser.add_argument("-o", "--output", type=Path, help="Export CSV optionnel")
    args = parser.parse_args()

    if not args.directory.is_dir():
        raise SystemExit(f"[!] Dossier introuvable : {args.directory}")

    rows = []
    for path in iter_files(args.directory):
        digest = sha256_file(path)
        rel = path.relative_to(args.directory)
        rows.append({"path": str(rel), "sha256": digest, "size_bytes": path.stat().st_size})
        print(f"{digest}  {rel}")

    if args.output:
        with args.output.open("w", newline="", encoding="utf-8") as handle:
            writer = csv.DictWriter(handle, fieldnames=["path", "sha256", "size_bytes"])
            writer.writeheader()
            writer.writerows(rows)
        print(f"[+] CSV écrit : {args.output}")


if __name__ == "__main__":
    main()
