#!/usr/bin/env python3
"""Helper de scan YARA défensif.

Nécessite yara-python : pip install yara-python
"""
from __future__ import annotations

import argparse
from pathlib import Path

try:
    import yara
except ImportError as exc:
    raise SystemExit("[!] Module manquant : pip install yara-python") from exc


def iter_targets(path: Path):
    if path.is_file():
        yield path
    else:
        yield from (p for p in path.rglob("*") if p.is_file())


def main() -> None:
    parser = argparse.ArgumentParser(description="Scan YARA récursif")
    parser.add_argument("rules", type=Path, help="Fichier .yar ou dossier de règles")
    parser.add_argument("target", type=Path, help="Fichier ou dossier à scanner")
    args = parser.parse_args()

    if args.rules.is_dir():
        rule_files = {str(p): str(p) for p in args.rules.rglob("*.yar")}
        rules = yara.compile(filepaths=rule_files)
    else:
        rules = yara.compile(filepath=str(args.rules))

    for target in iter_targets(args.target):
        try:
            matches = rules.match(str(target))
        except Exception as exc:
            print(f"[!] Erreur sur {target}: {exc}")
            continue
        for match in matches:
            print(f"[MATCH] {target} -> {match.rule}")


if __name__ == "__main__":
    main()
