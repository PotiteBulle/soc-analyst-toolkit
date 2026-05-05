#!/usr/bin/env python3
"""Calcule les hashes d'un fichier : MD5, SHA1, SHA256, SHA512."""
from __future__ import annotations

import argparse
import hashlib
from pathlib import Path

ALGORITHMS = ["md5", "sha1", "sha256", "sha512"]


def hash_file(path: Path, algorithm: str) -> str:
    h = hashlib.new(algorithm)
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def main() -> None:
    parser = argparse.ArgumentParser(description="Calcule les hashes d'un fichier")
    parser.add_argument("file", type=Path)
    parser.add_argument("-a", "--algorithm", choices=ALGORITHMS + ["all"], default="all")
    args = parser.parse_args()

    if not args.file.is_file():
        raise SystemExit(f"[!] Fichier introuvable : {args.file}")

    algorithms = ALGORITHMS if args.algorithm == "all" else [args.algorithm]
    for algo in algorithms:
        print(f"{algo.upper():7} {hash_file(args.file, algo)}  {args.file}")


if __name__ == "__main__":
    main()
