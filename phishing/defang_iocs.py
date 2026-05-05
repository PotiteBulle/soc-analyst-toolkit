#!/usr/bin/env python3
"""Défanger ou refanger des IOC : IP, domaines, URLs, emails."""
from __future__ import annotations

import argparse
import sys


def defang(text: str) -> str:
    return (
        text.replace("https://", "hxxps://")
        .replace("http://", "hxxp://")
        .replace(".", "[.]")
        .replace("@", "[@]")
    )


def refang(text: str) -> str:
    return (
        text.replace("hxxps://", "https://")
        .replace("hxxp://", "http://")
        .replace("[.]", ".")
        .replace("[@]", "@")
    )


def main() -> None:
    parser = argparse.ArgumentParser(description="Défang/refang d'IOC")
    parser.add_argument("value", nargs="*", help="Valeur à traiter. Si vide, lit stdin.")
    parser.add_argument("--refang", action="store_true", help="Transforme les IOC défangés en IOC normaux")
    args = parser.parse_args()

    text = " ".join(args.value) if args.value else sys.stdin.read()
    print(refang(text) if args.refang else defang(text))


if __name__ == "__main__":
    main()
