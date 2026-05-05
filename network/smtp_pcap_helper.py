#!/usr/bin/env python3
"""Helper d'analyse SMTP pour PCAP avec tshark.

Nécessite tshark.

Usage :
    python3 smtp_pcap_helper.py traffic.pcap
"""
from __future__ import annotations

import argparse
import shutil
import subprocess
from collections import Counter
from pathlib import Path


def executer_tshark(pcap: Path, champs: list[str], filtre: str = "smtp") -> list[list[str]]:
    """Exécute tshark et retourne les champs demandés."""
    commande = ["tshark", "-r", str(pcap), "-Y", filtre, "-T", "fields"]

    for champ in champs:
        commande.extend(["-e", champ])

    commande.extend(["-E", "separator=\t", "-E", "occurrence=f"])

    resultat = subprocess.run(commande, text=True, capture_output=True, check=False)

    if resultat.returncode not in {0, 1}:
        raise RuntimeError(resultat.stderr.strip())

    return [ligne.split("\t") for ligne in resultat.stdout.splitlines()]


def main() -> None:
    parseur = argparse.ArgumentParser(description="Analyse le trafic SMTP d'un PCAP avec tshark.")
    parseur.add_argument("pcap", type=Path, help="Fichier PCAP à analyser")
    args = parseur.parse_args()

    if not args.pcap.is_file():
        raise SystemExit(f"[!] Fichier introuvable : {args.pcap}")

    if not shutil.which("tshark"):
        raise SystemExit("[!] tshark est introuvable. Installe Wireshark/tshark.")

    lignes = executer_tshark(args.pcap, ["frame.number", "smtp.response.code", "smtp.response.parameter"])
    codes = Counter(ligne[1] for ligne in lignes if len(ligne) > 1 and ligne[1])

    print("# Codes de réponse SMTP")
    for code, nombre in sorted(codes.items()):
        print(f"{code}: {nombre}")

    print("\n# Réponses SMTP 4xx/5xx")
    for ligne in lignes:
        numero_trame = ligne[0] if len(ligne) > 0 else ""
        code = ligne[1] if len(ligne) > 1 else ""
        parametre = ligne[2] if len(ligne) > 2 else ""

        if code.startswith(("4", "5")):
            print(f"Trame {numero_trame}: {code} {parametre}")


if __name__ == "__main__":
    main()
