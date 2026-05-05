#!/usr/bin/env python3
"""Extrait les pièces jointes d'un fichier EML et calcule MD5/SHA1/SHA256.

Usage :
    python3 extract_attachments_hashes.py suspicious.eml -o extracted --json report.json
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
from email import policy
from email.parser import BytesParser
from pathlib import Path


def nettoyer_nom_fichier(nom: str) -> str:
    """Nettoie le nom de fichier pour éviter les chemins dangereux."""
    nom = nom.strip().replace("\\", "_").replace("/", "_")
    nom = re.sub(r"[\x00-\x1f\x7f]", "_", nom)
    return nom or "piece_jointe.bin"


def chemin_unique(dossier_sortie: Path, nom_fichier: str) -> Path:
    """Évite d'écraser un fichier déjà existant."""
    chemin = dossier_sortie / nom_fichier
    if not chemin.exists():
        return chemin

    racine, suffixe = chemin.stem, chemin.suffix
    compteur = 1

    while True:
        candidat = dossier_sortie / f"{racine}_{compteur}{suffixe}"
        if not candidat.exists():
            return candidat
        compteur += 1


def calculer_hashes(donnees: bytes) -> dict[str, str]:
    """Calcule les hashes classiques utiles en analyse SOC."""
    return {
        "md5": hashlib.md5(donnees).hexdigest(),
        "sha1": hashlib.sha1(donnees).hexdigest(),
        "sha256": hashlib.sha256(donnees).hexdigest(),
    }


def extraire_pieces_jointes(eml: Path, dossier_sortie: Path) -> list[dict[str, object]]:
    """Extrait les pièces jointes et retourne leurs métadonnées."""
    dossier_sortie.mkdir(parents=True, exist_ok=True)

    with eml.open("rb") as fichier:
        message = BytesParser(policy=policy.default).parse(fichier)

    resultats = []

    for index, partie in enumerate(message.walk(), start=1):
        nom_fichier = partie.get_filename()
        disposition = partie.get_content_disposition()

        if not nom_fichier and disposition != "attachment":
            continue

        contenu = partie.get_payload(decode=True)
        if not contenu:
            continue

        nom_fichier = nettoyer_nom_fichier(nom_fichier or f"piece_jointe_{index}.bin")
        chemin_sortie = chemin_unique(dossier_sortie, nom_fichier)
        chemin_sortie.write_bytes(contenu)

        resultats.append({
            "source_eml": str(eml),
            "nom_fichier": chemin_sortie.name,
            "chemin": str(chemin_sortie),
            "type_mime": partie.get_content_type(),
            "taille_octets": len(contenu),
            **calculer_hashes(contenu),
        })

    return resultats


def main() -> None:
    parseur = argparse.ArgumentParser(
        description="Extrait les pièces jointes d'un EML et calcule leurs hashes."
    )
    parseur.add_argument("eml", type=Path, help="Fichier .eml à analyser")
    parseur.add_argument(
        "-o", "--output",
        type=Path,
        default=Path("extracted_attachments"),
        help="Dossier de sortie des pièces jointes"
    )
    parseur.add_argument("--json", type=Path, help="Export JSON optionnel")
    args = parseur.parse_args()

    if not args.eml.is_file():
        raise SystemExit(f"[!] Fichier introuvable : {args.eml}")

    resultats = extraire_pieces_jointes(args.eml, args.output)

    if not resultats:
        print("[!] Aucune pièce jointe trouvée.")
        return

    for item in resultats:
        print(f"[+] Pièce jointe extraite : {item['nom_fichier']}")
        print(f"    Type MIME : {item['type_mime']}")
        print(f"    Taille    : {item['taille_octets']} octets")
        print(f"    MD5       : {item['md5']}")
        print(f"    SHA1      : {item['sha1']}")
        print(f"    SHA256    : {item['sha256']}")

    if args.json:
        args.json.write_text(json.dumps(resultats, indent=2, ensure_ascii=False), encoding="utf-8")
        print(f"[+] Rapport JSON généré : {args.json}")


if __name__ == "__main__":
    main()
