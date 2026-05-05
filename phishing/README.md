# Phishing

Ce dossier contient des scripts dédiés à l’analyse d’emails suspects et au triage phishing.

L’objectif est d’aider à extraire rapidement les artefacts importants d’un email :

- Headers.
- Expéditeur.
- Destinataire.
- Reply-To.
- Return-Path.
- URLs.
- Domaines.
- Adresses IP.
- Pièces jointes.
- Hashes.
- Résultats SPF/DKIM/DMARC.

## Scripts

```text
phishing/
├── defang_iocs.py
├── email_security_check.py
├── extract_attachments_hashes.py
├── extract_email_iocs.py
├── extract_eml_attachments.py
├── extract_urls_from_eml.py
├── parse_email_headers.py
└── url_defanger.py
```

## `extract_eml_attachments.py`

Extrait les pièces jointes d’un fichier `.eml`.

### Exemple

```bash
python3 phishing/extract_eml_attachments.py suspicious.eml -o extracted_attachments
```

## `extract_attachments_hashes.py`

Extrait les pièces jointes et calcule automatiquement leurs hashes.

### Exemple

```bash
python3 phishing/extract_attachments_hashes.py suspicious.eml -o extracted --json rapport.json
```

## `extract_email_iocs.py`

Extrait les IOC principaux depuis un email.

### Exemple

```bash
python3 phishing/extract_email_iocs.py suspicious.eml --json iocs.json
```

## `extract_urls_from_eml.py`

Extrait les URLs présentes dans un email.

### Exemple

```bash
python3 phishing/extract_urls_from_eml.py suspicious.eml
```

## `parse_email_headers.py`

Affiche les headers importants d’un email.

### Exemple

```bash
python3 phishing/parse_email_headers.py suspicious.eml
```

## `email_security_check.py`

Analyse SPF, DKIM et DMARC depuis les headers.

### Exemple

```bash
python3 phishing/email_security_check.py suspicious.eml
```

## `defang_iocs.py` et `url_defanger.py`

Rendent les IOC non cliquables ou restaurent leur forme normale.

### Exemple

```bash
python3 phishing/url_defanger.py --defang "https://evil.com/login"
```

Sortie :

```text
hxxps://evil[.]com/login
```

## Workflow conseillé

1. Identifier le sujet, l’expéditeur et le destinataire.
2. Vérifier `Reply-To` et `Return-Path`.
3. Lire les headers `Received`.
4. Vérifier SPF/DKIM/DMARC.
5. Extraire les URLs.
6. Defanger les IOC.
7. Extraire les pièces jointes.
8. Calculer SHA256.
9. Vérifier les artefacts dans des outils de réputation.
10. Rédiger un rapport.

## Bonnes pratiques

- Ne jamais ouvrir une pièce jointe suspecte sur la machine hôte.
- Ne jamais cliquer directement sur une URL suspecte.
- Utiliser une VM ou une sandbox.
- Defanger les IOC dans les rapports publics.
- Ne pas publier de vrais emails contenant des données personnelles.

## Exemple de triage rapide

```bash
python3 phishing/parse_email_headers.py suspicious.eml
python3 phishing/extract_email_iocs.py suspicious.eml --json iocs.json
python3 phishing/extract_attachments_hashes.py suspicious.eml -o extracted
```
