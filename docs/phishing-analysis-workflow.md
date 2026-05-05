# Workflow d'analyse phishing

## 1. Préservation

- Ne pas cliquer sur les liens.
- Ne pas exécuter les pièces jointes.
- Sauvegarder l'email au format `.eml`.

## 2. Analyse des headers

Champs importants :

- `From`
- `Reply-To`
- `Return-Path`
- `Received`
- `Authentication-Results`
- `SPF`, `DKIM`, `DMARC`

Commande utile :

```bash
python3 phishing/parse_email_headers.py suspicious.eml
```

## 3. Analyse du corps

- Identifier les marques usurpées.
- Extraire les URLs.
- Défanger les IOC avant partage.

```bash
python3 phishing/extract_urls_from_eml.py suspicious.eml --defang
```

## 4. Pièces jointes

- Extraire sans exécuter.
- Calculer SHA256.
- Vérifier le type réel avec `file`.

```bash
python3 phishing/extract_eml_attachments.py suspicious.eml
sha256sum extracted_attachments/*
file extracted_attachments/*
```

## 5. Décision SOC

Classer l'email :

- Benign
- Spam
- Phishing
- Malware delivery
- Credential harvesting
- Business Email Compromise

## 6. Actions défensives

- Bloquer domaines / URLs / IP si pertinent.
- Rechercher d'autres destinataires.
- Réinitialiser les mots de passe si compromission.
- Rédiger un rapport d'incident.
