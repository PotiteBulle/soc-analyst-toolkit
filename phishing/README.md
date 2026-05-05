# Phishing Tools

Scripts pour l’analyse statique d’emails suspects.

## Scripts

- `extract_eml_attachments.py` : extrait les pièces jointes depuis un `.eml`.
- `extract_urls_from_eml.py` : extrait les URLs depuis le corps d’un email.
- `parse_email_headers.py` : affiche les headers importants pour le triage.
- `defang_iocs.py` : défang/refang d’IOC.

## Exemple

```bash
python3 extract_eml_attachments.py suspicious.eml -o extracted_attachments
python3 extract_urls_from_eml.py suspicious.eml --defang
python3 parse_email_headers.py suspicious.eml
```
