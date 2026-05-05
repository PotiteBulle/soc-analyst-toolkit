# Analyse SMTP avec Wireshark

## Filtres utiles

```text
smtp
smtp.response.code
smtp.response.code == 220
smtp.response.code == 552
smtp.response.code == 553
frame contains "spamhaus.org"
smtp contains "Content-Disposition"
smtp contains "filename="
```

## Codes SMTP fréquents

- `220` : service prêt
- `250` : action demandée acceptée
- `354` : début de saisie du message
- `552` : action interrompue, problème potentiel de sécurité ou stockage dépassé
- `553` : action non effectuée, nom de boîte mail non autorisé

## Méthode rapide

1. Filtrer sur `smtp`.
2. Identifier les réponses SMTP 4xx/5xx.
3. Rechercher les messages de blocage.
4. Rechercher les pièces jointes MIME.
5. Noter les noms de fichiers, encodages et codes de réponse.
