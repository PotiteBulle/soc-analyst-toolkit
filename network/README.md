# Network

Ce dossier contient des outils et notes pour l’analyse réseau orientée SOC.

Les scripts peuvent aider à analyser :

- Fichiers PCAP.
- Trafic SMTP.
- Domaines DNS.
- IPs.
- URLs.
- Artefacts réseau.

## Scripts et documents

```text
network/
├── dns_suspicious_domains.py
├── extract_ips_domains.py
├── smtp_pcap_helper.py
└── wireshark_filters.md
```

## `extract_ips_domains.py`

Extrait des adresses IP et domaines depuis un fichier texte.

### Exemple

```bash
python3 network/extract_ips_domains.py logs.txt
```

### Cas d’usage

- Extraction rapide depuis des logs proxy.
- Extraction depuis un rapport texte.
- Extraction depuis une sortie d’outil.

## `smtp_pcap_helper.py`

Analyse un PCAP SMTP avec `tshark`.

### Prérequis

```bash
tshark --version
```

### Exemple

```bash
python3 network/smtp_pcap_helper.py traffic.pcap
```

### Fonctionnalités

- Compte les codes de réponse SMTP.
- Affiche les réponses SMTP 4xx/5xx.
- Aide à identifier les erreurs de livraison.
- Utile pour les labs d’analyse SMTP.

## `dns_suspicious_domains.py`

Attribue un score simple à des domaines potentiellement suspects.

### Exemple

```bash
python3 network/dns_suspicious_domains.py domains.txt
```

### Critères simples

- Domaine très long.
- Nombreux sous-domaines.
- TLD à risque.
- Mots-clés sensibles.
- Présence de chiffres.

## `wireshark_filters.md`

Mémo de filtres Wireshark utiles pour l’analyse réseau.

## Filtres Wireshark utiles

```text
dns
http
tls
smtp
tcp.port == 25
smtp.response.code == 552
frame contains "spamhaus.org"
```

## Bonnes pratiques

- Ne pas ouvrir directement des URLs suspectes.
- Travailler en VM ou environnement isolé.
- Defanger les domaines et URLs dans les rapports.
- Corréler les IPs avec les domaines et timestamps.
- Vérifier les flux sortants inhabituels.
