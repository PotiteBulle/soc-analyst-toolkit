# Wireshark Filters utiles SOC

## SMTP

```text
smtp
smtp.response.code
smtp.response.code == 220
smtp.response.code == 552
frame contains "spamhaus.org"
smtp contains "Content-Transfer-Encoding"
smtp contains "filename="
```

## DNS

```text
dns
dns.qry.name contains "example"
dns.flags.response == 0
```

## HTTP

```text
http
http.request
http.request.method == "POST"
http.host contains "example.com"
http.user_agent
```

## TLS / Certificats

```text
tls
tls.handshake.type == 1
tls.handshake.extensions_server_name
```
