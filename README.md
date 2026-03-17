# certbot-dot

Standalone certificate renewal tool using [CertMagic](https://github.com/caddyserver/certmagic)
with an embedded DNS-over-TLS (DoT) forwarder. Designed for environments where standard DNS
(port 53) is intercepted by local DNS services (e.g. firewall DNS interception).

## How it works

1. Starts an embedded UDP DNS server on `127.0.0.1:5053` that forwards all queries to
   Cloudflare via DoT (`1.1.1.1:853`), bypassing any local DNS interception
2. Uses CertMagic with the Cloudflare DNS provider to obtain/renew certificates via
   ACME DNS-01 challenges
3. Writes certificates to a shared volume, with flat-path copies for easy Caddy consumption
4. Exits after completion — designed to run via `docker compose run` on a systemd timer

## Environment variables

| Variable | Required | Default | Description |
|---|---|---|---|
| `CF_API_KEY` | Yes | — | Cloudflare API token with DNS edit permissions |
| `DOMAINS` | Yes | — | Comma-separated domain list (e.g. `*.example.com`) |
| `ACME_CA` | No | LE Production | ACME CA directory URL |
| `ACME_EMAIL` | No | — | ACME account email |
| `CERT_DIR` | No | `/certs` | Certificate storage path |

## Usage

```bash
# Create shared volume
docker volume create certs_data

# Run with staging CA (test first!)
docker compose run --rm certbot-dot

# Verify certs
docker run --rm -v certs_data:/c alpine ls -la /c/
```

## Output

Certificates are stored in two formats:

- **CertMagic native**: `/certs/certificates/<ca-dir>/<domain>/` (full structure)
- **Flat copies**: `/certs/wildcard.crt`, `/certs/wildcard.key` (for Caddy `tls` directive)

## Systemd timer

Run daily via systemd timer. Stagger same-zone hosts to avoid concurrent TXT record writes:

```ini
# /etc/systemd/system/certbot-dot.timer
[Timer]
OnCalendar=*-*-* 02:00:00
RandomizedDelaySec=900
Persistent=true
```
