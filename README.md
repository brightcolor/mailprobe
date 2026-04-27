# MailProbe

[![Contributions Welcome](https://img.shields.io/badge/contributions-welcome-brightgreen.svg)](./CONTRIBUTING.md)

Quickstart: `bash <(curl -fsSL https://raw.githubusercontent.com/brightcolor/mailprobe/main/scripts/quickstart.sh)`

MailProbe is a self-hosted email deliverability test service.
It accepts test emails on temporary addresses, stores the raw message, runs transparent checks, and shows a report with score + findings.

## Why this design

This project is intentionally built for small VPS setups (including ~1 GB RAM environments):

- Single Go binary (HTTP + SMTP + analysis + cleanup)
- SQLite (no external database service)
- Server-rendered UI (no heavy frontend framework)
- Docker Compose deployment (no Kubernetes)

## Core workflow

1. Open the web UI
2. Generate a random temporary mailbox
3. Send your campaign/test email to that address
4. MailProbe receives and stores the message
5. MailProbe analyzes the message and creates a report
6. Open the report with score, checks, warnings, and suggestions

## Features

### Mailbox and intake

- Random temporary mailbox addresses (`<token>@<request-host>` by default, or `<token>@SMTP_DOMAIN` when configured)
- Score-first web UI with a guided send-and-check workflow
- New test addresses can be generated in-place without a full page reload
- Multiple active mailboxes in parallel
- Multiple emails per mailbox
- Mailbox TTL and automatic expiration
- Raw source and raw headers view
- JSON report endpoint for automation/integrations

### Report UI

- Vvveb Admin Template based shell and visual system (Apache-2.0 vendor assets are shipped locally)
- Score-first dashboard with a large result hero, status counters, message metadata, and grouped diagnostics
- Check groups for authentication, DNS/infrastructure, spam filters, content/format, and raw/header details
- Check accordions show only values relevant to the current check instead of repeating global message metadata everywhere
- Collapsible technical sections for long diagnostics, headers, plaintext, HTML preview, HTML source, and full raw source
- Copy-to-clipboard actions for DNS records, recommendations, headers, source, and technical values
- Remediation blocks are shown only for warning/failing checks as `Wie wird's gemacht?`
- Detected URLs are grouped by domain with total and per-domain counts
- Responsive layout for desktop and mobile
- Light, dark, and auto theme mode with a UI toggle; `auto` follows `prefers-color-scheme`

### Analysis and scoring

- Score from `0.0` to `10.0`
- Non-black-box scoring model (rule deltas are visible in report)
- Report-first layout with status counters, prioritized checks, recommendations, raw views, and JSON export
- Sandboxed rendered HTML preview plus raw HTML source for received messages
- Check categories include:
  - SPF (header result + DNS context)
  - DKIM (signature/auth-result heuristics)
  - DMARC (record + alignment heuristics)
  - PTR/rDNS
  - HELO/EHLO plausibility
  - Envelope-From vs Header-From alignment
  - Return-Path presence
  - Received chain presence
  - ARC presence info
  - MIME structure and multipart sanity
  - Plaintext/HTML presence and ratio heuristics
  - Attachments detection
  - Link extraction
  - URL shortener and tracking marker heuristics
  - Basic HTML sanity / hidden content heuristics
  - Subject spam-style heuristics (caps / punctuation)
  - Date header plausibility
  - Message-ID presence
  - Unicode obfuscation heuristics
  - Newsletter hints: List-Unsubscribe / preheader heuristics
- Optional RBL checks (disabled by default)
- RBL findings include checked DNSBL zones, lookup responses, TXT evidence, impact text, pre-delisting checklist, and provider-specific delisting URLs where known
- Optional SpamAssassin integration (disabled by default)
- Optional Rspamd integration (disabled by default)
- Rspamd findings include top rejecting symbols and actionable recommendations in report output

Each check result is intentionally explainable. In addition to the legacy fields (`id`, `name`, `status`, `score_delta`, `summary`, `suggestion`), reports may include:

- `category`: UI/report grouping, for example `Authentifizierung` or `DNS und Infrastruktur`
- `severity`: `low`, `medium`, `high`, or `info`
- `technical_details`: structured key/value data used for DNS records, IPs, HELO/EHLO, headers, body metrics, RBL providers, and external filter output
- `explanation`: why this check matters for deliverability
- `recommendation`: concrete remediation text with example DNS, MTA, or template changes where possible

This is stored in the report JSON and visible in the web UI. Existing API consumers can keep reading the old fields; the new fields are additive.

## Non-goals

- Not a full production MTA
- Not an outbound mail relay
- Not a replacement for enterprise mailbox-provider proprietary filtering engines

## Architecture

- `cmd/mailprobe/main.go`: bootstrap and service wiring
- `internal/smtp`: lightweight SMTP receiver
- `internal/analyzer`: parsing + checks + scoring
- `internal/store`, `internal/db`: SQLite persistence layer
- `internal/web`: SSR pages + API endpoints
- `internal/cleanup`: periodic TTL/retention cleanup

Bundled UI vendor assets:

- `internal/web/static/vendor/vvveb/admin.css`
- `internal/web/static/vendor/vvveb/fonts/inter/*`
- `internal/web/static/vendor/vvveb/LICENSE`

The Vvveb Admin Template assets are Apache-2.0 licensed. MailProbe keeps them local to avoid third-party CDN calls.

Data path:

1. Web creates mailbox in SQLite
2. SMTP receives message and validates recipient
3. Message is stored in SQLite
4. Analyzer builds report
5. Report is stored and shown in UI

## Requirements

- Docker + Docker Compose
- Public IP VPS
- Domain/subdomain you control
- SMTP traffic routed to this host (`25 -> SMTP_PORT` or direct bind)

## Quick start

Fully automatic (installs Docker + Docker Compose if missing, no SSL/reverse-proxy setup):

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/brightcolor/mailprobe/main/scripts/quickstart.sh)
```

The installer asks whether optional `rspamd` and `redis` services should be enabled.
Based on your choice it generates `docker-compose.override.yml` (instead of editing comments in-place), and updates `.env` flags.

Optional environment overrides for the script:

```bash
INSTALL_DIR=/opt/mailprobe \
HTTP_PORT=8080 \
SMTP_PORT=2525 \
SMTP_DOMAIN= \
PUBLIC_BASE_URL= \
ENABLE_TLS=false \
FORCE_HTTPS=false \
ENABLE_RSPAMD=false \
ENABLE_REDIS=false \
bash <(curl -fsSL https://raw.githubusercontent.com/brightcolor/mailprobe/main/scripts/quickstart.sh)
```

Manual setup:

```bash
cp .env.example .env
# edit: MAILPROBE_IMAGE, ports, optional TLS/proxy settings

docker compose pull
docker compose up -d
```

Open UI:

- `http://<host>:8080` (or your reverse-proxy URL)

## DNS and SMTP setup

Example records:

- `A mailprobe.example.org -> <server-ip>`
- `MX mx-test.example.org 10 mailprobe.example.org`

Recommended runtime setup:

- Keep web behind reverse proxy/TLS (`443 -> 8080`)
- Route SMTP `25` to container SMTP port (`2525` by default)
- If `SMTP_DOMAIN` is empty, open the UI through the same DNS name you want in generated test addresses.

See examples:

- `deploy/examples/nginx.conf`
- `deploy/examples/Caddyfile`
- `deploy/examples/docker-compose.rspamd.yml`
- `deploy/examples/docker-compose.spamassassin.yml`

## Configuration

Copy `.env.example` and adjust.

Important variables:

- `MAILPROBE_IMAGE` (default: `ghcr.io/brightcolor/mailprobe:latest`; pin a version tag for production)
- `PUBLIC_BASE_URL` (optional override; leave empty to derive scheme + host from the request)
- `SMTP_DOMAIN` (optional override; leave empty to use the request host for generated mailbox domains)
- `ENABLE_TLS`, `TLS_CERT_FILE`, `TLS_KEY_FILE` (optional direct TLS for the built-in web server)
- `FORCE_HTTPS` (redirect HTTP requests to HTTPS when the app receives plain HTTP traffic)
- `HTTP_PORT`, `SMTP_PORT`
- `HEALTHCHECK_URL`
- `MAX_MESSAGE_BYTES`
- `MAILBOX_TTL`
- `DATA_RETENTION_TTL`
- `CLEANUP_INTERVAL`
- `MAX_ACTIVE_MAILBOXES_PER_IP`
- `MAX_ACTIVE_MAILBOXES_GLOBAL`
- `WEB_RATE_LIMIT_PER_MIN`
- `WEB_BURST_PER_10_SEC`
- `TRUSTED_PROXY_CIDRS` (only these proxy CIDRs may supply `X-Forwarded-For`)
- `SMTP_RATE_LIMIT_PER_HOUR`
- `SMTP_BURST_PER_MIN`
- `ENABLE_RBL_CHECKS`, `RBL_PROVIDERS` (default: `zen.spamhaus.org,bl.spamcop.net,b.barracudacentral.org,psbl.surriel.com,dnsbl.dronebl.org,bl.blocklist.de`)
- `ENABLE_SPAMASSASSIN`, `SPAMASSASSIN_HOSTPORT`
- `ENABLE_RSPAMD`, `RSPAMD_URL`, `RSPAMD_PASSWORD`
- `ALERT_WEBHOOK_URL` (optional outbound webhook for operational alerts)

### URL and domain autodetection

By default, MailProbe no longer needs `PUBLIC_BASE_URL` or `SMTP_DOMAIN` in `.env`.
The web server derives its public URL from the incoming request:

- direct access: `Host` and whether the request is TLS
- trusted proxy access: `X-Forwarded-Proto`, `X-Forwarded-Host`, or RFC `Forwarded` headers, but only when the direct proxy IP matches `TRUSTED_PROXY_CIDRS`

Generated addresses use the detected request host, with the port removed.
Example: opening `https://probe.example.org` generates addresses like `<token>@probe.example.org`.

Set `SMTP_DOMAIN` when your SMTP receiving domain differs from the web host, for example:

```env
SMTP_DOMAIN=mx-test.example.org
```

SMTP is still not an open relay: the receiver only accepts addresses that already exist as active temporary mailboxes.

### Built-in TLS

The web server can terminate TLS directly when you do not want a reverse proxy:

```env
ENABLE_TLS=true
TLS_CERT_FILE=/certs/fullchain.pem
TLS_KEY_FILE=/certs/privkey.pem
FORCE_HTTPS=false
HEALTHCHECK_URL=https://127.0.0.1:8080/healthz
```

Mount the certificate directory in `docker-compose.yml`, for example:

```yaml
volumes:
  - mailprobe_data:/data
  - ./certs:/certs:ro
```

Notes:

- Certificate files are only required when `ENABLE_TLS=true`.
- With `ENABLE_TLS=true`, the configured HTTP listener speaks HTTPS directly.
- `FORCE_HTTPS=true` is mainly useful when MailProbe receives plain HTTP behind a trusted reverse proxy or when running HTTP-only and redirecting users to the public HTTPS URL.
- For reverse proxy deployments, keep `ENABLE_TLS=false`, terminate TLS at the proxy, and set `TRUSTED_PROXY_CIDRS` so forwarded scheme/host headers are trusted.

## Security model

Implemented safeguards:

- No open relay behavior
- SMTP recipient validation against active temporary mailboxes
- Request and SMTP rate limits
- Maximum accepted message size
- Max active mailboxes per client IP
- TTL-based data lifecycle

Operational recommendations:

- Restrict host firewall to required ports
- Use reverse proxy with TLS for web access
- Keep `.env` private and backed up securely
- Run regular image updates

## Persistence and backup

Data is persisted in Docker volume `mailprobe_data`:

- SQLite database (`/data/mailprobe.db` + WAL/SHM)

Backup options:

- Volume snapshot
- Periodic DB copy/export during low activity windows

## Health and operations

Health endpoints:

- `GET /healthz`
- `GET /readyz`
- `GET /metrics` (Prometheus text format)

Report API:

- `GET /api/reports/<mailbox-token>/<message-ref>` returns mailbox metadata, message metadata, and the full analysis report as JSON.

Useful commands:

```bash
docker compose ps
docker compose logs -f mailprobe
```

## CI/CD and container publishing

GitHub Actions workflows are included:

- `.github/workflows/ci.yml`
  - runs `go test ./...`
  - builds multi-arch image (`linux/amd64`, `linux/arm64`)
  - publishes to GHCR on `main` and tags (`v*`)
- `.github/workflows/release.yml`
  - optional manual tag creation

Published image target:

- `ghcr.io/brightcolor/mailprobe:<tag>`

Image tag strategy:

- `latest`: newest image from `main`
- `main`: newest image from `main`, same moving channel as `latest`
- `sha-<shortsha>`: immutable image for every pushed commit
- `vX.Y.Z`: immutable release tag, created by `.github/workflows/release.yml`
- `X.Y.Z`, `X.Y`, `X`: SemVer aliases created from `vX.Y.Z` tags

Recommended production pin:

```bash
MAILPROBE_IMAGE=ghcr.io/brightcolor/mailprobe:v0.1.1
docker compose pull
docker compose up -d
```

Rollback to an older image:

```bash
MAILPROBE_IMAGE=ghcr.io/brightcolor/mailprobe:v0.1.0
docker compose pull
docker compose up -d
```

Use a `sha-<shortsha>` tag when you need an exact commit build instead of a named release.

## Resource profile (practical)

For standard usage, this is intended to run on small servers.
Current compose limits are conservative:

- `mem_limit: 512m`
- `cpus: 0.50`

Optional checks (RBL, SpamAssassin, Rspamd) increase resource usage and latency.

## Current limitations

- DKIM verification is heuristic-oriented (not full cryptographic verifier depth)
- SPF/DMARC outcomes rely on available headers + DNS lookups, not full receiver-grade policy pipeline
- Single-node design (no built-in clustering/HA)

## Roadmap

- Stronger DKIM verification path
- More rule configurability via external config
- Auth-protected/private deployment mode
- Report export formats

## License

MIT (see `LICENSE`).
