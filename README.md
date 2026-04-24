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

- Random temporary mailbox addresses (`<token>@SMTP_DOMAIN`)
- Score-first web UI with a guided send-and-check workflow
- New test addresses can be generated in-place without a full page reload
- Multiple active mailboxes in parallel
- Multiple emails per mailbox
- Mailbox TTL and automatic expiration
- Raw source and raw headers view
- JSON report endpoint for automation/integrations

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
- Optional SpamAssassin integration (disabled by default)
- Optional Rspamd integration (disabled by default)
- Rspamd findings include top rejecting symbols and actionable recommendations in report output

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
SMTP_DOMAIN=mx-test.example.org \
PUBLIC_BASE_URL=http://your-server-ip:8080 \
ENABLE_RSPAMD=false \
ENABLE_REDIS=false \
bash <(curl -fsSL https://raw.githubusercontent.com/brightcolor/mailprobe/main/scripts/quickstart.sh)
```

Manual setup:

```bash
cp .env.example .env
# edit: PUBLIC_BASE_URL, SMTP_DOMAIN, MAILPROBE_IMAGE, ports

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

See examples:

- `deploy/examples/nginx.conf`
- `deploy/examples/Caddyfile`
- `deploy/examples/docker-compose.rspamd.yml`
- `deploy/examples/docker-compose.spamassassin.yml`

## Configuration

Copy `.env.example` and adjust.

Important variables:

- `MAILPROBE_IMAGE` (default: `ghcr.io/brightcolor/mailprobe:latest`; pin a version tag for production)
- `PUBLIC_BASE_URL`
- `SMTP_DOMAIN`
- `HTTP_PORT`, `SMTP_PORT`
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
- `ENABLE_RBL_CHECKS`, `RBL_PROVIDERS`
- `ENABLE_SPAMASSASSIN`, `SPAMASSASSIN_HOSTPORT`
- `ENABLE_RSPAMD`, `RSPAMD_URL`, `RSPAMD_PASSWORD`
- `ALERT_WEBHOOK_URL` (optional outbound webhook for operational alerts)

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
