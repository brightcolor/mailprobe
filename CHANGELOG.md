# Changelog

All notable changes to this project will be documented in this file.

## [Unreleased]

### Added
- Added tokenized JSON report export at `GET /api/reports/<mailbox-token>/<message-ref>` for automation and integrations.
- Added JSON report links to mailbox and report pages.
- Added a score-first web UI with a guided send-and-check flow, live mailbox status, prioritized report checks, and clearer export actions.
- Added in-place test address generation without a full page reload.
- Added sandboxed rendered HTML mail preview alongside raw HTML source.
- Documented `TRUSTED_PROXY_CIDRS` in the environment template and README.

### Changed
- Redesigned the home, mailbox, and report pages into a more focused email testing workflow with prominent test address, status panels, score summary, diagnostics, and raw data sections.

### Fixed
- Only trust `X-Forwarded-For` when the direct client IP matches `TRUSTED_PROXY_CIDRS`, preventing spoofed client IPs from bypassing web rate limits.
- Decode folded and RFC 2047 encoded `Subject` headers before storing message metadata.
- Decode transfer encoding and declared charsets for displayed text and HTML mail bodies.

## [0.1.0] - 2026-04-22

### Added
- Initial self-hosted MailProbe implementation.
- Single-binary Go backend with integrated SMTP receiver and web UI.
- SQLite persistence for mailboxes, messages, and reports.
- Deliverability and spam heuristics (SPF, DKIM, DMARC, PTR, HELO, MIME, links, headers, newsletter checks, Unicode checks, optional RBL).
- Dockerfile + docker-compose stack with healthchecks and persistent volume.
- Cleanup worker for TTL-based deletion of old mailboxes/messages.
- Reverse proxy examples for NGINX and Caddy.
- Documentation, environment template, and MIT license.
- GitHub Actions CI for tests and multi-arch container publishing to GHCR.
- Optional Rspamd integration via controller API (`/checkv2`) with report scoring.
- Added `scripts/quickstart.sh` to install Docker/Compose (if missing) and deploy MailProbe in one command.
- Quickstart now prompts for optional `rspamd` and `redis`, writes `.env` flags, and generates `docker-compose.override.yml` accordingly.
- Rspamd analysis now surfaces top positive symbols and concrete remediation guidance in report checks.
