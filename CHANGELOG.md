# Changelog

All notable changes to this project will be documented in this file.

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
