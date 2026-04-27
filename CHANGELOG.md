# Changelog

All notable changes to this project will be documented in this file.

## [Unreleased]

### Added
- Added optional built-in HTTPS serving via `ENABLE_TLS`, `TLS_CERT_FILE`, and `TLS_KEY_FILE`.
- Added configurable HTTP-to-HTTPS redirects via `FORCE_HTTPS`.
- Added request-derived public URL and mailbox domain detection so `PUBLIC_BASE_URL` and `SMTP_DOMAIN` can stay empty by default.
- Added local Vvveb Admin Template vendor assets (`admin.css`, Inter fonts, Apache-2.0 license) for the web UI.
- Added explicit light/dark/auto theme switching with persisted browser preference.
- Added structured German check detail output with `technical_details`, `explanation`, `recommendation`, `severity`, and `category` fields.
- Added explicit MX, A/AAAA, SPF alignment, DKIM alignment, DMARC alignment, Reply-To, and TLS transport checks to the analyzer.
- Added a colorful report dashboard with score hero, grouped check cards, status icons, collapsible technical details, raw-data accordions, and copy buttons.
- Added tokenized JSON report export at `GET /api/reports/<mailbox-token>/<message-ref>` for automation and integrations.
- Added JSON report links to mailbox and report pages.
- Added a score-first web UI with a guided send-and-check flow, live mailbox status, prioritized report checks, and clearer export actions.
- Added in-place test address generation without a full page reload.
- Added sandboxed rendered HTML mail preview alongside raw HTML source.
- Added SemVer Docker image tags, immutable commit SHA image tags, and a validated release-tag workflow for safer rollbacks.
- Documented `TRUSTED_PROXY_CIDRS` in the environment template and README.

### Changed
- Made `SMTP_DOMAIN` an optional override instead of a required setting; SMTP acceptance still requires an active temporary mailbox.
- Updated quickstart defaults to leave `PUBLIC_BASE_URL` and `SMTP_DOMAIN` empty unless explicitly provided.
- Removed visible Metrics/Health navigation from the web UI while keeping the endpoints available.
- Removed EventSource/SSE usage in the web UI and switched mailbox/check updates to polling to avoid broken event-stream states behind proxies.
- Removed the left sidebar from the Vvveb-based shell in favor of a top navigation layout.
- Show check remediation as "Wie wird's gemacht?" only for warning and failing checks.
- Group report links by domain and show total link counts.
- Rebuilt the home, mailbox, and report screens around a Vvveb-style topbar dashboard shell.
- Enriched existing analysis checks with concrete remediation guidance, DNS/MTA examples, and raw values where available.
- Grouped report checks by authentication, DNS/infrastructure, spam filters, content/format, and header/raw-data categories.
- Redesigned the home, mailbox, and report pages into a more focused email testing workflow with prominent test address, status panels, score summary, diagnostics, and raw data sections.
- Adjusted the web UI closer to a mail-tester-style flow: central test address, clear check button, compact metadata, and accordion-style report checks.

### Fixed
- Extract links from decoded HTML source as well as visible text so `href` URLs are included in reports.
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
