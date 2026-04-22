# MailProbe

MailProbe ist ein selbst hostbarer Open-Source-Service zur Analyse von E-Mail-Zustellbarkeit mit ähnlichem Kern-Workflow wie bekannte Mail-Testing-Dienste: temporäre Adresse erzeugen, Mail empfangen, Report lesen.

## 1) Architekturentscheidung (1 GB RAM)

**Gewählt: Go-Monolith + SQLite + integrierter SMTP-Receiver + SSR-Templates.**

Kurzbegründung:
- Go liefert niedrigen Idle-RAM und ein einzelnes Deploy-Artefakt.
- SQLite spart einen separaten DB-Container und reduziert Betriebsaufwand.
- Ein Prozess für HTTP + SMTP + Analyse vermeidet Microservice-Overhead.
- SSR-Frontend (kein SPA-Framework) spart RAM/CPU und bleibt schnell.

Damit ist der Standardbetrieb auf kleinen 1-GB-VMs realistisch.

## Features

- Temporäre zufällige Testadressen pro Session/Token
- SMTP-Empfang für Testadressen
- Speicherung von Rohmail + Headern + Reports
- Transparenter Score (0-10) mit Einzelprüfungen
- Checks u. a. für:
  - SPF / DKIM / DMARC (Header- und DNS-basiert)
  - PTR/rDNS
  - HELO/EHLO-Plausibilität
  - Envelope-From vs Header-From
  - Return-Path, Received-Kette, ARC-Hinweis
  - MIME-Struktur, Plaintext-/HTML-Heuristik, Anhänge
  - Link-Extraktion, Tracking-Hinweise, Shortener-Checks
  - HTML-Basisanalyse, Spam-/Format-Heuristiken, Unicode-Obfuscation
  - Newsletter-Checks (List-Unsubscribe, Preheader-Heuristik)
  - optional DNSBL/RBL (deaktiviert per Default)
- Auto-Cleanup (TTL/Retention)
- Basis-Missbrauchsschutz:
  - Rate Limiting (Web + SMTP)
  - Mail-Size-Limit
  - Limit aktiver Mailboxen pro IP
- Docker Compose, Healthchecks, persistente Volumes

## Architekturübersicht

- `cmd/mailprobe/main.go`: App-Bootstrap, HTTP + SMTP + Cleanup
- `internal/smtp`: schlanker SMTP-Server (nur Inbound-Testzweck)
- `internal/analyzer`: Analyse-Engine + Scoring
- `internal/store`, `internal/db`: SQLite-Schema und Persistenz
- `internal/web`: SSR-UI, API-Endpunkte, statische Assets
- `internal/cleanup`: periodische Datenbereinigung

Datenfluss:
1. Nutzer erzeugt Mailbox via Web UI
2. SMTP nimmt Mail für `<token>@SMTP_DOMAIN` entgegen
3. Rohmail wird gespeichert
4. Analyse wird ausgeführt
5. Report wird gespeichert und im UI angezeigt

## Voraussetzungen

- Docker + Docker Compose
- VPS mit öffentlicher IP
- Domain/Subdomain für SMTP-Empfang
- Port 25 erreichbar oder Weiterleitung auf Host-Port `SMTP_PORT`

## Schnellstart

```bash
cp .env.example .env
# .env anpassen: PUBLIC_BASE_URL, SMTP_DOMAIN, MAILPROBE_IMAGE, Ports

docker compose up -d
```

Web-UI: `http://<host>:8080` (oder dein Reverse Proxy)

## Docker-Compose Start

```bash
docker compose pull
docker compose up -d
docker compose ps
docker compose logs -f mailprobe
```

Stoppen:

```bash
docker compose down
```

## DNS-/SMTP-Hinweise

Für realistischen Testbetrieb:
- A/AAAA: `mailprobe.example.org -> VPS`
- MX für Testdomain/Subdomain:
  - `mx-test.example.org MX 10 mailprobe.example.org`
- Optional SPF/DMARC auf Sender-Domain für eigene Testmails

Hinweis: Dieses Projekt ist **kein** vollwertiger Produktions-MTA, sondern eine interne Test-Mailbox-Engine.

## Reverse Proxy Beispiel

Siehe:
- `deploy/examples/nginx.conf`
- `deploy/examples/Caddyfile`

Typisches Setup:
- Proxy terminiert TLS für Web (`:443 -> :8080`)
- SMTP bleibt direkt auf Host-Port (z. B. `25 -> 2525`)

## Konfiguration

Alle relevanten Variablen in `.env.example`.

Wichtige Parameter:
- `MAILPROBE_IMAGE`: Registry-Image aus der CI (z. B. `ghcr.io/<owner>/<repo>:latest`)
- `SMTP_DOMAIN`: Domain, für die Testadressen erzeugt werden
- `MAX_MESSAGE_BYTES`: Maximalgröße je Mail
- `MAILBOX_TTL`: Lebensdauer einzelner Testadressen
- `DATA_RETENTION_TTL`: Aufbewahrung empfangener Daten
- `WEB_RATE_LIMIT_PER_MIN`, `SMTP_RATE_LIMIT_PER_HOUR`
- `ENABLE_RBL_CHECKS` + `RBL_PROVIDERS`
- `ENABLE_SPAMASSASSIN` + `SPAMASSASSIN_HOSTPORT`

## Sicherheit

- Kein Open Relay: keine externe Weiterleitung/Zustellung implementiert
- Verarbeitung nur für bekannte temporäre Adressen
- Rate-Limits für Web und SMTP
- Mailgrößenlimit
- Begrenzte aktive Mailboxen pro IP
- Minimal offene Ports (Web + SMTP)
- Secrets/Config via `.env`

## Persistenz & Backup

Persistente Daten liegen im Docker-Volume `mailprobe_data` (`/data` im Container):
- SQLite DB (`mailprobe.db`, WAL/SHM)

Backup (Beispiel):
- Volume snapshotten oder DB regelmäßig sichern
- Für konsistente Snapshots kurz stoppen oder SQLite-Backup-Mechanismus nutzen

## Healthchecks

- `GET /healthz`
- `GET /readyz`

Docker Healthcheck nutzt `/healthz`.

## GitHub CI / Container Registry

Das Repo enthält CI-Workflows unter `.github/workflows`:
- `ci.yml`
  - testet das Go-Projekt (`go test ./...`)
  - baut Multi-Arch-Container (`linux/amd64`, `linux/arm64`)
  - published bei Push auf `main` oder bei Tag `v*` nach GHCR:
    - `ghcr.io/<owner>/<repo>:latest` (auf Default-Branch)
    - `ghcr.io/<owner>/<repo>:vX.Y.Z` (bei Tag)
    - `ghcr.io/<owner>/<repo>:sha-<commit>`
- `release.yml`
  - optionaler manueller Tag-Workflow (`workflow_dispatch`)

Für GHCR muss im GitHub-Repository Packages-Publishing erlaubt sein (nutzt `GITHUB_TOKEN` mit `packages:write`).

## Ressourcenprofil (1 GB RAM)

Erwartung im Standardbetrieb:
- 1 Container
- Idle-RAM typischerweise deutlich unter 200 MB (abhängig von Last und DNS-Lookups)
- `docker-compose` setzt `mem_limit: 512m` als konservativen Guardrail

Optionalfeatures mit Mehrbedarf:
- DNSBL/RBL-Checks erhöhen DNS-Traffic/Latenz
- SpamAssassin ist optional integrierbar (siehe `deploy/examples/docker-compose.spamassassin.yml`), aber nicht Default, da auf 1 GB oft zu schwer

## Bekannte Abweichungen / Limitierungen

- DKIM wird standardmäßig heuristisch über Header/Auth-Results bewertet, keine vollständige kryptografische Tiefenverifikation.
- SPF/DMARC-Ergebnisse basieren auf DNS + vorhandenen Headern, nicht auf vollständiger MTA-Policy-Engine.
- Kein Cluster/HA-Setup, bewusst einfach und ressourcenschonend.
- Kein Captcha integriert (leichtgewichtiges Baseline-Setup).

## Roadmap

- Optionale echte DKIM-Signaturverifikation
- Optionaler SpamAssassin-Sidecar als umschaltbares Compose-Profil
- Erweiterte Rule-Sets und konfigurierbare Gewichtungen pro Check
- Optionales API-Token für geschützten Betrieb
- Exportfunktionen (JSON/PDF)

## Projektstruktur

```text
.
├─ cmd/mailprobe
├─ internal/
│  ├─ analyzer
│  ├─ cleanup
│  ├─ config
│  ├─ db
│  ├─ model
│  ├─ ratelimit
│  ├─ smtp
│  ├─ store
│  └─ web
├─ deploy/examples
├─ docker-compose.yml
├─ Dockerfile
├─ .env.example
├─ CHANGELOG.md
├─ LICENSE
└─ Makefile
```

## Entwicklung lokal (ohne Docker)

Go-Toolchain vorausgesetzt:

```bash
go mod tidy
go run ./cmd/mailprobe
```

## Lizenz

MIT (siehe `LICENSE`).
