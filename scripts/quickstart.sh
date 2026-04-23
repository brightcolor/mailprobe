#!/usr/bin/env bash
set -euo pipefail

REPO_URL="${REPO_URL:-https://github.com/brightcolor/mailprobe.git}"
BRANCH="${BRANCH:-main}"
INSTALL_DIR="${INSTALL_DIR:-/opt/mailprobe}"
HTTP_PORT="${HTTP_PORT:-8080}"
SMTP_PORT="${SMTP_PORT:-2525}"
MAILPROBE_IMAGE="${MAILPROBE_IMAGE:-ghcr.io/brightcolor/mailprobe:latest}"
SMTP_DOMAIN="${SMTP_DOMAIN:-$(hostname -f 2>/dev/null || hostname)}"
PUBLIC_BASE_URL="${PUBLIC_BASE_URL:-}"

have_cmd() {
  command -v "$1" >/dev/null 2>&1
}

log() {
  printf '[quickstart] %s\n' "$*"
}

if [[ "$(uname -s)" != "Linux" ]]; then
  echo "This quickstart script supports Linux only." >&2
  exit 1
fi

if [[ "$(id -u)" -eq 0 ]]; then
  SUDO=""
else
  if ! have_cmd sudo; then
    echo "sudo is required when running as non-root." >&2
    exit 1
  fi
  SUDO="sudo"
fi

install_base_packages() {
  if have_cmd apt-get; then
    log "Installing base packages (curl, ca-certificates, git)"
    $SUDO apt-get update -y
    $SUDO apt-get install -y curl ca-certificates git
  else
    echo "Unsupported distro: apt-get not found. Install Docker + Docker Compose manually." >&2
    exit 1
  fi
}

install_docker_if_needed() {
  if have_cmd docker; then
    log "Docker already installed"
    return
  fi

  log "Installing Docker"
  curl -fsSL https://get.docker.com | $SUDO sh
}

install_compose_if_needed() {
  if docker compose version >/dev/null 2>&1; then
    log "Docker Compose plugin already available"
    return
  fi

  log "Installing Docker Compose plugin"
  if have_cmd apt-get; then
    $SUDO apt-get update -y
    $SUDO apt-get install -y docker-compose-plugin
  fi

  if ! docker compose version >/dev/null 2>&1; then
    echo "Docker Compose plugin installation failed." >&2
    exit 1
  fi
}

prepare_docker_service() {
  if have_cmd systemctl; then
    $SUDO systemctl enable --now docker || true
  fi
}

ensure_repo() {
  local parent
  parent="$(dirname "$INSTALL_DIR")"
  $SUDO mkdir -p "$parent"

  if [[ ! -d "$INSTALL_DIR/.git" ]]; then
    log "Cloning repository into $INSTALL_DIR"
    $SUDO git clone --branch "$BRANCH" "$REPO_URL" "$INSTALL_DIR"
  else
    log "Updating existing repository in $INSTALL_DIR"
    $SUDO git -C "$INSTALL_DIR" fetch origin
    $SUDO git -C "$INSTALL_DIR" checkout "$BRANCH"
    $SUDO git -C "$INSTALL_DIR" pull --ff-only origin "$BRANCH"
  fi

  if [[ -n "${SUDO_USER:-}" ]]; then
    $SUDO chown -R "$SUDO_USER":"$SUDO_USER" "$INSTALL_DIR"
  fi
}

infer_public_base_url() {
  if [[ -n "$PUBLIC_BASE_URL" ]]; then
    return
  fi

  local ip
  ip="$(hostname -I 2>/dev/null | awk '{print $1}')"
  if [[ -z "$ip" ]]; then
    ip="127.0.0.1"
  fi
  PUBLIC_BASE_URL="http://${ip}:${HTTP_PORT}"
}

set_env_key() {
  local key="$1"
  local value="$2"

  if grep -qE "^${key}=" .env; then
    sed -i "s|^${key}=.*|${key}=${value}|" .env
  else
    printf '%s=%s\n' "$key" "$value" >> .env
  fi
}

setup_env_file() {
  cd "$INSTALL_DIR"

  if [[ ! -f .env ]]; then
    cp .env.example .env
  fi

  infer_public_base_url

  set_env_key "HTTP_PORT" "$HTTP_PORT"
  set_env_key "SMTP_PORT" "$SMTP_PORT"
  set_env_key "SMTP_DOMAIN" "$SMTP_DOMAIN"
  set_env_key "PUBLIC_BASE_URL" "$PUBLIC_BASE_URL"
  set_env_key "MAILPROBE_IMAGE" "$MAILPROBE_IMAGE"
}

docker_cmd() {
  if docker info >/dev/null 2>&1; then
    docker "$@"
  else
    $SUDO docker "$@"
  fi
}

start_stack() {
  cd "$INSTALL_DIR"
  log "Pulling container image"
  docker_cmd compose pull

  log "Starting MailProbe stack"
  docker_cmd compose up -d
}

main() {
  install_base_packages
  install_docker_if_needed
  prepare_docker_service
  install_compose_if_needed
  ensure_repo
  setup_env_file
  start_stack

  cat <<EOF

MailProbe setup complete.

Install path: $INSTALL_DIR
Web URL:      $PUBLIC_BASE_URL
SMTP target:  <token>@$SMTP_DOMAIN (mapped to host port $SMTP_PORT)

Next steps:
1. Point DNS A/MX records to this server.
2. Ensure inbound SMTP traffic reaches host port $SMTP_PORT (or map host :25 to container :2525).
3. Open the Web URL and generate a test mailbox.
EOF
}

main "$@"