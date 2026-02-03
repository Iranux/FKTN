#!/usr/bin/env bash
# ============================================================
# Iranux FKTN - Installer (Install-FKTN.sh)
# - Installs Docker + Compose, deploys fptnvpn/fptn-vpn-server
# - Installs Iranux management panel from GitHub (Iranux-Menu.sh)
# - Ubuntu supported (20.04/22.04/24.04)
# ============================================================

set -Eeuo pipefail

# -------------------------
# Constants
# -------------------------
APP_NAME="iranux-fktn"
BASE_DIR="/opt/${APP_NAME}"
DATA_DIR="${BASE_DIR}/fptn-server-data"
COMPOSE_FILE="${BASE_DIR}/docker-compose.yml"
ENV_FILE="${BASE_DIR}/.env"
STATE_DIR="${BASE_DIR}/state"

MANAGER_BIN="/usr/local/sbin/${APP_NAME}"
SYMLINK_CAP="/usr/local/bin/Iranux"
SYMLINK_LOW="/usr/local/bin/iranux"

# Your repo raw URLs
INSTALLER_RAW_URL="https://raw.githubusercontent.com/Iranux/FKTN/main/Install-FKTN.sh"
MENU_RAW_URL="https://raw.githubusercontent.com/Iranux/FKTN/main/Iranux-Menu.sh"

# Docker image
FPTN_IMAGE="fptnvpn/fptn-vpn-server:latest"

# Retry policy
RETRY_MAX=3
RETRY_DELAY=2

# -------------------------
# Logging & error trap
# -------------------------
log()  { echo -e "\e[32m[+]\e[0m $*"; }
warn() { echo -e "\e[33m[!]\e[0m $*" >&2; }
die()  { echo -e "\e[31m[x]\e[0m $*" >&2; exit 1; }

on_err() {
  local ec=$?
  warn "Installer failed."
  warn "Line: ${BASH_LINENO[0]} | Command: ${BASH_COMMAND}"
  warn "Exit code: ${ec}"
  # Show Docker daemon hint if relevant
  if command -v docker >/dev/null 2>&1; then
    if ! docker info >/dev/null 2>&1; then
      warn "Docker daemon not reachable at failure time."
      if [[ -f /var/log/dockerd.log ]]; then
        warn "Last 80 lines of /var/log/dockerd.log:"
        tail -n 80 /var/log/dockerd.log 2>/dev/null || true
      fi
    fi
  fi
  exit "${ec}"
}
trap on_err ERR

cmd_exists() { command -v "$1" >/dev/null 2>&1; }

retry() {
  local n=1
  local cmd=("$@")
  until "${cmd[@]}"; do
    if (( n >= RETRY_MAX )); then
      return 1
    fi
    warn "Retry $n/${RETRY_MAX} failed: ${cmd[*]}"
    sleep "${RETRY_DELAY}"
    ((n++))
  done
}

# -------------------------
# Root escalation
# -------------------------
need_root() {
  if [[ "${EUID}" -ne 0 ]]; then
    if cmd_exists sudo; then
      exec sudo -E bash "$0" "$@"
    else
      die "Root required. Install sudo or run as root."
    fi
  fi
}

# -------------------------
# OS checks
# -------------------------
detect_ubuntu() {
  [[ -f /etc/os-release ]] || die "Cannot detect OS. /etc/os-release missing."
  # shellcheck disable=SC1091
  source /etc/os-release
  [[ "${ID:-}" == "ubuntu" ]] || die "Unsupported OS: ${ID:-unknown}. Ubuntu only."
}

ensure_internet() {
  log "Checking internet connectivity (HTTPS)..."
  retry curl -fsS --max-time 8 https://api.ipify.org >/dev/null 2>&1 || die "No internet/HTTPS connectivity."
}

# -------------------------
# APT (fast + forced freshness)
# -------------------------
apt_prepare_fast() {
  export DEBIAN_FRONTEND=noninteractive
  log "Clearing APT caches (forced, every run)..."
  apt-get clean -y >/dev/null 2>&1 || true
  rm -rf /var/lib/apt/lists/* || true
  rm -rf /var/cache/apt/archives/* || true
  log "Refreshing package lists (apt-get update)..."
  retry apt-get update -y
}

apt_install_min() {
  export DEBIAN_FRONTEND=noninteractive
  retry apt-get install -y --no-install-recommends "$@"
}

# -------------------------
# Self-update installer (forced fresh)
# -------------------------
self_update_from_github() {
  [[ "${1:-}" == "--no-self-update" ]] && return 0

  local tmp="/tmp/${APP_NAME}-Install-FKTN.latest.sh"
  log "Fetching latest installer from GitHub (forced fresh)..."
  if retry curl -fsS -H "Cache-Control: no-cache" -H "Pragma: no-cache" "${INSTALLER_RAW_URL}" -o "${tmp}"; then
    chmod +x "${tmp}"
    log "Re-executing the latest installer from GitHub..."
    exec bash "${tmp}" --no-self-update
  else
    warn "Could not fetch latest installer from GitHub. Continuing with local script."
  fi
}

# -------------------------
# Network helpers
# -------------------------
detect_public_ipv4() {
  local ip=""
  ip="$(curl -fsS4 --max-time 8 https://api.ipify.org || true)"
  [[ "${ip}" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]] || return 1
  echo "${ip}"
}

port_in_use() {
  local p="$1"
  ss -ltnH "sport = :${p}" 2>/dev/null | grep -q .
}

pick_port_safe() {
  local preferred=443
  if ! port_in_use "${preferred}"; then echo "${preferred}"; return 0; fi
  for p in 8443 9443 10443 11443 12443; do
    if ! port_in_use "${p}"; then echo "${p}"; return 0; fi
  done
  local i p
  for i in {1..50}; do
    p=$(( (RANDOM % 20001) + 20000 ))
    if ! port_in_use "${p}"; then echo "${p}"; return 0; fi
  done
  echo "443"
}

# -------------------------
# TUN check
# -------------------------
ensure_tun() {
  if [[ ! -c /dev/net/tun ]]; then
    warn "/dev/net/tun not found. Attempting modprobe tun..."
    modprobe tun >/dev/null 2>&1 || true
  fi
  [[ -c /dev/net/tun ]] || die "TUN device not available (/dev/net/tun). VPS kernel may not support it."
}

# -------------------------
# systemd-less Docker daemon control
# -------------------------
systemd_usable() {
  cmd_exists systemctl || return 1
  systemctl list-units >/dev/null 2>&1 && return 0
  return 1
}

docker_daemon_running() {
  cmd_exists docker || return 1
  docker info >/dev/null 2>&1
}

start_docker_daemon_best_effort() {
  cmd_exists docker || return 1
  docker_daemon_running && return 0

  if systemd_usable; then
    systemctl enable --now docker >/dev/null 2>&1 || true
    sleep 1
    docker_daemon_running && return 0
  fi

  if cmd_exists service; then
    service docker start >/dev/null 2>&1 || true
    sleep 1
    docker_daemon_running && return 0
  fi

  mkdir -p /var/run || true
  nohup /usr/sbin/dockerd >/var/log/dockerd.log 2>&1 & disown || true
  sleep 2
  docker_daemon_running && return 0

  return 1
}

ensure_dockerd_persistence_if_no_systemd() {
  systemd_usable && return 0
  cmd_exists crontab || return 0
  local line='@reboot /usr/sbin/dockerd >/var/log/dockerd.log 2>&1 &'
  if crontab -l 2>/dev/null | grep -Fq "$line"; then
    return 0
  fi
  log "Systemd not usable. Adding cron @reboot to start dockerd..."
  (crontab -l 2>/dev/null; echo "$line") | crontab -
}

# -------------------------
# Docker official repo fallback
# -------------------------
docker_repo_install() {
  log "Configuring Docker official APT repository (for docker-compose-plugin)..."
  apt_install_min ca-certificates curl gnupg lsb-release

  install -m 0755 -d /etc/apt/keyrings
  if [[ ! -f /etc/apt/keyrings/docker.gpg ]]; then
    curl -fsSL https://download.docker.com/linux/ubuntu/gpg | gpg --dearmor -o /etc/apt/keyrings/docker.gpg
    chmod a+r /etc/apt/keyrings/docker.gpg
  fi

  # shellcheck disable=SC1091
  source /etc/os-release
  local codename="${VERSION_CODENAME:-}"
  if [[ -z "${codename}" ]] && cmd_exists lsb_release; then
    codename="$(lsb_release -cs 2>/dev/null || true)"
  fi
  [[ -n "${codename}" ]] || die "Cannot detect Ubuntu codename for Docker repo."

  cat > /etc/apt/sources.list.d/docker.list <<EOF
deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/ubuntu ${codename} stable
EOF

  apt_prepare_fast
  apt_install_min docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
}

ensure_docker() {
  # Install prerequisites early
  apt_install_min curl ca-certificates gnupg lsb-release iproute2

  if cmd_exists docker && docker --version >/dev/null 2>&1 && docker compose version >/dev/null 2>&1; then
    log "Docker and Docker Compose are already installed."
  else
    if ! cmd_exists docker; then
      log "Installing Docker (docker.io) from Ubuntu repos..."
      apt_install_min docker.io || true
    fi

    # Enable universe best-effort
    if ! cmd_exists add-apt-repository; then
      apt_install_min software-properties-common >/dev/null 2>&1 || true
    fi
    cmd_exists add-apt-repository && add-apt-repository -y universe >/dev/null 2>&1 || true

    apt_prepare_fast

    # Compose plugin attempt (Ubuntu repos)
    if ! (cmd_exists docker && docker compose version >/dev/null 2>&1); then
      log "Attempting to install docker-compose-plugin from Ubuntu repos..."
      if ! apt_install_min docker-compose-plugin; then
        warn "docker-compose-plugin not available in Ubuntu repos. Switching to Docker official repo method."
        docker_repo_install
      fi
    fi

    docker --version >/dev/null 2>&1 || die "Docker client installation failed."
    docker compose version >/dev/null 2>&1 || die "Docker Compose installation failed."
  fi

  log "Starting Docker daemon..."
  if ! start_docker_daemon_best_effort; then
    warn "Docker daemon did not start. Last 120 lines of /var/log/dockerd.log:"
    tail -n 120 /var/log/dockerd.log 2>/dev/null || true
    die "Docker daemon failed to start in this environment."
  fi
  ensure_dockerd_persistence_if_no_systemd
}

# -------------------------
# Targeted nuclear clean (safe)
# -------------------------
nuclear_clean_project() {
  log "Nuclear clean (targeted) for ${APP_NAME}..."

  # Try to stop stack only if docker daemon reachable and files exist
  if cmd_exists docker; then
    if ! docker_daemon_running; then
      warn "Docker daemon not running during clean. Best-effort start..."
      start_docker_daemon_best_effort || true
    fi

    if docker_daemon_running && [[ -f "${COMPOSE_FILE}" ]]; then
      (cd "${BASE_DIR}" && docker compose --env-file "${ENV_FILE}" down --remove-orphans --volumes >/dev/null 2>&1) || true
    fi
  fi

  # Remove installed commands
  rm -f "${SYMLINK_CAP}" "${SYMLINK_LOW}" >/dev/null 2>&1 || true
  rm -f "${MANAGER_BIN}" >/dev/null 2>&1 || true

  # Remove project directory
  rm -rf "${BASE_DIR}" >/dev/null 2>&1 || true
  rm -rf /tmp/${APP_NAME}-* >/dev/null 2>&1 || true

  log "Clean complete."
}

# -------------------------
# Compose deploy
# -------------------------
ensure_dirs() {
  mkdir -p "${BASE_DIR}" "${DATA_DIR}" "${STATE_DIR}"
  chmod 700 "${BASE_DIR}" || true
}

write_compose_file() {
  cat > "${COMPOSE_FILE}" <<YAML
services:
  fptn-server:
    restart: unless-stopped
    image: ${FPTN_IMAGE}
    cap_add:
      - NET_ADMIN
      - SYS_MODULE
      - NET_RAW
      - SYS_ADMIN
    sysctls:
      - net.ipv4.ip_forward=1
      - net.ipv6.conf.all.forwarding=1
      - net.ipv4.conf.all.rp_filter=0
      - net.ipv4.conf.default.rp_filter=0
    ulimits:
      nproc:
        soft: 524288
        hard: 524288
      nofile:
        soft: 524288
        hard: 524288
      memlock:
        soft: 524288
        hard: 524288
    devices:
      - /dev/net/tun:/dev/net/tun
    ports:
      - "\${FPTN_PORT}:443/tcp"
    volumes:
      - ./fptn-server-data:/etc/fptn
YAML
  [[ -s "${COMPOSE_FILE}" ]] || die "Failed to write ${COMPOSE_FILE}"
}

write_env_file() {
  local port="$1" pubip="$2"
  local prom_key
  prom_key="$(tr -dc 'A-Za-z0-9' </dev/urandom | head -c 32)"

  cat > "${ENV_FILE}" <<EOF
FPTN_PORT=${port}
SERVER_EXTERNAL_IPS=${pubip}

# Safe defaults (can be tuned later in menu)
ENABLE_DETECT_PROBING=true
DEFAULT_PROXY_DOMAIN=cdnvideo.com
DISABLE_BITTORRENT=true
PROMETHEUS_SECRET_ACCESS_KEY=${prom_key}
MAX_ACTIVE_SESSIONS_PER_USER=3
EOF

  [[ -s "${ENV_FILE}" ]] || die "Failed to write ${ENV_FILE}"
}

compose_up() {
  log "Starting container..."
  (cd "${BASE_DIR}" && docker compose --env-file "${ENV_FILE}" up -d)
}

# -------------------------
# Install management panel from GitHub (forced fresh)
# -------------------------
install_manager_panel_from_github() {
  local tmp="/tmp/${APP_NAME}-menu.latest.sh"
  log "Fetching latest Iranux management panel (forced fresh)..."

  if retry curl -fsS -H "Cache-Control: no-cache" -H "Pragma: no-cache" "${MENU_RAW_URL}" -o "${tmp}"; then
    chmod +x "${tmp}"
    install -m 0755 "${tmp}" "${MANAGER_BIN}"
    ln -sf "${MANAGER_BIN}" "${SYMLINK_CAP}"
    ln -sf "${MANAGER_BIN}" "${SYMLINK_LOW}"
  else
    die "Could not fetch Iranux management panel from GitHub (${MENU_RAW_URL})."
  fi
}

# -------------------------
# Main install
# -------------------------
install_main() {
  detect_ubuntu
  ensure_internet

  apt_prepare_fast
  apt_install_min curl ca-certificates gnupg lsb-release iproute2 openssl git ss

  ensure_tun
  ensure_dirs
  ensure_docker

  log "Detecting public IPv4..."
  local pub_ip
  pub_ip="$(detect_public_ipv4)" || die "Could not auto-detect public IPv4."
  log "Public IP detected: ${pub_ip}"

  log "Selecting external port for client connections..."
  local port
  port="$(pick_port_safe)"
  log "Selected external port for client connections: ${port}"

  log "Writing docker-compose.yml and .env..."
  write_compose_file
  write_env_file "${port}" "${pub_ip}"

  compose_up

  # Install menu AFTER container is up (menu can read status immediately)
  install_manager_panel_from_github

  log "Installation completed successfully."
  log "Run management panel: Iranux (or iranux)"
  exec "${SYMLINK_CAP}"
}

main() {
  need_root "$@"
  self_update_from_github "${1:-}"
  nuclear_clean_project
  install_main
}

main "$@"
