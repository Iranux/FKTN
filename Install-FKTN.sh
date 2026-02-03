#!/usr/bin/env bash
# ============================================================
# Iranux FKTN - One-shot Installer + Management Panel (Iranux)
# File name (canonical): Install-FKTN.sh
# Target OS: Ubuntu (20.04/22.04/24.04 recommended)
# Deploys: fptnvpn/fptn-vpn-server via Docker Compose
#
# Hard requirements implemented:
# - Must run as root (auto re-exec via sudo)
# - Targeted nuclear clean of THIS project on every run (safe even if Docker missing)
# - APT caches cleared on every run (fresh metadata)
# - Minimal OS update (NO apt upgrade) for speed/safety
# - Always fetch latest installer from GitHub (forced fresh) and re-exec once
# - Self-healing: tries to fix common issues before surfacing errors
# - Post-install: open Iranux menu with banner (IP/Port/Users/Domain/TLS)
# - After install: menu can add Domain + get SSL cert (Let's Encrypt preferred)
#   + fallback to self-signed + auto-renew + renew now
#
# Recommended run:
#   curl -fsSL https://raw.githubusercontent.com/Iranux/FKTN/main/Install-FKTN.sh | sudo bash
# ============================================================

set -euo pipefail

# -------------------------
# Project constants
# -------------------------
APP_NAME="iranux-fktn"
BASE_DIR="/opt/${APP_NAME}"
DATA_DIR="${BASE_DIR}/fptn-server-data"   # persisted /etc/fptn
COMPOSE_FILE="${BASE_DIR}/docker-compose.yml"
ENV_FILE="${BASE_DIR}/.env"
STATE_DIR="${BASE_DIR}/state"
DOMAIN_STATE="${STATE_DIR}/domain.conf"
CERT_STATE="${STATE_DIR}/cert.conf"

MANAGER="/usr/local/sbin/${APP_NAME}"
SYMLINK="/usr/local/bin/Iranux"

RENEW_SCRIPT="/usr/local/sbin/${APP_NAME}-renew"
RENEW_SERVICE="/etc/systemd/system/${APP_NAME}-renew.service"
RENEW_TIMER="/etc/systemd/system/${APP_NAME}-renew.timer"

# GitHub self-update (canonical filename: Install-FKTN.sh)
GITHUB_RAW_URL="https://raw.githubusercontent.com/Iranux/FKTN/main/Install-FKTN.sh"

# Docker image
FPTN_IMAGE="fptnvpn/fptn-vpn-server:latest"

# Retry policy
RETRY_MAX=3
RETRY_DELAY=2

# -------------------------
# Helpers
# -------------------------
log()  { echo -e "\e[32m[+]\e[0m $*"; }
warn() { echo -e "\e[33m[!]\e[0m $*" >&2; }
die()  { echo -e "\e[31m[x]\e[0m $*" >&2; exit 1; }

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

need_root() {
  if [[ "${EUID}" -ne 0 ]]; then
    if cmd_exists sudo; then
      exec sudo -E bash "$0" "$@"
    else
      die "Root required. Install sudo or run as root."
    fi
  fi
}

detect_ubuntu() {
  [[ -f /etc/os-release ]] || die "Cannot detect OS. /etc/os-release missing."
  # shellcheck disable=SC1091
  source /etc/os-release
  if [[ "${ID:-}" != "ubuntu" ]]; then
    die "Unsupported OS: ${ID:-unknown}. This installer supports Ubuntu."
  fi
}

ensure_internet() {
  log "Checking internet connectivity (HTTPS)..."
  if ! retry curl -fsS --max-time 8 https://api.ipify.org >/dev/null 2>&1; then
    die "No internet/HTTPS connectivity. Fix network/DNS and re-run."
  fi
}

# APT: fast and clean (NO upgrade)
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

detect_public_ipv4() {
  local ip=""
  ip="$(curl -fsS4 --max-time 8 https://api.ipify.org || true)"
  if [[ "${ip}" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]; then
    echo "${ip}"
    return 0
  fi
  return 1
}

port_in_use() {
  local p="$1"
  ss -ltn "( sport = :${p} )" | grep -q ":${p}" 2>/dev/null
}

pick_port() {
  local preferred=443
  if ! port_in_use "${preferred}"; then
    echo "${preferred}"
    return 0
  fi
  for p in 8443 9443 10443 11443 12443; do
    if ! port_in_use "${p}"; then
      echo "${p}"
      return 0
    fi
  done
  while true; do
    p=$(( (RANDOM % 20001) + 20000 ))
    if ! port_in_use "${p}"; then
      echo "${p}"
      return 0
    fi
  done
}

random_alnum() {
  local n="${1:-32}"
  tr -dc 'A-Za-z0-9' </dev/urandom | head -c "${n}"
}

ensure_tun() {
  if [[ ! -c /dev/net/tun ]]; then
    warn "/dev/net/tun not found. Attempting to load tun module..."
    modprobe tun >/dev/null 2>&1 || true
  fi
  [[ -c /dev/net/tun ]] || die "TUN device is not available (/dev/net/tun). Your VPS/kernel may not support it."
}

ensure_dirs() {
  mkdir -p "${BASE_DIR}" "${DATA_DIR}" "${STATE_DIR}"
  chmod 700 "${BASE_DIR}" || true
}

# -------------------------
# Self-update from GitHub (always latest)
# -------------------------
self_update_from_github() {
  # Avoid recursion
  if [[ "${1:-}" == "--no-self-update" ]]; then
    return 0
  fi

  local tmp="/tmp/${APP_NAME}-Install-FKTN.latest.sh"

  log "Fetching latest installer from GitHub (forced fresh)..."
  if retry curl -fsS -H "Cache-Control: no-cache" -H "Pragma: no-cache" "${GITHUB_RAW_URL}" -o "${tmp}"; then
    chmod +x "${tmp}"
    log "Re-executing the latest installer from GitHub..."
    exec bash "${tmp}" --no-self-update
  else
    warn "Could not fetch latest installer from GitHub. Continuing with local script."
  fi
}

# -------------------------
# Docker install (minimal + robust)
# -------------------------
ensure_docker() {
  if cmd_exists docker && docker --version >/dev/null 2>&1; then
    log "Docker is installed."
  else
    log "Installing Docker (docker.io)..."
    apt_install_min docker.io
    systemctl enable --now docker >/dev/null 2>&1 || true
  fi

  if docker compose version >/dev/null 2>&1; then
    log "Docker Compose plugin is available."
  else
    log "Installing Docker Compose plugin..."
    apt_install_min docker-compose-plugin
    docker compose version >/dev/null 2>&1 || die "Docker Compose plugin install failed."
  fi
}

compose() {
  (cd "${BASE_DIR}" && docker compose "$@")
}

# -------------------------
# Targeted nuclear clean (THIS project only) - SAFE if Docker missing
# -------------------------
nuclear_clean_project() {
  log "Nuclear clean (targeted) for ${APP_NAME}..."

  # Docker cleanup should never crash if docker not installed
  if ! cmd_exists docker; then
    warn "Docker not installed yet. Skipping Docker cleanup."
  else
    # Stop compose stack if exists
    if [[ -f "${COMPOSE_FILE}" ]]; then
      (cd "${BASE_DIR}" && docker compose down --remove-orphans --volumes >/dev/null 2>&1) || true
    fi

    # Remove containers created from this image (extra safety)
    docker ps -a --format '{{.ID}} {{.Image}}' | awk -v img="${FPTN_IMAGE}" '$2==img {print $1}' | while read -r cid; do
      [[ -n "${cid}" ]] && docker rm -f "${cid}" >/dev/null 2>&1 || true
    done
  fi

  # Disable renewal timer if present (safe even if not installed)
  systemctl disable --now "${APP_NAME}-renew.timer" >/dev/null 2>&1 || true
  rm -f "${RENEW_SERVICE}" "${RENEW_TIMER}" "${RENEW_SCRIPT}" >/dev/null 2>&1 || true
  systemctl daemon-reload >/dev/null 2>&1 || true

  # Remove Iranux command and manager
  rm -f "${SYMLINK}" >/dev/null 2>&1 || true
  rm -f "${MANAGER}" >/dev/null 2>&1 || true

  # Remove project directory (fresh install policy)
  rm -rf "${BASE_DIR}" >/dev/null 2>&1 || true

  # Remove temp installer downloads
  rm -rf /tmp/${APP_NAME}-* >/dev/null 2>&1 || true

  log "Clean complete."
}

# -------------------------
# Compose + env creation
# -------------------------
write_compose_file() {
  # NOTE: We intentionally DO NOT map 80:80 to avoid conflicts.
  # Let's Encrypt will use certbot standalone on host :80 when needed.
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
    environment:
      - ENABLE_DETECT_PROBING=\${ENABLE_DETECT_PROBING}
      - DEFAULT_PROXY_DOMAIN=\${DEFAULT_PROXY_DOMAIN}
      - ALLOWED_SNI_LIST=\${ALLOWED_SNI_LIST}
      - DISABLE_BITTORRENT=\${DISABLE_BITTORRENT}
      - PROMETHEUS_SECRET_ACCESS_KEY=\${PROMETHEUS_SECRET_ACCESS_KEY}
      - USE_REMOTE_SERVER_AUTH=\${USE_REMOTE_SERVER_AUTH}
      - REMOTE_SERVER_AUTH_HOST=\${REMOTE_SERVER_AUTH_HOST}
      - REMOTE_SERVER_AUTH_PORT=\${REMOTE_SERVER_AUTH_PORT}
      - MAX_ACTIVE_SESSIONS_PER_USER=\${MAX_ACTIVE_SESSIONS_PER_USER}
      - SERVER_EXTERNAL_IPS=\${SERVER_EXTERNAL_IPS}
      - DNS_IPV4_PRIMARY=\${DNS_IPV4_PRIMARY}
      - DNS_IPV4_SECONDARY=\${DNS_IPV4_SECONDARY}
      - DNS_IPV6_PRIMARY=\${DNS_IPV6_PRIMARY}
      - DNS_IPV6_SECONDARY=\${DNS_IPV6_SECONDARY}
    healthcheck:
      test: ["CMD", "sh", "-c", "pgrep dnsmasq && pgrep fptn-server"]
      interval: 30s
      timeout: 10s
      retries: 3
      start_period: 40s
YAML
}

write_env_file() {
  local port="$1"
  local pubip="$2"
  local prom_key
  prom_key="$(random_alnum 32)"

  cat > "${ENV_FILE}" <<EOF
FPTN_PORT=${port}
SERVER_EXTERNAL_IPS=${pubip}

ENABLE_DETECT_PROBING=true
DEFAULT_PROXY_DOMAIN=cdnvideo.com
ALLOWED_SNI_LIST=
DISABLE_BITTORRENT=true

USE_REMOTE_SERVER_AUTH=false
REMOTE_SERVER_AUTH_HOST=
REMOTE_SERVER_AUTH_PORT=443

PROMETHEUS_SECRET_ACCESS_KEY=${prom_key}
MAX_ACTIVE_SESSIONS_PER_USER=3

DNS_IPV4_PRIMARY=8.8.8.8
DNS_IPV4_SECONDARY=8.8.4.4
DNS_IPV6_PRIMARY=2001:4860:4860::8888
DNS_IPV6_SECONDARY=2001:4860:4860::8844
EOF
}

compose_up() {
  log "Starting FKTN container..."
  retry compose --env-file "${ENV_FILE}" up -d
}

ensure_initial_self_signed() {
  log "Ensuring initial TLS certs exist (non-interactive)..."
  retry compose --env-file "${ENV_FILE}" run --rm fptn-server sh -c \
    "cd /etc/fptn && [ -f server.key ] || openssl genrsa -out server.key 2048"
  retry compose --env-file "${ENV_FILE}" run --rm fptn-server sh -c \
    "cd /etc/fptn && [ -f server.crt ] || openssl req -new -x509 -key server.key -out server.crt -days 3650 -subj '/C=IR/ST=Tehran/L=Tehran/O=Iranux/OU=FKTN/CN=fktn-server'"

  local fp
  fp="$(compose --env-file "${ENV_FILE}" run --rm fptn-server sh -c \
    "openssl x509 -noout -fingerprint -md5 -in /etc/fptn/server.crt | cut -d'=' -f2 | tr -d ':' | tr 'A-F' 'a-f'")"
  echo "${fp}" > "${STATE_DIR}/cert-md5-fingerprint.txt"
}

ufw_allow_if_active() {
  local p="$1"
  if cmd_exists ufw; then
    if ufw status | grep -qi "Status: active"; then
      ufw allow "${p}/tcp" >/dev/null 2>&1 || true
    fi
  fi
}

# -------------------------
# Management panel (Iranux)
# -------------------------
write_manager_panel() {
  cat > "${MANAGER}" <<'BASH'
#!/usr/bin/env bash
set -euo pipefail

APP_NAME="iranux-fktn"
BASE_DIR="/opt/${APP_NAME}"
DATA_DIR="${BASE_DIR}/fptn-server-data"
ENV_FILE="${BASE_DIR}/.env"
STATE_DIR="${BASE_DIR}/state"
DOMAIN_STATE="${STATE_DIR}/domain.conf"
CERT_STATE="${STATE_DIR}/cert.conf"

die(){ echo "[x] $*" >&2; exit 1; }
need_root(){ [[ "${EUID}" -eq 0 ]] || die "Run: sudo Iranux"; }

cd "${BASE_DIR}" 2>/dev/null || die "Not installed. Run installer first."

compose() { (cd "${BASE_DIR}" && docker compose --env-file "${ENV_FILE}" "$@"); }

get_env() {
  local k="$1"
  grep -E "^${k}=" "${ENV_FILE}" | head -n1 | cut -d'=' -f2- || true
}

public_ip() { get_env SERVER_EXTERNAL_IPS; }
public_port() { get_env FPTN_PORT; }

domain_get() { [[ -f "${DOMAIN_STATE}" ]] && cat "${DOMAIN_STATE}" || true; }
tls_status_line() { [[ -f "${CERT_STATE}" ]] && cat "${CERT_STATE}" || echo "TLS: self-signed (default)"; }

endpoint_line() {
  local port dom ip
  ip="$(public_ip)"
  port="$(public_port)"
  dom="$(domain_get)"
  if [[ -n "${dom}" ]]; then
    if [[ "${port}" == "443" ]]; then
      echo "Endpoint: ${dom} (preferred) | Fallback: ${ip}:443"
    else
      echo "Endpoint: ${dom}:${port} (preferred) | Fallback: ${ip}:${port}"
    fi
  else
    echo "Endpoint: ${ip}:${port}"
  fi
}

# User count: best-effort, safe
user_count() {
  if compose exec -T fptn-server sh -c "command -v fptn-passwd >/dev/null 2>&1" >/dev/null 2>&1; then
    local out
    out="$(compose exec -T fptn-server sh -c "fptn-passwd --list-users 2>/dev/null || true" || true)"
    if [[ -n "${out}" ]]; then
      echo "${out}" | sed '/^\s*$/d' | wc -l | tr -d ' '
      return 0
    fi
  fi
  # fallback heuristic
  local out2
  out2="$(compose exec -T fptn-server sh -c "ls -1 /etc/fptn 2>/dev/null | wc -l" 2>/dev/null || true)"
  [[ -n "${out2}" ]] && echo "${out2}" || echo "unknown"
}

banner() {
  local ip port dom tls users ep
  ip="$(public_ip)"
  port="$(public_port)"
  dom="$(domain_get)"
  tls="$(tls_status_line)"
  users="$(user_count)"
  ep="$(endpoint_line)"

  echo "============================================================"
  echo " Iranux | FKTN VPN Server Management"
  echo "------------------------------------------------------------"
  echo " Server IP   : ${ip:-unknown}"
  echo " Server Port : ${port:-unknown}"
  echo " Users       : ${users}"
  echo " Domain      : ${dom:-not set}"
  echo " ${ep}"
  echo " ${tls}"
  echo "============================================================"
}

menu() {
  echo
  echo "1) Status (docker compose ps)"
  echo "2) Add VPN user"
  echo "3) Generate connection token"
  echo "4) Enable/Update Domain + SSL (Let's Encrypt preferred)"
  echo "5) Renew SSL now"
  echo "6) Backup (tar.gz)"
  echo "7) Restore from backup"
  echo "8) Tail logs (last 200)"
  echo "9) Restart server"
  echo "10) Update to latest image (pull + recreate)"
  echo "11) Uninstall (targeted)"
  echo "0) Exit"
  echo
}

status() { compose ps; }

add_user() {
  read -rp "Enter username: " u
  [[ -n "${u}" ]] || { echo "Username cannot be empty"; return 1; }
  read -rp "Bandwidth limit (Mbps) [default 100]: " bw
  bw="${bw:-100}"
  echo
  echo "Running: fptn-passwd --add-user ${u} --bandwidth ${bw}"
  echo "If prompted for a password, enter a strong password."
  compose exec fptn-server fptn-passwd --add-user "${u}" --bandwidth "${bw}"
}

gen_token() {
  local u p ip port
  read -rp "Username: " u
  [[ -n "${u}" ]] || { echo "Username cannot be empty"; return 1; }
  read -rsp "Password: " p; echo
  ip="$(public_ip)"
  port="$(public_port)"
  echo
  echo "Generating token (copy it into the client app):"
  compose run --rm fptn-server token-generator --user "${u}" --password "${p}" --server-ip "${ip}" --port "${port}"
}

ensure_pkg() {
  local pkg="$1"
  if ! dpkg -s "${pkg}" >/dev/null 2>&1; then
    export DEBIAN_FRONTEND=noninteractive
    apt-get update -y >/dev/null 2>&1 || true
    apt-get install -y --no-install-recommends "${pkg}"
  fi
}

svc_owner_of_port() {
  local p="$1"
  ss -ltnp "( sport = :${p} )" 2>/dev/null | tail -n +2 | sed -E 's/.*users:\(\("([^"]+)".*/\1/' | head -n1 || true
}

stop_known_conflict_service() {
  local owner
  owner="$(svc_owner_of_port 80)"
  if [[ "${owner}" == "nginx" ]]; then
    systemctl stop nginx >/dev/null 2>&1 || true
    echo "nginx"
    return 0
  fi
  if [[ "${owner}" == "apache2" ]]; then
    systemctl stop apache2 >/dev/null 2>&1 || true
    echo "apache2"
    return 0
  fi
  echo ""
}

start_service_if_exists() {
  local s="$1"
  [[ -z "${s}" ]] && return 0
  systemctl start "${s}" >/dev/null 2>&1 || true
}

dns_points_to_server() {
  local dom="$1"
  local ip res
  ip="$(public_ip)"
  res="$(getent ahostsv4 "${dom}" 2>/dev/null | awk '{print $1}' | head -n1 || true)"
  [[ -z "${res}" ]] && return 1
  [[ "${res}" == "${ip}" ]]
}

write_tls_state() {
  local line="$1"
  echo "${line}" > "${CERT_STATE}"
}

gen_self_signed_for_domain() {
  local dom="$1"
  mkdir -p "${DATA_DIR}"
  openssl genrsa -out "${DATA_DIR}/server.key" 2048 >/dev/null 2>&1 || true
  openssl req -new -x509 -key "${DATA_DIR}/server.key" -out "${DATA_DIR}/server.crt" -days 3650 \
    -subj "/C=IR/ST=Tehran/L=Tehran/O=Iranux/OU=FKTN/CN=${dom}" >/dev/null 2>&1 || true
}

install_cert_into_fktn() {
  local dom="$1"
  local src_crt="/etc/letsencrypt/live/${dom}/fullchain.pem"
  local src_key="/etc/letsencrypt/live/${dom}/privkey.pem"
  [[ -f "${src_crt}" && -f "${src_key}" ]] || die "Cert files not found for ${dom}."

  mkdir -p "${DATA_DIR}"
  install -m 600 "${src_key}" "${DATA_DIR}/server.key.tmp"
  install -m 644 "${src_crt}" "${DATA_DIR}/server.crt.tmp"
  mv -f "${DATA_DIR}/server.key.tmp" "${DATA_DIR}/server.key"
  mv -f "${DATA_DIR}/server.crt.tmp" "${DATA_DIR}/server.crt"
}

setup_auto_renew() {
  cat > "/usr/local/sbin/${APP_NAME}-renew" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail

# Self-healing renew:
# - If port 80 is blocked by nginx/apache2, stop temporarily then restore.
owner() {
  ss -ltnp "( sport = :80 )" 2>/dev/null | tail -n +2 | sed -E 's/.*users:\(\("([^"]+)".*/\1/' | head -n1 || true
}

stopped=""
o="$(owner)"
if [[ "${o}" == "nginx" ]]; then
  systemctl stop nginx >/dev/null 2>&1 || true
  stopped="nginx"
elif [[ "${o}" == "apache2" ]]; then
  systemctl stop apache2 >/dev/null 2>&1 || true
  stopped="apache2"
fi

certbot renew --quiet

if [[ -n "${stopped}" ]]; then
  systemctl start "${stopped}" >/dev/null 2>&1 || true
fi
EOF
  chmod 0755 "/usr/local/sbin/${APP_NAME}-renew"

  cat > "/etc/systemd/system/${APP_NAME}-renew.service" <<EOF
[Unit]
Description=Renew Let's Encrypt certificates for ${APP_NAME}

[Service]
Type=oneshot
ExecStart=/usr/local/sbin/${APP_NAME}-renew
EOF

  cat > "/etc/systemd/system/${APP_NAME}-renew.timer" <<EOF
[Unit]
Description=Run ${APP_NAME}-renew twice daily

[Timer]
OnCalendar=*-*-* 03,15:00:00
Persistent=true

[Install]
WantedBy=timers.target
EOF

  systemctl daemon-reload
  systemctl enable --now "${APP_NAME}-renew.timer" >/dev/null 2>&1 || true
}

install_domain_ssl() {
  need_root
  ensure_pkg certbot
  ensure_pkg openssl

  local dom email port stopped=""
  port="$(public_port)"

  read -rp "Domain (A record must point to this server IP): " dom
  [[ -n "${dom}" ]] || { echo "Domain cannot be empty"; return 1; }
  read -rp "Email for Let's Encrypt (required): " email
  [[ -n "${email}" ]] || { echo "Email cannot be empty"; return 1; }

  echo "${dom}" > "${DOMAIN_STATE}"

  echo
  echo "Pre-check: DNS resolution..."
  if ! dns_points_to_server "${dom}"; then
    echo "[x] DNS for ${dom} does NOT resolve to this server IP."
    echo "    Fix: set A record to $(public_ip), wait for propagation, then retry."
    return 1
  fi
  echo "[+] DNS OK."

  # Ensure port 80 free (self-healing)
  if ss -ltn "( sport = :80 )" | grep -q ":80"; then
    echo "[!] Port 80 is in use. Attempting self-heal..."
    stopped="$(stop_known_conflict_service)"
    if ss -ltn "( sport = :80 )" | grep -q ":80"; then
      echo "[x] Could not free port 80 automatically (unknown/high-risk service)."
      echo "    Fallback: self-signed cert for domain (encrypted, may warn)."
      gen_self_signed_for_domain "${dom}"
      compose restart
      write_tls_state "TLS: self-signed for ${dom} (fallback)"
      return 0
    fi
    echo "[+] Port 80 freed."
  fi

  # Open 80 if UFW active
  if command -v ufw >/dev/null 2>&1 && ufw status | grep -qi "Status: active"; then
    ufw allow 80/tcp >/dev/null 2>&1 || true
  fi

  echo
  echo "[+] Requesting Let's Encrypt certificate (standalone on :80)..."

  local ok=0
  for i in 1 2 3; do
    if certbot certonly --standalone -d "${dom}" --non-interactive --agree-tos -m "${email}" --preferred-challenges http; then
      ok=1
      break
    fi
    echo "[!] certbot attempt ${i}/3 failed. Retrying..."
    sleep 2
  done

  # Restore any stopped service
  start_service_if_exists "${stopped}"

  if [[ "${ok}" -ne 1 ]]; then
    echo "[x] Let's Encrypt issuance failed after retries."
    echo "    Fallback: generating self-signed cert for domain."
    gen_self_signed_for_domain "${dom}"
    compose restart
    write_tls_state "TLS: self-signed for ${dom} (fallback)"
    return 0
  fi

  echo "[+] Certificate obtained. Installing into FKTN..."
  install_cert_into_fktn "${dom}"
  setup_auto_renew

  # Restart FKTN to apply
  compose restart

  local exp
  exp="$(openssl x509 -in "/etc/letsencrypt/live/${dom}/fullchain.pem" -noout -enddate 2>/dev/null | cut -d'=' -f2 || true)"
  write_tls_state "TLS: Let's Encrypt for ${dom} (expires: ${exp:-unknown})"

  echo "[+] Done. Domain + SSL enabled."
  if [[ "${port}" == "443" ]]; then
    echo "    You can use: ${dom} (instead of IP)"
  else
    echo "    You can use: ${dom}:${port} (instead of IP)"
  fi
}

renew_now() {
  need_root
  if ! command -v certbot >/dev/null 2>&1; then
    echo "certbot not installed. Enable Domain+SSL first."
    return 1
  fi
  "/usr/local/sbin/${APP_NAME}-renew" || true

  # refresh expiry in banner if possible
  if [[ -f "${DOMAIN_STATE}" ]]; then
    local dom exp
    dom="$(cat "${DOMAIN_STATE}" 2>/dev/null || true)"
    if [[ -n "${dom}" && -f "/etc/letsencrypt/live/${dom}/fullchain.pem" ]]; then
      exp="$(openssl x509 -in "/etc/letsencrypt/live/${dom}/fullchain.pem" -noout -enddate 2>/dev/null | cut -d'=' -f2 || true)"
      write_tls_state "TLS: Let's Encrypt for ${dom} (expires: ${exp:-unknown})"
    fi
  fi

  echo "Renew attempted."
}

backup_now() {
  need_root
  mkdir -p "${BASE_DIR}/backups"
  local ts out
  ts="$(date +%Y%m%d-%H%M%S)"
  out="${BASE_DIR}/backups/fktn-backup-${ts}.tar.gz"
  tar -czf "${out}" -C "${BASE_DIR}" "fptn-server-data" "state" ".env" "docker-compose.yml" >/dev/null 2>&1
  echo "Backup created: ${out}"
}

restore_backup() {
  need_root
  local dir="${BASE_DIR}/backups"
  [[ -d "${dir}" ]] || { echo "No backups directory."; return 1; }
  echo "Available backups:"
  ls -1 "${dir}" | nl -w2 -s') '
  echo
  read -rp "Select number: " n
  local file
  file="$(ls -1 "${dir}" | sed -n "${n}p" || true)"
  [[ -n "${file}" ]] || { echo "Invalid selection."; return 1; }

  echo "[!] This will overwrite current data. Proceed? (y/N)"
  read -r yn
  [[ "${yn}" == "y" || "${yn}" == "Y" ]] || { echo "Cancelled."; return 0; }

  compose down --remove-orphans --volumes >/dev/null 2>&1 || true
  rm -rf "${BASE_DIR}/fptn-server-data" "${BASE_DIR}/state" "${BASE_DIR}/.env" "${BASE_DIR}/docker-compose.yml" >/dev/null 2>&1 || true
  tar -xzf "${dir}/${file}" -C "${BASE_DIR}"
  compose up -d
  echo "Restore complete."
}

tail_logs() { compose logs --tail 200 -f; }
restart_svc() { compose restart; }
update_image() { compose pull && compose up -d; }

uninstall() {
  need_root
  echo "[!] Uninstall will remove ${BASE_DIR} and Iranux command. Proceed? (y/N)"
  read -r yn
  [[ "${yn}" == "y" || "${yn}" == "Y" ]] || { echo "Cancelled."; return 0; }
  compose down --remove-orphans --volumes >/dev/null 2>&1 || true
  systemctl disable --now "${APP_NAME}-renew.timer" >/dev/null 2>&1 || true
  rm -f "/etc/systemd/system/${APP_NAME}-renew.service" "/etc/systemd/system/${APP_NAME}-renew.timer" "/usr/local/sbin/${APP_NAME}-renew" >/dev/null 2>&1 || true
  systemctl daemon-reload >/dev/null 2>&1 || true
  rm -f "/usr/local/bin/Iranux" "/usr/local/sbin/${APP_NAME}" >/dev/null 2>&1 || true
  rm -rf "${BASE_DIR}" >/dev/null 2>&1 || true
  echo "Uninstalled."
  exit 0
}

main() {
  need_root
  while true; do
    clear || true
    banner
    menu
    read -rp "Select: " c
    case "${c}" in
      1) status ;;
      2) add_user ;;
      3) gen_token ;;
      4) install_domain_ssl ;;
      5) renew_now ;;
      6) backup_now ;;
      7) restore_backup ;;
      8) tail_logs ;;
      9) restart_svc ;;
      10) update_image ;;
      11) uninstall ;;
      0) echo "Bye."; exit 0 ;;
      *) echo "Invalid option." ;;
    esac
    echo
    read -rp "Press Enter to continue..." _ || true
  done
}

main "$@"
BASH

  chmod 0755 "${MANAGER}"
  ln -sf "${MANAGER}" "${SYMLINK}"
}

# -------------------------
# Main installation flow
# -------------------------
install_main() {
  detect_ubuntu
  ensure_internet

  apt_prepare_fast
  apt_install_min curl ca-certificates gnupg lsb-release iproute2 openssl git

  ensure_tun
  ensure_dirs
  ensure_docker

  local pub_ip port
  log "Detecting public IPv4..."
  if pub_ip="$(detect_public_ipv4)"; then
    log "Public IP detected: ${pub_ip}"
  else
    die "Could not auto-detect public IPv4. Please ensure outbound HTTPS works, then re-run."
  fi

  port="$(pick_port)"
  log "Selected external port for client connections: ${port}"

  write_compose_file
  write_env_file "${port}" "${pub_ip}"

  ufw_allow_if_active "${port}"
  ufw_allow_if_active 80

  compose_up
  ensure_initial_self_signed
  write_manager_panel

  log "Installation completed successfully."
  log "Opening management panel now..."
  echo
  exec "${SYMLINK}"
}

# -------------------------
# Entry point
# -------------------------
main() {
  need_root "$@"

  # Always self-update first (ensures latest from GitHub)
  self_update_from_github "${1:-}"

  # Always targeted nuclear clean before install (safe if docker missing)
  nuclear_clean_project

  # Fresh install
  install_main
}

main "$@"
