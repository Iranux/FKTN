#!/usr/bin/env bash
# ============================================================
# Iranux FKTN - Management Panel (Iranux-Menu.sh)
# - Run: sudo Iranux   (or sudo iranux)
# ============================================================

set -Eeuo pipefail

APP_NAME="iranux-fktn"
BASE_DIR="/opt/${APP_NAME}"
DATA_DIR="${BASE_DIR}/fptn-server-data"
ENV_FILE="${BASE_DIR}/.env"
STATE_DIR="${BASE_DIR}/state"
DOMAIN_STATE="${STATE_DIR}/domain.conf"
CERT_STATE="${STATE_DIR}/cert.conf"

# -------------------------
# UI helpers
# -------------------------
green() { echo -e "\e[32m$*\e[0m"; }
yellow(){ echo -e "\e[33m$*\e[0m"; }
red()   { echo -e "\e[31m$*\e[0m"; }

die(){ red "[x] $*"; exit 1; }

need_root(){
  if [[ "${EUID}" -ne 0 ]]; then
    die "Run as root: sudo Iranux"
  fi
}

require_install(){
  [[ -d "${BASE_DIR}" ]] || die "Not installed. Run installer first."
  [[ -f "${ENV_FILE}" ]] || die "Missing ${ENV_FILE}. Re-run installer."
  mkdir -p "${STATE_DIR}" >/dev/null 2>&1 || true
}

compose(){
  (cd "${BASE_DIR}" && docker compose --env-file "${ENV_FILE}" "$@")
}

get_env(){
  local k="$1"
  grep -E "^${k}=" "${ENV_FILE}" | head -n1 | cut -d'=' -f2- || true
}

public_ip(){ get_env SERVER_EXTERNAL_IPS; }
public_port(){ get_env FPTN_PORT; }

domain_get(){
  [[ -f "${DOMAIN_STATE}" ]] && cat "${DOMAIN_STATE}" || true
}

tls_status_line(){
  [[ -f "${CERT_STATE}" ]] && cat "${CERT_STATE}" || echo "TLS: self-signed (default)"
}

endpoint_line(){
  local port dom ip
  ip="$(public_ip)"; port="$(public_port)"; dom="$(domain_get)"
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

# Best-effort user count: tries common paths/tools; if not possible -> unknown
user_count(){
  local out=""
  if compose exec -T fptn-server sh -c "command -v fptn-passwd >/dev/null 2>&1" >/dev/null 2>&1; then
    out="$(compose exec -T fptn-server sh -c "fptn-passwd --list-users 2>/dev/null || true" || true)"
    if [[ -n "${out}" ]]; then
      echo "${out}" | sed '/^\s*$/d' | wc -l | tr -d ' '
      return 0
    fi
  fi
  echo "unknown"
}

banner(){
  local ip port dom tls users ep
  ip="$(public_ip)"; port="$(public_port)"; dom="$(domain_get)"
  tls="$(tls_status_line)"; users="$(user_count)"; ep="$(endpoint_line)"
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

pause(){
  echo
  read -rp "Press Enter to continue..." _ || true
}

# -------------------------
# Package helpers
# -------------------------
ensure_pkg(){
  local pkg="$1"
  if ! dpkg -s "${pkg}" >/dev/null 2>&1; then
    export DEBIAN_FRONTEND=noninteractive
    apt-get update -y >/dev/null 2>&1 || true
    apt-get install -y --no-install-recommends "${pkg}"
  fi
}

# -------------------------
# ✅ TLS bootstrap fix (NEW)
# -------------------------
ensure_tls_present_or_create() {
  # Ensures ${DATA_DIR}/server.crt and ${DATA_DIR}/server.key exist.
  # If missing, generates a self-signed cert and restarts container.

  if [[ -f "${DATA_DIR}/server.crt" && -f "${DATA_DIR}/server.key" ]]; then
    return 0
  fi

  yellow "[!] TLS certificate not found in ${DATA_DIR}. Creating self-signed cert..."

  ensure_pkg openssl
  mkdir -p "${DATA_DIR}"

  # Prefer domain if set, else use server IP as CN
  local cn
  cn="$(domain_get)"
  [[ -n "${cn}" ]] || cn="$(public_ip)"

  openssl genrsa -out "${DATA_DIR}/server.key" 2048 >/dev/null 2>&1 || true
  openssl req -new -x509 -key "${DATA_DIR}/server.key" -out "${DATA_DIR}/server.crt" -days 3650 \
    -subj "/C=IR/ST=Tehran/L=Tehran/O=Iranux/OU=FKTN/CN=${cn}" >/dev/null 2>&1 || true

  chmod 600 "${DATA_DIR}/server.key" >/dev/null 2>&1 || true
  chmod 644 "${DATA_DIR}/server.crt" >/dev/null 2>&1 || true

  echo "TLS: self-signed (generated locally)" > "${CERT_STATE}"

  yellow "[*] Restarting server to load TLS..."
  compose restart >/dev/null 2>&1 || true
  green "[+] TLS is ready."
}

# -------------------------
# Core actions
# -------------------------
status(){
  compose ps
}

tail_logs(){
  compose logs --tail 200 -f
}

restart_server(){
  compose restart
  green "[+] Restart requested."
}

update_image(){
  yellow "[!] Pulling latest image and recreating..."
  compose pull
  compose up -d
  green "[+] Updated."
}

# -------------------------
# User management
# -------------------------
add_user(){
  read -rp "Enter username: " u
  [[ -n "${u}" ]] || { red "Username cannot be empty."; return 1; }

  read -rp "Bandwidth limit (Mbps) [default 100]: " bw
  bw="${bw:-100}"

  echo
  yellow "[!] If prompted for password, enter a strong password."
  if compose exec -T fptn-server sh -c "command -v fptn-passwd >/dev/null 2>&1"; then
    compose exec fptn-server fptn-passwd --add-user "${u}" --bandwidth "${bw}"
    green "[+] User added (if no errors above)."
  else
    red "[x] fptn-passwd not found inside container. This image may use a different user command."
    red "    Check container docs or exec into container to manage users."
    return 1
  fi
}

gen_token(){
  local u p ip port
  read -rp "Username: " u
  [[ -n "${u}" ]] || { red "Username cannot be empty."; return 1; }
  read -rsp "Password: " p; echo
  ip="$(public_ip)"; port="$(public_port)"

  # ✅ Ensure TLS exists BEFORE token generation to prevent:
  # "Certificate file not found: /etc/fptn/server.crt"
  ensure_tls_present_or_create

  echo
  yellow "[*] Generating token..."

  if compose run --rm fptn-server sh -c "command -v token-generator >/dev/null 2>&1"; then
    compose run --rm fptn-server token-generator --user "${u}" --password "${p}" --server-ip "${ip}" --port "${port}"
    green "[+] Done."
  else
    red "[x] token-generator not found inside container."
    red "    You may need to use the image's official client/token method."
    return 1
  fi
}

# -------------------------
# Domain + SSL
# Strategy:
#  - Preferred: Let's Encrypt using certbot standalone on :80
#  - If port 80 busy:
#      * attempt to stop nginx/apache if detected
#      * retry certbot
#      * if still fails -> fallback self-signed (do not crash)
#  - Install cert into FKTN data volume as server.key/server.crt
# -------------------------
dns_points_to_server(){
  local dom="$1" ip res
  ip="$(public_ip)"
  res="$(getent ahostsv4 "${dom}" 2>/dev/null | awk '{print $1}' | head -n1 || true)"
  [[ -n "${res}" && "${res}" == "${ip}" ]]
}

write_tls_state(){
  echo "$1" > "${CERT_STATE}"
}

install_cert_into_fktn(){
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

gen_self_signed_for_domain(){
  local dom="$1"
  ensure_pkg openssl
  mkdir -p "${DATA_DIR}"
  openssl genrsa -out "${DATA_DIR}/server.key" 2048 >/dev/null 2>&1 || true
  openssl req -new -x509 -key "${DATA_DIR}/server.key" -out "${DATA_DIR}/server.crt" -days 3650 \
    -subj "/C=IR/ST=Tehran/L=Tehran/O=Iranux/OU=FKTN/CN=${dom}" >/dev/null 2>&1 || true
  echo "TLS: self-signed for ${dom} (fallback)" > "${CERT_STATE}"
}

stop_conflicting_web_servers_best_effort(){
  local stopped=0

  if command -v systemctl >/dev/null 2>&1; then
    for svc in nginx apache2 caddy lighttpd; do
      if systemctl is-active --quiet "$svc" 2>/dev/null; then
        yellow "[!] Stopping conflicting service: ${svc}"
        systemctl stop "$svc" >/dev/null 2>&1 || true
        stopped=1
      fi
    done
  fi

  if command -v service >/dev/null 2>&1; then
    for svc in nginx apache2 caddy lighttpd; do
      service "$svc" status >/dev/null 2>&1 || continue
      yellow "[!] Attempting service stop: ${svc}"
      service "$svc" stop >/dev/null 2>&1 || true
      stopped=1
    done
  fi

  return "${stopped}"
}

port80_in_use(){
  ss -ltnH "sport = :80" 2>/dev/null | grep -q .
}

request_letsencrypt(){
  local dom="$1" email="$2"
  certbot certonly \
    --standalone \
    -d "${dom}" \
    --non-interactive \
    --agree-tos \
    -m "${email}" \
    --preferred-challenges http
}

enable_domain_ssl(){
  need_root
  ensure_pkg certbot

  local dom email ok=0
  read -rp "Domain (A record must point to this server IP): " dom
  [[ -n "${dom}" ]] || { red "Domain cannot be empty"; return 1; }
  read -rp "Email for Let's Encrypt (required): " email
  [[ -n "${email}" ]] || { red "Email cannot be empty"; return 1; }

  echo "${dom}" > "${DOMAIN_STATE}"

  echo
  yellow "[*] DNS pre-check..."
  if ! dns_points_to_server "${dom}"; then
    red "[x] DNS for ${dom} does NOT resolve to this server IP ($(public_ip))."
    red "    Fix A record, wait propagation, then retry."
    return 1
  fi
  green "[+] DNS OK."

  if port80_in_use; then
    yellow "[!] Port 80 is in use. Attempting to stop common conflicting services..."
    stop_conflicting_web_servers_best_effort >/dev/null 2>&1 || true
    sleep 1
  fi

  echo
  yellow "[*] Requesting Let's Encrypt certificate (standalone on :80)..."
  for i in 1 2 3; do
    if ! port80_in_use; then
      if request_letsencrypt "${dom}" "${email}"; then
        ok=1
        break
      fi
    else
      yellow "[!] Port 80 still in use. Attempt ${i}/3 cannot proceed."
    fi
    yellow "[!] Attempt ${i}/3 failed. Retrying..."
    sleep 2
  done

  if [[ "${ok}" -ne 1 ]]; then
    red "[x] Let's Encrypt failed or port 80 could not be freed."
    yellow "[!] Falling back to self-signed cert (server will still work)."
    gen_self_signed_for_domain "${dom}"
    compose restart
    green "[+] Fallback TLS applied."
    return 0
  fi

  install_cert_into_fktn "${dom}"
  compose restart

  local exp
  exp="$(openssl x509 -in "/etc/letsencrypt/live/${dom}/fullchain.pem" -noout -enddate 2>/dev/null | cut -d'=' -f2 || true)"
  write_tls_state "TLS: Let's Encrypt for ${dom} (expires: ${exp:-unknown})"

  green "[+] SSL enabled successfully."
  local port
  port="$(public_port)"
  [[ "${port}" == "443" ]] && green "[+] Use domain: ${dom}" || green "[+] Use domain: ${dom}:${port}"
}

renew_ssl_now(){
  need_root
  command -v certbot >/dev/null 2>&1 || { red "certbot not installed. Enable Domain+SSL first."; return 1; }

  yellow "[*] Renewing certificates (best-effort)..."
  certbot renew --quiet || true

  local dom exp
  dom="$(domain_get)"
  if [[ -n "${dom}" && -f "/etc/letsencrypt/live/${dom}/fullchain.pem" ]]; then
    exp="$(openssl x509 -in "/etc/letsencrypt/live/${dom}/fullchain.pem" -noout -enddate 2>/dev/null | cut -d'=' -f2 || true)"
    write_tls_state "TLS: Let's Encrypt for ${dom} (expires: ${exp:-unknown})"
    install_cert_into_fktn "${dom}" || true
    compose restart || true
    green "[+] Renew attempted + service restarted."
  else
    yellow "[!] No LE cert found for current domain. Nothing to install."
  fi
}

# -------------------------
# Menu
# -------------------------
menu(){
  echo
  echo "1) Status (docker compose ps)"
  echo "2) Add VPN user"
  echo "3) Generate connection token"
  echo "4) Add/Update Domain + SSL (Let's Encrypt preferred)"
  echo "5) Renew SSL now"
  echo "6) Tail logs (last 200)"
  echo "7) Restart server"
  echo "8) Update to latest image (pull + recreate)"
  echo "0) Exit"
  echo
}

main(){
  need_root
  require_install

  while true; do
    clear || true
    banner
    menu
    read -rp "Select: " c
    case "${c}" in
      1) status ;;
      2) add_user ;;
      3) gen_token ;;
      4) enable_domain_ssl ;;
      5) renew_ssl_now ;;
      6) tail_logs ;;
      7) restart_server ;;
      8) update_image ;;
      0) echo "Bye."; exit 0 ;;
      *) red "Invalid option." ;;
    esac
    pause
  done
}

main "$@"
