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

die(){ echo -e "\e[31m[x]\e[0m $*" >&2; exit 1; }
need_root(){ [[ "${EUID}" -eq 0 ]] || die "Run: sudo Iranux"; }

cd "${BASE_DIR}" 2>/dev/null || die "Not installed. Run installer first."
compose(){ (cd "${BASE_DIR}" && docker compose --env-file "${ENV_FILE}" "$@"); }

get_env(){ local k="$1"; grep -E "^${k}=" "${ENV_FILE}" | head -n1 | cut -d'=' -f2- || true; }
public_ip(){ get_env SERVER_EXTERNAL_IPS; }
public_port(){ get_env FPTN_PORT; }

domain_get(){ [[ -f "${DOMAIN_STATE}" ]] && cat "${DOMAIN_STATE}" || true; }
tls_status_line(){ [[ -f "${CERT_STATE}" ]] && cat "${CERT_STATE}" || echo "TLS: self-signed (default)"; }

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

user_count(){
  # Best-effort: if fptn-passwd supports listing, use it; else unknown.
  if compose exec -T fptn-server sh -c "command -v fptn-passwd >/dev/null 2>&1" >/dev/null 2>&1; then
    local out
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

menu(){
  echo
  echo "1) Status (docker compose ps)"
  echo "2) Add VPN user"
  echo "3) Generate connection token"
  echo "4) Enable/Update Domain + SSL (Let's Encrypt preferred)"
  echo "5) Renew SSL now"
  echo "6) Tail logs (last 200)"
  echo "7) Restart server"
  echo "8) Update to latest image (pull + recreate)"
  echo "0) Exit"
  echo
}

status(){ compose ps; }

add_user(){
  read -rp "Enter username: " u
  [[ -n "${u}" ]] || { echo "Username cannot be empty"; return 1; }
  read -rp "Bandwidth limit (Mbps) [default 100]: " bw
  bw="${bw:-100}"
  echo
  echo "If prompted for a password, enter a strong password."
  compose exec fptn-server fptn-passwd --add-user "${u}" --bandwidth "${bw}"
}

gen_token(){
  local u p ip port
  read -rp "Username: " u
  [[ -n "${u}" ]] || { echo "Username cannot be empty"; return 1; }
  read -rsp "Password: " p; echo
  ip="$(public_ip)"; port="$(public_port)"
  echo
  echo "Token:"
  compose run --rm fptn-server token-generator --user "${u}" --password "${p}" --server-ip "${ip}" --port "${port}"
}

ensure_pkg(){
  local pkg="$1"
  if ! dpkg -s "${pkg}" >/dev/null 2>&1; then
    export DEBIAN_FRONTEND=noninteractive
    apt-get update -y >/dev/null 2>&1 || true
    apt-get install -y --no-install-recommends "${pkg}"
  fi
}

dns_points_to_server(){
  local dom="$1" ip res
  ip="$(public_ip)"
  res="$(getent ahostsv4 "${dom}" 2>/dev/null | awk '{print $1}' | head -n1 || true)"
  [[ -n "${res}" && "${res}" == "${ip}" ]]
}

write_tls_state(){ echo "$1" > "${CERT_STATE}"; }

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
}

install_domain_ssl(){
  need_root
  ensure_pkg certbot

  local dom email ok=0 port
  port="$(public_port)"

  read -rp "Domain (A record must point to this server IP): " dom
  [[ -n "${dom}" ]] || { echo "Domain cannot be empty"; return 1; }
  read -rp "Email for Let's Encrypt (required): " email
  [[ -n "${email}" ]] || { echo "Email cannot be empty"; return 1; }

  echo "${dom}" > "${DOMAIN_STATE}"

  echo
  echo "Pre-check: DNS resolution..."
  if ! dns_points_to_server "${dom}"; then
    echo "[x] DNS for ${dom} does NOT resolve to this server IP ($(public_ip))."
    echo "    Fix A record, wait propagation, retry."
    return 1
  fi
  echo "[+] DNS OK."

  # Attempt LE issuance on :80. If :80 is blocked by unknown service, fallback to self-signed.
  if ss -ltn "( sport = :80 )" | grep -q ":80"; then
    echo "[!] Port 80 is in use and may block Let's Encrypt standalone."
    echo "    Falling back to self-signed for now."
    gen_self_signed_for_domain "${dom}"
    compose restart
    write_tls_state "TLS: self-signed for ${dom} (fallback)"
    return 0
  fi

  echo "[+] Requesting Let's Encrypt certificate (standalone :80)..."
  for i in 1 2 3; do
    if certbot certonly --standalone -d "${dom}" --non-interactive --agree-tos -m "${email}" --preferred-challenges http; then
      ok=1; break
    fi
    echo "[!] certbot attempt ${i}/3 failed. Retrying..."
    sleep 2
  done

  if [[ "${ok}" -ne 1 ]]; then
    echo "[x] Let's Encrypt failed. Fallback self-signed."
    gen_self_signed_for_domain "${dom}"
    compose restart
    write_tls_state "TLS: self-signed for ${dom} (fallback)"
    return 0
  fi

  install_cert_into_fktn "${dom}"
  compose restart

  local exp
  exp="$(openssl x509 -in "/etc/letsencrypt/live/${dom}/fullchain.pem" -noout -enddate 2>/dev/null | cut -d'=' -f2 || true)"
  write_tls_state "TLS: Let's Encrypt for ${dom} (expires: ${exp:-unknown})"

  [[ "${port}" == "443" ]] && echo "[+] Use domain: ${dom}" || echo "[+] Use domain: ${dom}:${port}"
}

renew_now(){
  need_root
  command -v certbot >/dev/null 2>&1 || { echo "certbot not installed. Enable Domain+SSL first."; return 1; }
  certbot renew --quiet || true
  local dom exp
  dom="$(domain_get)"
  if [[ -n "${dom}" && -f "/etc/letsencrypt/live/${dom}/fullchain.pem" ]]; then
    exp="$(openssl x509 -in "/etc/letsencrypt/live/${dom}/fullchain.pem" -noout -enddate 2>/dev/null | cut -d'=' -f2 || true)"
    write_tls_state "TLS: Let's Encrypt for ${dom} (expires: ${exp:-unknown})"
  fi
  echo "Renew attempted."
}

tail_logs(){ compose logs --tail 200 -f; }
restart_svc(){ compose restart; }
update_image(){ compose pull && compose up -d; }

main(){
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
      6) tail_logs ;;
      7) restart_svc ;;
      8) update_image ;;
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
  ln -sf "${MANAGER}" "${SYMLINK_CAP}"
  ln -sf "${MANAGER}" "${SYMLINK_LOW}"
}
