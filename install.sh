#!/usr/bin/env bash
set -euo pipefail

########################################
# CONFIG (edit as needed)
########################################
PIHOLE_WEB_PORT=8080

# Squid / proxy config
PROXY_PORT="3128" # Use to add misp.local to chromium proxy settings both http and https and make CA trust installing
## sudo cp /etc/squid/ssl_cert/myCA.crt /usr/local/share/ca-certificates/squid-proxy.crt
## sudo update-ca-certificates - 
SQUID_USER="proxy"
SQUID_GROUP="proxy"
CA_DIR="/etc/squid/ssl_cert"
SSL_DB_DIR="/var/lib/squid/ssl_db"
MISP_LIST_DIR="/opt/misp-proxy/lists"
MISP_URL_REGEX_FILE="${MISP_LIST_DIR}/misp_blocked_url_regex.txt"
SQUID_CONF="/etc/squid/squid.conf"

# DN info for the local CA & server cert
ORG_COUNTRY="EE"
ORG_STATE="Harju"
ORG_LOCALITY="Tallinn"
ORG_NAME="YourOrg"
ORG_UNIT="IT"
CA_CN="YourOrg Proxy CA"
SERVER_CN="$(hostname -f 2>/dev/null || hostname)"

# Optionally seed the MISP regex file from these paths if present
SEED_LISTS=(
  "${HOME}/Documents/misp_blocked_url_regex.txt"
  "/opt/misp-proxy/misp_blocked_url_regex.txt"
)

########################################
# Helpers
########################################
say()   { echo -e "[+] $*"; }
info()  { echo -e "[i]  $*"; }
warn()  { echo -e "[!] $*" >&2; }
die()   { echo -e "[x] $*" >&2; exit 1; }

have_cmd() { command -v "$1" >/dev/null 2>&1; }
svc_exists() { systemctl list-unit-files | grep -q "^$1"; }
require_root() { [ "$(id -u)" -eq 0 ] || die "Please run as root (sudo)."; }

ensure_pkgs() {
  say "Installing base packages..."
  apt-get update -y
  DEBIAN_FRONTEND=noninteractive apt-get install -y \
    curl wget git ca-certificates openssl ssl-cert
}

########################################
# Step 1: MISP (install if missing)
########################################
install_misp_if_missing() {
  if [ -d /var/www/MISP ] || [ -f /etc/apache2/sites-available/misp.conf ] || [ -f /etc/nginx/sites-available/misp.conf ]; then
    info "MISP appears to be installed already — skipping install."
  else
    say "Installing MISP (idempotent)…"
    ensure_pkgs
    wget -O /tmp/INSTALL.ubuntu2404.sh https://raw.githubusercontent.com/MISP/MISP/refs/heads/2.5/INSTALL/INSTALL.ubuntu2404.sh
    chmod +x /tmp/INSTALL.ubuntu2404.sh
    # '-c' = core-only non-interactive routine from upstream
    bash /tmp/INSTALL.ubuntu2404.sh -c
  fi

  # Add misp.local to hosts (idempotent)
  if ! grep -q "misp.local" /etc/hosts; then
    say "Adding misp.local to /etc/hosts"
    echo "127.0.0.1 misp.local" >> /etc/hosts
  else
    info "misp.local already present in /etc/hosts"
  fi

  say "MISP ready (expected on https://misp.local/)."
}

########################################
# Step 2: Pi-hole (install if missing)
########################################
install_pihole_if_missing() {
  if have_cmd pihole || svc_exists pihole-FTL.service; then
    info "Pi-hole appears to be installed — ensuring config."
  else
    say "Installing Pi-hole unattended…"
    curl -sSL https://install.pi-hole.net | bash /dev/stdin --unattended
  fi

  # Ensure port config in TOML (idempotent)
  local PIHOLE_TOML="/etc/pihole/pihole.toml"
  local PORT_LINE='port = "8080o,8443os,[::]:8080o,[::]:8443os"'
  mkdir -p /etc/pihole
  if grep -E '^[[:space:]]*(#\s*)?port\s*=' "$PIHOLE_TOML" >/dev/null 2>&1; then
    sed -E -i "s|^[[:space:]]*(#\s*)?port\s*=.*|$PORT_LINE|" "$PIHOLE_TOML"
  else
    echo "$PORT_LINE" >> "$PIHOLE_TOML"
  fi

  systemctl restart pihole-FTL || true
  say "Pi-hole ready (http://misp.local:${PIHOLE_WEB_PORT}/admin)."
}

########################################
# Step 3: Squid + ssl-bump + MISP URL blocking
########################################
install_or_update_squid() {
  say "Installing Squid (if needed)…"
  apt-get update -y
  DEBIAN_FRONTEND=noninteractive apt-get install -y squid squid-common squid-langpack

  # Confirm OpenSSL support (should show --with-openssl and --enable-ssl-crtd)
  if ! squid -v | grep -q -- "--with-openssl"; then
    warn "Squid was built without OpenSSL; installing squid-openssl (if available)…"
    apt-get install -y squid-openssl || true
  fi

  say "Preparing directories…"
  mkdir -p "${CA_DIR}" "${SSL_DB_DIR}" "${MISP_LIST_DIR}"
  chown -R "${SQUID_USER}:${SQUID_GROUP}" "${CA_DIR}" || true

  # Seed/ensure MISP URL regex file
  if [ ! -s "${MISP_URL_REGEX_FILE}" ]; then
    for f in "${SEED_LISTS[@]}"; do
      if [ -f "$f" ]; then
        info "Seeding URL regex list from $f"
        cp -f "$f" "${MISP_URL_REGEX_FILE}"
        break
      fi
    done
    touch "${MISP_URL_REGEX_FILE}"
  fi
  chown "${SQUID_USER}:${SQUID_GROUP}" "${MISP_URL_REGEX_FILE}" || true

  # Generate CA if missing
  if [ ! -f "${CA_DIR}/myCA.key" ]; then
    say "Generating local CA for HTTPS interception…"
    openssl genrsa -out "${CA_DIR}/myCA.key" 2048
    openssl req -x509 -new -nodes -key "${CA_DIR}/myCA.key" -sha256 -days 3650 \
      -out "${CA_DIR}/myCA.crt" \
      -subj "/C=${ORG_COUNTRY}/ST=${ORG_STATE}/L=${ORG_LOCALITY}/O=${ORG_NAME}/OU=${ORG_UNIT}/CN=${CA_CN}"
  else
    info "Local CA already exists — reusing."
  fi

  # Generate/refresh Squid server cert signed by our CA (keep crt & key)
  say "Ensuring Squid server cert signed by local CA…"
  openssl genrsa -out "${CA_DIR}/myServer.key" 2048
  openssl req -new -key "${CA_DIR}/myServer.key" -out "${CA_DIR}/myServer.csr" \
    -subj "/C=${ORG_COUNTRY}/ST=${ORG_STATE}/L=${ORG_LOCALITY}/O=${ORG_NAME}/OU=${ORG_UNIT}/CN=${SERVER_CN}"
  openssl x509 -req -in "${CA_DIR}/myServer.csr" -CA "${CA_DIR}/myCA.crt" -CAkey "${CA_DIR}/myCA.key" \
    -CAcreateserial -out "${CA_DIR}/myServer.crt" -days 3650 -sha256
  chown -R "${SQUID_USER}:${SQUID_GROUP}" "${CA_DIR}"
  chmod 640 "${CA_DIR}/myServer.key" "${CA_DIR}/myServer.crt" || true

  # Detect ssl_crtd helper (prefer ssl_crtd over security_file_certgen)
  say "Detecting ssl_crtd helper…"
  local SSL_CRTD=""
  for CAND in \
    /usr/libexec/squid/ssl_crtd \
    /usr/lib/squid/ssl_crtd \
    /usr/libexec/squid/security_file_certgen \
    /usr/lib/squid/security_file_certgen
  do
    if [ -x "$CAND" ]; then SSL_CRTD="$CAND"; break; fi
  done

  if [ -z "$SSL_CRTD" ]; then
    warn "Could not find ssl_crtd/security_file_certgen — ssl-bump will NOT work!"
  else
    say "Using helper: $SSL_CRTD"
    # Ensure parent owned by squid user and create DB as squid user
    mkdir -p "$(dirname "${SSL_DB_DIR}")"
    chown "${SQUID_USER}:${SQUID_GROUP}" "$(dirname "${SSL_DB_DIR}")" || true

    rm -rf "${SSL_DB_DIR}"
    # security_file_certgen requires -M during create; ssl_crtd accepts it too
    sudo -u "${SQUID_USER}" "${SSL_CRTD}" -c -s "${SSL_DB_DIR}" -M 16MB

    chown -R "${SQUID_USER}:${SQUID_GROUP}" "${SSL_DB_DIR}"
    chmod 700 "${SSL_DB_DIR}"
  fi

  # Backup existing squid.conf once
  if [ -f "$SQUID_CONF" ] && ! grep -q "# MISP-PIHOLE-SQUID" "$SQUID_CONF" 2>/dev/null; then
    cp "$SQUID_CONF" "/etc/squid/squid.conf.bak.$(date +%Y%m%d%H%M%S)" || true
  fi

  # Write a modern Squid 6 config using tls-cert/tls-key and the detected helper
  cat > "$SQUID_CONF" <<SQUID
# MISP-PIHOLE-SQUID  (managed by installer)
http_port ${PROXY_PORT} ssl-bump tls-cert=${CA_DIR}/myServer.crt tls-key=${CA_DIR}/myServer.key generate-host-certificates=on dynamic_cert_mem_cache_size=16MB

# Dynamic certificate generator (detected helper)
sslcrtd_program ${SSL_CRTD:-/usr/libexec/squid/ssl_crtd} -s ${SSL_DB_DIR} -M 16MB
sslcrtd_children 5 startup=1 idle=1

# Allow LANs
acl localnet src 127.0.0.1/32
acl localnet src 10.0.0.0/8
acl localnet src 172.16.0.0/12
acl localnet src 192.168.0.0/16

# Block URLs from MISP list (regex)
acl misp_urls url_regex -i "${MISP_URL_REGEX_FILE}"

# SSL-bump rules
acl step1 at_step SslBump1
ssl_bump peek step1
ssl_bump bump all

# Policy: block MISP URLs first, then allow LAN, deny rest
http_access deny misp_urls
http_access allow localnet
http_access deny all

# Logging
access_log /var/log/squid/access.log
cache_log  /var/log/squid/cache.log

# Outbound trust bundle
tls_outgoing_options cafile=/etc/ssl/certs/ca-certificates.crt
SQUID

  say "Initializing Squid cache dir…"
  squid -z || true

  say "Validating squid.conf…"
  if ! squid -k parse; then
    die "squid.conf failed to parse — see the error above."
  fi

  say "Restarting Squid…"
  systemctl enable squid >/dev/null 2>&1 || true
  systemctl restart squid || (journalctl -xeu squid.service | sed -n '1,120p' ; exit 1)

  say "Squid is running on port ${PROXY_PORT}"
  echo "CA to deploy to clients: ${CA_DIR}/myCA.crt"
  echo "MISP URL regex list:     ${MISP_URL_REGEX_FILE}"
}

########################################
# Run all steps
########################################
require_root

say "System update…"
apt-get update -y && apt-get upgrade -y

install_misp_if_missing
install_pihole_if_missing
install_or_update_squid

echo
say "DONE."
echo "Next steps:"
echo "  1) Point clients' HTTP/HTTPS proxy to: http://$(hostname -f 2>/dev/null || hostname):${PROXY_PORT}"
echo "  2) Install the proxy CA on clients: ${CA_DIR}/myCA.crt"
echo "  3) Ensure your MISP fetcher writes URL regexes to:"
echo "     ${MISP_URL_REGEX_FILE}  (reload Squid after updates: systemctl reload squid)"
echo "  4) Watch logs: tail -f /var/log/squid/access.log"
