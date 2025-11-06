#!/usr/bin/env bash
set -euo pipefail

########################################
# CONFIG
########################################
PIHOLE_WEB_PORT=8080

# Squid / proxy config
PROXY_PORT="3128"
SQUID_USER="proxy"
SQUID_GROUP="proxy"
CA_DIR="/etc/squid/ssl_cert"
SSL_DB_DIR="/var/lib/squid/ssl_db"
MISP_LIST_DIR="/opt/misp-proxy/lists"
MISP_URL_REGEX_FILE="${MISP_LIST_DIR}/misp_blocked_url_regex.txt"
MISP_DOMAIN_FILE="${MISP_LIST_DIR}/misp_blocked_domains.txt"
SQUID_CONF="/etc/squid/squid.conf"

# DN info for the local CA & server cert
ORG_COUNTRY="EE"
ORG_STATE="Harju"
ORG_LOCALITY="Tallinn"
ORG_NAME="YourOrg"
ORG_UNIT="IT"
CA_CN="YourOrg Proxy CA"
SERVER_CN="$(hostname -f 2>/dev/null || hostname)"

# Where to probe for a user-generated list to seed the proxy (optional)
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
    curl wget git ca-certificates openssl ssl-cert squid squid-common squid-langpack \
    libnss3-tools
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
    bash /tmp/INSTALL.ubuntu2404.sh -c
  fi

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
# Helper: check CA is v3 & CA:TRUE
########################################
ca_is_good() {
  local cafile="$1"
  [ -f "$cafile" ] || return 1
  local ver
  ver=$(openssl x509 -in "$cafile" -noout -text 2>/dev/null | sed -n '1,40p' | grep -E 'Version:' || true)
  if echo "$ver" | grep -q "Version: 3"; then
    if openssl x509 -in "$cafile" -noout -text 2>/dev/null | grep -q "X509v3 Basic Constraints:.*CA:TRUE"; then
      return 0
    fi
  fi
  return 1
}

########################################
# Step 3: Squid + ssl-bump (if helper) + CA + MISP lists
########################################
install_or_update_squid() {
  say "Installing Squid (and deps)…"
  ensure_pkgs

  say "Preparing directories…"
  mkdir -p "${CA_DIR}" "${SSL_DB_DIR}" "${MISP_LIST_DIR}"
  chown -R "${SQUID_USER}:${SQUID_GROUP}" "${CA_DIR}" "${SSL_DB_DIR}" || true
  chmod 700 "${CA_DIR}" || true

  # Ensure list files exist
  [ -s "${MISP_URL_REGEX_FILE}" ] || {
    for f in "${SEED_LISTS[@]}"; do
      if [ -f "$f" ]; then
        info "Seeding URL regex list from $f"
        cp -f "$f" "${MISP_URL_REGEX_FILE}"
        break
      fi
    done
    touch "${MISP_URL_REGEX_FILE}"
  }
  [ -s "${MISP_DOMAIN_FILE}" ] || touch "${MISP_DOMAIN_FILE}"
  chown "${SQUID_USER}:${SQUID_GROUP}" "${MISP_URL_REGEX_FILE}" "${MISP_DOMAIN_FILE}" || true

  # v3 CA + server cert
  local OPENSSL_CONF="/tmp/openssl-squid-ca.cnf"
  cat > "${OPENSSL_CONF}" <<EOF
[ req ]
default_bits       = 4096
prompt             = no
distinguished_name = dn
x509_extensions    = v3_ca

[ dn ]
C=${ORG_COUNTRY}
ST=${ORG_STATE}
L=${ORG_LOCALITY}
O=${ORG_NAME}
OU=${ORG_UNIT}
CN=${CA_CN}

[ v3_ca ]
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always,issuer
basicConstraints = critical, CA:true
keyUsage = critical, digitalSignature, cRLSign, keyCertSign

[ server_cert ]
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid,issuer
basicConstraints = CA:FALSE
keyUsage = critical, digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth
subjectAltName = @alt_names

[ alt_names ]
DNS.1 = ${SERVER_CN}
DNS.2 = localhost
IP.1  = 127.0.0.1
EOF

  local CA_KEY="${CA_DIR}/myCA.key"
  local CA_CRT="${CA_DIR}/myCA.crt"
  local SERVER_KEY="${CA_DIR}/myServer.key"
  local SERVER_CSR="${CA_DIR}/myServer.csr"
  local SERVER_CRT="${CA_DIR}/myServer.crt"

  if ca_is_good "$CA_CRT"; then
    info "Existing CA is a valid v3 CA — reusing."
  else
    say "Generating new v3 CA…"
    openssl genrsa -out "${CA_KEY}" 4096
    openssl req -x509 -new -nodes -key "${CA_KEY}" -sha256 -days 3650 \
      -out "${CA_CRT}" -config "${OPENSSL_CONF}" -extensions v3_ca
    chmod 600 "${CA_KEY}"
    chown "${SQUID_USER}:${SQUID_GROUP}" "${CA_KEY}" "${CA_CRT}" || true
  fi

  say "Issuing server certificate from CA…"
  openssl genrsa -out "${SERVER_KEY}" 2048
  openssl req -new -key "${SERVER_KEY}" -out "${SERVER_CSR}" \
    -subj "/C=${ORG_COUNTRY}/ST=${ORG_STATE}/L=${ORG_LOCALITY}/O=${ORG_NAME}/OU=${ORG_UNIT}/CN=${SERVER_CN}"
  openssl x509 -req -in "${SERVER_CSR}" -CA "${CA_CRT}" -CAkey "${CA_KEY}" -CAcreateserial \
    -out "${SERVER_CRT}" -days 3650 -sha256 -extfile "${OPENSSL_CONF}" -extensions server_cert

  chown -R "${SQUID_USER}:${SQUID_GROUP}" "${CA_DIR}"
  chmod 640 "${SERVER_KEY}" || true
  chmod 644 "${SERVER_CRT}" "${CA_CRT}" || true

  # Trust the CA system-wide + Firefox policy
  say "Installing CA into system trust store…"
  cp "${CA_CRT}" /usr/local/share/ca-certificates/squid-proxy-ca.crt
  update-ca-certificates || true

  say "Installing Firefox enterprise policy…"
  mkdir -p /usr/lib/firefox/distribution
  cat > /usr/lib/firefox/distribution/policies.json <<'POL'
{
  "policies": {
    "Certificates": {
      "ImportEnterpriseRoots": true,
      "Install": ["/usr/local/share/ca-certificates/squid-proxy-ca.crt"]
    }
  }
}
POL

  # Helper discovery
  say "Detecting ssl_crtd/security_file_certgen helper…"
  local SSL_CRTD=""
  for CAND in \
    /usr/lib/squid/security_file_certgen \
    /usr/lib/squid/ssl_crtd \
    /usr/libexec/squid/security_file_certgen \
    /usr/libexec/squid/ssl_crtd
  do
    [ -x "$CAND" ] && SSL_CRTD="$CAND" && break
  done
  if [ -z "$SSL_CRTD" ]; then
    local DPKG_CAND
    DPKG_CAND="$(dpkg -L squid 2>/dev/null | grep -E '/(ssl_crtd|security_file_certgen)$' | head -n1 || true)"
    [ -n "$DPKG_CAND" ] && [ -x "$DPKG_CAND" ] && SSL_CRTD="$DPKG_CAND"
  fi
  if [ -z "$SSL_CRTD" ]; then
    local FIND_CAND
    FIND_CAND="$(find /usr -maxdepth 4 -type f -regextype posix-extended -regex '.*/(ssl_crtd|security_file_certgen)$' 2>/dev/null | head -n1 || true)"
    [ -n "$FIND_CAND" ] && [ -x "$FIND_CAND" ] && SSL_CRTD="$FIND_CAND"
  fi
  if [ -z "$SSL_CRTD" ]; then
    warn "Helper not found; reinstalling squid packages once…"
    apt-get update -y
    DEBIAN_FRONTEND=noninteractive apt-get install -y --reinstall squid squid-common squid-langpack || true
    # try again
    for CAND in \
      /usr/lib/squid/security_file_certgen \
      /usr/lib/squid/ssl_crtd \
      /usr/libexec/squid/security_file_certgen \
      /usr/libexec/squid/ssl_crtd
    do
      [ -x "$CAND" ] && SSL_CRTD="$CAND" && break
    done
  fi

  # Feature flags
  local HAS_SSLCRTD_FLAG=0
  local HAS_HELPER=0
  if squid -v 2>/dev/null | grep -q -- '--enable-ssl-crtd'; then
    HAS_SSLCRTD_FLAG=1
  fi
  if [ -n "$SSL_CRTD" ]; then
    HAS_HELPER=1
  fi

  # Initialize ssl_db only if helper is available
  if [ "$HAS_HELPER" -eq 1 ]; then
    say "Using helper: $SSL_CRTD"
    rm -rf "${SSL_DB_DIR}"
    mkdir -p "${SSL_DB_DIR}"
    chown "${SQUID_USER}:${SQUID_GROUP}" "$(dirname "${SSL_DB_DIR}")" || true
    sudo -u "${SQUID_USER}" "${SSL_CRTD}" -c -s "${SSL_DB_DIR}" -M 16MB
    chown -R "${SQUID_USER}:${SQUID_GROUP}" "${SSL_DB_DIR}"
    chmod 700 "${SSL_DB_DIR}"
  else
    warn "No helper available — will configure **NO ssl-bump** (domain blocking & CONNECT host logging only)."
  fi

  # Backup squid.conf once
  if [ -f "$SQUID_CONF" ] && ! grep -q "# MISP-PIHOLE-SQUID" "$SQUID_CONF" 2>/dev/null; then
    cp "$SQUID_CONF" "/etc/squid/squid.conf.bak.$(date +%Y%m%d%H%M%S)" || true
  fi

  # Write Squid config
  if [ "$HAS_HELPER" -eq 1 ] && [ "$HAS_SSLCRTD_FLAG" -eq 1 ]; then
    # Full MITM mode (urls + blocking by path)
    cat > "$SQUID_CONF" <<SQUID
# MISP-PIHOLE-SQUID  (managed by installer)
https_port ${PROXY_PORT} ssl-bump cert=${SERVER_CRT} key=${SERVER_KEY} generate-host-certificates=on dynamic_cert_mem_cache_size=16MB

sslcrtd_program ${SSL_CRTD} -s ${SSL_DB_DIR} -M 16MB
sslcrtd_children 8 startup=1 idle=1

# LAN
acl localnet src 127.0.0.1/32
acl localnet src 10.0.0.0/8
acl localnet src 172.16.0.0/12
acl localnet src 192.168.0.0/16

# MISP lists
acl misp_domains dstdomain "${MISP_DOMAIN_FILE}"
acl misp_urls    url_regex -i "${MISP_URL_REGEX_FILE}"

# Bump logic
acl step1 at_step SslBump1
ssl_bump peek step1
ssl_bump bump all

# Policy
http_access deny misp_urls
http_access deny misp_domains
http_access allow localnet
http_access deny all

# Logs: full URL in bump mode
logformat custom "%>a %ui %un [%tl] \\"%rm %ru %rv\\" %>Hs %<st %Ss:%Sh"
access_log /var/log/squid/access.log custom

tls_outgoing_options cafile=/etc/ssl/certs/ca-certificates.crt
SQUID
  else
    # Fallback: NO ssl-bump (cannot decrypt). We still block domains (dstdomain) and log CONNECT host.
    cat > "$SQUID_CONF" <<SQUID
# MISP-PIHOLE-SQUID (no-bump fallback)
http_port ${PROXY_PORT}

# LAN
acl localnet src 127.0.0.1/32
acl localnet src 10.0.0.0/8
acl localnet src 172.16.0.0/12
acl localnet src 192.168.0.0/16

# MISP lists
acl misp_domains dstdomain "${MISP_DOMAIN_FILE}"
acl misp_urls    url_regex -i "${MISP_URL_REGEX_FILE}"   # applies to HTTP only (not HTTPS CONNECT)

# Policy: domain block works for both HTTP and CONNECT
http_access deny misp_domains
http_access allow localnet
http_access deny all

# Logs: include CONNECT host:port in %>ru, HTTP gets full URL in %ru
logformat nobump "%>a %ui %un [%tl] \\"%rm %>ru %rv\\" %>Hs %<st %Ss:%Sh"
access_log /var/log/squid/access.log nobump
SQUID
  fi

  # Initialize cache and start
  say "Initializing Squid cache dir…"
  squid -z || true

  say "Validating squid.conf…"
  if ! squid -k parse; then
    die "squid.conf failed to parse — see errors above."
  fi

  say "Enabling and starting Squid service…"
  systemctl enable squid >/dev/null 2>&1 || true
  systemctl restart squid || (journalctl -xeu squid.service | sed -n '1,160p' ; exit 1)

  say "Squid is running on port ${PROXY_PORT}"
  echo "CA to deploy to clients (system trust): /usr/local/share/ca-certificates/squid-proxy-ca.crt"
  echo "Firefox policy file: /usr/lib/firefox/distribution/policies.json"
  echo "MISP domain list: ${MISP_DOMAIN_FILE}"
  echo "MISP URL regex list: ${MISP_URL_REGEX_FILE}"
  if [ "$HAS_HELPER" -eq 0 ]; then
    warn "Running in NO-BUMP mode (no HTTPS URL paths). You can still block by domain and log CONNECT hosts."
  fi
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
echo "  1) Point clients' proxy to: http://$(hostname -f 2>/dev/null || hostname):${PROXY_PORT}"
echo "  2) Install the proxy CA on clients (already in system store here)."
echo "  3) If helper becomes available later, re-run this script to enable full ssl-bump."
echo "  4) Tail logs:  sudo tail -f /var/log/squid/access.log"
