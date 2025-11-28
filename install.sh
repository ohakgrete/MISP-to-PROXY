#!/usr/bin/env bash
set -euo pipefail

########################################
# CONFIG
########################################
PIHOLE_WEB_PORT=8080

PROXY_PORT="3128"
SQUID_USER="proxy"
SQUID_GROUP="proxy"

CA_DIR="/etc/squid/ssl_cert"
SSL_DB_DIR="/var/lib/squid/ssl_db"
MISP_LIST_DIR="/opt/misp-proxy/lists"
MISP_URL_REGEX_FILE="${MISP_LIST_DIR}/misp_blocked_url_regex.txt"
MISP_DOMAIN_FILE="${MISP_LIST_DIR}/misp_blocked_domains.txt"    # for Pi-hole / other scripts
SQUID_CONF="/etc/squid/squid.conf"
LOG_URL_ONLY="/var/log/squid/url-only.log"

ORG_COUNTRY="EE"
ORG_STATE="Harju"
ORG_LOCALITY="Tallinn"
ORG_NAME="YourOrg"
ORG_UNIT="IT"
CA_CN="YourOrg Proxy CA"
SERVER_CN="$(hostname -f 2>/dev/null || hostname)"

# user-seeded regex list (optional)
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

require_root() { [ "$(id -u)" -eq 0 ] || die "Please run as root (sudo)."; }
have_cmd()     { command -v "$1" >/dev/null 2>&1; }
svc_exists()   { systemctl list-unit-files | grep -q "^$1"; }

ensure_base_pkgs() {
  say "Ensuring base packages…"
  apt-get update -y
  DEBIAN_FRONTEND=noninteractive apt-get install -y \
    ca-certificates openssl ssl-cert libnss3-tools \
    curl wget git squid-openssl squid-common squid-langpack
}

# verify CA is v3 + CA:TRUE
ca_is_good() {
  local cafile="$1"
  [ -f "$cafile" ] || return 1
  local txt
  txt="$(openssl x509 -in "$cafile" -noout -text 2>/dev/null || true)"
  echo "$txt" | grep -q "Version: 3" || return 1
  echo "$txt" | grep -q "Basic Constraints:.*CA:TRUE" || return 1
  echo "$txt" | grep -q "Key Usage:.*Cert Sign" || return 1
  return 0
}

########################################
# MISP
########################################
install_misp_if_missing() {
  if [ -d /var/www/MISP ] || \
     [ -f /etc/apache2/sites-available/misp.conf ] || \
     [ -f /etc/nginx/sites-available/misp.conf ]; then
    info "MISP already installed – skipping."
  else
    say "Installing MISP (core-only script)…"
    ensure_base_pkgs
    wget -O /tmp/INSTALL.ubuntu2404.sh \
      https://raw.githubusercontent.com/MISP/MISP/refs/heads/2.5/INSTALL/INSTALL.ubuntu2404.sh
    chmod +x /tmp/INSTALL.ubuntu2404.sh
    bash /tmp/INSTALL.ubuntu2404.sh -c
  fi

  if ! grep -q "misp.local" /etc/hosts; then
    echo "127.0.0.1 misp.local" >> /etc/hosts
  fi
  say "MISP ready on https://misp.local/"
}

########################################
# Pi-hole
########################################
install_pihole_if_missing() {
  if have_cmd pihole || svc_exists pihole-FTL.service; then
    info "Pi-hole already installed – ensuring config."
  else
    say "Installing Pi-hole unattended…"
    curl -sSL https://install.pi-hole.net | bash /dev/stdin --unattended
  fi

  ######################################################
  # 1) Web port (so it doesn't collide with anything)
  ######################################################
  local PIHOLE_TOML="/etc/pihole/pihole.toml"
  local PORT_LINE='port = "8080o,8443os,[::]:8080o,[::]:8443os"'
  mkdir -p /etc/pihole
  if grep -Eq '^[[:space:]]*(#\s*)?port\s*=' "$PIHOLE_TOML" 2>/dev/null; then
    sed -E -i "s|^[[:space:]]*(#\s*)?port\s*=.*|$PORT_LINE|" "$PIHOLE_TOML"
  else
    echo "$PORT_LINE" >> "$PIHOLE_TOML"
  fi

  ######################################################
  # 2) Make sure Pi-hole actually logs DNS queries
  #    (time + client IP + domain + status)
  ######################################################
  say "Enabling Pi-hole DNS query logging…"

  # Preferred, version-independent way
  if have_cmd pihole; then
    # This turns on both FTL DB logging and the dnsmasq/FTL query log
    pihole logging on || warn "pihole logging on failed – continuing anyway."
  fi

  # Additional safety net for newer FTL versions (if available)
  if have_cmd pihole-FTL; then
    pihole-FTL --config dns.queryLogging=true || true
  fi

  ######################################################
  # 3) Make sure we have a stable DNS query logfile path
  ######################################################
  # Classic Pi-hole path is /var/log/pihole.log
  # Your scripts use /var/log/pihole/pihole.log – keep that working.
  mkdir -p /var/log/pihole

  # If classic log exists but the subdir one does not, create a symlink
  if [ -e /var/log/pihole.log ] && [ ! -e /var/log/pihole/pihole.log ]; then
    ln -sf /var/log/pihole.log /var/log/pihole/pihole.log
  fi

  # If neither exists yet, create the file we want and let FTL/dnsmasq append
  if [ ! -e /var/log/pihole.log ] && [ ! -e /var/log/pihole/pihole.log ]; then
    touch /var/log/pihole/pihole.log
  fi

  # Ensure FTL can write – user/group names may differ slightly per install,
  # so we try pihole and fall back to root if needed.
  chown pihole:pihole /var/log/pihole/pihole.log 2>/dev/null || \
    chown root:root /var/log/pihole/pihole.log 2>/dev/null || true

  ######################################################
  # 4) (Optional) dnsmasq-level logging override if needed
  #    Only add if *no* existing dnsmasq conf uses log-queries/log-facility
  ######################################################
  if [ -d /etc/dnsmasq.d ] && ! grep -Rqs "log-queries" /etc/dnsmasq.d 2>/dev/null; then
    say "Adding explicit dnsmasq logging config for Pi-hole…"
    cat > /etc/dnsmasq.d/99-misp-logging.conf <<'EOF'
# Added by MISP proxy installer – DNS query logging for retrohunt
log-queries
log-facility=/var/log/pihole/pihole.log
EOF
  fi

  ######################################################
  # 5) Restart FTL so all logging settings are applied
  ######################################################
  systemctl restart pihole-FTL || true

  say "Pi-hole ready on http://misp.local:${PIHOLE_WEB_PORT}/admin"
  echo "  - DNS query log (for retrohunt): /var/log/pihole/pihole.log"
  echo "    Each line contains timestamp + resolver + client IP + query/response."
}

########################################
# Squid: CA + ssl-bump + URL logging
########################################
install_or_update_squid() {
  say "Ensuring Squid (squid-openssl) and dependencies…"
  ensure_base_pkgs

  #######################
  # 1) Helper discovery
  #######################
  say "Locating helpers…"
  local SSL_HELPER=""
  if [ -x /usr/lib/squid/ssl_crtd ]; then
    SSL_HELPER="/usr/lib/squid/ssl_crtd"
  elif [ -x /usr/lib/squid/security_file_certgen ]; then
    warn "ssl_crtd not found; falling back to security_file_certgen"
    SSL_HELPER="/usr/lib/squid/security_file_certgen"
  else
    die "No ssl_crtd/security_file_certgen found (squid-openssl should provide one)."
  fi

  ############################
  # 2) Directories + MISP lists
  ############################
  say "Preparing directories and MISP list files…"
  mkdir -p "${CA_DIR}" "${MISP_LIST_DIR}"

  # Seed regex list if empty
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
  touch "${MISP_DOMAIN_FILE}"

  chown -R "${SQUID_USER}:${SQUID_GROUP}" "${MISP_LIST_DIR}" || true

  ########################################
  # 3) OpenSSL config and CA/server certs
  ########################################
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

# Root CA profile – *no* extendedKeyUsage here.
[ v3_ca ]
subjectKeyIdentifier   = hash
authorityKeyIdentifier = keyid:always,issuer
basicConstraints       = critical, CA:true
keyUsage               = critical, keyCertSign, cRLSign

# Profile for the Squid listening certificate (normal TLS server).
[ server_cert ]
subjectKeyIdentifier   = hash
authorityKeyIdentifier = keyid,issuer
basicConstraints       = CA:false
keyUsage               = critical, digitalSignature, keyEncipherment
extendedKeyUsage       = serverAuth
subjectAltName         = @alt_names

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

  # (Re)generate CA if not valid
  if ca_is_good "${CA_CRT}"; then
    info "Existing CA looks fine: ${CA_CRT}"
  else
    say "Generating new v3 CA for Squid bump…"
    rm -f "${CA_KEY}" "${CA_CRT}" || true
    openssl genrsa -out "${CA_KEY}" 4096
    openssl req -x509 -new -nodes -key "${CA_KEY}" -sha256 -days 3650 \
      -out "${CA_CRT}" -config "${OPENSSL_CONF}" -extensions v3_ca
  fi

  # Server cert (used only for the proxy endpoint itself)
  say "Issuing server certificate from CA…"
  openssl genrsa -out "${SERVER_KEY}" 2048
  openssl req -new -key "${SERVER_KEY}" -out "${SERVER_CSR}" \
    -subj "/C=${ORG_COUNTRY}/ST=${ORG_STATE}/L=${ORG_LOCALITY}/O=${ORG_NAME}/OU=${ORG_UNIT}/CN=${SERVER_CN}"
  openssl x509 -req -in "${SERVER_CSR}" -CA "${CA_CRT}" -CAkey "${CA_KEY}" -CAcreateserial \
    -out "${SERVER_CRT}" -days 3650 -sha256 -extfile "${OPENSSL_CONF}" -extensions server_cert

  chown -R "${SQUID_USER}:${SQUID_GROUP}" "${CA_DIR}" || true
  chmod 600 "${CA_KEY}" "${SERVER_KEY}" || true
  chmod 644 "${CA_CRT}" "${SERVER_CRT}" || true

  ########################################
  # 4) Install CA into system trust (curl, etc.)
  ########################################
  say "Installing CA into system trust store…"
  mkdir -p /usr/local/share/ca-certificates
  cp -f "${CA_CRT}" /usr/local/share/ca-certificates/misp-proxy-ca.crt
  chmod 644 /usr/local/share/ca-certificates/misp-proxy-ca.crt
  update-ca-certificates

  ########################################
  # 5) Make CA visible to Firefox (snap-friendly)
  ########################################
  say "Installing Firefox enterprise policy to trust CA…"
  mkdir -p /etc/firefox/certs /etc/firefox/policies
  cp -f "${CA_CRT}" /etc/firefox/certs/misp-proxy-ca.crt
  chmod 644 /etc/firefox/certs/misp-proxy-ca.crt

  cat > /etc/firefox/policies/policies.json <<'POL'
{
  "policies": {
    "Certificates": {
      "Install": ["/etc/firefox/certs/misp-proxy-ca.crt"]
    }
  }
}
POL

  ########################################
  # 6) Initialize ssl_db
  ########################################
  say "Initializing ssl_db (helper: ${SSL_HELPER})…"

  # Clean any old DB
  rm -rf "${SSL_DB_DIR}" 2>/dev/null || true

  # Ensure parent directory exists and is writable by 'proxy'
  SSL_DB_PARENT="$(dirname "${SSL_DB_DIR}")"
  mkdir -p "${SSL_DB_PARENT}"

  # Typical Debian/Ubuntu defaults: root:proxy 750 on /var/lib/squid
  chown root:"${SQUID_GROUP}" "${SSL_DB_PARENT}" || true
  chmod 750 "${SSL_DB_PARENT}" || true

  # First try as 'proxy' user (recommended)
  say "  -> Creating ssl_db as ${SQUID_USER} in ${SSL_DB_DIR}"
  if sudo -u "${SQUID_USER}" "${SSL_HELPER}" -c -s "${SSL_DB_DIR}" -M 16MB \
       >/tmp/ssl_db_init.log 2>&1; then
    info "ssl_db initialized by ${SQUID_USER}"
  else
    warn "ssl_db init as ${SQUID_USER} failed, trying as root…"
    sed -n '1,40p' /tmp/ssl_db_init.log >&2 || true

    # Fallback: run helper as root
    if "${SSL_HELPER}" -c -s "${SSL_DB_DIR}" -M 16MB \
         >/tmp/ssl_db_init.log 2>&1; then
      info "ssl_db initialized by root"
    else
      warn "Helper failed to initialize ${SSL_DB_DIR}"
      sed -n '1,80p' /tmp/ssl_db_init.log >&2 || true
      die "Failed to initialize ssl_db with ${SSL_HELPER}"
    fi
  fi

  # Final ownership + permissions
  chown -R "${SQUID_USER}:${SQUID_GROUP}" "${SSL_DB_DIR}" || true
  chmod 700 "${SSL_DB_DIR}" || true

  ########################################
  # 7) Squid config – full bump + URL logging
  ########################################
  if [ -f "${SQUID_CONF}" ] && ! grep -q "MISP-PIHOLE-SQUID" "${SQUID_CONF}" 2>/dev/null; then
    cp "${SQUID_CONF}" "/etc/squid/squid.conf.bak.$(date +%Y%m%d%H%M%S)" || true
  fi

  say "Writing Squid config (explicit proxy + ssl-bump + url-only log)…"
  mkdir -p /etc/squid
  cat > "${SQUID_CONF}" <<SQUID
# MISP-PIHOLE-SQUID (managed by install.sh)

# Explicit proxy with ssl-bump; clients must be configured to use this proxy.
http_port ${PROXY_PORT} ssl-bump cert=${CA_CRT} key=${CA_KEY} generate-host-certificates=on dynamic_cert_mem_cache_size=16MB

sslcrtd_program ${SSL_HELPER} -s ${SSL_DB_DIR} -M 16MB
sslcrtd_children 8 startup=1 idle=1

acl step1 at_step SslBump1
ssl_bump peek step1
ssl_bump bump all

# Local networks
acl localnet src 127.0.0.1/32
acl localnet src 10.0.0.0/8
acl localnet src 172.16.0.0/12
acl localnet src 192.168.0.0/16

# MISP URL regex list (HTTP + HTTPS via bump)
acl misp_urls url_regex -i "${MISP_URL_REGEX_FILE}"

# Access policy
http_access deny misp_urls
http_access allow localnet
http_access deny all

# Do not strip path/query from logged URL
strip_query_terms off
uri_whitespace encode

# Full access log (includes client IP, URL, status, etc.)
logformat custom "%ts.%03tu %>a %un \"%>rm %>ru %rv\" %>Hs %<st %Ss:%Sh"
access_log /var/log/squid/access.log custom

# URL-only retrohunt log:
#   time | client IP | username | method | full URL
logformat urlonly "%ts.%03tu %>a %un %>rm %>ru"
access_log ${LOG_URL_ONLY} urlonly

tls_outgoing_options cafile=/etc/ssl/certs/ca-certificates.crt
SQUID

  mkdir -p /var/log/squid
  chown "${SQUID_USER}:${SQUID_GROUP}" /var/log/squid || true

  say "Validating squid.conf…"
  squid -k parse

  say "Initializing Squid cache dir…"
  squid -z || true

  say "Enabling and starting Squid service…"
  systemctl enable squid >/dev/null 2>&1 || true
  systemctl restart squid || (journalctl -xeu squid.service | sed -n '1,160p'; exit 1)

  say "Squid is running on port ${PROXY_PORT}"
  echo "  - URL log (retronhunt): ${LOG_URL_ONLY}"
  echo "  - System CA: /usr/local/share/ca-certificates/misp-proxy-ca.crt"
  echo "  - Firefox CA: /etc/firefox/certs/misp-proxy-ca.crt"
  echo "  - Firefox policy: /etc/firefox/policies/policies.json"
}

########################################
# Main
########################################
require_root

install_misp_if_missing
install_pihole_if_missing
install_or_update_squid

echo
say "DONE."
echo "Set your browser / curl proxy to: http://$(hostname -f 2>/dev/null || hostname):${PROXY_PORT}"
echo "Check curl trust with:"
echo "  curl -x http://misp.local:${PROXY_PORT} https://www.neti.ee -v"
echo "Squid retrohunt log (IP + URL):"
echo "  sudo tail -f ${LOG_URL_ONLY}"
echo "Pi-hole DNS log (IP + domain):"
echo "  sudo tail -f /var/log/pihole/pihole.log"
