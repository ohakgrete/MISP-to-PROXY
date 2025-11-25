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
LOG_URL_ONLY="/var/log/squid/url-only.log"

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

have_cmd()     { command -v "$1" >/dev/null 2>&1; }
svc_exists()   { systemctl list-unit-files | grep -q "^$1"; }
require_root() { [ "$(id -u)" -eq 0 ] || die "Please run as root (sudo)."; }

ensure_base_pkgs() {
  say "Ensuring base packages…"
  apt-get update -y
  DEBIAN_FRONTEND=noninteractive apt-get install -y \
    ca-certificates openssl ssl-cert libnss3-tools \
    curl wget git \
    squid-openssl squid-common squid-langpack
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
# Step 1: MISP (install if missing)
########################################
install_misp_if_missing() {
  if [ -d /var/www/MISP ] || [ -f /etc/apache2/sites-available/misp.conf ] || [ -f /etc/nginx/sites-available/misp.conf ]; then
    info "MISP appears to be installed already — skipping install."
  else
    say "Installing MISP (idempotent)…"
    ensure_base_pkgs
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
# Squid helper discovery
########################################
find_squid_helper() {
  local helper=""
  # Prefer ssl_crtd, fallback to security_file_certgen
  for CAND in \
    /usr/lib/squid/ssl_crtd \
    /usr/lib/squid/security_file_certgen \
    /usr/libexec/squid/ssl_crtd \
    /usr/libexec/squid/security_file_certgen
  do
    [ -x "$CAND" ] && helper="$CAND" && break
  done
  echo "$helper"
}

########################################
# Automatically install Squid bump CA into system trust
########################################
install_squid_mitm_ca_to_system() {
  say "Extracting Squid MITM CA via openssl s_client…"

  local ALL_CERTS="/tmp/squid-mitm-all-$$.pem"
  local FOUND_CA=""
  local CERT_FILES=()

  # 1) Fetch the full chain from Squid via CONNECT
  if ! echo | openssl s_client \
        -proxy "127.0.0.1:${PROXY_PORT}" \
        -connect "www.neti.ee:443" \
        -servername "www.neti.ee" \
        -showcerts 2>/dev/null > "$ALL_CERTS"
  then
    warn "openssl s_client via proxy failed; cannot auto-extract Squid MITM CA."
    rm -f "$ALL_CERTS"
    return 1
  fi

  # 2) Split all certs into separate temp files
  awk '
    /BEGIN CERTIFICATE/ {
      if (out != "") close(out);
      n++;
      out=sprintf("/tmp/squid-mitm-%d-'"$$"' .pem", n);
    }
    { if (out != "") print > out }
    /END CERTIFICATE/ { out="" }
  ' "$ALL_CERTS"

  rm -f "$ALL_CERTS"

  # Build list of created files
  CERT_FILES=(/tmp/squid-mitm-*-"$$".pem)
  if [ ! -e "${CERT_FILES[0]}" ]; then
    warn "No certificates were extracted; cannot find Squid MITM CA."
    return 1
  fi

  # 3) Find self-signed CA (subject == issuer && CA:TRUE)
  for f in "${CERT_FILES[@]}"; do
    [ -f "$f" ] || continue

    local subj iss
    subj=$(openssl x509 -in "$f" -noout -subject 2>/dev/null || true)
    iss=$(openssl x509 -in "$f" -noout -issuer 2>/dev/null || true)

    if [ -z "$subj" ] || [ -z "$iss" ]; then
      continue
    fi

    if [ "$subj" = "$iss" ]; then
      # Check BasicConstraints CA:TRUE
      if openssl x509 -in "$f" -noout -text 2>/dev/null | grep -q "CA:TRUE"; then
        FOUND_CA="$f"
        break
      fi
    fi
  done

  if [ -z "$FOUND_CA" ]; then
    warn "Could not locate a self-signed CA certificate in the Squid chain."
    rm -f /tmp/squid-mitm-*-"$$".pem
    return 1
  fi

  say "Installing Squid MITM CA from $FOUND_CA to /usr/local/share/ca-certificates/squid-mitm.crt"
  cp "$FOUND_CA" /usr/local/share/ca-certificates/squid-mitm.crt
  rm -f /tmp/squid-mitm-*-"$$".pem

  # 4) Update system trust
  update-ca-certificates || warn "update-ca-certificates reported an issue (check output above)."

  info "System trust store updated; local tools like curl should now trust Squid-bumped HTTPS certs."
}


########################################
# Step 3: Squid + ssl-bump + CA + MISP lists + url-only log
########################################
install_or_update_squid() {
  ensure_base_pkgs

  say "Locating helpers…"
  local SSL_HELPER
  SSL_HELPER="$(find_squid_helper)"
  if [ -z "$SSL_HELPER" ]; then
    warn "No ssl_crtd/security_file_certgen helper found — reinstalling squid-openssl…"
    apt-get install -y --reinstall squid-openssl squid-common squid-langpack
    SSL_HELPER="$(find_squid_helper)"
  fi
  if [ -z "$SSL_HELPER" ]; then
    die "No ssl_crtd/security_file_certgen helper available; cannot enable ssl-bump."
  fi
  info "Using helper: $SSL_HELPER"

  say "Preparing directories and list files…"
  mkdir -p "${CA_DIR}" "${MISP_LIST_DIR}"
  # ssl_db will be created by helper
  rm -rf "${SSL_DB_DIR}"

  # Ensure lists exist
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
  [ -s "${MISP_DOMAIN_FILE}" ] || touch "${MISP_DOMAIN_FILE}"
  chown "${SQUID_USER}:${SQUID_GROUP}" "${MISP_URL_REGEX_FILE}" "${MISP_DOMAIN_FILE}" || true

  # Generate or reuse CA + server cert
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
    info "Reusing existing v3 CA: ${CA_CRT}"
  else
    say "Generating new local CA…"
    openssl genrsa -out "${CA_KEY}" 4096
    openssl req -x509 -new -nodes -key "${CA_KEY}" -sha256 -days 3650 \
      -out "${CA_CRT}" -config "${OPENSSL_CONF}" -extensions v3_ca
  fi

  say "Generating (or refreshing) server certificate…"
  openssl genrsa -out "${SERVER_KEY}" 2048
  openssl req -new -key "${SERVER_KEY}" -out "${SERVER_CSR}" \
    -subj "/C=${ORG_COUNTRY}/ST=${ORG_STATE}/L=${ORG_LOCALITY}/O=${ORG_NAME}/OU=${ORG_UNIT}/CN=${SERVER_CN}"
  openssl x509 -req -in "${SERVER_CSR}" -CA "${CA_CRT}" -CAkey "${CA_KEY}" -CAcreateserial \
    -out "${SERVER_CRT}" -days 3650 -sha256 -extfile "${OPENSSL_CONF}" -extensions server_cert

  chown -R "${SQUID_USER}:${SQUID_GROUP}" "${CA_DIR}" || true
  chmod 640 "${SERVER_KEY}" || true
  chmod 644 "${SERVER_CRT}" "${CA_CRT}" || true

  # Trust the "outer" proxy CA as well (this one is not the bump CA, but no harm)
  say "Trusting proxy CA system-wide…"
  cp "${CA_CRT}" /usr/local/share/ca-certificates/squid-proxy-ca.crt
  update-ca-certificates || true

  # Install Firefox enterprise policy
  say "Installing Firefox enterprise policy…"
  mkdir -p /usr/lib/firefox/distribution
  cat > /usr/lib/firefox/distribution/policies.json <<'POL'
{
  "policies": {
    "Certificates": {
      "ImportEnterpriseRoots": true,
      "Install": ["/usr/local/share/ca-certificates/squid-proxy-ca.crt", "/usr/local/share/ca-certificates/squid-mitm.crt"]
    }
  }
}
POL

  # Initialize ssl_db (helper creates directory)
  say "Initializing ssl_db (let helper create the directory)…"
  mkdir -p "$(dirname "${SSL_DB_DIR}")"
  if ! "${SSL_HELPER}" -c -s "${SSL_DB_DIR}" -M 16MB; then
    warn "Helper failed to initialize ssl_db at ${SSL_DB_DIR}"
  fi
  chown -R "${SQUID_USER}:${SQUID_GROUP}" "${SSL_DB_DIR}" || true
  chmod 700 "${SSL_DB_DIR}" || true

  # Backup squid.conf once
  if [ -f "$SQUID_CONF" ] && ! grep -q "# MISP-PIHOLE-SQUID" "$SQUID_CONF" 2>/dev/null; then
    cp "$SQUID_CONF" "/etc/squid/squid.conf.bak.$(date +%Y%m%d%H%M%S)" || true
  fi

  say "Writing Squid config (explicit proxy + ssl-bump + url-only log)…"
  cat > "$SQUID_CONF" <<SQUID
# MISP-PIHOLE-SQUID  (managed by installer)

# Explicit proxy port with ssl-bump
http_port ${PROXY_PORT} ssl-bump cert=${SERVER_CRT} key=${SERVER_KEY} generate-host-certificates=on dynamic_cert_mem_cache_size=16MB

# Dynamic certificate generator
sslcrtd_program ${SSL_HELPER} -s ${SSL_DB_DIR} -M 16MB
sslcrtd_children 8 startup=1 idle=1

# SSL bumping
acl step1 at_step SslBump1
ssl_bump peek step1
ssl_bump bump all

# LAN
acl localnet src 127.0.0.1/32
acl localnet src 10.0.0.0/8
acl localnet src 172.16.0.0/12
acl localnet src 192.168.0.0/16

# MISP lists
acl misp_domains dstdomain "${MISP_DOMAIN_FILE}"
acl misp_urls    url_regex -i "${MISP_URL_REGEX_FILE}"

# Access policy
http_access deny misp_urls
http_access deny misp_domains
http_access allow localnet
http_access deny all

# Do not strip query terms; encode whitespace
strip_query_terms off
uri_whitespace encode

# Logs
# 1) Full access log with full URL
logformat custom "%ts.%03tu %>a %un \"%>rm %>ru %rv\" %>Hs %<st %Ss:%Sh"
access_log /var/log/squid/access.log custom

# 2) URL-only log (method + full URL)
logformat urlonly "%>rm %>ru"
access_log ${LOG_URL_ONLY} urlonly

# Outbound trust (system CAs, including squid-proxy-ca.crt and squid-mitm.crt)
tls_outgoing_options cafile=/etc/ssl/certs/ca-certificates.crt
SQUID

  # Init cache and restart
  say "Validating squid.conf…"
  squid -k parse

  say "Initializing Squid cache dir…"
  squid -z || true

  say "Restarting Squid…"
  systemctl enable squid >/dev/null 2>&1 || true
  systemctl restart squid || (journalctl -xeu squid.service | sed -n '1,160p' ; exit 1)

  say "Squid should now be running on port ${PROXY_PORT} with ssl-bump."

  # Now that Squid is up and bumping, auto-install Squid MITM CA
  install_squid_mitm_ca_to_system || warn "Automatic MITM CA install failed; you may need to debug manually."

  echo
  say "Summary:"
  echo "  - Proxy listening on: http://$(hostname -f 2>/dev/null || hostname):${PROXY_PORT}"
  echo "  - URL-only log: ${LOG_URL_ONLY}"
  echo "  - MISP domain list: ${MISP_DOMAIN_FILE}"
  echo "  - MISP URL regex list: ${MISP_URL_REGEX_FILE}"
  echo "  - System CAs now include squid-proxy-ca.crt and (if extraction succeeded) squid-mitm.crt."
}

########################################
# Run all steps
########################################
require_root
say "System update…"
apt-get update -y && apt-get upgrade -y || true

install_misp_if_missing
install_pihole_if_missing
install_or_update_squid

echo
say "DONE."
echo "Next steps:"
echo "  1) Point clients' proxy to: http://$(hostname -f 2>/dev/null || hostname):${PROXY_PORT}"
echo "  2) On this box, curl should now accept Squid-bumped HTTPS certs."
echo "  3) Tail URL log:   sudo tail -f /var/log/squid/url-only.log"
echo "  4) Tail full log:  sudo tail -f /var/log/squid/access.log"
