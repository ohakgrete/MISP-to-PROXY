#!/bin/bash

set -e

### CONFIGURATION ###
MISP_DIR="/var/www/MISP"
PIHOLE_WEB_PORT=8080

echo "[+] Updating system..."
sudo apt update && sudo apt upgrade -y

### STEP 1: INSTALL MISP ###
echo "[+] Installing dependencies for MISP..."
sudo apt install -y curl git

echo "[+] Installing MISP "
wget https://raw.githubusercontent.com/MISP/MISP/refs/heads/2.5/INSTALL/INSTALL.ubuntu2404.sh

echo "[+] Running MISP install script (Ubuntu 24.04 supported as 22.04)..."
sudo chmod +x INSTALL.ubuntu2404.sh
sudo bash INSTALL.ubuntu2404.sh -c

echo "[✔] MISP installation complete and running on default ports 80/443"

### ADD misp.local TO HOSTS ###
if ! grep -q "misp.local" /etc/hosts; then
  echo "[+] Adding misp.local to /etc/hosts..."
  echo "127.0.0.1 misp.local" | sudo tee -a /etc/hosts
else
  echo "[i] misp.local already exists in /etc/hosts"
fi
### STEP 2: INSTALL PIHOLE ###
echo "[+] Installing Pi-hole..."

# Install Pi-hole unattended
curl -sSL https://install.pi-hole.net | sudo bash /dev/stdin --unattended

echo "[+] Pi-hole installed. Reconfiguring lighttpd to use misp.local:${PIHOLE_WEB_PORT}..."

# Path to the Pi-hole TOML config
PIHOLE_TOML="/etc/pihole/pihole.toml"
PORT_LINE='port = "8080o,8443os,[::]:8080o,[::]:8443os"'

if grep -E '^[[:space:]]*(#\s*)?port\s*=' "$PIHOLE_TOML" > /dev/null; then
  sudo sed -E -i "s|^[[:space:]]*(#\s*)?port\s*=.*|$PORT_LINE|" "$PIHOLE_TOML"
else
  echo "$PORT_LINE" | sudo tee -a "$PIHOLE_TOML"
fi

sudo systemctl restart pihole-FTL

echo "[✔] Pi-hole is now accessible at http://misp.local:${PIHOLE_WEB_PORT}/admin"
echo "[✔] MISP is running on https://misp.local/"
