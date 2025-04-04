#!/bin/bash
# Script to install MISP and Pi-hole on Ubuntu
# Pi-hole will run on port 8080 using lighttpd
# MISP will run on HTTPS port 443 using Apache2 (installed by MISP's own script)

set +e  # Continue even if some commands fail

BLUE="\033[1;34m"
NC="\033[0m"

print_status() {
  echo -e "${BLUE}[STATUS]${NC} $1"
}

#########################
# System Update
#########################
print_status "Updating system packages..."
sudo apt update && sudo apt upgrade -y

#########################
# Install Required Packages
#########################
print_status "Installing required packages (curl, git, lighttpd)..."
sudo apt install -y curl git lighttpd

#########################
# Install Pi-hole
#########################
print_status "Installing Pi-hole..."
curl -sSL https://install.pi-hole.net | bash /dev/stdin --unattended

#########################
# Configure lighttpd to use port 8080
#########################
print_status "Reconfiguring lighttpd to use port 8080..."
sudo sed -i 's/server.port *=.*/server.port = 8080/' /etc/lighttpd/lighttpd.conf
sudo systemctl restart lighttpd

#########################
# Install MISP
#########################
print_status "Cloning MISP repository..."
sudo git clone https://github.com/MISP/MISP.git /var/www/MISP
cd /var/www/MISP || exit
print_status "Pulling latest updates from MISP repository..."
sudo git pull

print_status "Running MISP installer..."
cd /var/www/MISP/INSTALL || exit
sudo ./INSTALL.ubuntu2404.sh

#########################
# Add MISP hostname to /etc/hosts
#########################
MISP_DOMAIN="misp.local"
print_status "Adding ${MISP_DOMAIN} to /etc/hosts"
echo "127.0.0.1 ${MISP_DOMAIN}" | sudo tee -a /etc/hosts

#########################
# Done
#########################
print_status "Installation complete."
echo "- MISP available at: https://${MISP_DOMAIN}"
echo "- Pi-hole available at: http://<your-ip>:8080/admin"
