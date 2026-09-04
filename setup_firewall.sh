#$/usr/bin/env bash
set -euo pipefail

# Require sudo

if [[ $EUID -ne 0 ]]; then
    echo "This script must be run with sudo: sudo ./setup_firewall.sh"
    exit 1
fi

echo "Detecting package manager..."
if command -v apt >/dev/null 2>&1; then
    echo "Configuring firewall for Ubuntu/Debian..."
    apt update
    apt install -y ufw
elif command -v pacman >/dev/null 2>&1; then
    echo "Configuring firewall for Arch"
    pacman -S --noconfirm ufw
    systemctl enable --now ufw
else
    echo "Unsupported distro. Please intall and enable UFW manually."
    exit 1
fi

echo "Enabling service..."
ufw default deny incoming
ufw default allow outgoing
ufw --force enable

echo ""
echo "Firewall status:"
ufw status verbose
