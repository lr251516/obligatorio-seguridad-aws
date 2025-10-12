#!/bin/bash
# setup-base.sh
# Configuración base para instancias AWS

set -e

HOSTNAME=$1
INTERNAL_IP=$2

if [ -z "$HOSTNAME" ] || [ -z "$INTERNAL_IP" ]; then
    echo "Uso: $0 <hostname> <internal-ip>"
    exit 1
fi

echo "[+] Configurando $HOSTNAME ($INTERNAL_IP)"

# Actualizar sistema
sudo apt-get update
sudo apt-get upgrade -y

# Instalar herramientas base
sudo apt-get install -y \
    curl \
    wget \
    git \
    vim \
    htop \
    net-tools \
    ufw

# Configurar hostname
sudo hostnamectl set-hostname "$HOSTNAME"

# Agregar a /etc/hosts
sudo tee -a /etc/hosts > /dev/null <<HOSTS
10.0.1.10   waf-kong
10.0.1.20   wazuh-siem
10.0.1.30   vpn-iam
10.0.1.40   hardening-vm
HOSTS

echo "[✓] Configuración base completada"
