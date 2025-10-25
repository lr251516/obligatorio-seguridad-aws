#!/bin/bash
set -e
apt-get update
apt-get upgrade -y
apt-get install -y git curl wget htop

hostnamectl set-hostname wazuh-siem
mkdir -p /opt/fosil/scripts

# Swap para backup (4GB)
fallocate -l 4G /swapfile
chmod 600 /swapfile
mkswap /swapfile
swapon /swapfile
echo '/swapfile none swap sw 0 0' >> /etc/fstab

# Límites del sistema para Wazuh
cat >> /etc/security/limits.conf <<EOF
* soft nofile 65536
* hard nofile 65536
* soft nproc 65536
* hard nproc 65536
wazuh-indexer soft memlock unlimited
wazuh-indexer hard memlock unlimited
EOF

# Sysctl para Wazuh Indexer
cat >> /etc/sysctl.d/99-wazuh.conf <<EOF
vm.max_map_count=262144
vm.swappiness=10
EOF
sysctl -p /etc/sysctl.d/99-wazuh.conf

# /etc/hosts
cat >> /etc/hosts <<HOSTS

# Obligatorio SRD - AWS Internal IPs
10.0.1.10   waf-kong       waf
10.0.1.20   wazuh-siem     wazuh
10.0.1.30   vpn-iam        vpn keycloak
10.0.1.40   hardening-vm   hardening
HOSTS

# Instalar Wazuh All-in-One
echo "Instalando Wazuh SIEM..." >> /tmp/user-data.log
cd /tmp
curl -sO https://packages.wazuh.com/4.13/wazuh-install.sh
bash wazuh-install.sh -a 2>&1 | tee -a /tmp/wazuh-installation.log

# Extraer y guardar contraseña
PASSWORD=$(grep "Password:" /tmp/wazuh-installation.log | tail -1 | awk '{print $2}')
echo "$PASSWORD" > /root/wazuh-password.txt
chmod 600 /root/wazuh-password.txt

echo "Wazuh SIEM instalado - Password en /root/wazuh-password.txt" > /tmp/user-data-completed.log
date >> /tmp/user-data-completed.log