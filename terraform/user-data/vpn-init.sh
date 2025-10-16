#!/bin/bash
set -e
apt-get update
apt-get upgrade -y
apt-get install -y git curl wireguard-tools openjdk-17-jre-headless

hostnamectl set-hostname vpn-iam
mkdir -p /opt/fosil/scripts

# Swap moderado (2GB)
fallocate -l 2G /swapfile
chmod 600 /swapfile
mkswap /swapfile
swapon /swapfile
echo '/swapfile none swap sw 0 0' >> /etc/fstab

# Swappiness bajo (preferir RAM)
echo "vm.swappiness=10" >> /etc/sysctl.conf
sysctl -p

# Límites del sistema
cat >> /etc/security/limits.conf <<EOF
* soft nofile 65536
* hard nofile 65536
* soft nproc 65536
* hard nproc 65536
EOF

# /etc/hosts
cat >> /etc/hosts <<HOSTS

# Obligatorio SRD - AWS Internal IPs
10.0.1.10   waf-kong       waf
10.0.1.20   wazuh-siem     wazuh
10.0.1.30   vpn-iam        vpn keycloak
10.0.1.40   hardening-vm   hardening
HOSTS

echo "VPN/IAM init completed" > /tmp/user-data-completed.log
date >> /tmp/user-data-completed.log