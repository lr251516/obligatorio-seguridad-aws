#!/bin/bash
set -e
apt-get update
apt-get upgrade -y
apt-get install -y git curl auditd aide ufw fail2ban unattended-upgrades

hostnamectl set-hostname hardening-vm
mkdir -p /opt/fosil/scripts

# Habilitar servicios de seguridad
systemctl enable auditd
systemctl start auditd
systemctl enable fail2ban
systemctl start fail2ban

# Configurar firewall UFW básico
ufw --force enable
ufw default deny incoming
ufw default allow outgoing
ufw allow from 10.0.1.0/24 to any port 22  # SSH desde VPC
ufw allow 22/tcp  # SSH para testing (será restringido por Security Group)
ufw allow 51820/udp  # WireGuard

# /etc/hosts
cat >> /etc/hosts <<HOSTS

# Obligatorio SRD - AWS Internal IPs
10.0.1.10   waf-kong       waf
10.0.1.20   wazuh-siem     wazuh
10.0.1.30   vpn-iam        vpn keycloak
10.0.1.40   hardening-vm   hardening
HOSTS

echo "Hardening VM init completed - Ready for Wazuh agent with SCA" > /tmp/user-data-completed.log
date >> /tmp/user-data-completed.log