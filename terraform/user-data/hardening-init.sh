#!/bin/bash
set -e
export DEBIAN_FRONTEND=noninteractive
apt-get update
apt-get upgrade -y
apt-get install -y git curl auditd aide ufw fail2ban unattended-upgrades

hostnamectl set-hostname hardening-vm
mkdir -p /opt/fosil/scripts
cd /opt && git clone https://github.com/lr251516/obligatorio-srd-aws.git fosil || (cd fosil && git pull)

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
ufw allow 22/tcp  # SSH para testing (restringido luego por Security Group)
ufw allow 51820/udp  # WireGuard

# /etc/hosts
cat >> /etc/hosts <<HOSTS

# Obligatorio SRD - AWS Internal IPs
10.0.1.10   waf-kong       waf
10.0.1.20   wazuh-siem     wazuh
10.0.1.30   vpn-iam        vpn keycloak
10.0.1.40   hardening-vm   hardening
HOSTS

# Instalar agente Wazuh
echo "Instalando agente Wazuh..." >> /tmp/user-data.log
curl -s https://packages.wazuh.com/key/GPG-KEY-WAZUH | apt-key add -
echo "deb https://packages.wazuh.com/4.x/apt/ stable main" | tee /etc/apt/sources.list.d/wazuh.list
apt-get update

# Evitar conflictos con postfix
apt-get remove --purge -y postfix 2>/dev/null || true

# Instalar agente
WAZUH_MANAGER="10.0.1.20" \
WAZUH_AGENT_NAME="hardening-vm" \
DEBIAN_FRONTEND=noninteractive \
apt-get install -y wazuh-agent=4.13.1-1

# Configurar FIM (File Integrity Monitoring)
sed -i '/<\/ossec_config>$/i \
  <syscheck>\n\
    <disabled>no</disabled>\n\
    <frequency>300</frequency>\n\
    <alert_new_files>yes</alert_new_files>\n\
    <directories check_all="yes" realtime="yes" report_changes="yes">/etc/passwd</directories>\n\
    <directories check_all="yes" realtime="yes" report_changes="yes">/etc/shadow</directories>\n\
    <directories check_all="yes" realtime="yes" report_changes="yes">/etc/group</directories>\n\
    <directories check_all="yes" realtime="yes" report_changes="yes">/etc/sudoers</directories>\n\
    <directories check_all="yes" realtime="yes" report_changes="yes">/etc/sudoers.d</directories>\n\
    <directories check_all="yes" realtime="yes" report_changes="yes">/etc/ssh/sshd_config</directories>\n\
    <directories check_all="yes" realtime="yes" report_changes="yes">/root/.ssh</directories>\n\
    <directories check_all="yes" realtime="yes" report_changes="yes">/etc/ufw</directories>\n\
    <ignore>/etc/mtab</ignore>\n\
    <ignore type="sregex">\\.log$</ignore>\n\
    <ignore type="sregex">\\.swp$</ignore>\n\
  </syscheck>' /var/ossec/etc/ossec.conf

# Iniciar agente
systemctl daemon-reload
systemctl enable wazuh-agent
systemctl start wazuh-agent

echo "Hardening VM init completed with Wazuh agent and FIM" > /tmp/user-data-completed.log
date >> /tmp/user-data-completed.log