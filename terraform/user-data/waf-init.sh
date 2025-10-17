#!/bin/bash
set -e
apt-get update
apt-get upgrade -y
apt-get install -y git curl
hostnamectl set-hostname waf-kong
mkdir -p /opt/fosil/scripts

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

apt-get remove --purge -y postfix 2>/dev/null || true

WAZUH_MANAGER="10.0.1.20" \
WAZUH_AGENT_NAME="waf-kong" \
DEBIAN_FRONTEND=noninteractive \
apt-get install -y wazuh-agent

# FIM básico para WAF
sed -i '/<\/ossec_config>$/i \
  <syscheck>\n\
    <disabled>no</disabled>\n\
    <frequency>300</frequency>\n\
    <alert_new_files>yes</alert_new_files>\n\
    <directories check_all="yes" realtime="yes" report_changes="yes">/etc/kong</directories>\n\
    <directories check_all="yes" realtime="yes">/etc/nginx</directories>\n\
    <ignore type="sregex">\\.log$</ignore>\n\
  </syscheck>' /var/ossec/etc/ossec.conf

systemctl daemon-reload
systemctl enable wazuh-agent
systemctl start wazuh-agent

echo "WAF init completed with Wazuh agent" > /tmp/user-data-completed.log
