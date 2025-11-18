#!/bin/bash
set -e
export DEBIAN_FRONTEND=noninteractive
exec > >(tee /tmp/user-data.log) 2>&1

echo "[$(date)] Iniciando deployment Hardening VM (VANILLA + Wazuh SCA mode)" >> /tmp/user-data.log

# Timezone y NTP Uruguay
timedatectl set-timezone America/Montevideo

# Actualización de sistema base
apt-get update
apt-get upgrade -y

# Paquetes mínimos requeridos
apt-get install -y git curl systemd-timesyncd

# Configurar NTP después de asegurar que está instalado
echo "NTP=0.uy.pool.ntp.org 1.uy.pool.ntp.org" >> /etc/systemd/timesyncd.conf
systemctl enable systemd-timesyncd
systemctl restart systemd-timesyncd

hostnamectl set-hostname hardening-vm

# Clonar repositorio con scripts de hardening
cd /opt
if [ -d "fosil/.git" ]; then
  echo "Repo already exists, pulling latest changes..."
  cd fosil
  git pull origin main
else
  echo "Cloning repository..."
  rm -rf fosil
  git clone https://github.com/lr251516/obligatorio-seguridad-aws.git fosil
  cd fosil
fi
chown -R ubuntu:ubuntu /opt/fosil

# Hacer scripts ejecutables
chmod +x /opt/fosil/Hardening/scripts/*.sh

# /etc/hosts para resolución interna
cat >> /etc/hosts <<HOSTS

# Obligatorio SRD - AWS Internal IPs
10.0.1.10   waf-kong       waf
10.0.1.20   wazuh-siem     wazuh
10.0.1.30   vpn-iam        vpn keycloak
10.0.1.40   hardening-vm   hardening
HOSTS

# Wazuh-agent
echo "[$(date)] Instalando Wazuh agent para SCA..." >> /tmp/user-data.log
curl -s https://packages.wazuh.com/key/GPG-KEY-WAZUH | apt-key add -
echo "deb https://packages.wazuh.com/4.x/apt/ stable main" | tee /etc/apt/sources.list.d/wazuh.list
apt-get update

# Evitar conflictos con postfix
apt-get remove --purge -y postfix 2>/dev/null || true

# Instalar agente Wazuh
WAZUH_MANAGER="10.0.1.20" \
WAZUH_AGENT_NAME="hardening-vm" \
DEBIAN_FRONTEND=noninteractive \
apt-get install -y wazuh-agent=4.13.1-1

# Configurar FIM (File Integrity Monitoring) mínimo
# Se monitoreará /etc/passwd y SSH config para demostrar FIM antes/después de hardening
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

# Iniciar agente Wazuh
systemctl daemon-reload
systemctl enable wazuh-agent
systemctl start wazuh-agent

echo "============================================" > /tmp/user-data-completed.log
echo "Hardening VM - VANILLA + Wazuh SCA" >> /tmp/user-data-completed.log
echo "============================================" >> /tmp/user-data-completed.log
echo "" >> /tmp/user-data-completed.log
echo "✅ VM levantada SIN hardening CIS aplicado" >> /tmp/user-data-completed.log
echo "✅ Wazuh agent instalado y conectado" >> /tmp/user-data-completed.log
echo "" >> /tmp/user-data-completed.log
echo "📊 SCA Score Actual: ~40-50% (sin hardening)" >> /tmp/user-data-completed.log
echo "" >> /tmp/user-data-completed.log
echo "📋 PRÓXIMO PASO: Aplicar CIS Hardening manualmente" >> /tmp/user-data-completed.log
echo "" >> /tmp/user-data-completed.log
echo "1. Verificar SCA baseline en Wazuh Dashboard:" >> /tmp/user-data-completed.log
echo "   http://wazuh-dashboard → Security Configuration Assessment" >> /tmp/user-data-completed.log
echo "" >> /tmp/user-data-completed.log
echo "2. Conectar a la VM:" >> /tmp/user-data-completed.log
echo "   ssh -i ~/.ssh/obligatorio-srd ubuntu@<HARDENING_IP>" >> /tmp/user-data-completed.log
echo "" >> /tmp/user-data-completed.log
echo "3. Aplicar hardening CIS Level 1:" >> /tmp/user-data-completed.log
echo "   cd /opt/fosil/Hardening/scripts" >> /tmp/user-data-completed.log
echo "   sudo ./apply-cis-hardening.sh" >> /tmp/user-data-completed.log
echo "" >> /tmp/user-data-completed.log
echo "4. Verificar mejora de SCA score en Wazuh (esperado: 80-85%)" >> /tmp/user-data-completed.log
echo "" >> /tmp/user-data-completed.log
echo "Deployment completado: $(date)" >> /tmp/user-data-completed.log
echo "============================================" >> /tmp/user-data-completed.log

date >> /tmp/user-data.log
echo "[$(date)] Hardening VM deployment completado" >> /tmp/user-data.log