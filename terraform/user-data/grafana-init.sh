#!/bin/bash
set -e

# Timezone y NTP Uruguay
timedatectl set-timezone America/Montevideo

apt-get update
apt-get upgrade -y
apt-get install -y git curl systemd-timesyncd apt-transport-https software-properties-common wget gnupg

# Configurar NTP
echo "NTP=0.uy.pool.ntp.org 1.uy.pool.ntp.org" >> /etc/systemd/timesyncd.conf
systemctl enable systemd-timesyncd
systemctl restart systemd-timesyncd

hostnamectl set-hostname grafana

# Clonar repo con scripts
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

# /etc/hosts
cat >> /etc/hosts <<HOSTS

# Obligatorio SRD - AWS Internal IPs
10.0.1.10   waf-kong       waf
10.0.1.20   wazuh-siem     wazuh
10.0.1.30   vpn-iam        vpn keycloak
10.0.1.40   hardening-vm   hardening
10.0.1.50   grafana        grafana-vm
HOSTS

# Instalar agente Wazuh
echo "[$(date)] Instalando agente Wazuh..." >> /tmp/user-data.log
curl -s https://packages.wazuh.com/key/GPG-KEY-WAZUH | apt-key add -
echo "deb https://packages.wazuh.com/4.x/apt/ stable main" | tee /etc/apt/sources.list.d/wazuh.list
apt-get update

apt-get remove --purge -y postfix 2>/dev/null || true

WAZUH_MANAGER="10.0.1.20" \
WAZUH_AGENT_NAME="grafana" \
DEBIAN_FRONTEND=noninteractive \
apt-get install -y wazuh-agent=4.13.1-1

# FIM para Grafana
sed -i '/<\/ossec_config>$/i \
  <syscheck>\n\
    <disabled>no</disabled>\n\
    <frequency>300</frequency>\n\
    <alert_new_files>yes</alert_new_files>\n\
    <directories check_all="yes" realtime="yes">/etc/grafana</directories>\n\
    <directories check_all="yes" realtime="yes" report_changes="yes">/etc/ssh/sshd_config</directories>\n\
    <ignore type="sregex">\\.log$</ignore>\n\
  </syscheck>' /var/ossec/etc/ossec.conf

systemctl daemon-reload
systemctl enable wazuh-agent
systemctl start wazuh-agent

# Instalar Grafana
echo "[$(date)] Instalando Grafana..." >> /tmp/user-data.log

# Variables para OAuth2
KEYCLOAK_SERVER="http://10.0.1.30:8080"
KEYCLOAK_REALM="fosil"
GRAFANA_CLIENT_ID="grafana-oauth"
GRAFANA_CLIENT_SECRET="grafana-secret-2024"

# Agregar repositorio de Grafana
mkdir -p /etc/apt/keyrings/
wget -q -O - https://apt.grafana.com/gpg.key | gpg --dearmor | tee /etc/apt/keyrings/grafana.gpg > /dev/null
echo "deb [signed-by=/etc/apt/keyrings/grafana.gpg] https://apt.grafana.com stable main" | tee /etc/apt/sources.list.d/grafana.list

# Instalar Grafana
apt-get update
apt-get install -y grafana

# Configurar Grafana con OAuth2
cat > /etc/grafana/grafana.ini <<EOF
[server]
http_port = 3000
domain = 10.0.1.50
root_url = http://10.0.1.50:3000

[auth]
# Permitir login local (admin) además de OAuth
disable_login_form = false

[auth.generic_oauth]
enabled = true
name = Keycloak
allow_sign_up = true
client_id = ${GRAFANA_CLIENT_ID}
client_secret = ${GRAFANA_CLIENT_SECRET}
scopes = openid email profile offline_access roles
email_attribute_path = email
login_attribute_path = username
name_attribute_path = full_name
auth_url = ${KEYCLOAK_SERVER}/realms/${KEYCLOAK_REALM}/protocol/openid-connect/auth
token_url = ${KEYCLOAK_SERVER}/realms/${KEYCLOAK_REALM}/protocol/openid-connect/token
api_url = ${KEYCLOAK_SERVER}/realms/${KEYCLOAK_REALM}/protocol/openid-connect/userinfo
role_attribute_path = contains(roles[*], 'infraestructura-admin') && 'Admin' || contains(roles[*], 'devops') && 'Editor' || 'Viewer'
use_refresh_token = true

[security]
allow_embedding = true
admin_user = admin
admin_password = admin

[users]
auto_assign_org = true
auto_assign_org_role = Viewer

[log]
mode = console file
level = info
EOF

# Habilitar e iniciar Grafana
systemctl daemon-reload
systemctl enable grafana-server
systemctl start grafana-server

# Esperar que Grafana esté listo
echo "[$(date)] Esperando que Grafana inicie..." >> /tmp/user-data.log
RETRIES=0
MAX_RETRIES=30
until curl -s http://localhost:3000/api/health | grep -q "ok" || [ $RETRIES -eq $MAX_RETRIES ]; do
  echo "[$(date)] Grafana aún no está listo, esperando... (intento $((RETRIES+1))/$MAX_RETRIES)" >> /tmp/user-data.log
  sleep 5
  RETRIES=$((RETRIES+1))
done

if [ $RETRIES -eq $MAX_RETRIES ]; then
  echo "[$(date)] WARNING: Grafana no respondió después de 2.5 minutos (probablemente OK)" >> /tmp/user-data.log
else
  echo "[$(date)] Grafana está listo!" >> /tmp/user-data.log
fi

# Resumen final
echo "Grafana init completed with Wazuh agent + OAuth2 Keycloak" > /tmp/user-data-completed.log
echo "" >> /tmp/user-data-completed.log
echo "Grafana Dashboard: http://10.0.1.50:3000" >> /tmp/user-data-completed.log
echo "" >> /tmp/user-data-completed.log
echo "Login opciones:" >> /tmp/user-data-completed.log
echo "  1. Click 'Sign in with Keycloak' (OAuth2)" >> /tmp/user-data-completed.log
echo "     - jperez@fosil.uy (Admin123!) → Grafana Admin" >> /tmp/user-data-completed.log
echo "     - mgonzalez@fosil.uy (DevOps123!) → Grafana Editor" >> /tmp/user-data-completed.log
echo "     - arodriguez@fosil.uy (Viewer123!) → Grafana Viewer" >> /tmp/user-data-completed.log
echo "" >> /tmp/user-data-completed.log
echo "  2. Login local (admin/admin)" >> /tmp/user-data-completed.log
echo "" >> /tmp/user-data-completed.log
echo "Keycloak OAuth2 configurado:" >> /tmp/user-data-completed.log
echo "  - Server: http://10.0.1.30:8080" >> /tmp/user-data-completed.log
echo "  - Realm: fosil" >> /tmp/user-data-completed.log
echo "  - Client ID: grafana-oauth" >> /tmp/user-data-completed.log
echo "" >> /tmp/user-data-completed.log
echo "Ver logs detallados en: /tmp/user-data.log" >> /tmp/user-data-completed.log
date >> /tmp/user-data-completed.log

echo "[$(date)] Grafana deployment completado" >> /tmp/user-data.log
