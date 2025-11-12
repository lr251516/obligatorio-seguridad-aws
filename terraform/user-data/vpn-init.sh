#!/bin/bash
set -e
apt-get update
apt-get upgrade -y
apt-get install -y git curl wireguard-tools openjdk-17-jre-headless

hostnamectl set-hostname vpn-iam

# Clonar repo con scripts
cd /opt
if [ -d "fosil/.git" ]; then
  cd fosil && git pull origin main || true
else
  rm -rf fosil
  git clone https://github.com/lr251516/obligatorio-seguridad-aws.git fosil
  cd fosil
fi
chown -R ubuntu:ubuntu /opt/fosil

# Permisos ejecutables en scripts
chmod +x /opt/fosil/VPN-IAM/scripts/*.sh
chmod +x /opt/fosil/Hardening/scripts/*.sh

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

# Instalar agente Wazuh
echo "Instalando agente Wazuh..." >> /tmp/user-data.log
curl -s https://packages.wazuh.com/key/GPG-KEY-WAZUH | apt-key add -
echo "deb https://packages.wazuh.com/4.x/apt/ stable main" | tee /etc/apt/sources.list.d/wazuh.list
apt-get update

apt-get remove --purge -y postfix 2>/dev/null || true

WAZUH_MANAGER="10.0.1.20" \
WAZUH_AGENT_NAME="vpn-iam" \
DEBIAN_FRONTEND=noninteractive \
apt-get install -y wazuh-agent=4.13.1-1

# FIM para VPN/Keycloak
sed -i '/<\/ossec_config>$/i \
  <syscheck>\n\
    <disabled>no</disabled>\n\
    <frequency>300</frequency>\n\
    <alert_new_files>yes</alert_new_files>\n\
    <directories check_all="yes" realtime="yes" report_changes="yes">/etc/wireguard</directories>\n\
    <directories check_all="yes" realtime="yes">/opt/keycloak/conf</directories>\n\
    <directories check_all="yes" realtime="yes" report_changes="yes">/etc/ssh/sshd_config</directories>\n\
    <ignore type="sregex">\\.log$</ignore>\n\
  </syscheck>' /var/ossec/etc/ossec.conf

systemctl daemon-reload
systemctl enable wazuh-agent
systemctl start wazuh-agent

# ============================================
# INSTALAR KEYCLOAK
# ============================================
echo "[$(date)] Instalando Keycloak..." >> /tmp/user-data.log

# PostgreSQL para Keycloak
apt-get install -y postgresql postgresql-contrib
sudo -u postgres psql <<PSQL
CREATE DATABASE keycloak;
CREATE USER keycloak WITH ENCRYPTED PASSWORD 'keycloak_password';
GRANT ALL PRIVILEGES ON DATABASE keycloak TO keycloak;
PSQL

# Descargar Keycloak
KEYCLOAK_VERSION="23.0.0"
cd /opt
wget -q https://github.com/keycloak/keycloak/releases/download/${KEYCLOAK_VERSION}/keycloak-${KEYCLOAK_VERSION}.tar.gz
tar -xzf keycloak-${KEYCLOAK_VERSION}.tar.gz
mv keycloak-${KEYCLOAK_VERSION} keycloak
rm keycloak-${KEYCLOAK_VERSION}.tar.gz

# Usuario keycloak con directorio home
useradd -r -m -d /home/keycloak -s /bin/false keycloak || true
mkdir -p /home/keycloak/.keycloak
chown -R keycloak:keycloak /opt/keycloak /home/keycloak

# Obtener IP pública de la instancia
PUBLIC_IP=$(curl -s http://169.254.169.254/latest/meta-data/public-ipv4)

# Configuración para permitir HTTP (proyecto académico)
cat > /opt/keycloak/conf/keycloak.conf <<'KC'
# Database
db=postgres
db-url=jdbc:postgresql://localhost:5432/keycloak
db-username=keycloak
db-password=keycloak_password

# Network
http-enabled=true
http-host=0.0.0.0
http-port=8080

# Hostname - permitir acceso desde cualquier IP
hostname-strict=false

# Logs
log-level=INFO

# Features
metrics-enabled=true
KC

cat > /opt/keycloak/conf/jvm-opts.conf <<JVM
-Xms512m
-Xmx1024m
-XX:MetaspaceSize=128m
-XX:MaxMetaspaceSize=256m
JVM

# Build
cd /opt/keycloak
sudo -u keycloak bin/kc.sh build >> /tmp/user-data.log 2>&1

# Systemd service
cat > /etc/systemd/system/keycloak.service <<SVC
[Unit]
Description=Keycloak Identity Provider
After=network.target postgresql.service
Requires=postgresql.service

[Service]
Type=simple
User=keycloak
Group=keycloak
WorkingDirectory=/opt/keycloak
Environment="KEYCLOAK_ADMIN=admin"
Environment="KEYCLOAK_ADMIN_PASSWORD=admin"
ExecStart=/opt/keycloak/bin/kc.sh start
StandardOutput=journal
StandardError=journal
Restart=on-failure
RestartSec=10s

[Install]
WantedBy=multi-user.target
SVC

systemctl daemon-reload
systemctl enable keycloak
systemctl start keycloak

# Esperar que Keycloak esté listo
echo "[$(date)] Esperando que Keycloak inicie..." >> /tmp/user-data.log
sleep 45

# Configurar realm master para permitir HTTP
echo "[$(date)] Configurando realm master para HTTP..." >> /tmp/user-data.log
cd /opt/keycloak
sudo -u keycloak bin/kcadm.sh config credentials \
  --server http://localhost:8080 \
  --realm master \
  --user admin \
  --password admin 2>&1 | tee -a /tmp/user-data.log

sudo -u keycloak bin/kcadm.sh update realms/master \
  -s sslRequired=NONE 2>&1 | tee -a /tmp/user-data.log

# Crear realm fosil automáticamente
echo "[$(date)] Creando realm fosil..." >> /tmp/user-data.log
sleep 10
cd /opt/fosil/VPN-IAM/scripts
sudo -u keycloak /opt/fosil/VPN-IAM/scripts/create-realm.sh 2>&1 | tee -a /tmp/user-data.log || echo "Warning: create-realm.sh falló, ejecutar manualmente" >> /tmp/user-data.log

echo "VPN/IAM init completed with Wazuh agent + Keycloak" > /tmp/user-data-completed.log
echo "Keycloak: http://10.0.1.30:8080 (admin/admin)" >> /tmp/user-data-completed.log
echo "Keycloak realm master configurado para HTTP" >> /tmp/user-data-completed.log
date >> /tmp/user-data-completed.log