#!/bin/bash
set -e

# Timezone y NTP Uruguay
timedatectl set-timezone America/Montevideo

apt-get update
# Nota: apt-get upgrade removido porque puede fallar por paquetes 404 en repos
# y no es crítico para deployment inicial
apt-get install -y git curl wireguard wireguard-tools resolvconf openjdk-17-jre-headless systemd-timesyncd jq

# Configurar NTP después de asegurar que está instalado
echo "NTP=0.uy.pool.ntp.org 1.uy.pool.ntp.org" >> /etc/systemd/timesyncd.conf
systemctl enable systemd-timesyncd
systemctl restart systemd-timesyncd

hostnamectl set-hostname vpn-iam

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

# Instalar keycloak
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
wget -q https://github.com/keycloak/keycloak/releases/download/$${KEYCLOAK_VERSION}/keycloak-$${KEYCLOAK_VERSION}.tar.gz
tar -xzf keycloak-$${KEYCLOAK_VERSION}.tar.gz
mv keycloak-$${KEYCLOAK_VERSION} keycloak
rm keycloak-$${KEYCLOAK_VERSION}.tar.gz

# Usuario keycloak con directorio home
useradd -r -m -d /home/keycloak -s /bin/bash keycloak || true
mkdir -p /home/keycloak/.keycloak
chown -R keycloak:keycloak /opt/keycloak /home/keycloak

# Agregar keycloak a sudoers para que pueda ejecutar kcadm.sh
echo "keycloak ALL=(keycloak) NOPASSWD: ALL" > /etc/sudoers.d/keycloak
chmod 440 /etc/sudoers.d/keycloak

# Obtener IP pública de la instancia
PUBLIC_IP=$(curl -s http://169.254.169.254/latest/meta-data/public-ipv4)

# Configuración para permitir HTTP 
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
log=console,file
log-file=/opt/keycloak/data/log/keycloak.log
log-file-output=json

# Features
metrics-enabled=true
KC

cat > /opt/keycloak/conf/jvm-opts.conf <<JVM
-Xms512m
-Xmx2g
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

# Crear directorio de logs Keycloak si no existe
mkdir -p /opt/keycloak/data/log
chown keycloak:keycloak /opt/keycloak/data/log

# Esperar a que keycloak.log se cree
echo "[$(date)] Esperando archivo de log de Keycloak..." >> /tmp/user-data.log
RETRIES=0
while [ ! -f /opt/keycloak/data/log/keycloak.log ] && [ $RETRIES -lt 30 ]; do
  sleep 2
  RETRIES=$((RETRIES+1))
done

# Agregar monitoreo de keycloak.log a Wazuh
if [ -f /opt/keycloak/data/log/keycloak.log ]; then
  echo "[$(date)] Agregando keycloak.log a Wazuh agent..." >> /tmp/user-data.log
  sed -i '/<\/ossec_config>$/i \  <localfile>\n    <log_format>json</log_format>\n    <location>/opt/keycloak/data/log/keycloak.log</location>\n  </localfile>' /var/ossec/etc/ossec.conf
  systemctl restart wazuh-agent
  echo "[$(date)] Wazuh agent reiniciado con monitoreo de Keycloak" >> /tmp/user-data.log
fi

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
echo "[$(date)] Creando realm 'fosil' con usuarios y cliente OAuth2 Grafana..." >> /tmp/user-data.log
sleep 5

# IP pública de Grafana inyectada por Terraform
GRAFANA_PUBLIC_IP="${grafana_public_ip}"
echo "[$(date)] Grafana IP pública desde Terraform: $GRAFANA_PUBLIC_IP" >> /tmp/user-data.log

cd /opt/fosil/VPN-IAM/scripts
sudo -u ubuntu /opt/fosil/VPN-IAM/scripts/create-realm.sh --auto --grafana-ip "$GRAFANA_PUBLIC_IP" 2>&1 | tee -a /tmp/user-data.log

if [ $? -eq 0 ]; then
  echo "[$(date)] Realm 'fosil' creado exitosamente" >> /tmp/user-data.log

  # Configurar realm fosil para permitir HTTP también
  echo "[$(date)] Configurando realm fosil para HTTP..." >> /tmp/user-data.log
  cd /opt/keycloak
  sudo -u keycloak bin/kcadm.sh update realms/fosil \
    -s sslRequired=NONE 2>&1 | tee -a /tmp/user-data.log
else
  echo "[$(date)] ERROR: create-realm.sh falló, verificar logs arriba" >> /tmp/user-data.log
fi

# Configurar servidor VPN WireGuard automáticamente
echo "[$(date)] Configurando servidor VPN WireGuard..." >> /tmp/user-data.log
cd /opt/fosil/VPN-IAM/scripts
sudo /opt/fosil/VPN-IAM/scripts/setup-vpn-server.sh 2>&1 | tee -a /tmp/user-data.log

if [ $? -eq 0 ]; then
  echo "[$(date)] Servidor VPN WireGuard configurado exitosamente" >> /tmp/user-data.log

  # Guardar información del servidor VPN para fácil acceso
  VPN_PUBLIC_KEY=$(cat /etc/wireguard/public.key 2>/dev/null || echo "N/A")
  VPN_PUBLIC_IP=$(curl -s http://169.254.169.254/latest/meta-data/public-ipv4)

  echo "" >> /tmp/user-data.log
  echo "=== VPN Server Info ===" >> /tmp/user-data.log
  echo "Public IP: $VPN_PUBLIC_IP" >> /tmp/user-data.log
  echo "Public Key: $VPN_PUBLIC_KEY" >> /tmp/user-data.log
  echo "Port: 51820" >> /tmp/user-data.log
  echo "======================" >> /tmp/user-data.log
else
  echo "[$(date)] ERROR: setup-vpn-server.sh falló, verificar logs arriba" >> /tmp/user-data.log
fi

echo "VPN/IAM init completed with Wazuh agent + Keycloak + Realm 'fosil' + WireGuard VPN" > /tmp/user-data-completed.log
echo "" >> /tmp/user-data-completed.log
echo "Keycloak Admin Console: http://10.0.1.30:8080 (admin/admin)" >> /tmp/user-data-completed.log
echo "Realm: fosil" >> /tmp/user-data-completed.log
echo "" >> /tmp/user-data-completed.log
echo "Usuarios creados (3):" >> /tmp/user-data-completed.log
echo "  - jperez@fosil.uy (Admin123!) - infraestructura-admin → Grafana Admin" >> /tmp/user-data-completed.log
echo "  - mgonzalez@fosil.uy (DevOps123!) - devops → Grafana Editor" >> /tmp/user-data-completed.log
echo "  - arodriguez@fosil.uy (Viewer123!) - viewer → Grafana Viewer" >> /tmp/user-data-completed.log
echo "" >> /tmp/user-data-completed.log
echo "Cliente OAuth2 creado:" >> /tmp/user-data-completed.log
echo "  - grafana-oauth (Secret: grafana-secret-2024)" >> /tmp/user-data-completed.log
echo "" >> /tmp/user-data-completed.log
echo "WireGuard VPN Server:" >> /tmp/user-data-completed.log
VPN_PUBLIC_KEY_DISPLAY=$(cat /etc/wireguard/public.key 2>/dev/null || echo "N/A")
VPN_PUBLIC_IP_DISPLAY=$(curl -s http://169.254.169.254/latest/meta-data/public-ipv4 2>/dev/null || echo "N/A")
echo "  - Public IP: $VPN_PUBLIC_IP_DISPLAY" >> /tmp/user-data-completed.log
echo "  - Public Key: $VPN_PUBLIC_KEY_DISPLAY" >> /tmp/user-data-completed.log
echo "  - Port: 51820 (UDP)" >> /tmp/user-data-completed.log
echo "  - Status: sudo wg show" >> /tmp/user-data-completed.log
echo "" >> /tmp/user-data-completed.log
echo "Generar config VPN para usuario:" >> /tmp/user-data-completed.log
echo "  cd /opt/fosil/VPN-IAM/scripts" >> /tmp/user-data-completed.log
echo "  export VPN_SERVER_PUBLIC_IP=$VPN_PUBLIC_IP_DISPLAY" >> /tmp/user-data-completed.log
echo "  export VPN_SERVER_PUBLIC_KEY=$VPN_PUBLIC_KEY_DISPLAY" >> /tmp/user-data-completed.log
echo "  ./vpn-config-generator.sh jperez@fosil.uy" >> /tmp/user-data-completed.log
echo "" >> /tmp/user-data-completed.log
echo "Ver logs detallados en: /tmp/user-data.log" >> /tmp/user-data-completed.log
date >> /tmp/user-data-completed.log