#!/bin/bash
set -e

# Timezone y NTP Uruguay
timedatectl set-timezone America/Montevideo

apt-get update
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

# --- COMIENZA LA CONFIGURACIÓN UNIFICADA DE WAZUH ---

# 1. Bloque base (Abre <ossec_config> y añade la mayoría de la configuración)
rm -f /var/ossec/etc/ossec.conf
cat > /var/ossec/etc/ossec.conf <<'WAZUH_CONFIG_SECTION_1_OPEN'
<ossec_config>
  <client>
    <server>
      <address>10.0.1.20</address>
      <port>1514</port>
      <protocol>tcp</protocol>
    </server>
    <config-profile>ubuntu, ubuntu22, ubuntu22.04</config-profile>
    <notify_time>20</notify_time>
    <time-reconnect>60</time-reconnect>
    <auto_restart>yes</auto_restart>
    <crypto_method>aes</crypto_method>
    <enrollment>
      <enabled>yes</enabled>
      <agent_name>vpn-iam</agent_name>
      <authorization_pass_path>etc/authd.pass</authorization_pass_path>
    </enrollment>
  </client>
  
  <client_buffer>
    <disabled>no</disabled>
    <queue_size>5000</queue_size>
    <events_per_second>500</events_per_second>
  </client_buffer>

  <rootcheck>
    <disabled>no</disabled>
    <check_files>yes</check_files>
    <check_trojans>yes</check_trojans>
    <check_dev>yes</check_dev>
    <check_sys>yes</check_sys>
    <check_pids>yes</check_pids>
    <check_ports>yes</check_ports>
    <check_if>yes</check_if>
    <frequency>43200</frequency>
    <rootkit_files>etc/shared/rootkit_files.txt</rootkit_files>
    <rootkit_trojans>etc/shared/rootkit_trojans.txt</rootkit_trojans>
    <skip_nfs>yes</skip_nfs>
    <ignore>/var/lib/containerd</ignore>
    <ignore>/var/lib/docker/overlay2</ignore>
  </rootcheck>

  <wodle name="cis-cat">
    <disabled>yes</disabled>
    <timeout>1800</timeout>
    <interval>1d</interval>
    <scan-on-start>yes</scan-on-start>
    <java_path>wodles/java</java_path>
    <ciscat_path>wodles/ciscat</ciscat_path>
  </wodle>

  <wodle name="osquery">
    <disabled>yes</disabled>
    <run_daemon>yes</run_daemon>
    <log_path>/var/log/osquery/osqueryd.results.log</log_path>
    <config_path>/etc/osquery/osquery.conf</config_path>
    <add_labels>yes</add_labels>
  </wodle>

  <wodle name="syscollector">
    <disabled>no</disabled>
    <interval>1h</interval>
    <scan_on_start>yes</scan_on_start>
    <hardware>yes</hardware>
    <os>yes</os>
    <network>yes</network>
    <packages>yes</packages>
    <ports all="yes">yes</ports>
    <processes>yes</processes>
    <synchronization>
      <max_eps>10</max_eps>
    </synchronization>
  </wodle>

  <sca>
    <enabled>yes</enabled>
    <scan_on_start>yes</scan_on_start>
    <interval>12h</interval>
    <skip_nfs>yes</skip_nfs>
  </sca>

  <syscheck>
    <disabled>no</disabled>
    <frequency>43200</frequency>
    <scan_on_start>yes</scan_on_start>
    <directories>/etc,/usr/bin,/usr/sbin</directories>
    <directories>/bin,/sbin,/boot</directories>
    <ignore>/etc/mtab</ignore>
    <ignore>/etc/hosts.deny</ignore>
    <ignore>/etc/mail/statistics</ignore>
    <ignore>/etc/random-seed</ignore>
    <ignore>/etc/random.seed</ignore>
    <ignore>/etc/adjtime</ignore>
    <ignore>/etc/httpd/logs</ignore>
    <ignore>/etc/utmpx</ignore>
    <ignore>/etc/wtmpx</ignore>
    <ignore>/etc/cups/certs</ignore>
    <ignore>/etc/dumpdates</ignore>
    <ignore>/etc/svc/volatile</ignore>
    <ignore type="sregex">.log$|.swp$</ignore>
    <nodiff>/etc/ssl/private.key</nodiff>
    <skip_nfs>yes</skip_nfs>
    <skip_dev>yes</skip_dev>
    <skip_proc>yes</skip_proc>
    <skip_sys>yes</skip_sys>
    <process_priority>10</process_priority>
    <max_eps>50</max_eps>
    <synchronization>
      <enabled>yes</enabled>
      <interval>5m</interval>
      <max_eps>10</max_eps>
    </synchronization>
WAZUH_CONFIG_SECTION_1_OPEN
# -----------------------------------------------------------------------------------------------------------------------

# 2. Bloque FIM Adicional (Añade la configuración específica FIM y cierra <syscheck>)
if ! grep -q '/etc/wireguard' /var/ossec/etc/ossec.conf; then
  cat >> /var/ossec/etc/ossec.conf <<'FIM_CONFIG_APPEND'
    <frequency>300</frequency> <alert_new_files>yes</alert_new_files>
    <directories check_all="yes" realtime="yes" report_changes="yes">/etc/wireguard</directories>
    <directories check_all="yes" realtime="yes">/opt/keycloak/conf</directories>
    <directories check_all="yes" realtime="yes" report_changes="yes">/etc/ssh/sshd_config</directories>
    <ignore type="sregex">\.log$</ignore>
  </syscheck> 
FIM_CONFIG_APPEND
  echo "[$(date)] FIM configurado en Wazuh agent" >> /tmp/user-data.log
else
  echo "[$(date)] FIM ya está configurado en Wazuh" >> /tmp/user-data.log
fi
# -----------------------------------------------------------------------------------------------------------------------

# 3. Bloque de Cierre (Añade el resto de localfiles, active-response, logging Y CIERRA <ossec_config>)
if ! grep -q '</ossec_config>' /var/ossec/etc/ossec.conf; then
    cat >> /var/ossec/etc/ossec.conf <<'WAZUH_CONFIG_CLOSE'
  <localfile>
    <log_format>command</log_format>
    <command>df -P</command>
    <frequency>360</frequency>
  </localfile>
  <localfile>
    <log_format>full_command</log_format>
    <command>netstat -tulpn | sed 's/\([[:alnum:]]\+\)\ \+[[:digit:]]\+\ \+[[:digit:]]\+\ \+\(.*\):\([[:digit:]]*\)\ \+\([0-9\.\:\*]\+\).\+\ \([[:digit:]]*\/[[:alnum:]\-]*\).*/\1 \2 == \3 == \4 \5/' | sort -k 4 -g | sed 's/ == \(.*\) ==/:\1/' | sed 1,2d</command>
    <alias>netstat listening ports</alias>
    <frequency>360</frequency>
  </localfile>
  <localfile>
    <log_format>full_command</log_format>
    <command>last -n 20</command>
    <frequency>360</frequency>
  </localfile>

  <localfile>
    <log_format>journald</log_format>
    <location>journald</location>
  </localfile>
  <localfile>
    <log_format>syslog</log_format>
    <location>/var/ossec/logs/active-responses.log</location>
  </localfile>
  <localfile>
    <log_format>syslog</log_format>
    <location>/var/log/dpkg.log</location>
  </localfile>

  <active-response>
    <disabled>no</disabled>
    <ca_store>etc/wpk_root.pem</ca_store>
    <ca_verification>yes</ca_verification>
  </active-response>
  
  <logging>
    <log_format>plain</log_format>
  </logging>
</ossec_config> 
WAZUH_CONFIG_CLOSE
    echo "[$(date)] ossec.conf cerrado para el inicio del agente" >> /tmp/user-data.log
fi
# -----------------------------------------------------------------------------------------------------------------------

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

# 4. Monitoreo de Keycloak Log (Añade la configuración extra a un archivo cerrado y reinicia)
if [ -f /opt/keycloak/data/log/keycloak.log ]; then
  echo "[$(date)] Agregando keycloak.log a Wazuh agent..." >> /tmp/user-data.log

  if ! grep -q '/opt/keycloak/data/log/keycloak.log' /var/ossec/etc/ossec.conf; then
    # Remover el cierre, agregar la configuración y cerrar de nuevo
    sed -i '/<\/ossec_config>/d' /var/ossec/etc/ossec.conf
    
    cat >> /var/ossec/etc/ossec.conf <<'KEYCLOAK_LOG_APPEND_CLOSE_AGAIN'
  <localfile>
    <log_format>json</log_format>
    <location>/opt/keycloak/data/log/keycloak.log</location>
  </localfile>
</ossec_config>
KEYCLOAK_LOG_APPEND_CLOSE_AGAIN
# -----------------------------------------------------------------------------------------------------------------------
    systemctl restart wazuh-agent
    echo "[$(date)] Wazuh agent reiniciado con monitoreo de Keycloak" >> /tmp/user-data.log
  else
    echo "[$(date)] keycloak.log ya está configurado en Wazuh" >> /tmp/user-data.log
  fi
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