#!/bin/bash
set -e

# Timezone y NTP Uruguay
timedatectl set-timezone America/Montevideo

apt-get update
# Nota: apt-get upgrade removido porque puede fallar por paquetes 404 en repos
apt-get install -y git curl wget htop systemd-timesyncd

# Configurar NTP después de asegurar que está instalado
echo "NTP=0.uy.pool.ntp.org 1.uy.pool.ntp.org" >> /etc/systemd/timesyncd.conf
systemctl enable systemd-timesyncd
systemctl restart systemd-timesyncd

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

# Wait for Wazuh Manager to fully initialize (crear local_rules.xml default)
echo "[$(date)] Esperando a que Wazuh Manager termine de inicializar..." >> /tmp/user-data.log
sleep 10

# ============================================
# CLONAR REPOSITORIO PRIMERO (necesario para custom rules)
# ============================================
echo "[$(date)] Clonando repositorio..." >> /tmp/user-data.log

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

# ============================================
# APLICAR REGLAS CUSTOM DE WAZUH DESDE REPO
# ============================================
echo "[$(date)] Aplicando reglas personalizadas de Wazuh desde repo..." >> /tmp/user-data.log

# Wait for local_rules.xml to exist (created by Wazuh post-install)
RETRIES=0
while [ ! -f /var/ossec/etc/rules/local_rules.xml ] && [ $RETRIES -lt 30 ]; do
  echo "[$(date)] Esperando a que /var/ossec/etc/rules/local_rules.xml sea creado... (intento $((RETRIES+1))/30)" >> /tmp/user-data.log
  sleep 2
  RETRIES=$((RETRIES+1))
done

if [ ! -f /var/ossec/etc/rules/local_rules.xml ]; then
  echo "[$(date)] ERROR: /var/ossec/etc/rules/local_rules.xml no fue creado después de 60 segundos" >> /tmp/user-data.log
  exit 1
fi

cp /opt/fosil/SIEM/scripts/wazuh-custom-rules.xml /var/ossec/etc/rules/local_rules.xml

# Set proper ownership and permissions (ossec group should exist after Wazuh installation)
if getent group ossec > /dev/null 2>&1; then
  chown root:ossec /var/ossec/etc/rules/local_rules.xml
  chmod 640 /var/ossec/etc/rules/local_rules.xml
else
  echo "WARNING: ossec group not found, using root:root ownership"
  chown root:root /var/ossec/etc/rules/local_rules.xml
  chmod 644 /var/ossec/etc/rules/local_rules.xml
fi

# Aplicar Active Response
echo "[$(date)] Aplicando Active Response..." >> /tmp/user-data.log
if grep -q '</ossec_config>' /var/ossec/etc/ossec.conf; then
  # Eliminar solo la ÚLTIMA línea </ossec_config>
  tac /var/ossec/etc/ossec.conf | sed '0,/<\/ossec_config>/d' | tac > /tmp/ossec.conf.tmp
  mv /tmp/ossec.conf.tmp /var/ossec/etc/ossec.conf
fi
cat /opt/fosil/SIEM/scripts/wazuh-active-response.xml >> /var/ossec/etc/ossec.conf
echo "" >> /var/ossec/etc/ossec.conf
echo "</ossec_config>" >> /var/ossec/etc/ossec.conf

# Reiniciar Wazuh Manager para aplicar reglas y Active Response
echo "[$(date)] Reiniciando Wazuh Manager..." >> /tmp/user-data.log
systemctl restart wazuh-manager

# Permisos del repositorio (ya clonado arriba)
chown -R ubuntu:ubuntu /opt/fosil

echo "Wazuh SIEM instalado - Password en /root/wazuh-password.txt" > /tmp/user-data-completed.log
echo "Reglas personalizadas aplicadas en /var/ossec/etc/rules/local_rules.xml" >> /tmp/user-data-completed.log
echo "Active Response configurado (Rules 100002, 100014)" >> /tmp/user-data-completed.log
echo "Repositorio clonado en /opt/fosil" >> /tmp/user-data-completed.log
date >> /tmp/user-data-completed.log