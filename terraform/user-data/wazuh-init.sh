#!/bin/bash
set -e

# Timezone y NTP Uruguay
timedatectl set-timezone America/Montevideo

apt-get update
apt-get upgrade -y
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

cp /opt/fosil/SIEM/scripts/wazuh-custom-rules.xml /var/ossec/etc/rules/local_rules.xml
chown root:ossec /var/ossec/etc/rules/local_rules.xml
chmod 640 /var/ossec/etc/rules/local_rules.xml

# Backup del HEREDOC viejo (por si acaso) - INICIO
cat > /var/ossec/etc/rules/local_rules.xml.backup-heredoc <<'RULES'
<!-- /var/ossec/etc/rules/local_rules.xml -->
<!-- Reglas personalizadas - Fósil Energías Renovables -->
<!-- Estas reglas funcionan con Wazuh 4.13.1 -->

<group name="local,authentication,">

  <!-- CASO 1: Múltiples intentos de autenticación fallidos (SSH) -->
  <rule id="100001" level="10" frequency="3" timeframe="120">
    <if_matched_sid>5503</if_matched_sid>
    <description>Wazuh: Múltiples intentos de autenticación SSH fallidos</description>
    <mitre>
      <id>T1110</id>
    </mitre>
    <group>authentication_failures,</group>
  </rule>

  <!-- Alerta crítica desde IP externa -->
  <rule id="100002" level="12">
    <if_sid>100001</if_sid>
    <srcip>!10.0.1.0/24</srcip>
    <description>Wazuh: Brute force desde IP externa (fuera de VPC)</description>
    <mitre>
      <id>T1110</id>
    </mitre>
    <group>authentication_failures,attacks,</group>
  </rule>

  <!-- Alerta crítica en usuario privilegiado -->
  <rule id="100003" level="12">
    <if_sid>100001</if_sid>
    <user>root|admin|ubuntu</user>
    <description>Wazuh: Brute force en cuenta privilegiada</description>
    <mitre>
      <id>T1110</id>
    </mitre>
    <group>authentication_failures,privilege_escalation,</group>
  </rule>

</group>

<group name="local,web,attack,">

  <!-- CASO 2: Ataques Web (OWASP Top 10) via ModSecurity/Kong -->

  <!-- SQL Injection detectado por ModSecurity -->
  <rule id="100010" level="10">
    <if_sid>31100</if_sid>
    <match>sql|union|select|insert|drop|delete|update</match>
    <description>Kong: Intento de SQL Injection detectado</description>
    <mitre>
      <id>T1190</id>
    </mitre>
    <group>web_attack,sql_injection,</group>
  </rule>

  <!-- XSS detectado -->
  <rule id="100011" level="10">
    <if_sid>31100</if_sid>
    <match>script|onerror|onload|alert\(|eval\(|javascript:</match>
    <description>Kong: Intento de XSS (Cross-Site Scripting) detectado</description>
    <mitre>
      <id>T1190</id>
    </mitre>
    <group>web_attack,xss,</group>
  </rule>

  <!-- RCE (Remote Code Execution) -->
  <rule id="100012" level="12">
    <if_sid>31100</if_sid>
    <match>exec|system|passthru|shell_exec|/bin/bash|/bin/sh</match>
    <description>Kong: Intento CRÍTICO de RCE (Remote Code Execution)</description>
    <mitre>
      <id>T1190</id>
    </mitre>
    <group>web_attack,rce,</group>
  </rule>

  <!-- Path Traversal / LFI -->
  <rule id="100013" level="10">
    <if_sid>31100</if_sid>
    <match>\.\.\/|\.\.\\|etc/passwd|boot\.ini</match>
    <description>Kong: Intento de Path Traversal detectado</description>
    <mitre>
      <id>T1190</id>
    </mitre>
    <group>web_attack,path_traversal,</group>
  </rule>

  <!-- Múltiples ataques web desde misma IP -->
  <rule id="100014" level="12" frequency="10" timeframe="300">
    <if_matched_sid>100010</if_matched_sid>
    <same_source_ip />
    <description>Kong: Múltiples ataques web desde la misma IP (posible escaneo)</description>
    <mitre>
      <id>T1190</id>
      <id>T1595</id>
    </mitre>
    <group>web_attack,reconnaissance,</group>
  </rule>

</group>

<group name="local,syscheck,">

  <!-- CASO 3: File Integrity Monitoring -->

  <!-- Cambios en archivos de usuarios -->
  <rule id="100020" level="10">
    <if_sid>550</if_sid>
    <match>/etc/passwd|/etc/shadow|/etc/group</match>
    <description>Wazuh: Cambio en archivos de usuarios del sistema</description>
    <mitre>
      <id>T1098</id>
    </mitre>
    <group>syscheck,account_changed,</group>
  </rule>

  <!-- Cambios en sudoers (crítico) -->
  <rule id="100021" level="12">
    <if_sid>550</if_sid>
    <match>/etc/sudoers</match>
    <description>Wazuh: Cambio CRÍTICO en configuración sudo</description>
    <mitre>
      <id>T1548.003</id>
    </mitre>
    <group>syscheck,privilege_escalation,</group>
  </rule>

  <!-- Cambios en SSH -->
  <rule id="100022" level="10">
    <if_sid>550</if_sid>
    <match>/etc/ssh/sshd_config|authorized_keys</match>
    <description>Wazuh: Cambio en configuración SSH</description>
    <mitre>
      <id>T1098.004</id>
    </mitre>
    <group>syscheck,ssh,</group>
  </rule>

  <!-- Cambios en firewall -->
  <rule id="100023" level="10">
    <if_sid>550</if_sid>
    <match>/etc/ufw|/etc/iptables</match>
    <description>Wazuh: Cambio en configuración de firewall</description>
    <mitre>
      <id>T1562.004</id>
    </mitre>
    <group>syscheck,firewall,</group>
  </rule>

</group>
RULES
# FIN backup HEREDOC viejo (no se usa, solo referencia)

# Reiniciar Wazuh Manager para aplicar reglas desde repo
echo "[$(date)] Reiniciando Wazuh Manager para aplicar reglas desde repo..." >> /tmp/user-data.log
systemctl restart wazuh-manager

# Permisos del repositorio (ya clonado arriba)
chown -R ubuntu:ubuntu /opt/fosil

echo "Wazuh SIEM instalado - Password en /root/wazuh-password.txt" > /tmp/user-data-completed.log
echo "Reglas personalizadas aplicadas en /var/ossec/etc/rules/local_rules.xml" >> /tmp/user-data-completed.log
echo "Repositorio clonado en /opt/fosil" >> /tmp/user-data-completed.log
date >> /tmp/user-data-completed.log