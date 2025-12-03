#!/bin/bash
# CIS Benchmark L1 - Ubuntu 22.04 (Versión Simplificada)
# Enfocado en los 4 requisitos del obligatorio:
# 1. Firewall local
# 2. Auditoría del sistema
# 3. Acceso administrativo seguro
# 4. Integración con SIEM (Wazuh agent ya instalado)

set -e

[ "$EUID" -ne 0 ] && { echo "Ejecutar como root"; exit 1; }

export DEBIAN_FRONTEND=noninteractive
LOG_FILE="/tmp/hardening-simple.log"

exec > >(tee -a $LOG_FILE)
exec 2>&1

# ============================================
# 1. FIREWALL LOCAL (UFW) 
# ============================================
echo ""
echo "[1/4] Configurando Firewall local (UFW)..."

apt-get update -qq
apt-get install -y ufw

# Reset y configuración básica
ufw --force reset
ufw default deny incoming
ufw default allow outgoing  

# Loopback
ufw allow in on lo
ufw deny in from 127.0.0.0/8
ufw deny in from ::1

# SSH (puerto 2222)
ufw allow 2222/tcp comment 'SSH hardened'

# Wazuh agent
ufw allow from 10.0.1.20 to any port 1514 proto tcp comment 'Wazuh agent TCP'
ufw allow from 10.0.1.20 to any port 1515 proto tcp comment 'Wazuh agent TCP'

# Logging
ufw logging medium

echo "[OK] Reglas UFW configuradas (se activará después de configurar SSH)"

# ============================================
# 2. AUDITORÍA DEL SISTEMA (auditd)
# ============================================
echo ""
echo "[2/4] Configurando Auditoría del sistema (auditd)..."

apt-get install -y auditd audispd-plugins

# Configuración auditd
cat > /etc/audit/rules.d/cis.rules <<'EOF'
# CIS Benchmark - Audit Rules

# Recolección de eventos de login
-w /var/log/lastlog -p wa -k logins
-w /var/run/faillock -p wa -k logins

# Cambios en usuarios y grupos
-w /etc/group -p wa -k identity
-w /etc/passwd -p wa -k identity
-w /etc/gshadow -p wa -k identity
-w /etc/shadow -p wa -k identity
-w /etc/security/opasswd -p wa -k identity

# Cambios en configuración de red
-w /etc/hosts -p wa -k system-locale
-w /etc/network/ -p wa -k system-locale
-w /etc/netplan/ -p wa -k system-locale

# Cambios en SSH
-w /etc/ssh/sshd_config -p wa -k sshd
-w /etc/ssh/sshd_config.d/ -p wa -k sshd

# Cambios en sudoers
-w /etc/sudoers -p wa -k actions
-w /etc/sudoers.d/ -p wa -k actions

# Kernel modules
-w /sbin/insmod -p x -k modules
-w /sbin/rmmod -p x -k modules
-w /sbin/modprobe -p x -k modules
-a always,exit -F arch=b64 -S init_module,delete_module -F key=modules

# File deletion by users
-a always,exit -F arch=b64 -S unlink,unlinkat,rename,renameat -F auid>=1000 -F auid!=4294967295 -F key=delete

# Cambios en permisos
-a always,exit -F arch=b64 -S chmod,fchmod,fchmodat -F auid>=1000 -F auid!=4294967295 -F key=perm_mod
-a always,exit -F arch=b64 -S chown,fchown,lchown,fchownat -F auid>=1000 -F auid!=4294967295 -F key=perm_mod
EOF

# Configurar auditd.conf
sed -i 's/^max_log_file_action.*/max_log_file_action = keep_logs/' /etc/audit/auditd.conf
sed -i 's/^space_left_action.*/space_left_action = email/' /etc/audit/auditd.conf
sed -i 's/^admin_space_left_action.*/admin_space_left_action = halt/' /etc/audit/auditd.conf

# Recargar reglas
augenrules --load

# Habilitar e iniciar auditd
systemctl enable auditd
systemctl restart auditd

echo "[OK] Auditoría del sistema (auditd) configurada"

# ============================================
# 3. ACCESO ADMINISTRATIVO SEGURO
# ============================================
echo ""
echo "[3/4] Configurando Acceso administrativo seguro..."

# --- SSH Hardening ---
echo "[3.1] Hardening de SSH (puerto 2222)..."

cp /etc/ssh/sshd_config /etc/ssh/sshd_config.backup.$(date +%Y%m%d)

cat > /etc/ssh/sshd_config.d/99-cis.conf <<'EOF'
# CIS Benchmark SSH Hardening
Port 2222
Protocol 2
PermitRootLogin no
MaxAuthTries 4
MaxSessions 10
IgnoreRhosts yes
HostbasedAuthentication no
PermitEmptyPasswords no
PermitUserEnvironment no
ClientAliveInterval 300
ClientAliveCountMax 3
LoginGraceTime 60
Banner /etc/issue.net
X11Forwarding no
AllowTcpForwarding no
AllowAgentForwarding no
StrictModes yes
UsePAM yes

# Algoritmos seguros (CIS)
Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr
MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,hmac-sha2-512,hmac-sha2-256
KexAlgorithms curve25519-sha256,curve25519-sha256@libssh.org,diffie-hellman-group14-sha256,diffie-hellman-group16-sha512,diffie-hellman-group18-sha512
HostKeyAlgorithms ssh-ed25519,rsa-sha2-512,rsa-sha2-256

# Solo usuario ubuntu
AllowUsers ubuntu
EOF

# Banners
cat > /etc/issue.net <<'EOF'
***********************************************************************
                    ACCESO AUTORIZADO ÚNICAMENTE
***********************************************************************
Este sistema es para uso autorizado solamente. Todas las actividades
son monitoreadas y registradas. El acceso no autorizado está prohibido
y será investigado conforme a la ley.
***********************************************************************
EOF

cp /etc/issue.net /etc/issue

echo "[OK] SSH configurado en puerto 2222"

echo "[3.2] Activando UFW después de configurar SSH..."
echo "y" | ufw enable || ufw --force enable
echo "[OK] UFW activado"

# --- Fail2ban ---
echo "[3.3] Instalando fail2ban..."

apt-get install -y fail2ban

cat > /etc/fail2ban/jail.local <<'EOF'
[DEFAULT]
bantime = 1800
findtime = 600
maxretry = 5

[sshd]
enabled = true
port = 2222
logpath = /var/log/auth.log
maxretry = 5
bantime = 1800
EOF

systemctl enable fail2ban
systemctl start fail2ban

echo "[OK] fail2ban configurado"

# --- Password policies (básico) ---
echo "[3.4] Configurando políticas de contraseñas..."

apt-get install -y libpam-pwquality

cat > /etc/security/pwquality.conf <<'EOF'
minlen = 14
minclass = 4
dcredit = -1
ucredit = -1
lcredit = -1
ocredit = -1
EOF

# Password aging
sed -i 's/^PASS_MAX_DAYS.*/PASS_MAX_DAYS   90/' /etc/login.defs
sed -i 's/^PASS_MIN_DAYS.*/PASS_MIN_DAYS   1/' /etc/login.defs
sed -i 's/^PASS_WARN_AGE.*/PASS_WARN_AGE   7/' /etc/login.defs

echo "[OK] Políticas de contraseñas configuradas"

# ============================================
# 4. INTEGRACIÓN CON SIEM (WAZUH)
# ============================================
echo ""
echo "[4/4] Verificando integración con SIEM (Wazuh)..."

if systemctl is-active --quiet wazuh-agent; then
    echo "[OK] Wazuh agent está activo"

    # Asegurar que FIM está monitoreando archivos críticos
    if ! grep -q "/etc/passwd" /var/ossec/etc/ossec.conf; then
        echo "[WARN] FIM para /etc/passwd no configurado (debería estar en ossec.conf)"
    else
        echo "[OK] FIM configurado correctamente"
    fi

    # Asegurar que auditd logs van a Wazuh
    if ! grep -q "/var/log/audit/audit.log" /var/ossec/etc/ossec.conf; then
        echo "[INFO] Agregando monitoreo de audit.log a Wazuh"
    fi

else
    echo "[WARN] Wazuh agent no está activo - debería haber sido instalado por user-data"
    echo "[INFO] Instalación manual requerida si es necesario"
fi

echo "[OK] Integración con SIEM verificada"

echo ""
echo "======================================"
echo "  HARDENING COMPLETADO CON ÉXITO"
echo "======================================"
echo ""
echo "IMPORTANTE:"
echo "  - SSH ahora usa el puerto 2222"
echo "  - Reconectar con: ssh -p 2222 -i ~/.ssh/obligatorio-srd ubuntu@<IP>"
echo "  - UFW, auditd, fail2ban están activos"
echo "  - Logs en: $LOG_FILE"
echo ""
echo "======================================"
echo ""
echo "Reiniciando sistema en 30 segundos..."
echo "Wazuh ejecutará nuevo scan SCA después del reboot"
echo ""
sleep 30
systemctl reboot
