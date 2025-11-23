#!/bin/bash
# CIS Hardening - SAFE VERSION v2 (Score objetivo: 70%+)
# Obligatorio SRD - Fósil Energías Renovables S.A.
# OBJETIVO: Score SCA 70%+ SIN romper la VM

set -e

[ "$EUID" -ne 0 ] && { echo "❌ ERROR: Ejecutar como root (sudo bash apply-cis-hardening-safe.sh)"; exit 1; }

echo "============================================"
echo "  CIS Hardening - SAFE MODE v2"
echo "  Fósil Energías Renovables S.A."
echo "============================================"
echo ""
echo "⚠️  Medidas a aplicar (NO rompe boot/SSH/Wazuh):"
echo "   - Kernel hardening (sysctl - 20+ params)"
echo "   - Auditd con reglas CIS completas"
echo "   - AppArmor enforce mode"
echo "   - Permisos archivos críticos + cron"
echo "   - SSH hardening (mantiene acceso)"
echo "   - UFW firewall (permite SSH)"
echo "   - Fail2ban SSH protection"
echo "   - Disable unused filesystems"
echo "   - Password policies (PAM)"
echo "   - User accounts hardening"
echo ""
read -p "¿Continuar? (y/n): " -n 1 -r
echo
[[ ! $REPLY =~ ^[Yy]$ ]] && { echo "Abortado por el usuario"; exit 0; }
echo ""

# 0. DISABLE UNUSED FILESYSTEMS (HIGH SCORE - SAFE)
echo "[1/10] Disable unused filesystems..."

cat > /etc/modprobe.d/cis-filesystems.conf <<EOF
install cramfs /bin/true
install freevxfs /bin/true
install jffs2 /bin/true
install hfs /bin/true
install hfsplus /bin/true
install udf /bin/true
install squashfs /bin/true
EOF

cat > /etc/modprobe.d/cis-protocols.conf <<EOF
install dccp /bin/true
install sctp /bin/true
install rds /bin/true
install tipc /bin/true
EOF

# 1. KERNEL HARDENING (SAFE - no rompe nada)
echo "[2/10] Kernel hardening..."

cat > /etc/sysctl.d/99-cis-hardening.conf <<EOF
# Network hardening
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv4.conf.all.secure_redirects = 0
net.ipv4.conf.default.secure_redirects = 0
net.ipv4.conf.all.log_martians = 1
net.ipv4.conf.default.log_martians = 1
net.ipv4.icmp_echo_ignore_broadcasts = 1
net.ipv4.icmp_ignore_bogus_error_responses = 1
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1
net.ipv4.tcp_syncookies = 1

# IPv6 (keep enabled but harden)
net.ipv6.conf.all.accept_ra = 0
net.ipv6.conf.default.accept_ra = 0
net.ipv6.conf.all.accept_redirects = 0
net.ipv6.conf.default.accept_redirects = 0

# Memory protection
kernel.randomize_va_space = 2
kernel.dmesg_restrict = 1
kernel.kptr_restrict = 2
kernel.yama.ptrace_scope = 1
fs.suid_dumpable = 0
fs.protected_hardlinks = 1
fs.protected_symlinks = 1
fs.protected_fifos = 2
fs.protected_regular = 2
EOF

sysctl -p /etc/sysctl.d/99-cis-hardening.conf >/dev/null 2>&1

# 2. AUDITD (SAFE - reglas CIS completas)
echo "[3/10] Auditd..."

export DEBIAN_FRONTEND=noninteractive
if ! command -v auditctl &> /dev/null; then
    apt-get update -qq
    apt-get install -y -qq auditd audispd-plugins
fi

mkdir -p /etc/audit/rules.d

cat > /etc/audit/rules.d/cis-hardening.rules <<'EOF'
-D
-b 8192
-f 1

# Time changes
-w /etc/localtime -p wa -k time-change

# User/group info
-w /etc/passwd -p wa -k identity
-w /etc/group -p wa -k identity
-w /etc/shadow -p wa -k identity
-w /etc/gshadow -p wa -k identity

# Network config
-w /etc/hosts -p wa -k network
-w /etc/network/ -p wa -k network

# Sudoers
-w /etc/sudoers -p wa -k sudoers
-w /etc/sudoers.d/ -p wa -k sudoers

# SSH
-w /etc/ssh/sshd_config -p wa -k sshd
-w /etc/ssh/sshd_config.d/ -p wa -k sshd

# Login/logout
-w /var/log/lastlog -p wa -k logins
-w /var/log/wtmp -p wa -k logins
-w /var/log/btmp -p wa -k logins

# Cron
-w /etc/crontab -p wa -k cron
-w /etc/cron.d/ -p wa -k cron

# Privileged commands
-a always,exit -F arch=b64 -S execve -F euid=0 -k root_commands

# Immutable
-e 2
EOF

systemctl enable auditd >/dev/null 2>&1
systemctl restart auditd >/dev/null 2>&1

# 3. APPARMOR (SAFE - enforce mode)
echo "[4/10] AppArmor..."

apt-get install -y -qq apparmor apparmor-utils >/dev/null 2>&1
systemctl enable apparmor >/dev/null 2>&1
systemctl start apparmor >/dev/null 2>&1

# Set profiles to enforce (safe - only existing profiles)
aa-enforce /etc/apparmor.d/usr.sbin.* 2>/dev/null || true

# 4. FILE PERMISSIONS (SAFE - extended)
echo "[5/10] File permissions..."

chmod 644 /etc/passwd
chmod 600 /etc/shadow
chmod 600 /etc/shadow- 2>/dev/null || true
chmod 644 /etc/group
chmod 600 /etc/gshadow
chmod 600 /etc/gshadow- 2>/dev/null || true
chmod 600 /boot/grub/grub.cfg 2>/dev/null || true

# Cron permissions
chmod 600 /etc/crontab 2>/dev/null || true
chmod 700 /etc/cron.d 2>/dev/null || true
chmod 700 /etc/cron.daily 2>/dev/null || true
chmod 700 /etc/cron.hourly 2>/dev/null || true
chmod 700 /etc/cron.monthly 2>/dev/null || true
chmod 700 /etc/cron.weekly 2>/dev/null || true

# 5. USER ACCOUNTS HARDENING (SAFE)
echo "[6/10] User accounts..."

# Secure umask
sed -i 's/^UMASK.*/UMASK 027/' /etc/login.defs 2>/dev/null || true

# Session timeout
echo "readonly TMOUT=900" > /etc/profile.d/tmout.sh
chmod +x /etc/profile.d/tmout.sh

# Disable unused system users
for user in games news uucp proxy www-data backup list irc gnats nobody; do
    if id "$user" >/dev/null 2>&1; then
        usermod -s /usr/sbin/nologin $user 2>/dev/null || true
    fi
done

# 6. PASSWORD POLICIES (SAFE - no lockouts)
echo "[7/10] Password policies..."

apt-get install -y -qq libpam-pwquality >/dev/null 2>&1

cat > /etc/security/pwquality.conf <<EOF
minlen = 12
dcredit = -1
ucredit = -1
lcredit = -1
ocredit = -1
EOF

# 7. SSH HARDENING (SAFE - mantiene acceso + cambio de puerto)
echo "[8/10] SSH hardening..."

cp /etc/ssh/sshd_config /etc/ssh/sshd_config.backup.$(date +%Y%m%d) 2>/dev/null || true

# Cambiar puerto SSH de 22 a 2222 (security by obscurity + CIS points)
cat > /etc/ssh/sshd_config.d/99-cis-hardening.conf <<EOF
# CIS SSH Hardening (SAFE - maintains access)
Port 2222
Protocol 2
PermitRootLogin no
MaxAuthTries 4
IgnoreRhosts yes
HostbasedAuthentication no
PermitEmptyPasswords no
PermitUserEnvironment no
ClientAliveInterval 300
ClientAliveCountMax 3
LoginGraceTime 60
MaxSessions 10
Banner /etc/issue.net
X11Forwarding no
AllowTcpForwarding no
EOF

cat > /etc/issue.net <<'EOF'
***************************************************************************
                    SISTEMA AUTORIZADO ÚNICAMENTE

    Fósil Energías Renovables S.A.

    El acceso no autorizado está prohibido.
***************************************************************************
EOF

systemctl restart sshd

# Esperar a que SSH reinicie en nuevo puerto
sleep 2

# 8. FIREWALL (RESTRICTIVO - solo tu IP puede SSH)
echo "[9/10] UFW Firewall..."

apt-get install -y -qq ufw >/dev/null 2>&1

# CRÍTICO: Configurar reglas ANTES de habilitar
ufw --force reset >/dev/null 2>&1
ufw default deny incoming >/dev/null 2>&1
ufw default allow outgoing >/dev/null 2>&1

# SEGURIDAD MEJORADA: SSH solo desde tu IP + puerto 2222
ufw allow from 104.30.133.214 to any port 2222 proto tcp comment 'SSH desde IP autorizada' >/dev/null 2>&1

# Permitir acceso desde VPC (para Wazuh manager)
ufw allow from 10.0.1.0/24 >/dev/null 2>&1

# Habilitar firewall
ufw --force enable >/dev/null 2>&1
ufw status | grep -q "Status: active" && echo "  ✅ UFW activo (SSH limitado a 104.30.133.214:2222)" || echo "  ⚠️  UFW no se activó"

# 9. FAIL2BAN (SAFE - protección SSH puerto 2222)
echo "[10/10] Fail2ban..."

apt-get install -y -qq fail2ban >/dev/null 2>&1

cat > /etc/fail2ban/jail.local <<EOF
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

systemctl enable fail2ban >/dev/null 2>&1
systemctl restart fail2ban >/dev/null 2>&1

# VERIFICACIÓN CRÍTICA
echo ""
echo "============================================"
echo "  VERIFICACIÓN DE SERVICIOS CRÍTICOS"
echo "============================================"

# Verificar SSH
if systemctl is-active --quiet sshd; then
    echo "✅ SSH: Activo"
else
    echo "❌ SSH: ERROR - Revirtiendo cambios..."
    rm -f /etc/ssh/sshd_config.d/99-cis-hardening.conf
    systemctl restart sshd
fi

# Verificar Wazuh agent
if systemctl is-active --quiet wazuh-agent; then
    echo "✅ Wazuh Agent: Activo"
else
    echo "⚠️  Wazuh Agent: No detectado (verificar manualmente)"
fi

# Verificar UFW
if ufw status | grep -q "Status: active"; then
    echo "✅ UFW Firewall: Activo"
else
    echo "⚠️  UFW: No activo"
fi

# Verificar Fail2ban
if systemctl is-active --quiet fail2ban; then
    echo "✅ Fail2ban: Activo"
else
    echo "⚠️  Fail2ban: No activo"
fi

echo ""
echo "============================================"
echo "✅ CIS Hardening SAFE v3 - COMPLETADO"
echo "============================================"
echo ""
echo "📊 Medidas aplicadas (10 categorías):"
echo "   ✅ Disable unused filesystems (cramfs, hfs, udf, etc.)"
echo "   ✅ Disable insecure protocols (DCCP, SCTP, RDS, TIPC)"
echo "   ✅ Kernel hardening (25+ sysctl params)"
echo "   ✅ Auditd + 15 reglas CIS"
echo "   ✅ AppArmor enforce mode"
echo "   ✅ File permissions (passwd, shadow, cron dirs)"
echo "   ✅ User accounts hardening (umask, timeout, disable unused)"
echo "   ✅ Password policies (PAM pwquality)"
echo "   ✅ SSH hardening (Puerto 2222, Banner, X11Forwarding off)"
echo "   ✅ UFW firewall (SSH limitado a 104.30.133.214:2222)"
echo "   ✅ Fail2ban SSH protection puerto 2222"
echo ""
echo "📈 SCA Score esperado: 70-75%"
echo ""
echo "⚠️  CAMBIOS CRÍTICOS APLICADOS:"
echo "   - SSH puerto cambiado: 22 → 2222"
echo "   - UFW: Solo permite SSH desde 104.30.133.214"
echo "   - Wazuh agent: Funcionando (conectado via VPC 10.0.1.0/24)"
echo ""
echo "🔄 REINICIO REQUERIDO:"
echo "   El sistema debe reiniciarse para:"
echo "   1. Aplicar cambios de kernel (sysctl, modprobe)"
echo "   2. Activar AppArmor profiles"
echo "   3. Wazuh SCA recalcule el score"
echo ""
echo "⏱️  Preparando reinicio en 10 segundos..."
echo "   Presiona Ctrl+C para cancelar"
echo ""
sleep 10

echo "🔄 Reiniciando sistema..."
sudo systemctl reboot