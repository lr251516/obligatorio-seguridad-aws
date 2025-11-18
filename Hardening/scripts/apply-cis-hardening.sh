#!/bin/bash
# CIS Hardening Level 1 - Ubuntu 22.04
# Obligatorio SRD - Fósil Energías Renovables S.A.
set -e

[ "$EUID" -ne 0 ] && { echo "❌ ERROR: Ejecutar como root (sudo ./apply-cis-hardening.sh)"; exit 1; }

clear
echo "============================================"
echo "  CIS Hardening Ubuntu 22.04 - Level 1"
echo "  Fósil Energías Renovables S.A."
echo "============================================"
echo ""
echo "⚠️  Este script aplicará las siguientes medidas de seguridad:"
echo "   - Filesystem hardening (modprobe, /tmp secure mount)"
echo "   - Bootloader permissions"
echo "   - Kernel hardening (sysctl)"
echo "   - Auditd con reglas CIS"
echo "   - Permisos de archivos críticos"
echo "   - Políticas de contraseñas fuertes (PAM)"
echo "   - User account hardening"
echo "   - SSH hardening (PermitRootLogin no, MaxAuthTries 4)"
echo "   - Servicios innecesarios deshabilitados"
echo "   - Firewall UFW habilitado"
echo "   - Fail2ban para SSH brute force"
echo ""
read -p "¿Continuar? (y/n): " -n 1 -r
echo
[[ ! $REPLY =~ ^[Yy]$ ]] && { echo "Abortado por el usuario"; exit 0; }
echo ""
echo "Iniciando hardening..."
echo ""

# 1. FILESYSTEM HARDENING
echo "[1/8] Filesystem..."

# Deshabilitar filesystems no usados
cat >> /etc/modprobe.d/cis-hardening.conf <<EOF
install cramfs /bin/true
install freevxfs /bin/true
install jffs2 /bin/true
install hfs /bin/true
install hfsplus /bin/true
install udf /bin/true
install vfat /bin/true
EOF

# Configurar /tmp con opciones seguras
systemctl unmask tmp.mount
cat > /etc/systemd/system/tmp.mount <<'EOF'
[Unit]
Description=Temporary Directory
ConditionPathIsSymbolicLink=!/tmp

[Mount]
What=tmpfs
Where=/tmp
Type=tmpfs
Options=mode=1777,strictatime,noexec,nodev,nosuid,size=2G

[Install]
WantedBy=local-fs.target
EOF

systemctl daemon-reload
systemctl enable tmp.mount
systemctl start tmp.mount

# 2. BOOT LOADER HARDENING
echo "[2/8] Bootloader..."
chown root:root /boot/grub/grub.cfg
chmod og-rwx /boot/grub/grub.cfg

# 3. KERNEL HARDENING
echo "[3/8] Kernel..."

cat > /etc/sysctl.d/99-cis-hardening.conf <<EOF
# Protección de red
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
net.ipv6.conf.all.accept_ra = 0
net.ipv6.conf.default.accept_ra = 0
net.ipv6.conf.all.accept_redirects = 0
net.ipv6.conf.default.accept_redirects = 0

# Protección de memoria
kernel.randomize_va_space = 2
kernel.dmesg_restrict = 1
kernel.kptr_restrict = 2
fs.suid_dumpable = 0
EOF

sysctl -p /etc/sysctl.d/99-cis-hardening.conf

# 4. AUDITING
echo "[4/8] Auditd..."
cat > /etc/audit/rules.d/cis-hardening.rules <<'EOF'
# Borrar reglas existentes
-D

# Buffer size
-b 8192

# Failure mode (1 = log only)
-f 1

# Auditar cambios en configuración de usuarios
-w /etc/passwd -p wa -k identity
-w /etc/group -p wa -k identity
-w /etc/shadow -p wa -k identity
-w /etc/gshadow -p wa -k identity
-w /etc/security/opasswd -p wa -k identity

# Auditar configuración de red
-w /etc/network/ -p wa -k network
-w /etc/hosts -p wa -k network
-w /etc/hostname -p wa -k network

# Auditar cambios en sudoers
-w /etc/sudoers -p wa -k sudoers
-w /etc/sudoers.d/ -p wa -k sudoers

# Auditar comandos privilegiados
-a always,exit -F arch=b64 -S execve -F euid=0 -k root_commands
-a always,exit -F arch=b32 -S execve -F euid=0 -k root_commands

# Auditar cambios en SSH
-w /etc/ssh/sshd_config -p wa -k sshd

# Auditar login/logout
-w /var/log/lastlog -p wa -k logins
-w /var/run/faillock/ -p wa -k logins

# Auditar cambios en crontab
-w /etc/crontab -p wa -k cron
-w /etc/cron.allow -p wa -k cron
-w /etc/cron.deny -p wa -k cron
-w /etc/cron.d/ -p wa -k cron
-w /etc/cron.daily/ -p wa -k cron
-w /etc/cron.hourly/ -p wa -k cron
-w /etc/cron.monthly/ -p wa -k cron
-w /etc/cron.weekly/ -p wa -k cron

# Make configuration immutable
-e 2
EOF

service auditd restart

# 5. INSTALAR PAQUETES ADICIONALES
echo "[5/9] Instalando paquetes de seguridad adicionales..."
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y ufw fail2ban 2>/dev/null || true

# 6. ACCESS CONTROL
echo "[6/9] Access control..."
chmod 644 /etc/passwd
chmod 600 /etc/shadow
chmod 644 /etc/group
chmod 600 /etc/gshadow
chmod 600 /boot/grub/grub.cfg

# Configurar PAM para contraseñas fuertes
apt-get install -y libpam-pwquality

cat > /etc/security/pwquality.conf <<EOF
minlen = 14
dcredit = -1
ucredit = -1
ocredit = -1
lcredit = -1
EOF

# Configurar lockout de cuentas
cat >> /etc/pam.d/common-auth <<EOF
auth required pam_faillock.so preauth silent audit deny=5 unlock_time=900
auth [default=die] pam_faillock.so authfail audit deny=5 unlock_time=900
EOF

# 7. USER ACCOUNTS
echo "[7/9] User accounts..."
echo "readonly TMOUT=900" >> /etc/profile.d/tmout.sh
echo "readonly HISTSIZE=5000" >> /etc/profile.d/history.sh
chmod +x /etc/profile.d/tmout.sh
chmod +x /etc/profile.d/history.sh

# Configurar umask seguro
sed -i 's/UMASK\s*022/UMASK 027/' /etc/login.defs

# Deshabilitar usuarios del sistema
for user in games news uucp proxy www-data backup list irc gnats; do
    if id "$user" >/dev/null 2>&1; then
        usermod -s /usr/sbin/nologin $user
    fi
done

# 8. SSH HARDENING
echo "[8/9] SSH..."
cp /etc/ssh/sshd_config /etc/ssh/sshd_config.backup

cat > /etc/ssh/sshd_config.d/99-cis-hardening.conf <<EOF
# CIS Hardening SSH
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
Banner /etc/issue.net
MaxSessions 10
X11Forwarding no
AllowTcpForwarding no
AllowAgentForwarding no
EOF

# Banner de login
cat > /etc/issue.net <<'EOF'
***************************************************************************
                    SISTEMA AUTORIZADO ÚNICAMENTE
    
    Fósil Energías Renovables S.A.
    
    El acceso no autorizado está prohibido. Todas las actividades
    son monitoreadas y registradas. El uso indebido será perseguido
    legalmente según corresponda.
***************************************************************************
EOF

systemctl restart sshd

# 9. SERVICES, FIREWALL Y FAIL2BAN
echo "[9/9] Services, firewall y fail2ban..."
apt-get remove -y avahi-daemon cups isc-dhcp-server isc-dhcp-server6 \
    ldap-utils rpcbind rsync slapd snmp nis 2>/dev/null || true

# Configurar actualizaciones automáticas de seguridad
cat > /etc/apt/apt.conf.d/50unattended-upgrades <<EOF
Unattended-Upgrade::Allowed-Origins {
    "\${distro_id}:\${distro_codename}-security";
};
Unattended-Upgrade::AutoFixInterruptedDpkg "true";
Unattended-Upgrade::MinimalSteps "true";
Unattended-Upgrade::Remove-Unused-Kernel-Packages "true";
Unattended-Upgrade::Remove-Unused-Dependencies "true";
Unattended-Upgrade::Automatic-Reboot "false";
EOF

systemctl enable unattended-upgrades
systemctl start unattended-upgrades

# Configurar UFW (firewall)
echo "  - Configurando UFW firewall..."
ufw --force enable
ufw default deny incoming
ufw default allow outgoing
ufw allow from 10.0.1.0/24 to any port 22  # SSH desde VPC
ufw allow 22/tcp  # SSH (limitado por Security Group de AWS)

# Configurar Fail2ban para SSH
echo "  - Configurando Fail2ban (SSH brute force protection)..."
cat > /etc/fail2ban/jail.local <<EOF
[DEFAULT]
bantime = 1800
findtime = 600
maxretry = 3
destemail = admin@fosil.com.uy
sendername = Fail2Ban

[sshd]
enabled = true
port = ssh
logpath = /var/log/auth.log
maxretry = 3
bantime = 1800
EOF

systemctl enable fail2ban
systemctl restart fail2ban

echo ""
echo "============================================"
echo "✅ CIS Hardening Level 1 - COMPLETADO"
echo "============================================"
echo ""
echo "📊 Medidas aplicadas:"
echo "   ✅ Filesystem hardening"
echo "   ✅ Bootloader permissions"
echo "   ✅ Kernel hardening (sysctl)"
echo "   ✅ Auditd + reglas CIS"
echo "   ✅ Access control (permisos archivos críticos)"
echo "   ✅ Políticas de contraseñas fuertes"
echo "   ✅ User accounts hardening"
echo "   ✅ SSH hardening"
echo "   ✅ UFW firewall habilitado"
echo "   ✅ Fail2ban configurado (SSH)"
echo "   ✅ Servicios innecesarios removidos"
echo "   ✅ Actualizaciones automáticas de seguridad"
echo ""
echo "📈 SCA Score esperado en Wazuh: 80-85% (mejora desde ~40-50%)"
echo ""
echo "⚠️  IMPORTANTE: Reiniciar el sistema para aplicar todos los cambios:"
echo "   sudo reboot"
echo ""
echo "🔍 Verificar SCA score en Wazuh Dashboard después del reboot:"
echo "   http://wazuh-dashboard → Security Configuration Assessment → hardening-vm"
echo ""