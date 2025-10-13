#!/bin/bash
# Hardening basado en CIS Benchmark Level 1 para Ubuntu 22.04
# Fósil Energías Renovables - VM4 (10.0.1.40)

set -e

LOG_FILE="/opt/fosil/hardening-$(date +%Y%m%d-%H%M%S).log"
BACKUP_DIR="/opt/fosil/backups/$(date +%Y%m%d)"

log() {
    echo "[$(date +'%Y-%m-%d %H:%M:%S')] $1" | tee -a "$LOG_FILE"
}

backup_file() {
    local file=$1
    if [ -f "$file" ]; then
        sudo mkdir -p "$BACKUP_DIR"
        sudo cp "$file" "$BACKUP_DIR/$(basename $file).bak"
        log "Backup: $file → $BACKUP_DIR"
    fi
}

log "=========================================="
log "Iniciando Hardening CIS Level 1"
log "=========================================="

# ============================================
# 1. FILESYSTEM HARDENING
# ============================================
log "[1/10] Configurando opciones de montaje seguras..."

# Deshabilitar filesystems no utilizados
cat << 'EOF' | sudo tee /etc/modprobe.d/hardening-fs.conf > /dev/null
install cramfs /bin/true
install freevxfs /bin/true
install jffs2 /bin/true
install hfs /bin/true
install hfsplus /bin/true
install udf /bin/true
EOF

# ============================================
# 2. NETWORK HARDENING (Sysctl)
# ============================================
log "[2/10] Configurando parámetros de red seguros..."

backup_file "/etc/sysctl.conf"

cat << 'EOF' | sudo tee /etc/sysctl.d/99-hardening.conf > /dev/null
# IP Forwarding (necesario para VPN)
net.ipv4.ip_forward = 1

# Syn Cookies (protección contra SYN flood)
net.ipv4.tcp_syncookies = 1

# No aceptar ICMP redirects
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv6.conf.all.accept_redirects = 0
net.ipv6.conf.default.accept_redirects = 0

# No enviar ICMP redirects
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0

# No aceptar source routing
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0
net.ipv6.conf.all.accept_source_route = 0
net.ipv6.conf.default.accept_source_route = 0

# Protección contra IP spoofing
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1

# Ignorar pings broadcast
net.ipv4.icmp_echo_ignore_broadcasts = 1

# Ignorar mensajes ICMP bogus
net.ipv4.icmp_ignore_bogus_error_responses = 1

# Log packets sospechosos
net.ipv4.conf.all.log_martians = 1
net.ipv4.conf.default.log_martians = 1

# IPv6 Router Advertisements
net.ipv6.conf.all.accept_ra = 0
net.ipv6.conf.default.accept_ra = 0

# TCP Hardening
net.ipv4.tcp_timestamps = 0
net.ipv4.tcp_syn_retries = 2
net.ipv4.tcp_synack_retries = 2
EOF

sudo sysctl -p /etc/sysctl.d/99-hardening.conf

# ============================================
# 3. FIREWALL (UFW)
# ============================================
log "[3/10] Configurando firewall UFW..."

sudo apt install -y ufw

# Reset UFW
sudo ufw --force reset

# Políticas por defecto
sudo ufw default deny incoming
sudo ufw default allow outgoing
sudo ufw default deny routed

# Permitir SSH solo desde red interna
sudo ufw allow from 10.0.1.0/24 to any port 22 proto tcp comment 'SSH desde VPC'

# Permitir WireGuard
sudo ufw allow 51820/udp comment 'WireGuard VPN'

# Permitir tráfico interno VPC
sudo ufw allow from 10.0.1.0/24 comment 'Tráfico interno VPC'

# Rate limiting SSH
sudo ufw limit ssh comment 'Rate limit SSH'

# Logging
sudo ufw logging on

# Habilitar firewall
sudo ufw --force enable

log "UFW configurado y habilitado"

# ============================================
# 4. AUDITD
# ============================================
log "[4/10] Configurando auditd..."

sudo apt install -y auditd audispd-plugins

backup_file "/etc/audit/rules.d/audit.rules"

cat << 'EOF' | sudo tee /etc/audit/rules.d/hardening.rules > /dev/null
# Auditd Rules - CIS Benchmark

# Buffer size
-b 8192

# Failure mode (1 = print error, 2 = panic)
-f 1

# Ignore errors
-i

# Eventos de autenticación
-w /var/log/auth.log -p wa -k auth
-w /var/log/faillog -p wa -k logins
-w /var/log/lastlog -p wa -k logins

# Cambios en usuarios y grupos
-w /etc/passwd -p wa -k identity
-w /etc/group -p wa -k identity
-w /etc/gshadow -p wa -k identity
-w /etc/shadow -p wa -k identity
-w /etc/security/opasswd -p wa -k identity

# Cambios en sudoers
-w /etc/sudoers -p wa -k sudoers
-w /etc/sudoers.d/ -p wa -k sudoers

# Cambios en configuración SSH
-w /etc/ssh/sshd_config -p wa -k sshd
-w /etc/ssh/sshd_config.d/ -p wa -k sshd

# Cambios en cron
-w /etc/cron.allow -p wa -k cron
-w /etc/cron.deny -p wa -k cron
-w /etc/cron.d/ -p wa -k cron
-w /etc/cron.daily/ -p wa -k cron
-w /etc/cron.hourly/ -p wa -k cron
-w /etc/cron.monthly/ -p wa -k cron
-w /etc/cron.weekly/ -p wa -k cron
-w /etc/crontab -p wa -k cron

# Cambios en el kernel
-w /etc/sysctl.conf -p wa -k sysctl
-w /etc/sysctl.d/ -p wa -k sysctl

# Eventos de red
-a always,exit -F arch=b64 -S socket -S connect -k network
-a always,exit -F arch=b32 -S socket -S connect -k network

# Comandos privilegiados
-a always,exit -F path=/usr/bin/sudo -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged
-a always,exit -F path=/usr/bin/su -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged

# Montajes
-a always,exit -F arch=b64 -S mount -F auid>=1000 -F auid!=4294967295 -k mounts
-a always,exit -F arch=b32 -S mount -F auid>=1000 -F auid!=4294967295 -k mounts

# Hacer las reglas inmutables (debe ser la última línea)
-e 2
EOF

sudo systemctl restart auditd
log "Auditd configurado"

# ============================================
# 5. SSH HARDENING
# ============================================
log "[5/10] Endureciendo configuración SSH..."

backup_file "/etc/ssh/sshd_config"

cat << 'EOF' | sudo tee /etc/ssh/sshd_config.d/99-hardening.conf > /dev/null
# SSH Hardening - CIS Benchmark

# Protocolo y puerto
Port 22
AddressFamily inet

# Autenticación
PermitRootLogin no
PubkeyAuthentication yes
PasswordAuthentication no
PermitEmptyPasswords no
ChallengeResponseAuthentication no
UsePAM yes

# Timeouts
LoginGraceTime 60
ClientAliveInterval 300
ClientAliveCountMax 2

# Restricciones
MaxAuthTries 3
MaxSessions 2
MaxStartups 10:30:60

# Forwarding
AllowTcpForwarding no
X11Forwarding no
AllowAgentForwarding no

# Banner
Banner /etc/issue.net

# Logging
SyslogFacility AUTH
LogLevel VERBOSE

# Criptografía fuerte
KexAlgorithms curve25519-sha256,curve25519-sha256@libssh.org
Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com
MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com
EOF

# Crear banner
cat << 'EOF' | sudo tee /etc/issue.net > /dev/null
###############################################################
#           ACCESO NO AUTORIZADO PROHIBIDO                   #
#                                                             #
#   Este sistema es propiedad de Fósil Energías Renovables   #
#   Todos los accesos son monitoreados y registrados          #
#   El uso no autorizado será perseguido legalmente           #
#                                                             #
###############################################################
EOF

sudo systemctl restart sshd
log "SSH endurecido"

# ============================================
# 6. FAIL2BAN
# ============================================
log "[6/10] Instalando y configurando Fail2Ban..."

sudo apt install -y fail2ban

cat << 'EOF' | sudo tee /etc/fail2ban/jail.local > /dev/null
[DEFAULT]
bantime = 3600
findtime = 600
maxretry = 3
destemail = admin@fosil.uy
action = %(action_mwl)s

[sshd]
enabled = true
port = 22
logpath = /var/log/auth.log
maxretry = 3

[sshd-ddos]
enabled = true
port = 22
logpath = /var/log/auth.log
maxretry = 6
EOF

sudo systemctl enable fail2ban
sudo systemctl restart fail2ban
log "Fail2ban configurado"

# ============================================
# 7. PASSWORD POLICIES
# ============================================
log "[7/10] Configurando políticas de contraseñas..."

backup_file "/etc/pam.d/common-password"
backup_file "/etc/login.defs"

# Instalar libpam-pwquality
sudo apt install -y libpam-pwquality

# Configurar complejidad
sudo sed -i 's/^password.*pam_unix.so.*/password requisite pam_pwquality.so retry=3 minlen=12 difok=3 ucredit=-1 lcredit=-1 dcredit=-1 ocredit=-1 enforce_for_root/' /etc/pam.d/common-password

# Password aging
sudo sed -i 's/^PASS_MAX_DAYS.*/PASS_MAX_DAYS   90/' /etc/login.defs
sudo sed -i 's/^PASS_MIN_DAYS.*/PASS_MIN_DAYS   7/' /etc/login.defs
sudo sed -i 's/^PASS_WARN_AGE.*/PASS_WARN_AGE   14/' /etc/login.defs

log "Políticas de contraseñas configuradas"

# ============================================
# 8. DISABLE UNNECESSARY SERVICES
# ============================================
log "[8/10] Deshabilitando servicios innecesarios..."

SERVICES_TO_DISABLE=(
    "cups.service"
    "avahi-daemon.service"
    "bluetooth.service"
)

for service in "${SERVICES_TO_DISABLE[@]}"; do
    if systemctl is-enabled "$service" 2>/dev/null; then
        sudo systemctl disable "$service"
        sudo systemctl stop "$service"
        log "Deshabilitado: $service"
    fi
done

# ============================================
# 9. PERMISSIONS
# ============================================
log "[9/10] Ajustando permisos de archivos críticos..."

sudo chmod 644 /etc/passwd
sudo chmod 640 /etc/shadow
sudo chown root:shadow /etc/shadow
sudo chmod 644 /etc/group
sudo chmod 640 /etc/gshadow
sudo chown root:shadow /etc/gshadow

sudo chmod 600 /boot/grub/grub.cfg 2>/dev/null || true

log "Permisos ajustados"

# ============================================
# 10. INSTALL LYNIS
# ============================================
log "[10/10] Instalando Lynis para auditoría..."

sudo apt install -y lynis

log "=========================================="
log "Hardening completado"
log "=========================================="
log ""
log "Ejecutar auditoría con:"
log "  sudo lynis audit system"
log ""
log "Ver reporte de auditd:"
log "  sudo aureport"
log ""
log "Ver logs de UFW:"
log "  sudo tail -f /var/log/ufw.log"
log ""
log "Log completo: $LOG_FILE"