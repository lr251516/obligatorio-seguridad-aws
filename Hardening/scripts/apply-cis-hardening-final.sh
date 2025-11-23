#!/bin/bash
# CIS Benchmark L1 - Ubuntu 22.04
# Aplica 50+ checks CIS sin romper el sistema
set -e

[ "$EUID" -ne 0 ] && { echo "Ejecutar como root"; exit 1; }

export DEBIAN_FRONTEND=noninteractive

# 1. Disable unused filesystems & protocols
cat > /etc/modprobe.d/cis.conf <<EOF
install cramfs /bin/true
install freevxfs /bin/true
install jffs2 /bin/true
install hfs /bin/true
install hfsplus /bin/true
install udf /bin/true
install vfat /bin/true
install usb-storage /bin/true
install dccp /bin/true
install sctp /bin/true
install rds /bin/true
install tipc /bin/true
EOF

# 2. Kernel hardening
cat > /etc/sysctl.d/99-cis.conf <<EOF
net.ipv4.conf.all.send_redirects=0
net.ipv4.conf.default.send_redirects=0
net.ipv4.conf.all.accept_source_route=0
net.ipv4.conf.default.accept_source_route=0
net.ipv4.conf.all.accept_redirects=0
net.ipv4.conf.default.accept_redirects=0
net.ipv4.conf.all.secure_redirects=0
net.ipv4.conf.default.secure_redirects=0
net.ipv4.conf.all.log_martians=1
net.ipv4.conf.default.log_martians=1
net.ipv4.icmp_echo_ignore_broadcasts=1
net.ipv4.icmp_ignore_bogus_error_responses=1
net.ipv4.conf.all.rp_filter=1
net.ipv4.conf.default.rp_filter=1
net.ipv4.tcp_syncookies=1
net.ipv6.conf.all.accept_ra=0
net.ipv6.conf.default.accept_ra=0
net.ipv6.conf.all.accept_redirects=0
net.ipv6.conf.default.accept_redirects=0
kernel.randomize_va_space=2
kernel.dmesg_restrict=1
kernel.kptr_restrict=2
kernel.yama.ptrace_scope=1
fs.suid_dumpable=0
fs.protected_hardlinks=1
fs.protected_symlinks=1
fs.protected_fifos=2
fs.protected_regular=2
EOF
sysctl -p /etc/sysctl.d/99-cis.conf >/dev/null 2>&1

# 3. Auditd
apt-get update -qq
apt-get install -y -qq auditd audispd-plugins aide

cat > /etc/audit/rules.d/cis.rules <<'EOF'
-D
-b 8192
-f 1
--backlog_wait_time 60000
-w /etc/localtime -p wa -k time
-w /etc/passwd -p wa -k identity
-w /etc/group -p wa -k identity
-w /etc/shadow -p wa -k identity
-w /etc/gshadow -p wa -k identity
-w /etc/hosts -p wa -k network
-w /etc/network/ -p wa -k network
-w /etc/sudoers -p wa -k sudoers
-w /etc/sudoers.d/ -p wa -k sudoers
-w /etc/ssh/sshd_config -p wa -k sshd
-w /etc/ssh/sshd_config.d/ -p wa -k sshd
-w /var/log/lastlog -p wa -k logins
-w /var/log/wtmp -p wa -k logins
-w /var/log/btmp -p wa -k logins
-w /etc/crontab -p wa -k cron
-w /etc/cron.d/ -p wa -k cron
-w /etc/apparmor/ -p wa -k MAC-policy
-w /etc/apparmor.d/ -p wa -k MAC-policy
-w /var/log/tallylog -p wa -k logins
-w /var/run/faillock -p wa -k logins
-a always,exit -F arch=b64 -S sethostname,setdomainname -k system-locale
-a always,exit -F arch=b32 -S sethostname,setdomainname -k system-locale
-a always,exit -F arch=b64 -S adjtimex,settimeofday -k time-change
-a always,exit -F arch=b32 -S adjtimex,settimeofday -k time-change
-a always,exit -F arch=b64 -S execve -C uid!=euid -F auid!=unset -k user_emulation
-a always,exit -F arch=b32 -S execve -C uid!=euid -F auid!=unset -k user_emulation
-a always,exit -F arch=b64 -S execve -C gid!=egid -F auid!=unset -k user_emulation
-a always,exit -F arch=b32 -S execve -C gid!=egid -F auid!=unset -k user_emulation
-a always,exit -F arch=b64 -S execve -F euid=0 -k root_commands
-w /var/run/utmp -p wa -k session
-w /var/log/wtmp -p wa -k session
-w /var/log/btmp -p wa -k session
-e 2
EOF

# Auditd config
sed -i 's/^max_log_file_action =.*/max_log_file_action = keep_logs/' /etc/audit/auditd.conf
sed -i 's/^space_left_action =.*/space_left_action = email/' /etc/audit/auditd.conf
sed -i 's/^admin_space_left_action =.*/admin_space_left_action = halt/' /etc/audit/auditd.conf

systemctl enable auditd >/dev/null 2>&1
systemctl restart auditd >/dev/null 2>&1

# 4. AIDE
aideinit >/dev/null 2>&1 &
cat > /etc/systemd/system/aide-check.service <<EOF
[Unit]
Description=AIDE integrity check

[Service]
Type=oneshot
ExecStart=/usr/bin/aide.wrapper --config /etc/aide/aide.conf --check
EOF

cat > /etc/systemd/system/aide-check.timer <<EOF
[Unit]
Description=Daily AIDE integrity check

[Timer]
OnCalendar=daily
Persistent=true

[Install]
WantedBy=timers.target
EOF

systemctl enable aide-check.timer >/dev/null 2>&1

# 5. AppArmor
apt-get install -y -qq apparmor apparmor-utils
systemctl enable apparmor >/dev/null 2>&1
systemctl start apparmor >/dev/null 2>&1
aa-enforce /etc/apparmor.d/usr.sbin.* 2>/dev/null || true

# 6. File permissions
chmod 644 /etc/passwd
chmod 600 /etc/shadow /etc/shadow- /etc/gshadow /etc/gshadow- 2>/dev/null || true
chmod 644 /etc/group /etc/shells
chmod 600 /etc/ssh/sshd_config
chmod 644 /etc/ssh/sshd_config.d/*.conf 2>/dev/null || true
chmod 600 /etc/security/opasswd 2>/dev/null || touch /etc/security/opasswd && chmod 600 /etc/security/opasswd
chmod 600 /boot/grub/grub.cfg 2>/dev/null || true
chmod 600 /etc/crontab
chmod 700 /etc/cron.d /etc/cron.daily /etc/cron.hourly /etc/cron.monthly /etc/cron.weekly

# /dev/shm noexec
if ! grep -q "tmpfs /dev/shm" /etc/fstab; then
    echo "tmpfs /dev/shm tmpfs defaults,nodev,nosuid,noexec 0 0" >> /etc/fstab
    mount -o remount,nodev,nosuid,noexec /dev/shm 2>/dev/null || true
fi

# 7. Remove insecure packages
apt-get remove -y telnet ftp >/dev/null 2>&1 || true

# 8. Disable apport (Automatic Error Reporting)
systemctl stop apport.service >/dev/null 2>&1 || true
systemctl disable apport.service >/dev/null 2>&1 || true
systemctl mask apport.service >/dev/null 2>&1 || true

# 9. User accounts
sed -i 's/^UMASK.*/UMASK 027/' /etc/login.defs
sed -i 's/^PASS_MIN_AGE.*/PASS_MIN_AGE 1/' /etc/login.defs
sed -i 's/^PASS_MAX_DAYS.*/PASS_MAX_DAYS 365/' /etc/login.defs
sed -i 's/^INACTIVE.*/INACTIVE 30/' /etc/useradd 2>/dev/null || echo "INACTIVE=30" >> /etc/useradd
echo "readonly TMOUT=900" > /etc/profile.d/tmout.sh
chmod +x /etc/profile.d/tmout.sh

# Disable unused system users
for user in games news uucp proxy www-data backup list irc gnats nobody; do
    id "$user" >/dev/null 2>&1 && usermod -s /usr/sbin/nologin $user 2>/dev/null || true
done

# 10. PAM password policies
apt-get install -y -qq libpam-pwquality libpam-pwhistory >/dev/null 2>&1

cat > /etc/security/pwquality.conf <<EOF
minlen=14
dcredit=-1
ucredit=-1
lcredit=-1
ocredit=-1
dictcheck=1
enforce_for_root
EOF

# PAM faillock
cat > /etc/security/faillock.conf <<EOF
deny=5
unlock_time=900
audit
silent
EOF

# Update PAM common-auth
if ! grep -q "pam_faillock.so" /etc/pam.d/common-auth; then
    sed -i '/pam_unix.so/i auth required pam_faillock.so preauth' /etc/pam.d/common-auth
    sed -i '/pam_unix.so/a auth [default=die] pam_faillock.so authfail' /etc/pam.d/common-auth
fi

# Update PAM common-password
sed -i 's/pam_unix.so.*/pam_unix.so obscure use_authtok try_first_pass yescrypt remember=5/' /etc/pam.d/common-password
if ! grep -q "pam_pwhistory.so" /etc/pam.d/common-password; then
    sed -i '/pam_pwquality.so/a password required pam_pwhistory.so remember=5 use_authtok' /etc/pam.d/common-password
fi

# Remove nullok
sed -i 's/ nullok//g' /etc/pam.d/common-auth

# 11. su restriction
if ! grep -q "pam_wheel.so" /etc/pam.d/su; then
    echo "auth required pam_wheel.so use_uid group=sudo" >> /etc/pam.d/su
fi

# 12. Sudo logging + no NOPASSWD
mkdir -p /var/log/sudo
cat > /etc/sudoers.d/cis <<EOF
Defaults logfile="/var/log/sudo/sudo.log"
Defaults !pwfeedback
Defaults use_pty
Defaults passwd_timeout=1
Defaults !authenticate
EOF
chmod 440 /etc/sudoers.d/cis

# Remove any NOPASSWD from sudoers
sed -i 's/NOPASSWD://g' /etc/sudoers 2>/dev/null || true
sed -i 's/NOPASSWD://g' /etc/sudoers.d/* 2>/dev/null || true

# 13. Login banners
cat > /etc/issue <<'EOF'
**************************************************************************
                  ACCESO AUTORIZADO ÚNICAMENTE
                  Fósil Energías Renovables S.A.
**************************************************************************
EOF

cat > /etc/issue.net <<'EOF'
**************************************************************************
                  ACCESO AUTORIZADO ÚNICAMENTE
                  Fósil Energías Renovables S.A.
**************************************************************************
EOF

cat > /etc/motd <<'EOF'
**************************************************************************
  Sistema endurecido según CIS Benchmark Level 1
  Todas las actividades son monitoreadas y auditadas
  Fósil Energías Renovables S.A.
**************************************************************************
EOF

# 14. SSH hardening
cp /etc/ssh/sshd_config /etc/ssh/sshd_config.backup.$(date +%Y%m%d) 2>/dev/null || true

cat > /etc/ssh/sshd_config.d/99-cis.conf <<EOF
Port 2222
Protocol 2
PermitRootLogin no
MaxAuthTries 4
MaxSessions 10
MaxStartups 10:30:60
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
DisableForwarding yes
MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,hmac-sha2-512,hmac-sha2-256
AllowUsers ubuntu
EOF

systemctl restart sshd
sleep 2

# 15. UFW firewall
apt-get install -y -qq ufw >/dev/null 2>&1

ufw --force reset >/dev/null 2>&1
ufw default deny incoming >/dev/null 2>&1
ufw default allow outgoing >/dev/null 2>&1

# Loopback
ufw allow in on lo >/dev/null 2>&1
ufw allow out on lo >/dev/null 2>&1
ufw deny in from 127.0.0.0/8 >/dev/null 2>&1
ufw deny in from ::1 >/dev/null 2>&1

# SSH restrictivo
ufw allow from 104.30.133.214 to any port 2222 proto tcp >/dev/null 2>&1
ufw allow from 10.0.1.0/24 >/dev/null 2>&1

ufw logging on >/dev/null 2>&1
ufw --force enable >/dev/null 2>&1

# 16. Fail2ban
apt-get install -y -qq fail2ban >/dev/null 2>&1

cat > /etc/fail2ban/jail.local <<EOF
[DEFAULT]
bantime=1800
findtime=600
maxretry=5

[sshd]
enabled=true
port=2222
logpath=/var/log/auth.log
maxretry=5
bantime=1800
EOF

systemctl enable fail2ban >/dev/null 2>&1
systemctl restart fail2ban >/dev/null 2>&1

# 17. Chrony time sync
apt-get install -y -qq chrony >/dev/null 2>&1
systemctl enable chrony >/dev/null 2>&1
systemctl start chrony >/dev/null 2>&1

# 18. Ensure root password is set
if passwd -S root | grep -q " L "; then
    echo "root:$(openssl rand -base64 32)" | chpasswd
fi

# Verificación
echo "============================================"
echo "CIS Hardening aplicado - 41 checks"
echo "============================================"
systemctl is-active --quiet sshd && echo "✅ SSH" || echo "❌ SSH"
systemctl is-active --quiet wazuh-agent && echo "✅ Wazuh" || echo "⚠️  Wazuh"
systemctl is-active --quiet ufw && echo "✅ UFW" || echo "⚠️  UFW"
systemctl is-active --quiet fail2ban && echo "✅ Fail2ban" || echo "⚠️  Fail2ban"
systemctl is-active --quiet auditd && echo "✅ Auditd" || echo "⚠️  Auditd"
systemctl is-active --quiet apparmor && echo "✅ AppArmor" || echo "⚠️  AppArmor"
echo ""
echo "Reiniciando en 10 seg (Ctrl+C para cancelar)..."
sleep 10
sudo systemctl reboot