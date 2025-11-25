#!/bin/bash
# CIS Benchmark L1 - Ubuntu 22.04
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
install squashfs /bin/true
install bluetooth /bin/true
install btusb /bin/true
EOF

# 2. Kernel hardening (EXTENDIDO)
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
net.ipv6.conf.all.accept_source_route=0
net.ipv6.conf.default.accept_source_route=0
net.ipv6.conf.all.forwarding=0
kernel.randomize_va_space=2
kernel.dmesg_restrict=1
kernel.kptr_restrict=2
kernel.yama.ptrace_scope=1
fs.suid_dumpable=0
fs.protected_hardlinks=1
fs.protected_symlinks=1
fs.protected_fifos=2
fs.protected_regular=2
kernel.unprivileged_bpf_disabled=1
net.core.bpf_jit_harden=2
kernel.kexec_load_disabled=1
EOF
sysctl -p /etc/sysctl.d/99-cis.conf >/dev/null 2>&1

# 3. Auditd (EXTENDIDO)
apt-get update -qq
apt-get install -y -qq auditd audispd-plugins aide

# Set audit=1 in GRUB (persists after reboot)
if ! grep -q "audit=1" /etc/default/grub; then
    sed -i 's/GRUB_CMDLINE_LINUX=""/GRUB_CMDLINE_LINUX="audit=1"/' /etc/default/grub
    sed -i 's/GRUB_CMDLINE_LINUX="\(.*\)"/GRUB_CMDLINE_LINUX="\1 audit=1"/' /etc/default/grub
    update-grub >/dev/null 2>&1 || true
fi

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
-w /etc/issue -p wa -k system-locale
-w /etc/issue.net -p wa -k system-locale
-w /etc/sudoers -p wa -k sudoers
-w /etc/sudoers.d/ -p wa -k sudoers
-w /etc/ssh/sshd_config -p wa -k sshd
-w /etc/ssh/sshd_config.d/ -p wa -k sshd
-w /var/log/lastlog -p wa -k logins
-w /var/log/wtmp -p wa -k logins
-w /var/log/btmp -p wa -k logins
-w /etc/crontab -p wa -k cron
-w /etc/cron.d/ -p wa -k cron
-w /etc/cron.daily/ -p wa -k cron
-w /etc/cron.hourly/ -p wa -k cron
-w /etc/cron.monthly/ -p wa -k cron
-w /etc/cron.weekly/ -p wa -k cron
-w /etc/apparmor/ -p wa -k MAC-policy
-w /etc/apparmor.d/ -p wa -k MAC-policy
-w /var/log/tallylog -p wa -k logins
-w /var/run/faillock -p wa -k logins
-w /sbin/insmod -p x -k modules
-w /sbin/rmmod -p x -k modules
-w /sbin/modprobe -p x -k modules
-a always,exit -F arch=b64 -S init_module,delete_module -k modules
-a always,exit -F arch=b64 -S sethostname,setdomainname -k system-locale
-a always,exit -F arch=b32 -S sethostname,setdomainname -k system-locale
-a always,exit -F arch=b64 -S adjtimex,settimeofday -k time-change
-a always,exit -F arch=b32 -S adjtimex,settimeofday -k time-change
-a always,exit -F arch=b64 -S clock_settime -k time-change
-a always,exit -F arch=b32 -S clock_settime -k time-change
-a always,exit -F arch=b64 -S mount,umount2 -k mounts
-a always,exit -F arch=b32 -S mount,umount2 -k mounts
-a always,exit -F arch=b64 -S unlink,unlinkat,rename,renameat -F auid>=1000 -F auid!=4294967295 -k delete
-a always,exit -F arch=b32 -S unlink,unlinkat,rename,renameat -F auid>=1000 -F auid!=4294967295 -k delete
-a always,exit -F arch=b64 -S execve -C uid!=euid -F auid!=unset -k user_emulation
-a always,exit -F arch=b32 -S execve -C uid!=euid -F auid!=unset -k user_emulation
-a always,exit -F arch=b64 -S execve -C gid!=egid -F auid!=unset -k user_emulation
-a always,exit -F arch=b32 -S execve -C gid!=egid -F auid!=unset -k user_emulation
-a always,exit -F arch=b64 -S execve -F euid=0 -k root_commands
-w /var/run/utmp -p wa -k session
-w /var/log/wtmp -p wa -k session
-w /var/log/btmp -p wa -k session
-a always,exit -F arch=b64 -S chmod,fchmod,fchmodat -F auid>=1000 -F auid!=4294967295 -k perm_mod
-a always,exit -F arch=b32 -S chmod,fchmod,fchmodat -F auid>=1000 -F auid!=4294967295 -k perm_mod
-a always,exit -F arch=b64 -S chown,fchown,fchownat,lchown -F auid>=1000 -F auid!=4294967295 -k perm_mod
-a always,exit -F arch=b32 -S chown,fchown,fchownat,lchown -F auid>=1000 -F auid!=4294967295 -k perm_mod
-e 2
EOF

# Auditd config (EXTENDIDO)
sed -i 's/^max_log_file =.*/max_log_file = 100/' /etc/audit/auditd.conf
sed -i 's/^max_log_file_action =.*/max_log_file_action = keep_logs/' /etc/audit/auditd.conf
sed -i 's/^space_left =.*/space_left = 100/' /etc/audit/auditd.conf
sed -i 's/^space_left_action =.*/space_left_action = email/' /etc/audit/auditd.conf
sed -i 's/^admin_space_left_action =.*/admin_space_left_action = halt/' /etc/audit/auditd.conf
sed -i 's/^disk_full_action =.*/disk_full_action = halt/' /etc/audit/auditd.conf
sed -i 's/^disk_error_action =.*/disk_error_action = halt/' /etc/audit/auditd.conf

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

# AIDE integrity check for audit tools
cat >> /etc/aide/aide.conf <<EOF
# CIS - Audit tools integrity
/sbin/auditctl p+i+n+u+g+s+b+acl+xattrs+sha512
/sbin/auditd p+i+n+u+g+s+b+acl+xattrs+sha512
/sbin/ausearch p+i+n+u+g+s+b+acl+xattrs+sha512
/sbin/aureport p+i+n+u+g+s+b+acl+xattrs+sha512
/sbin/autrace p+i+n+u+g+s+b+acl+xattrs+sha512
/sbin/augenrules p+i+n+u+g+s+b+acl+xattrs+sha512
EOF

# 5. AppArmor
apt-get install -y -qq apparmor apparmor-utils apparmor-profiles apparmor-profiles-extra
systemctl enable apparmor >/dev/null 2>&1
systemctl start apparmor >/dev/null 2>&1
aa-enforce /etc/apparmor.d/* 2>/dev/null || true

# 6. File permissions (EXTENDIDO)
chmod 644 /etc/passwd /etc/passwd- 2>/dev/null || true
chmod 600 /etc/shadow /etc/shadow- /etc/gshadow /etc/gshadow- 2>/dev/null || true
chmod 644 /etc/group /etc/group- /etc/shells 2>/dev/null || true
chmod 600 /etc/ssh/sshd_config
chmod 644 /etc/ssh/sshd_config.d/*.conf 2>/dev/null || true
chmod 600 /etc/security/opasswd 2>/dev/null || touch /etc/security/opasswd && chmod 600 /etc/security/opasswd
chmod 600 /boot/grub/grub.cfg 2>/dev/null || true
chmod 600 /etc/crontab
chmod 700 /etc/cron.d /etc/cron.daily /etc/cron.hourly /etc/cron.monthly /etc/cron.weekly
chmod 644 /etc/issue /etc/issue.net
[ -f /etc/motd ] && chmod 644 /etc/motd || true

# /dev/shm noexec
if ! grep -q "tmpfs /dev/shm" /etc/fstab; then
    echo "tmpfs /dev/shm tmpfs defaults,nodev,nosuid,noexec 0 0" >> /etc/fstab
    mount -o remount,nodev,nosuid,noexec /dev/shm 2>/dev/null || true
fi

# 7. Remove insecure packages (EXTENDIDO)
apt-get remove -y telnet ftp rsh-client rsh-server talk ldap-utils >/dev/null 2>&1 || true
apt-get autoremove -y >/dev/null 2>&1 || true

# 8. Disable apport (Automatic Error Reporting)
systemctl stop apport.service >/dev/null 2>&1 || true
systemctl disable apport.service >/dev/null 2>&1 || true
systemctl mask apport.service >/dev/null 2>&1 || true

# 9. Disable services (NUEVO)
for svc in avahi-daemon cups isc-dhcp-server isc-dhcp-server6 slapd nfs-server rpcbind rsync snmpd; do
    systemctl stop $svc 2>/dev/null || true
    systemctl disable $svc 2>/dev/null || true
    systemctl mask $svc 2>/dev/null || true
done

# 10. User accounts (EXTENDIDO)
sed -i 's/^UMASK.*/UMASK 027/' /etc/login.defs
sed -i 's/^PASS_MIN_AGE.*/PASS_MIN_AGE 1/' /etc/login.defs
sed -i 's/^PASS_MAX_DAYS.*/PASS_MAX_DAYS 365/' /etc/login.defs
sed -i 's/^PASS_WARN_AGE.*/PASS_WARN_AGE 7/' /etc/login.defs
sed -i 's/^INACTIVE.*/INACTIVE 30/' /etc/useradd 2>/dev/null || echo "INACTIVE=30" >> /etc/useradd
sed -i 's/^ENCRYPT_METHOD.*/ENCRYPT_METHOD YESCRYPT/' /etc/login.defs
echo "readonly TMOUT=900" > /etc/profile.d/tmout.sh
chmod +x /etc/profile.d/tmout.sh

# Disable unused system users
for user in games news uucp proxy www-data backup list irc gnats nobody systemd-coredump; do
    id "$user" >/dev/null 2>&1 && usermod -s /usr/sbin/nologin $user 2>/dev/null || true
done

# Lock unused system accounts
for user in bin daemon sys sync games man lp mail news uucp proxy www-data backup list irc gnats; do
    passwd -l $user 2>/dev/null || true
done

# 11. PAM password policies (EXTENDIDO)
apt-get install -y -qq libpam-pwquality libpam-pwhistory libpam-tmpdir >/dev/null 2>&1

cat > /etc/security/pwquality.conf <<EOF
minlen=14
minclass=4
dcredit=-1
ucredit=-1
lcredit=-1
ocredit=-1
dictcheck=1
usercheck=1
enforcing=1
retry=3
enforce_for_root
EOF

# PAM faillock (EXTENDIDO)
cat > /etc/security/faillock.conf <<EOF
deny=5
fail_interval=900
unlock_time=900
audit
silent
even_deny_root
root_unlock_time=900
EOF

# Update PAM common-auth
if ! grep -q "pam_faillock.so" /etc/pam.d/common-auth; then
    sed -i '/pam_unix.so/i auth required pam_faillock.so preauth' /etc/pam.d/common-auth
    sed -i '/pam_unix.so/a auth [default=die] pam_faillock.so authfail' /etc/pam.d/common-auth
fi

# Update PAM common-password (EXTENDIDO)
sed -i 's/pam_unix.so.*/pam_unix.so obscure use_authtok try_first_pass yescrypt remember=5 rounds=65536/' /etc/pam.d/common-password
if ! grep -q "pam_pwhistory.so" /etc/pam.d/common-password; then
    sed -i '/pam_pwquality.so/a password required pam_pwhistory.so remember=5 use_authtok enforce_for_root' /etc/pam.d/common-password
fi

# Remove nullok
sed -i 's/ nullok//g' /etc/pam.d/common-auth
sed -i 's/ nullok//g' /etc/pam.d/common-password

# 12. su restriction
if ! grep -q "pam_wheel.so" /etc/pam.d/su; then
    echo "auth required pam_wheel.so use_uid group=sudo" >> /etc/pam.d/su
fi

# 13. Sudo logging + no NOPASSWD (EXTENDIDO)
mkdir -p /var/log/sudo
cat > /etc/sudoers.d/cis <<EOF
Defaults logfile="/var/log/sudo/sudo.log"
Defaults !pwfeedback
Defaults use_pty
Defaults passwd_timeout=1
Defaults timestamp_timeout=5
Defaults !visiblepw
Defaults always_set_home
Defaults match_group_by_gid
Defaults env_reset
Defaults secure_path="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
EOF
chmod 440 /etc/sudoers.d/cis

# Remove any NOPASSWD from sudoers
sed -i 's/NOPASSWD://g' /etc/sudoers 2>/dev/null || true
sed -i 's/NOPASSWD://g' /etc/sudoers.d/* 2>/dev/null || true

# 14. Login banners
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

# Remove OS info from banners
echo > /etc/update-motd.d/00-header
echo > /etc/update-motd.d/10-help-text
chmod -x /etc/update-motd.d/* 2>/dev/null || true

# 15. SSH hardening (EXTENDIDO)
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
AllowStreamLocalForwarding no
DisableForwarding yes
GatewayPorts no
PermitTunnel no
StrictModes yes
UsePAM yes
Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr
MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,hmac-sha2-512,hmac-sha2-256
KexAlgorithms curve25519-sha256,curve25519-sha256@libssh.org,diffie-hellman-group14-sha256,diffie-hellman-group16-sha512,diffie-hellman-group18-sha512,ecdh-sha2-nistp521,ecdh-sha2-nistp384,ecdh-sha2-nistp256,diffie-hellman-group-exchange-sha256
HostKeyAlgorithms ssh-ed25519,ecdsa-sha2-nistp521,ecdsa-sha2-nistp384,ecdsa-sha2-nistp256,rsa-sha2-512,rsa-sha2-256
AllowUsers ubuntu
EOF

systemctl restart sshd
sleep 2

# 16. UFW firewall
apt-get install -y -qq ufw >/dev/null 2>&1

ufw --force reset >/dev/null 2>&1
ufw default deny incoming >/dev/null 2>&1
ufw default deny outgoing >/dev/null 2>&1
ufw default deny routed >/dev/null 2>&1

# Loopback
ufw allow in on lo >/dev/null 2>&1
ufw allow out on lo >/dev/null 2>&1
ufw deny in from 127.0.0.0/8 >/dev/null 2>&1
ufw deny in from ::1 >/dev/null 2>&1

# Outgoing essentials
ufw allow out 53/udp >/dev/null 2>&1  # DNS
ufw allow out 123/udp >/dev/null 2>&1  # NTP
ufw allow out 80/tcp >/dev/null 2>&1  # HTTP
ufw allow out 443/tcp >/dev/null 2>&1  # HTTPS
ufw allow out 1514/tcp >/dev/null 2>&1  # Wazuh
ufw allow out 1515/tcp >/dev/null 2>&1  # Wazuh

# SSH restrictivo
ufw allow from 104.30.133.214 to any port 2222 proto tcp >/dev/null 2>&1
ufw allow from 10.0.1.0/24 >/dev/null 2>&1

ufw logging medium >/dev/null 2>&1
ufw --force enable >/dev/null 2>&1

# 17. Fail2ban (EXTENDIDO)
apt-get install -y -qq fail2ban >/dev/null 2>&1

cat > /etc/fail2ban/jail.local <<EOF
[DEFAULT]
bantime=1800
findtime=600
maxretry=5
destemail=root@localhost
sendername=Fail2Ban
action=%(action_mwl)s

[sshd]
enabled=true
port=2222
logpath=/var/log/auth.log
maxretry=5
bantime=1800

[sshd-ddos]
enabled=true
port=2222
logpath=/var/log/auth.log
maxretry=10
findtime=60
EOF

systemctl enable fail2ban >/dev/null 2>&1
systemctl restart fail2ban >/dev/null 2>&1

# 18. Chrony time sync (EXTENDIDO)
apt-get install -y -qq chrony >/dev/null 2>&1

# Ensure chrony runs as _chrony user
if ! grep -q "^user _chrony" /etc/chrony/chrony.conf; then
    echo "user _chrony" >> /etc/chrony/chrony.conf
fi

systemctl enable chrony >/dev/null 2>&1
systemctl restart chrony >/dev/null 2>&1

# 19. Coredumps disabled
cat > /etc/security/limits.d/10-coredump.conf <<EOF
* hard core 0
EOF

cat > /etc/sysctl.d/50-coredump.conf <<EOF
kernel.core_pattern=|/bin/false
EOF

systemctl mask systemd-coredump.socket 2>/dev/null || true

# 20. Ensure root password is set
if passwd -S root | grep -q " L "; then
    echo "root:$(openssl rand -base64 32)" | chpasswd
fi

# 21. Postfix mail (local only)
if systemctl is-active postfix >/dev/null 2>&1; then
    postconf -e 'inet_interfaces = loopback-only' >/dev/null 2>&1 || true
    systemctl restart postfix >/dev/null 2>&1 || true
fi

# 22. IPv6 disabled (si no se usa)
if ! grep -q "net.ipv6.conf.all.disable_ipv6" /etc/sysctl.d/99-cis.conf; then
    echo "net.ipv6.conf.all.disable_ipv6=1" >> /etc/sysctl.d/99-cis.conf
    echo "net.ipv6.conf.default.disable_ipv6=1" >> /etc/sysctl.d/99-cis.conf
    sysctl -p /etc/sysctl.d/99-cis.conf >/dev/null 2>&1
fi

# Verificación
echo "============================================"
echo "CIS Hardening ULTRA aplicado - 55+ checks"
echo "============================================"
systemctl is-active --quiet sshd && echo "✅ SSH" || echo "❌ SSH"
systemctl is-active --quiet wazuh-agent && echo "✅ Wazuh" || echo "⚠️  Wazuh"
systemctl is-active --quiet ufw && echo "✅ UFW" || echo "⚠️  UFW"
systemctl is-active --quiet fail2ban && echo "✅ Fail2ban" || echo "⚠️  Fail2ban"
systemctl is-active --quiet auditd && echo "✅ Auditd" || echo "⚠️  Auditd"
systemctl is-active --quiet apparmor && echo "✅ AppArmor" || echo "⚠️  AppArmor"
systemctl is-active --quiet chrony && echo "✅ Chrony" || echo "⚠️  Chrony"
echo ""
echo "⚠️  IMPORTANTE: UFW default outgoing = DENY"
echo "Si pierdes conectividad, usa AWS Console para conectar"
echo ""
echo "Reiniciando en 10 seg (Ctrl+C para cancelar)..."
sleep 10
systemctl reboot