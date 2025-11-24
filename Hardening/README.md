# Hardening CIS Benchmark Level 1

VM Ubuntu 22.04 con **Wazuh SCA** (Security Configuration Assessment) demostrando mejora de postura de seguridad mediante aplicación manual de **CIS Benchmark Level 1**.

---

## 🎯 Objetivo

Demostrar **antes y después** de aplicar hardening CIS:

| Estado | SCA Score | Descripción |
|--------|-----------|-------------|
| **ANTES** (vanilla) | ~45% | Sistema sin hardening |
| **DESPUÉS** (CIS L1) | **65%** | Script con 55+ checks CIS |

**Score final limitado por:**
- 23 checks requieren particiones separadas (/tmp, /var, /home) - imposible sin recrear VM
- 9 checks de firewall nativo (iptables/nftables) - conflicto con UFW
- 1 check bootloader password - rompe boot AWS EC2

**Máximo score posible sin recrear VM: ~70%**

---

## 🚀 Deployment

### 1. Deployment Automático (Terraform)

La VM se levanta en **modo VANILLA** con:
- ✅ Wazuh Agent instalado
- ✅ FIM (File Integrity Monitoring) configurado
- ❌ **SIN hardening CIS** aplicado

```bash
terraform apply -auto-approve
```

### 2. Verificar SCA Baseline (ANTES del hardening)

1. Acceder a Wazuh Dashboard: `https://<WAZUH_IP>`
2. **Security Configuration Assessment** → agente **hardening-vm**
3. **Capturar screenshot** del score (~45%)

### 3. Aplicar CIS Hardening

```bash
# Conectar a VM (puerto 2222 después de hardening)
ssh -i ~/.ssh/obligatorio-srd ubuntu@$(terraform output -raw hardening_public_ip)

# Ejecutar script de hardening
cd /opt/fosil/Hardening/scripts
sudo bash apply-cis-hardening.sh

# VM reiniciará automáticamente en 10 seg
```

**Script aplica 55+ checks CIS:**

1. **Kernel & Filesystem**
   - Disable 15+ filesystems/protocols no usados (cramfs, usb-storage, dccp, bluetooth, etc.)
   - 30+ parámetros kernel hardening (sysctl)
   - /dev/shm con noexec

2. **Auditoría (20+ checks)**
   - audit=1 en GRUB
   - Auditd con 40+ reglas CIS
   - Monitoreo: sudoers, SSH, passwd, módulos kernel, mount/umount, file deletions
   - AIDE (filesystem integrity) con timer diario
   - Cryptographic verification de audit tools

3. **AppArmor**
   - Enforce mode en todos los perfiles

4. **File Permissions**
   - /etc/passwd, /etc/shadow, /etc/ssh/sshd_config, etc.
   - Permisos crontab y directorios cron

5. **User Accounts**
   - UMASK 027, PASS_MIN_AGE 1, INACTIVE 30
   - TMOUT 900 (15 min sesión inactiva)
   - Deshabilitar/lockear usuarios innecesarios

6. **PAM & Passwords**
   - pwquality: minlen=14, minclass=4, dictcheck
   - faillock: 5 intentos, 900s unlock time
   - Password history: 5 passwords remembered
   - No nullok, yescrypt encryption

7. **SSH Hardening**
   - **Puerto 2222** (no 22)
   - PermitRootLogin no, MaxAuthTries 4
   - DisableForwarding yes
   - Ciphers/MACs/KexAlgorithms fuertes
   - AllowUsers ubuntu

8. **Firewall UFW**
   - Default deny incoming/outgoing/routed
   - Loopback configurado
   - SSH desde IP específica (104.30.133.214) + VPC (10.0.1.0/24)
   - Outgoing solo: DNS, NTP, HTTP/HTTPS, Wazuh

9. **Fail2ban**
   - SSH protection puerto 2222
   - maxretry 5, bantime 1800s

10. **Chrony NTP**
    - Usuario _chrony

11. **Servicios & Seguridad**
    - Disable apport, avahi, cups, nfs, snmpd
    - Coredumps deshabilitados
    - IPv6 disabled
    - Root password set (random)
    - Sudo sin NOPASSWD

### 4. Verificar SCA Mejorado (DESPUÉS del hardening)

Esperar 2-3 min después del reboot para que Wazuh actualice.

1. Acceder a Wazuh Dashboard: `https://<WAZUH_IP>`
2. **Security Configuration Assessment** → agente **hardening-vm**
3. **Capturar screenshot** del score mejorado (**65%**)

---

## 🔍 FIM (File Integrity Monitoring)

Archivos monitoreados en tiempo real por Wazuh:
- `/etc/passwd`, `/etc/shadow`, `/etc/group`
- `/etc/sudoers`, `/etc/sudoers.d/`
- `/etc/ssh/sshd_config`, `/etc/ssh/sshd_config.d/`
- `/root/.ssh/`
- `/etc/ufw/` (firewall rules)

**Testing:**
```bash
sudo echo "test_fim:x:9999:9999::/tmp:/bin/false" >> /etc/passwd
# Ver alerta inmediata en Wazuh Dashboard: Rule 100020
```

---

## 🧪 Testing Post-Hardening

### Test 1: Conectar SSH puerto 2222

```bash
ssh -i ~/.ssh/obligatorio-srd -p 2222 ubuntu@<HARDENING_IP>
```

### Test 2: Verificar SSH hardening

```bash
sudo sshd -T | grep -E "permitrootlogin|maxauthtries|disableforwarding"
# Esperado:
# permitrootlogin no
# maxauthtries 4
# disableforwarding yes
```

### Test 3: Verificar UFW firewall

```bash
sudo ufw status verbose
# Esperado:
# Status: active
# Logging: medium
# Default: deny (incoming), deny (outgoing), deny (routed)
```

### Test 4: Verificar auditd

```bash
sudo auditctl -l | wc -l
# Esperado: 40+ reglas
```

### Test 5: Fail2ban SSH brute force

```bash
# Desde otra máquina, 6 intentos fallidos:
for i in {1..6}; do ssh -p 2222 wronguser@<HARDENING_IP>; done

# En la VM hardening, verificar ban:
sudo fail2ban-client status sshd
```

---

## 📊 Análisis de Checks CIS

**Total: 72 checks CIS Benchmark L1**

| Estado | Cantidad | %  | Motivo |
|--------|----------|-----|--------|
| ✅ **Implementados** | **39** | **54%** | Todos los posibles |
| ❌ **Particiones** | 23 | 32% | Requiere recrear VM con fstab custom |
| ❌ **Firewall nativo** | 9 | 13% | Conflicto iptables/nftables vs UFW |
| ❌ **Bootloader password** | 1 | 1% | Rompe boot AWS EC2 |

**Checks implementados incluyen:**
- Filesystems & kernel hardening
- Auditd (14 checks)
- SSH (4 checks)
- PAM & passwords (12 checks)
- File permissions (5 checks)
- AppArmor, AIDE, Chrony, UFW, Fail2ban

---

## 📁 Archivos del Proyecto

### Scripts disponibles

- **`apply-cis-hardening.sh`** - ✅ Script productivo (55+ checks, 65% SCA score)

### Configuraciones aplicadas

- `/etc/modprobe.d/cis.conf` - Filesystems disabled
- `/etc/sysctl.d/99-cis.conf` - Kernel hardening
- `/etc/audit/rules.d/cis.rules` - Auditd rules
- `/etc/systemd/system/aide-check.timer` - AIDE daily check
- `/etc/ssh/sshd_config.d/99-cis.conf` - SSH hardening
- `/etc/fail2ban/jail.local` - Fail2ban config
- `/etc/security/pwquality.conf` - Password policies
- `/etc/security/faillock.conf` - Failed login lockout

---

## ⚠️ Importante

### Después de aplicar hardening:

1. **SSH puerto cambia a 2222** (desde 22)
2. **UFW default outgoing = DENY** - Solo permite DNS, NTP, HTTP/HTTPS, Wazuh
3. **Sudo pide password** - NOPASSWD eliminado
4. **Sesión timeout 15 min** - TMOUT=900

### Si pierdes acceso SSH:

Usar **AWS EC2 Instance Connect** desde AWS Console (no requiere SSH).

---

**Documentación:** [README principal](../README.md) | [SIEM](../SIEM/README.md) | [WAF](../WAF/README.md) | [VPN-IAM](../VPN-IAM/README.md)
