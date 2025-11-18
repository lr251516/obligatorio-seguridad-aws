# Hardening con SCA (Security Configuration Assessment)

VM Ubuntu 22.04 con **Wazuh SCA** para demostrar mejora de postura de seguridad aplicando **CIS Benchmark Level 1** manualmente.

## 🎯 Objetivo

Demostrar el **antes y después** de aplicar hardening CIS:
1. **VM Vanilla** → SCA score bajo (~40-50%)
2. **Aplicar script de hardening** → SCA score mejorado (~80-85%)

---

## 🚀 Workflow de Deployment

### Paso 1: Deployment Automático (Terraform)

La VM se levanta en **modo VANILLA** con:
- ✅ **Wazuh Agent** instalado (para SCA baseline)
- ✅ **FIM** (File Integrity Monitoring) configurado
- ❌ **SIN hardening CIS** aplicado

```bash
terraform apply -auto-approve
```

**Resultado:** VM básica conectada a Wazuh, con SCA mostrando score bajo.

---

### Paso 2: Verificar SCA Baseline (ANTES del hardening)

1. Acceder a Wazuh Dashboard: `http://<wazuh-ip>`
2. Ir a: **Security Configuration Assessment**
3. Seleccionar agente: **hardening-vm**
4. **Capturar screenshot** del score bajo (~40-50%)

---

### Paso 3: Aplicar CIS Hardening Manualmente

Conectar a la VM y ejecutar el script de hardening:

```bash
# Conectar a VM
ssh -i ~/.ssh/obligatorio-srd ubuntu@$(terraform output -raw hardening_public_ip)

# Ejecutar hardening CIS Level 1
cd /opt/fosil/Hardening/scripts
sudo ./apply-cis-hardening.sh

# Reiniciar para aplicar todos los cambios
sudo reboot
```

**El script aplica:**
- ✅ Filesystem hardening (modprobe, /tmp secure mount)
- ✅ Bootloader permissions
- ✅ Kernel hardening (sysctl: net.ipv4.*, kernel.randomize_va_space, etc.)
- ✅ Auditd con reglas CIS (monitoreo de /etc/passwd, sudoers, SSH, etc.)
- ✅ Permisos de archivos críticos (chmod 600 /etc/shadow, etc.)
- ✅ Políticas de contraseñas fuertes (PAM + pwquality: minlen=14)
- ✅ User account hardening (TMOUT, umask, deshabilitar usuarios innecesarios)
- ✅ SSH hardening (PermitRootLogin no, MaxAuthTries 4, ClientAliveInterval)
- ✅ UFW firewall habilitado (default deny incoming)
- ✅ Fail2ban para SSH brute force (maxretry=3, bantime=1800s)
- ✅ Servicios innecesarios removidos (avahi, cups, rpcbind, etc.)
- ✅ Actualizaciones automáticas de seguridad

---

### Paso 4: Verificar SCA Mejorado (DESPUÉS del hardening)

Después del reboot (esperar ~2-3 min para que Wazuh actualice):

1. Acceder a Wazuh Dashboard: `http://<wazuh-ip>`
2. Ir a: **Security Configuration Assessment**
3. Seleccionar agente: **hardening-vm**
4. **Capturar screenshot** del score mejorado (~80-85%)

---

## 📊 Score Esperado

| Estado | SCA Score | Descripción |
|--------|-----------|-------------|
| **ANTES** (vanilla) | 40-50% | Sistema sin hardening, múltiples checks fallando |
| **DESPUÉS** (CIS L1) | 80-85% | Hardening aplicado, configuración segura |

---

## 🔍 FIM (File Integrity Monitoring)

**Archivos monitoreados en tiempo real:**
- `/etc/passwd`, `/etc/shadow`, `/etc/group`
- `/etc/sudoers`, `/etc/sudoers.d/`
- `/etc/ssh/sshd_config`
- `/root/.ssh/`
- `/etc/ufw/` (firewall rules)

**Cualquier modificación genera alerta en Wazuh Dashboard.**

---

## 📋 Testing Manual

### Test 1: FIM - Modificar archivo crítico
```bash
sudo echo "test_user:x:9999:9999::/tmp:/bin/false" >> /etc/passwd
# Ver alerta en Wazuh Dashboard (Rule 100020)
```

### Test 2: Fail2ban - Brute force SSH
```bash
# Desde máquina externa, 4 intentos SSH fallidos:
ssh wrong_user@<hardening-ip>  # repetir 4 veces
# Ver IP baneada: sudo fail2ban-client status sshd
```

### Test 3: Verificar SSH hardening
```bash
sudo sshd -T | grep -E "permitrootlogin|maxauthtries|allowtcpforwarding"
# Debe mostrar:
# permitrootlogin no
# maxauthtries 4
# allowtcpforwarding no
```

---

## 🛠️ Troubleshooting

**Ver logs de hardening:**
```bash
cat /tmp/user-data.log
cat /tmp/user-data-completed.log
```

**Verificar Wazuh agent:**
```bash
sudo systemctl status wazuh-agent
sudo /var/ossec/bin/agent_control -l  # desde manager
```

**Ver reglas auditd aplicadas:**
```bash
sudo auditctl -l
```

**Ver estado UFW:**
```bash
sudo ufw status verbose
```

**Ver bans de Fail2ban:**
```bash
sudo fail2ban-client status sshd
```
