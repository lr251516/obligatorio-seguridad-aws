# Hardening CIS Benchmark Level 1

VM Ubuntu 22.04 con **Wazuh SCA** demostrando mejora de postura de seguridad mediante aplicación de **CIS Benchmark Level 1**.

---

## 🎯 Objetivo

Cumplir con los **4 requisitos del obligatorio** mediante script automatizado:

1. ✅ **Firewall local** (UFW)
2. ✅ **Auditoría del sistema** (auditd)
3. ✅ **Acceso administrativo seguro** (SSH + fail2ban)
4. ✅ **Integración con SIEM** (Wazuh agent)

### SCA Score Mejora

| Estado | SCA Score | Descripción |
|--------|-----------|-------------|
| **ANTES** | 45% | Sistema vanilla sin hardening |
| **DESPUÉS** | **65%** | Script CIS aplicado |

**Mejora: +20% (de 45% → 65%)**

---

## 🚀 Deployment

### 1. Deployment Automático (Terraform)

La VM se levanta en **modo vanilla** (sin hardening):

```bash
terraform apply -auto-approve
```

VM incluye:
- Wazuh Agent conectado al SIEM
- FIM configurado para archivos críticos
- Sin hardening CIS aplicado

### 2. Capturar SCA Baseline (ANTES)

1. Wazuh Dashboard → **Security Configuration Assessment**
2. Seleccionar agente **hardening-vm**
3. Screenshot del score inicial (**~45%**)

### 3. Aplicar CIS Hardening

```bash
# Conectar a VM
ssh -i ~/.ssh/obligatorio-srd ubuntu@<HARDENING_IP>

# Ejecutar script
cd /opt/fosil/Hardening/scripts
sudo bash apply-cis-hardening.sh

# VM reinicia automáticamente
```

### 4. Verificar SCA Mejorado (DESPUÉS)

Esperar 2-3 min después del reboot:

1. Wazuh Dashboard → **Security Configuration Assessment**
2. Agente **hardening-vm**
3. Screenshot del score mejorado (**~65%**)

**Reconectar SSH:**
```bash
ssh -p 2222 -i ~/.ssh/obligatorio-srd ubuntu@<HARDENING_IP>
```

---

## 📋 Requisitos Implementados

### 1. Firewall Local (UFW)

- Default deny incoming
- Default allow outgoing
- SSH puerto 2222
- Wazuh agent (puertos 1514, 1515)
- Logging activado

**Verificar:**
```bash
sudo ufw status verbose
```

### 2. Auditoría del Sistema (auditd)

Reglas CIS para:
- Cambios en `/etc/passwd`, `/etc/shadow`, `/etc/group`
- Cambios en `/etc/ssh/sshd_config`
- Cambios en `/etc/sudoers`
- Módulos kernel (insmod, rmmod, modprobe)
- File deletions por usuarios
- Cambios de permisos (chmod, chown)

**Verificar:**
```bash
sudo auditctl -l | wc -l  # Debe mostrar 15+ reglas
```

### 3. Acceso Administrativo Seguro

**SSH Hardening:**
- Puerto 2222 (no 22)
- PermitRootLogin no
- MaxAuthTries 4
- Algoritmos fuertes (ChaCha20, AES-256-GCM)
- Banner de advertencia

**Fail2ban:**
- SSH protection puerto 2222
- Bantime: 1800s (30 min)
- Maxretry: 5 intentos

**Password Policies:**
- Longitud mínima: 14 caracteres
- 4 clases de caracteres requeridas
- Password aging: 90 días máximo

**Verificar:**
```bash
systemctl is-active fail2ban
sudo fail2ban-client status sshd
```

### 4. Integración con SIEM (Wazuh)

- Wazuh agent activo
- FIM monitoreando archivos críticos
- Logs de auditd enviados a SIEM

**Verificar:**
```bash
systemctl is-active wazuh-agent
sudo /var/ossec/bin/agent_control -i 001  # Ver info del agente
```

---

## 🧪 Testing

### Test 1: SSH puerto 2222

```bash
ssh -p 2222 -i ~/.ssh/obligatorio-srd ubuntu@<HARDENING_IP>
```

### Test 2: UFW activo

```bash
sudo ufw status
# Esperado: Status: active
```

### Test 3: Auditd funcionando

```bash
sudo ausearch -k passwd | tail -5
```

### Test 4: Fail2ban SSH brute force

```bash
# Desde otra máquina, 6 intentos fallidos
for i in {1..6}; do ssh -p 2222 wronguser@<HARDENING_IP>; done

# En hardening VM, verificar ban
sudo fail2ban-client status sshd
```

### Test 5: FIM en Wazuh

```bash
sudo echo "test:x:9999:9999::/tmp:/bin/false" >> /etc/passwd
# Ver alerta inmediata en Wazuh Dashboard: Rule 100020
```

---

## 📁 Archivos

### Scripts
- [apply-cis-hardening.sh](scripts/apply-cis-hardening.sh) - Script productivo (65% SCA)

### Configuraciones Aplicadas
- `/etc/audit/rules.d/cis.rules` - Reglas auditd
- `/etc/ssh/sshd_config.d/99-cis.conf` - SSH hardening
- `/etc/fail2ban/jail.local` - Fail2ban SSH
- `/etc/security/pwquality.conf` - Password policies

---

## ⚠️ Importante

Después de aplicar hardening:

1. **SSH puerto 2222** (no 22)
2. **UFW activo** - Deny incoming por defecto
3. **Fail2ban activo** - Banea después de 5 intentos fallidos
4. **VM reinicia** automáticamente al finalizar script

Si pierdes acceso SSH: usar **AWS EC2 Instance Connect** desde AWS Console.

---

**Documentación:** [README principal](../README.md) | [SIEM](../SIEM/README.md) | [WAF](../WAF/README.md) | [VPN-IAM](../VPN-IAM/README.md)
