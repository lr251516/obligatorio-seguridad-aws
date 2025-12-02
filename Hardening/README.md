# Hardening CIS Benchmark Level 1

VM Ubuntu 22.04 con Wazuh SCA demostrando mejora de seguridad mediante CIS Benchmark Level 1.

---

## 🎯 Objetivo

Cumplir **4 requisitos del obligatorio** mediante script automatizado:

1. ✅ **Firewall local** (UFW)
2. ✅ **Auditoría del sistema** (auditd)
3. ✅ **Acceso administrativo seguro** (SSH + fail2ban)
4. ✅ **Integración con SIEM** (Wazuh agent + FIM)

**IP VM:** `10.0.1.40` (t3.micro)

### Mejora SCA

| Estado | Score | Descripción |
|--------|-------|-------------|
| ANTES | 45% | Sistema vanilla sin hardening |
| DESPUÉS | **57%** | Script CIS aplicado |

**Mejora: +12 puntos porcentuales**

---

## 🚀 Deployment

### 1. Deployment Automático (Vanilla)

```bash
terraform apply -auto-approve
```

**VM incluye automáticamente:**
- Wazuh Agent conectado
- FIM configurado
- **Sin hardening CIS** (modo vanilla para demo)

### 2. Capturar SCA Baseline

1. Wazuh Dashboard → Security Configuration Assessment
2. Seleccionar **hardening-vm**
3. Screenshot score inicial (~45%)

### 3. Aplicar Hardening

```bash
ssh -i ~/.ssh/obligatorio-srd ubuntu@<HARDENING_IP>
cd /opt/fosil/Hardening/scripts
sudo bash apply-cis-hardening.sh
# VM reinicia automáticamente
```

### 4. Verificar SCA Mejorado

**Esperar 2-3 min después del reboot**

1. Wazuh Dashboard → Security Configuration Assessment
2. Agente **hardening-vm**
3. Screenshot score mejorado (~57%)

**Reconectar SSH (puerto cambió a 2222):**
```bash
ssh -p 2222 -i ~/.ssh/obligatorio-srd ubuntu@<HARDENING_IP>
```

---

## 📋 Requisitos Implementados

### 1. Firewall Local (UFW)

- Default deny incoming / allow outgoing
- Puertos: SSH 2222, Wazuh 1514/1515
- Logging activado

```bash
sudo ufw status verbose
# Esperado: Status: active, puertos permitidos
```

### 2. Auditoría (auditd)

**Reglas CIS:**
- Cambios en `/etc/passwd`, `/etc/shadow`, `/etc/group`
- Cambios en `/etc/ssh/sshd_config`, `/etc/sudoers`
- Módulos kernel (insmod, rmmod, modprobe)
- File deletions por usuarios
- Cambios de permisos (chmod, chown)

```bash
sudo auditctl -l | wc -l
# Esperado: 15+ reglas activas
```

### 3. Acceso Administrativo Seguro

**SSH Hardening:**
- Puerto 2222 (no 22)
- PermitRootLogin no
- MaxAuthTries 4
- Algoritmos fuertes (ChaCha20, AES-256-GCM)

**Fail2ban:**
- Puerto SSH 2222
- Bantime: 1800s (30 min)
- Maxretry: 5 intentos

**Password Policies:**
- Longitud mínima: 14 caracteres
- 4 clases de caracteres
- Password aging: 90 días

```bash
systemctl is-active fail2ban
sudo fail2ban-client status sshd
# Esperado: active, 0 banned IPs inicialmente
```

### 4. Integración SIEM

- Wazuh agent activo
- FIM monitoreando `/etc/passwd`, `/etc/shadow`, `/etc/ssh/sshd_config`
- Logs auditd enviados a SIEM

```bash
systemctl is-active wazuh-agent
# Esperado: active
```

---

## 🧪 Testing

```bash
# 1. SSH puerto 2222
ssh -p 2222 -i ~/.ssh/obligatorio-srd ubuntu@<HARDENING_IP>

# 2. UFW activo
sudo ufw status

# 3. Auditd funcionando
sudo ausearch -k passwd | tail -5

# 4. Fail2ban SSH brute force
for i in {1..6}; do ssh -p 2222 wronguser@<HARDENING_IP>; done
sudo fail2ban-client status sshd
# Esperado: 1 banned IP

# 5. FIM en Wazuh
sudo echo "test:x:9999:9999::/tmp:/bin/false" >> /etc/passwd
# Ver alerta en Wazuh Dashboard: Rule 100020
```

---

## 📁 Archivos

```bash
# Script productivo
/opt/fosil/Hardening/scripts/apply-cis-hardening.sh

# Configuraciones aplicadas
/etc/audit/rules.d/cis.rules              # Auditd CIS
/etc/ssh/sshd_config.d/99-cis.conf        # SSH hardening
/etc/fail2ban/jail.local                  # Fail2ban SSH
/etc/security/pwquality.conf              # Password policies
```

---

## ⚠️ Importante

**Después de aplicar hardening:**

1. SSH puerto **2222** (no 22)
2. UFW activo - Deny incoming por defecto
3. Fail2ban - Banea después de 5 intentos
4. VM reinicia automáticamente

**Si pierdes acceso SSH:** Usar AWS EC2 Instance Connect desde AWS Console.

---

**Documentación:** [README principal](../README.md) | [SIEM](../SIEM/README.md) | [WAF](../WAF/README.md) | [VPN-IAM](../VPN-IAM/README.md)
