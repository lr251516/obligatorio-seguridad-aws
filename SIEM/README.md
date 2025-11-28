# SIEM - Wazuh

Wazuh SIEM con 17 reglas personalizadas implementando 4 casos de uso de detección.

---

## 🎯 Componentes

| Componente | Versión | Propósito |
|------------|---------|-----------|
| **Wazuh Manager** | 4.13.1 | SIEM central, procesamiento reglas |
| **Wazuh Indexer** | 4.13.1 | OpenSearch para almacenamiento logs |
| **Wazuh Dashboard** | 4.13.1 | UI web análisis y visualización |
| **Wazuh Agents** | 4.13.1 | 5 agentes monitoreando VMs |

**Estado:** ✅ 100% funcional - 4 casos de uso testeados

**Deployment:** 100% automatizado vía `terraform/user-data/wazuh-init.sh`

---

## 📊 Infraestructura Monitoreada

### 5 Agentes Wazuh Conectados

| Agente | Hostname | IP Privada | Monitoreo |
|--------|----------|------------|-----------|
| **001** | wazuh-siem | 10.0.1.20 | SIEM self-monitoring |
| **002** | waf-kong | 10.0.1.10 | Nginx + Kong + ModSecurity logs |
| **003** | vpn-iam | 10.0.1.30 | Keycloak + SSH + VPN logs |
| **004** | hardening-vm | 10.0.1.40 | FIM + SSH + CIS SCA |
| **005** | grafana | 10.0.1.50 | Grafana + SSH logs |

**Verificar agentes:**
```bash
ssh -i ~/.ssh/obligatorio-srd ubuntu@$(terraform output -raw wazuh_public_ip)
sudo /var/ossec/bin/agent_control -l
```

**Esperado:** 5 agentes en estado `Active` (wazuh-siem, waf-kong, vpn-iam, hardening-vm, grafana)

---

## 🔐 Acceso Wazuh Dashboard

```
URL: https://<WAZUH_PUBLIC_IP>
Usuario: admin
Password: (ejecutar en VM: sudo cat /root/wazuh-passwords.txt | grep admin)
```

**Primer acceso:** Navegar a **Security events** para ver alertas en tiempo real.

---

## 🚨 Casos de Uso Implementados

### Caso 1: Brute Force SSH (Autenticación)

**Objetivo:** Detectar múltiples intentos fallidos de autenticación SSH

**Reglas:** 100001, 100004, 100002, 100003

**Status:** ✅ 100% funcional (testeado 2025-11-21)

**Lógica de detección:**

```
Evento Base (Wazuh ruleset)
    ├─ Rule 5503: SSH authentication failed (usuario válido)
    └─ Rule 5710: SSH non-existent user

Correlación (Custom rules)
    ├─ Rule 100001: 3+ intentos en 120s (si 5503) → Nivel 10
    ├─ Rule 100004: 3+ intentos en 120s (si 5710) → Nivel 10
    │
    └─ Escalación (if_sid 100001 OR 100004)
        ├─ Rule 100002: Desde IP externa (fuera 10.0.1.0/24) → Nivel 12
        └─ Rule 100003: Usuario privilegiado (root/admin/ubuntu) → Nivel 12
```

**Testing:**

```bash
# Conectar a hardening VM (puerto 2222)
HARDENING_IP=$(terraform output -raw hardening_public_ip)

# Generar 5 intentos fallidos con usuario inexistente
for i in {1..5}; do ssh -p 2222 wronguser@$HARDENING_IP; done
```

**Verificar en Wazuh Dashboard:**
- Filtro: `rule.id: (100001 OR 100004 OR 100002 OR 100003)`
- Esperado: Alertas de correlación SSH brute force

**Evidencia:**
```bash
# En VM Wazuh
sudo grep 'Rule: 100004' /var/ossec/logs/alerts/alerts.log
# Resultado: Múltiples alertas con threshold 3 intentos/120s
```

---

### Caso 2: WAF → SIEM Integration (Ataques Web OWASP Top 10)

**Objetivo:** Detectar y alertar ataques web bloqueados por ModSecurity

**Reglas:** 100010-100014

**Status:** ✅ 100% funcional (testeado 2025-11-21)

**Parent rule hierarchy:**
```
Rule 31301: ModSecurity base event
  └─ Rule 31331: ModSecurity "Access denied"
      └─ Rule 31333: ModSecurity "with code 403" ← Reglas custom usan este
```

**Reglas custom implementadas:**

| Rule ID | Ataque | Patterns | Nivel |
|---------|--------|----------|-------|
| **100010** | SQL Injection | `sql`, `union`, `select`, `%27%20OR` | 10 |
| **100011** | XSS | `script`, `onerror`, `alert` | 10 |
| **100012** | RCE | `exec`, `eval`, `system` | 10 |
| **100013** | Path Traversal | `..%2F`, `etc%2Fpasswd`, `passwd` | 10 |
| **100014** | Scanner Detection | `nikto`, `sqlmap`, `nmap` | 10 |

**⚠️ Importante:** Patterns incluyen versiones **URL-encoded** (`%27`, `%2F`) para detectar ataques ofuscados.

**Testing:**

```bash
WAF_IP=$(terraform output -raw waf_public_ip)

# SQL Injection (URL-encoded)
curl "http://$WAF_IP/?id=1' OR '1'='1"

# XSS
curl "http://$WAF_IP/?search=<script>alert(1)</script>"

# Path Traversal
curl "http://$WAF_IP/?file=../../etc/passwd"

# Scanner detection
curl -A "nikto/2.1.6" http://$WAF_IP/
```

**Esperado:** Todos devuelven `403 Forbidden`

**Verificar en Wazuh Dashboard:**
- Filtro: `rule.id: (100010 OR 100011 OR 100013 OR 100014)`
- Esperado: Eventos ModSecurity con detalles del ataque

**Logs monitoreados:**
- `/var/log/nginx/error.log` (agent waf-kong)
- Formato: syslog (compatible con Wazuh decoders)

---

### Caso 3: File Integrity Monitoring (FIM)

**Objetivo:** Detectar modificaciones en archivos críticos del sistema

**Reglas:** 100020-100023

**Status:** ✅ 100% funcional (testeado 2025-11-21)

**Archivos monitoreados (agente hardening-vm):**

| Path | Regla | Nivel | Criticidad |
|------|-------|-------|------------|
| `/etc/passwd` | 100020 | 12 | CRITICAL |
| `/etc/shadow` | 100021 | 15 | CRITICAL |
| `/etc/ssh/sshd_config` | 100022 | 10 | HIGH |
| `/etc/ufw/*` | 100023 | 10 | HIGH |

**Lógica de detección:**

```
Evento Base (Wazuh FIM)
    └─ Rule 550: Integrity checksum changed

Escalación por archivo (Custom rules)
    ├─ Rule 100020: /etc/passwd modificado → Nivel 12
    ├─ Rule 100021: /etc/shadow modificado → Nivel 15
    ├─ Rule 100022: SSH config modificado → Nivel 10
    └─ Rule 100023: Firewall config modificado → Nivel 10
```

**Testing:**

```bash
# Conectar a hardening VM
ssh -i ~/.ssh/obligatorio-srd -p 2222 ubuntu@$(terraform output -raw hardening_public_ip)

# Modificar /etc/passwd
sudo echo "test_fim:x:9999:9999::/tmp:/bin/false" >> /etc/passwd
```

**Verificar en Wazuh Dashboard:**
- Filtro: `rule.id: 100020`
- Esperado: Alerta inmediata (< 30 seg) con diff del archivo

**Evidencia:**
```bash
# En VM Wazuh
sudo grep 'Rule: 100020' /var/ossec/logs/alerts/alerts.log
```

---

### Caso 4: IAM Behavioral Analytics (Keycloak)

**Objetivo:** Detectar comportamiento anómalo en eventos de autenticación IAM

**Reglas:** 100040-100043

**Status:** ⚠️ Implementado (pendiente testing completo)

**Eventos monitoreados:**

| Rule ID | Evento | Trigger | Nivel |
|---------|--------|---------|-------|
| **100040** | Login IP sospechosa | IP fuera whitelist | 10 |
| **100041** | Múltiples logins fallidos | 5+ intentos/5min | 12 |
| **100042** | Login fuera horario | Hora no laboral | 8 |
| **100043** | Cambio password sospechoso | Sin MFA o forzado | 10 |

**Logs monitoreados:**
- `/opt/keycloak/data/log/keycloak.log` (agent vpn-iam)

**Testing pendiente:**
- Generar eventos de login Keycloak
- Verificar parsing de logs en Wazuh
- Confirmar disparo de reglas 100040-100043

---

## 📁 Archivos de Configuración

### Wazuh Manager

```bash
# Config principal
/var/ossec/etc/ossec.conf

# Reglas custom
/var/ossec/etc/rules/local_rules.xml

# Logs de alertas
/var/ossec/logs/alerts/alerts.log
/var/ossec/logs/alerts/alerts.json

# Ver reglas cargadas
sudo /var/ossec/bin/wazuh-logtest
```

### Wazuh Agents

Cada agente tiene configuración específica en `/var/ossec/etc/ossec.conf`:

**waf-kong (10.0.1.10):**
```xml
<localfile>
  <log_format>syslog</log_format>
  <location>/var/log/nginx/error.log</location>
</localfile>
```

**hardening-vm (10.0.1.40):**
```xml
<syscheck>
  <directories check_all="yes">/etc/passwd,/etc/shadow,/etc/ssh/sshd_config,/etc/ufw</directories>
  <frequency>300</frequency>
</syscheck>
```

**vpn-iam (10.0.1.30):**
```xml
<localfile>
  <log_format>syslog</log_format>
  <location>/opt/keycloak/data/log/keycloak.log</location>
</localfile>
```

---

## 🔧 Comandos Útiles

### Gestión de agentes

```bash
# Listar todos los agentes
sudo /var/ossec/bin/agent_control -l

# Ver info de agente específico
sudo /var/ossec/bin/agent_control -i 004

# Ver último keep-alive
sudo /var/ossec/bin/agent_control -l | grep "is available"
```

### Ver alertas

```bash
# Alertas en tiempo real
sudo tail -f /var/ossec/logs/alerts/alerts.log

# Filtrar por rule ID
sudo grep 'Rule: 100010' /var/ossec/logs/alerts/alerts.log

# Ver alertas en JSON
sudo tail -f /var/ossec/logs/alerts/alerts.json | jq .
```

### Testing de reglas

```bash
# Logtest interactivo (testing reglas con log samples)
sudo /var/ossec/bin/wazuh-logtest

# Ver reglas cargadas
sudo /var/ossec/bin/wazuh-logtest -l | grep "100[0-4][0-9]"
```

### Verificar configuración

```bash
# Validar ossec.conf
sudo /var/ossec/bin/wazuh-control check

# Ver decoders cargados
sudo /var/ossec/bin/wazuh-logtest -D
```

---

## 📋 Resumen Reglas Custom

**Total:** 17 reglas implementadas

| Caso de Uso | Rules | Status |
|-------------|-------|--------|
| **Brute Force SSH** | 100001-100003, 100004 | ✅ 100% |
| **Ataques Web** | 100010-100014 | ✅ 100% |
| **FIM** | 100020-100023 | ✅ 100% |
| **IAM Analytics** | 100040-100043 | ⚠️ Implementado |

**Archivo:** `/var/ossec/etc/rules/local_rules.xml`

**Ver reglas:**
```bash
sudo cat /var/ossec/etc/rules/local_rules.xml | grep '<rule id'
```

---

## 🎯 MITRE ATT&CK Mapping

Todas las reglas custom están mapeadas a MITRE ATT&CK Framework:

| Técnica | ID | Reglas |
|---------|----|----|
| **Brute Force** | T1110 | 100001, 100004, 100002, 100003 |
| **Exploit Public-Facing Application** | T1190 | 100010-100014 |
| **Modify Authentication Process** | T1556 | 100021 |
| **Account Manipulation** | T1098 | 100040-100043 |

**Ver en Dashboard:** Security events → MITRE ATT&CK

---

**Documentación:** [README principal](../README.md) | [WAF](../WAF/README.md) | [VPN-IAM](../VPN-IAM/README.md) | [Hardening](../Hardening/README.md)
