# SIEM - Wazuh

Wazuh SIEM con 17 reglas custom implementando 4 casos de uso de detección.

---

## 🎯 Componentes

**Wazuh 4.13.1 All-in-One:**
- **Manager**: SIEM central, procesamiento de reglas
- **Indexer**: OpenSearch para almacenamiento de logs
- **Dashboard**: UI web (HTTPS)

**Agentes:** 4 VMs monitoreadas automáticamente

**IP VM:** `10.0.1.20` (m7i-flex.large, 8GB RAM)

**Deployment:** 100% automatizado vía `terraform/user-data/wazuh-init.sh`

---

## 🔐 Acceso

```
URL: https://<WAZUH_PUBLIC_IP>
Usuario: admin
Password: (ejecutar en VM: sudo cat /root/wazuh-passwords.txt)
```

**Navegar a:** Security events → Ver alertas en tiempo real

---

## 📊 Agentes Conectados

| ID | Hostname | IP | Monitoreo |
|----|----------|-------|-----------|
| 001 | waf-kong | 10.0.1.10 | Nginx + ModSecurity + Kong |
| 002 | vpn-iam | 10.0.1.30 | Keycloak + SSH |
| 003 | hardening-vm | 10.0.1.40 | FIM + SSH + CIS SCA |
| 004 | grafana | 10.0.1.50 | Grafana + SSH |

**Verificar:**
```bash
ssh ubuntu@<WAZUH_IP> "sudo /var/ossec/bin/agent_control -l"
# Esperado: 4 agentes Active
```

---

## 🚨 Casos de Uso

| # | Descripción | Reglas | Testing |
|---|-------------|--------|---------|
| 1 | SSH Brute Force (Autenticación) | 100001-100004 | ✅ 2025-11-21 |
| 2 | Ataques Web OWASP Top 10 | 100010-100014 | ✅ 2025-11-21 |
| 3 | File Integrity Monitoring | 100020-100023 | ✅ 2025-11-21 |
| 4 | IAM Behavioral Analytics | 100040-100043 | ✅ 2025-11-28 |

**Total:** 17 reglas custom

---

## Caso 1: SSH Brute Force

**Detección:** Múltiples intentos fallidos SSH

**Reglas:**
- `100001`: 3+ intentos fallidos (usuario válido) en 120s → Level 10
- `100004`: 3+ intentos fallidos (usuario inexistente) en 120s → Level 10
- `100002`: Escalación si origen es IP externa → Level 12
- `100003`: Escalación si usuario privilegiado (root/admin) → Level 12

**Testing:**
```bash
# Generar 6 intentos fallidos
HARDENING_IP=$(terraform output -raw hardening_public_ip)
for i in {1..6}; do ssh wronguser@$HARDENING_IP -p 2222; sleep 3; done
```

**Verificar en Wazuh Dashboard:**
- Filtro: `rule.id: (100001 OR 100004)`
- Esperado: 2+ alertas en ~2 minutos

**CLI:**
```bash
ssh ubuntu@<WAZUH_IP>
sudo grep 'Rule: 100004' /var/ossec/logs/alerts/alerts.log | tail -5
```

---

## Caso 2: Ataques Web (OWASP Top 10)

**Detección:** WAF ModSecurity → SIEM integration

**Reglas:**
- `100010`: SQL Injection → Level 10
- `100011`: XSS → Level 10
- `100012`: Remote Code Execution → Level 12
- `100013`: Path Traversal → Level 10
- `100014`: Scanner Detection → Level 8

**Testing:**
```bash
WAF_IP=$(terraform output -raw waf_public_ip)

# SQL Injection
curl -v "http://$WAF_IP/?id=1%27%20OR%20%271%27%3D%271"
# Esperado: 403 Forbidden

# XSS
curl -v "http://$WAF_IP/?search=%3Cscript%3Ealert%281%29%3C%2Fscript%3E"
# Esperado: 403 Forbidden

# Path Traversal
curl -v "http://$WAF_IP/?file=..%2F..%2Fetc%2Fpasswd"
# Esperado: 403 Forbidden
```

**Verificar en Wazuh Dashboard:**
- Filtro: `rule.id: (100010 OR 100011 OR 100013)`
- Esperado: 3+ alertas con detalles del ataque

**Logs monitoreados:**
- `/var/log/nginx/error.log` (agent: waf-kong)

---

## Caso 3: File Integrity Monitoring

**Detección:** Cambios en archivos críticos del sistema

**Reglas:**
- `100020`: /etc/passwd modificado → Level 12
- `100021`: /etc/shadow modificado → Level 15
- `100022`: SSH config modificado → Level 10
- `100023`: Firewall config modificado → Level 10

**Testing:**
```bash
ssh -i ~/.ssh/obligatorio-srd -p 2222 ubuntu@<HARDENING_IP>

# Modificar /etc/passwd
sudo echo "test:x:9999:9999::/tmp:/bin/false" >> /etc/passwd
```

**Verificar en Wazuh Dashboard:**
- Filtro: `rule.id: 100020`
- Esperado: Alerta inmediata (< 30s) con diff del archivo

**FIM configurado en:**
- `/etc/passwd`, `/etc/shadow`
- `/etc/ssh/sshd_config`
- `/etc/ufw/`, `/etc/iptables/`

---

## Caso 4: IAM Behavioral Analytics

**Detección:** Comportamiento anómalo en Keycloak

**Reglas:**
- `100040`: Login fallido → Level 5
- `100041`: Brute force (5+ intentos en 300s) → Level 10
- `100042`: Login desde IP externa (no VPC) → Level 8
- `100043`: Login fuera horario (6pm-9am) → Level 7

**Testing:**
```bash
# Generar logins fallidos en Keycloak
# URL: http://<VPN_IP>:8080
# Intentar login 6 veces con credenciales incorrectas
```

**Verificar en Wazuh Dashboard:**
- Filtro: `rule.id: (100040 OR 100042)`
- Esperado: Múltiples alertas agrupadas en ~2 min

**Logs monitoreados:**
- `/opt/keycloak/data/log/keycloak.log` (formato JSON, agent: vpn-iam)

**Evidencia de testing (2025-11-28):**
- `100040`: Login fallido desde IP interna → Level 5 ✅
- `100042`: 15+ eventos en 2 min desde IP externa → Level 8 ✅
- `100041`: Correlación de 5+ eventos detectada → Level 10 ✅

---

## 📁 Archivos Clave

```bash
# Reglas custom
/var/ossec/etc/rules/local_rules.xml     # 17 reglas custom

# Configuración agentes
/var/ossec/etc/ossec.conf                # Manager config
/var/ossec/etc/shared/default/agent.conf # Agent config (FIM, localfile)

# Logs
/var/ossec/logs/alerts/alerts.log        # Alertas en texto plano
/var/ossec/logs/ossec.log                # Log del manager

# Verificar reglas
sudo grep -E '<rule id="100' /var/ossec/etc/rules/local_rules.xml

# Reiniciar manager (después de cambios)
sudo systemctl restart wazuh-manager
```

---

## 🧪 Testing Completo

```bash
# 1. Verificar 4 agentes activos
ssh ubuntu@<WAZUH_IP> "sudo /var/ossec/bin/agent_control -l"

# 2. Test SSH Brute Force
for i in {1..6}; do ssh wronguser@<HARDENING_IP> -p 2222; sleep 3; done

# 3. Test WAF → SIEM
curl "http://<WAF_IP>/?id=1%27%20OR%20%271%27%3D%271"

# 4. Test FIM
ssh -p 2222 ubuntu@<HARDENING_IP>
sudo echo "test" >> /etc/passwd

# 5. Test IAM Analytics
# Login fallido 6 veces en Keycloak UI

# 6. Ver alertas en Dashboard
# https://<WAZUH_IP> → Security events
# Filtros: rule.id: (100001 OR 100010 OR 100020 OR 100040)
```

---

## 🔍 SCA (Security Configuration Assessment)

**CIS Benchmark Level 1 para Ubuntu 22.04 integrado automáticamente**

**Ver score en Dashboard:**
- Configuration Assessment → hardening-vm
- Esperado antes hardening: ~45%
- Esperado después hardening: ~57% (+12%)

---

**Documentación:** [README principal](../README.md) | [VPN-IAM](../VPN-IAM/README.md) | [WAF](../WAF/README.md) | [Hardening](../Hardening/README.md)
