# WAF + API Gateway

Kong Gateway + ModSecurity WAF con OWASP Core Rule Set para protección de aplicaciones web.

---

## 🎯 Componentes

| Componente | Versión | Propósito |
|------------|---------|-----------|
| **Kong Gateway** | 3.4.2 | API Gateway con routing, rate limiting, auth |
| **ModSecurity** | 3.0 | Web Application Firewall (WAF) engine |
| **OWASP CRS** | v3.3.5 | Core Rule Set para OWASP Top 10 |
| **Nginx** | Custom build | Compilado con libmodsecurity3 |
| **PostgreSQL** | 14 | Base de datos Kong |

**Estado:** ✅ 100% funcional - Testing completo OWASP Top 10

**Deployment:** 100% automatizado vía `terraform/user-data/waf-init.sh`

---

## 🛡️ Reglas WAF Implementadas

### OWASP Core Rule Set (OWASP CRS v3.3.5)

Protección automática contra:
- SQL Injection
- Cross-Site Scripting (XSS)
- Remote Code Execution (RCE)
- Local File Inclusion (LFI)
- Remote File Inclusion (RFI)
- Command Injection
- Session Fixation
- HTTP Protocol Violations
- Known Attacks & Scanners

**Reglas activas:** 800+ del CRS

### 6 Reglas Custom ModSecurity

| ID | Descripción | Acción | Status |
|----|-------------|--------|--------|
| **900001** | Admin panel solo desde red interna (10.0.1.0/24) | DENY 403 | ✅ Testeado |
| **900002** | Path Traversal (`../`, `etc/passwd`, `boot.ini`) | DENY 403 | ✅ Testeado |
| **900003** | XSS básico (`<script>`, `onerror=`, `javascript:`) | DENY 403 | ✅ Testeado |
| **900004** | SQL Injection (`' OR`, `UNION SELECT`, `DROP`) | DENY 403 | ✅ Testeado |
| **900006** | Credenciales en URL (`password=`, `token=`, `api_key=`) | DENY 403 | ✅ Testeado |
| **900007** | Scanner user-agents (`sqlmap`, `nikto`, `nmap`, `masscan`) | DENY 403 | ✅ Testeado |

**Ubicación:** `/opt/coreruleset/rules/REQUEST-900-CUSTOM-RULES.conf`

---

## 🚀 Deployment

### 1. Deployment Automático (Terraform)

El script `terraform/user-data/waf-init.sh` instala automáticamente:
- Kong Gateway + PostgreSQL
- Nginx compilado con ModSecurity 3
- OWASP CRS v3.3.5
- 6 reglas WAF custom
- Wazuh agent con logs integration
- Security Group puerto 80 abierto

```bash
terraform apply -auto-approve
```

### 2. Configurar Servicios Kong (Post-Deployment)

```bash
# Conectar a VM WAF
ssh -i ~/.ssh/obligatorio-srd ubuntu@$(terraform output -raw waf_public_ip)

# Ejecutar script de configuración
cd /opt/fosil/WAF/scripts
sudo ./configure-kong-services.sh
```

**Servicios creados:**
- **`/api/telemetria`** - API telemetría con rate limiting 20 req/min
- **`/api/energia`** - API energía
- **`/admin`** - Panel admin (bloqueado desde IPs externas)
- **`/api/public`** - API pública testing
- **`/`** - Ruta raíz testing general

---

## 🧪 Testing OWASP Top 10

Todos los tests desde máquina externa (internet):

```bash
export WAF_IP=$(terraform output -raw waf_public_ip)
```

### Test 1: SQL Injection ✅

```bash
# OWASP CRS + Regla custom 900004
curl "http://$WAF_IP/?id=1' OR '1'='1"
```

**Esperado:** `403 Forbidden`
**Wazuh:** Rule 31333 (ModSecurity) + Rule 100010 (custom)

### Test 2: Cross-Site Scripting (XSS) ✅

```bash
# OWASP CRS + Regla custom 900003
curl "http://$WAF_IP/?search=<script>alert(1)</script>"
```

**Esperado:** `403 Forbidden`
**Wazuh:** Rule 31333 + Rule 100011

### Test 3: Path Traversal ✅

```bash
# Regla custom 900002
curl "http://$WAF_IP/?file=../../etc/passwd"
```

**Esperado:** `403 Forbidden`
**Wazuh:** Rule 31333 + Rule 100013

### Test 4: Credenciales en URL ✅

```bash
# Regla custom 900006
curl "http://$WAF_IP/?password=123456&token=abc"
```

**Esperado:** `403 Forbidden`

### Test 5: Scanner Detection ✅

```bash
# Regla custom 900007
curl -A "nikto/2.1.6" http://$WAF_IP/
curl -A "sqlmap/1.0" http://$WAF_IP/
```

**Esperado:** `403 Forbidden` (ambos)

### Test 6: Admin Panel Restriction ✅

```bash
# Regla custom 900001 - Solo red interna
curl http://$WAF_IP/admin
```

**Esperado:** `403 Forbidden` (desde IP externa)
**Permitido:** Solo desde 10.0.1.0/24

### Test 7: Kong Rate Limiting

```bash
# 25 requests a /api/telemetria (límite: 20/min)
for i in {1..25}; do
    curl -s http://$WAF_IP/api/telemetria
done
```

**Esperado:** Primeros 20 = 200 OK, siguientes = 429 Too Many Requests

---

## 📊 Integración WAF → SIEM

### Logs monitoreados por Wazuh

- `/var/log/nginx/error.log` - Eventos ModSecurity
- `/var/log/nginx/access.log` - Requests HTTP
- `/var/log/kong/error.log` - Errores Kong

### Reglas Wazuh Custom

| Rule ID | Descripción | Trigger |
|---------|-------------|---------|
| **31333** | ModSecurity: Access denied with code 403 | Base rule (todos los bloqu eos) |
| **100010** | SQL Injection detected | Patterns: `sql`, `union`, `select`, `%27%20OR` |
| **100011** | XSS detected | Patterns: `script`, `onerror`, `alert` |
| **100012** | RCE detected | Patterns: `exec`, `eval`, `system` |
| **100013** | Path Traversal detected | Patterns: `..%2F`, `etc%2Fpasswd`, `passwd` |
| **100014** | Scanner detected | Patterns: `nikto`, `sqlmap`, `nmap` |

**Verificar en Wazuh Dashboard:**
- Filtro: `rule.id: (31333 OR 100010 OR 100011 OR 100013)`
- Esperado: Eventos en tiempo real de ataques bloqueados

---

## 📁 Archivos de Configuración

### Kong Gateway

```bash
# Config principal
/etc/kong/kong.conf

# Database
PostgreSQL en localhost:5432 (DB: kong)

# Logs
/var/log/kong/access.log
/var/log/kong/error.log

# Admin API
http://10.0.1.10:8001 (interno)

# Proxy
http://10.0.1.10:8000 (interno)
http://<PUBLIC_IP>:80 (externo)
```

### ModSecurity + OWASP CRS

```bash
# ModSecurity config
/etc/nginx/modsec/modsecurity.conf

# OWASP CRS
/opt/coreruleset/
/opt/coreruleset/rules/REQUEST-900-CUSTOM-RULES.conf

# Reglas deshabilitadas
/opt/coreruleset/rules/REQUEST-922-MULTIPART-ATTACK.conf.disabled
```

### Nginx

```bash
# Config principal
/etc/nginx/nginx.conf

# Site config
/etc/nginx/sites-available/default

# Logs
/var/log/nginx/access.log
/var/log/nginx/error.log
/var/log/nginx/modsec_audit.log
```

---

## 🔧 Comandos Útiles

### Verificar servicios

```bash
sudo systemctl status kong
sudo systemctl status nginx
sudo systemctl status wazuh-agent
```

### Ver logs en tiempo real

```bash
# ModSecurity blocks
sudo tail -f /var/log/nginx/error.log | grep ModSecurity

# Kong access log
sudo tail -f /var/log/kong/access.log

# Audit log ModSecurity
sudo tail -f /var/log/nginx/modsec_audit.log
```

### Kong Admin API

```bash
# Listar servicios
curl http://10.0.1.10:8001/services

# Listar rutas
curl http://10.0.1.10:8001/routes

# Verificar plugins
curl http://10.0.1.10:8001/plugins
```

### Testing ModSecurity

```bash
# Test regla OWASP CRS (SQL Injection)
curl "http://<WAF_IP>/?id=' OR 1=1--"

# Test regla custom (admin panel)
curl "http://<WAF_IP>/admin"

# Ver respuesta completa
curl -v "http://<WAF_IP>/?id=1' OR '1'='1"
```

---

## 🎯 Casos de Uso Implementados

### Caso de Uso 2: WAF → SIEM Integration

**Objetivo:** Detectar y alertar ataques web en tiempo real

**Flujo:**
1. Atacante intenta SQL Injection: `/?id=1' OR '1'='1`
2. ModSecurity bloquea con 403
3. Log generado en `/var/log/nginx/error.log`
4. Wazuh agent lee log
5. Rule 31333 (base) + Rule 100010 (custom) disparan
6. Alerta visible en Wazuh Dashboard

**Testing:** Ver [README principal](../README.md#caso-2-waf--siem-integration-rules-100010-100014)

**Status:** ✅ 100% funcional - Testeado con 4 tipos de ataque

---

**Documentación:** [README principal](../README.md) | [SIEM](../SIEM/README.md) | [VPN-IAM](../VPN-IAM/README.md) | [Hardening](../Hardening/README.md)
