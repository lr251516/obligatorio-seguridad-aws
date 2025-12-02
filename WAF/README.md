# WAF + API Gateway

Kong Gateway + ModSecurity WAF con OWASP Core Rule Set.

---

## 🎯 Componentes

- **Kong Gateway 3.4.2**: API Gateway (routing, rate limiting, auth)
- **ModSecurity 3.0**: Web Application Firewall engine
- **OWASP CRS v3.3.5**: 800+ reglas OWASP Top 10
- **Nginx**: Build custom con libmodsecurity3
- **PostgreSQL 14**: DB Kong

**IP VM:** `10.0.1.10` (t3.micro)

**Deployment:** 100% automatizado vía `terraform/user-data/waf-init.sh`

---

## 🛡️ Reglas WAF

### OWASP Core Rule Set (CRS)

**800+ reglas activas** protegiendo contra:
- SQL Injection, XSS, RCE
- LFI/RFI, Command Injection
- Protocol violations, scanners

### 6 Reglas Custom ModSecurity

| ID | Descripción | Acción | Testing |
|----|-------------|--------|---------|
| 900001 | Admin panel solo red interna (10.0.1.0/24) | DENY 403 | ✅ |
| 900002 | Path Traversal (`../`, `etc/passwd`) | DENY 403 | ✅ |
| 900003 | XSS básico (`<script>`, `onerror=`) | DENY 403 | ✅ |
| 900004 | SQL Injection (`' OR`, `UNION`, `DROP`) | DENY 403 | ✅ |
| 900006 | Credenciales en URL (`password=`, `token=`) | DENY 403 | ✅ |
| 900007 | Scanner user-agents (`sqlmap`, `nikto`) | DENY 403 | ✅ |

**Ubicación:** `/opt/coreruleset/rules/REQUEST-900-CUSTOM-RULES.conf`

---

## 🚀 Setup

### 1. Deployment Automático

```bash
terraform apply -auto-approve
```

**Instala automáticamente:**
- Kong + PostgreSQL
- Nginx + ModSecurity + OWASP CRS
- 6 reglas custom
- Wazuh agent + log integration
- Puerto 80 abierto (Security Group)

### 2. Configurar Servicios Kong

```bash
ssh -i ~/.ssh/obligatorio-srd ubuntu@<WAF_IP>
cd /opt/fosil/WAF/scripts
sudo ./configure-kong-services.sh
```

**Servicios creados:**
- `/api/telemetria` - Rate limiting 20 req/min
- `/api/energia` - API energía
- `/admin` - Bloqueado desde IPs externas
- `/` - Testing general

---

## 🧪 Testing OWASP Top 10

**Obtener IP:**
```bash
export WAF_IP=$(terraform output -raw waf_public_ip)
```

### SQL Injection

```bash
curl -s -o /dev/null -w "%{http_code}\n" 'http://'"$WAF_IP"'/?id=1%27%20OR%20%271%27=%271'
# Esperado: 403
```

**Wazuh:** Rules 31333 + 100010

### XSS

```bash
curl -s -o /dev/null -w "%{http_code}\n" "http://$WAF_IP/?search=<script>alert(1)</script>"
# Esperado: 403
```

**Wazuh:** Rules 31333 + 100011

### Path Traversal

```bash
curl -s -o /dev/null -w "%{http_code}\n" "http://$WAF_IP/?file=../../etc/passwd"
# Esperado: 403
```

**Wazuh:** Rules 31333 + 100013

### Credenciales en URL

```bash
curl -s -o /dev/null -w "%{http_code}\n" "http://$WAF_IP/?password=123&token=abc"
# Esperado: 403
```

### Scanner Detection

```bash
curl -s -o /dev/null -w "%{http_code}\n" -A "sqlmap/1.0" http://$WAF_IP/
# Esperado: 403
```

### Admin Panel Restriction

```bash
curl -s -o /dev/null -w "%{http_code}\n" http://$WAF_IP/admin
# Esperado: 403 (desde IP externa)
# Permitido: Solo 10.0.1.0/24
```

### Kong Rate Limiting

```bash
for i in {1..25}; do
    echo -n "Request $i: "
    curl -s -o /dev/null -w "%{http_code}\n" http://$WAF_IP/api/telemetria
done
# Esperado: Primeros 20 = 200, siguientes = 429
```

---

## 📊 Integración WAF → SIEM

**Logs monitoreados por Wazuh:**
- `/var/log/nginx/error.log` - Eventos ModSecurity
- `/var/log/nginx/access.log` - Requests HTTP
- `/var/log/kong/error.log` - Errores Kong

**Reglas Wazuh custom:**

| Rule | Descripción | Patterns |
|------|-------------|----------|
| 31333 | ModSecurity access denied 403 | Base (todos los bloqueos) |
| 100010 | SQL Injection detected | `sql`, `union`, `%27%20OR` |
| 100011 | XSS detected | `script`, `onerror`, `alert` |
| 100012 | RCE detected | `exec`, `eval`, `system` |
| 100013 | Path Traversal detected | `..%2F`, `passwd` |
| 100014 | Scanner detected | `nikto`, `sqlmap`, `nmap` |

**Verificar en Wazuh Dashboard:**
- Filtro: `rule.id: (31333 OR 100010 OR 100011 OR 100013)`
- Esperado: Eventos en tiempo real

---

## 📁 Archivos Clave

```bash
# Kong
/etc/kong/kong.conf                      # Config principal
/var/log/kong/access.log                 # Logs

# ModSecurity + OWASP CRS
/etc/nginx/modsec/modsecurity.conf       # ModSecurity config
/opt/coreruleset/rules/                  # OWASP CRS rules
/opt/coreruleset/rules/REQUEST-900-CUSTOM-RULES.conf  # Custom rules

# Nginx
/etc/nginx/nginx.conf                    # Config principal
/var/log/nginx/error.log                 # ModSecurity events
/var/log/nginx/modsec_audit.log          # Audit log
```

**Endpoints:**
```
http://<WAF_IP>:80    - WAF ModSecurity (público)
http://<WAF_IP>:8000  - Kong Proxy (público)
http://<WAF_IP>:8001  - Kong Admin API (JSON REST)
http://<WAF_IP>:8002  - Kong Admin GUI (web)
```

---

## 🔧 Comandos Útiles

```bash
# Verificar servicios
sudo systemctl status kong nginx wazuh-agent

# Ver logs en tiempo real
sudo tail -f /var/log/nginx/error.log | grep ModSecurity
sudo tail -f /var/log/kong/access.log

# Kong Admin API
curl http://10.0.1.10:8001/services  # Listar servicios
curl http://10.0.1.10:8001/routes    # Listar rutas
curl http://10.0.1.10:8001/plugins   # Listar plugins
```

---

## 🎯 Caso de Uso 2: WAF → SIEM

**Flujo:**
1. Atacante intenta SQL Injection: `/?id=1' OR '1'='1`
2. ModSecurity bloquea → 403 Forbidden
3. Log en `/var/log/nginx/error.log`
4. Wazuh agent envía evento
5. Rules 31333 + 100010 disparan
6. Alerta en Wazuh Dashboard

**Status:** ✅ 100% funcional (testeado 2025-11-21)

---

**Documentación:** [README principal](../README.md) | [SIEM](../SIEM/README.md) | [VPN-IAM](../VPN-IAM/README.md) | [Hardening](../Hardening/README.md)
