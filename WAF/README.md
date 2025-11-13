# WAF + API Gateway

Kong Gateway + ModSecurity WAF con OWASP Core Rule Set desplegado automáticamente via `terraform/user-data/waf-init.sh`.

## Instalado Automáticamente

- Kong Gateway 3.4 con PostgreSQL
- Nginx compilado con ModSecurity 3
- OWASP Core Rule Set (CRS)
- 6 reglas WAF personalizadas
- Wazuh agent con FIM en `/etc/kong` y `/etc/nginx`
- Logs integrados con Wazuh SIEM

## Verificación

```bash
# Verificar servicios
ssh -i ~/.ssh/obligatorio-srd ubuntu@$(terraform output -raw waf_public_ip)
systemctl status kong
systemctl status nginx

# Ver logs
tail -f /var/log/nginx/modsec_audit.log
tail -f /var/log/kong/access.log
```

## Reglas Personalizadas

| ID | Descripción | Acción | Severidad |
|----|-------------|--------|-----------|
| 900001 | Admin solo desde red interna | BLOCK | CRITICAL |
| 900002 | Path Traversal | BLOCK | CRITICAL |
| 900003-5 | Rate Limiting telemetría (20/min) | BLOCK | WARNING |
| 900006 | Credenciales en URL | BLOCK | ERROR |
| 900007 | User-Agents maliciosos | BLOCK | CRITICAL |
| 900008 | Validación JSON APIs energía | BLOCK | WARNING |

## Testing

```bash
# SQL Injection
curl "http://10.0.1.10:8000/?id=1' OR '1'='1"

# XSS
curl "http://10.0.1.10:8000/?search=<script>alert(1)</script>"

# Path Traversal
curl "http://10.0.1.10:8000/../../../etc/passwd"

# Credenciales en URL
curl "http://10.0.1.10:8000/?password=123456"

# Scanner bloqueado
curl -A "nikto" http://10.0.1.10:8000/
```

## Verificación en Wazuh

Dashboard > Security Events → Filtrar por `rule.id: 100010-100014` y `agent.name: waf-kong`

```bash
sudo tail -f /var/ossec/logs/alerts/alerts.log | grep ModSecurity
```
