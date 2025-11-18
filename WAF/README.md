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

## Configurar Servicios Kong (Paso Manual)

**Problema:** Las rutas de Kong no persisten entre reinicios (no están en DB/config file).

**Solución:** Ejecutar script de configuración después del deployment:

```bash
# Conectar a VM WAF
ssh -i ~/.ssh/obligatorio-srd ubuntu@$(terraform output -raw waf_public_ip)

# Ejecutar script de configuración
cd /opt/fosil/WAF/scripts
chmod +x configure-kong-services.sh
./configure-kong-services.sh
```

**Servicios creados:**
- `/api/telemetria` - API de telemetría con rate limiting (20 req/min)
- `/api/energia` - API de energía
- `/admin` - Panel de administración (bloqueado desde IPs externas)
- `/api/public` - API pública para testing de ataques
- `/` - Ruta raíz para testing general

## Testing

**Desde tu máquina local** (sustituir `<WAF_IP>` por la IP pública del WAF):

```bash
export WAF_IP=$(terraform output -raw waf_public_ip)

# 1. SQL Injection (bloquea OWASP CRS + regla custom 900004)
curl "http://$WAF_IP/api/public?id=1' OR '1'='1"
# Esperado: 403 Forbidden

# 2. XSS (bloquea OWASP CRS + regla custom 900003)
curl "http://$WAF_IP/api/public?search=<script>alert(1)</script>"
# Esperado: 403 Forbidden

# 3. Path Traversal (bloquea regla custom 900002)
curl "http://$WAF_IP/api/public?file=../../etc/passwd"
# Esperado: 403 Forbidden

# 4. Credenciales en URL (bloquea regla custom 900006)
curl "http://$WAF_IP/api/public?password=123456&token=abc"
# Esperado: 403 Forbidden

# 5. Scanner detection (bloquea regla custom 900007)
curl -A "nikto/2.1.6" http://$WAF_IP/api/public
# Esperado: 403 Forbidden

# 6. Admin panel desde IP externa (bloquea regla custom 900001)
curl http://$WAF_IP/admin
# Esperado: 403 Forbidden

# 7. Rate limiting (20 req/min)
for i in {1..25}; do
  curl -s http://$WAF_IP/api/telemetria -w "\nStatus: %{http_code}\n"
done
# Esperado: Primeras 20 OK (200), siguientes 5 bloqueadas (429 Too Many Requests)
```

**Desde dentro de la VPC** (SSH a cualquier VM de la VPC):

```bash
# Admin panel desde IP interna (debería pasar)
curl http://10.0.1.10/admin
# Esperado: 200 OK (regla 900001 permite IPs 10.0.1.0/24)
```

## Verificación en Wazuh

Dashboard > Security Events → Filtrar por `rule.id: 100010-100014` y `agent.name: waf-kong`

```bash
sudo tail -f /var/ossec/logs/alerts/alerts.log | grep ModSecurity
```
