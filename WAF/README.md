# Maqueta 1: WAF + API Gateway (Kong)

## Componentes

- **Kong Gateway 3.4.1**: API Gateway y reverse proxy
- **ModSecurity 3**: Web Application Firewall
- **OWASP CRS**: Core Rule Set (reglas base)
- **Reglas personalizadas**: 6 reglas custom para Fósil Energías

## Arquitectura

```
Internet/Usuarios
       ↓
   Kong Proxy (8000/8443)
       ↓
   ModSecurity WAF
       ↓
   Backend Services
       ↓
   Logs → Wazuh SIEM
```

## Instalación

### 1. Instalar Kong + ModSecurity

```bash
cd WAF/scripts
chmod +x install-kong.sh
sudo ./install-kong.sh
```

Este script:
- Instala PostgreSQL
- Instala Kong Gateway
- Instala ModSecurity
- Clona OWASP CRS
- Configura servicios básicos
- Integra con Keycloak

### 2. Aplicar reglas personalizadas

```bash
# Copiar reglas personalizadas
sudo cp custom-rules.conf /opt/coreruleset/rules/REQUEST-900-CUSTOM-RULES.conf

# Reiniciar Kong
sudo kong restart
```

### 3. Integrar con Wazuh

```bash
# Primero instalar agente Wazuh (si no está)
cd /opt/fosil/scripts
sudo ./wazuh-agent-install.sh vm-waf waf

# Luego integrar logs
cd /opt/fosil/WAF-APIgw/scripts
chmod +x integrate-kong-wazuh.sh
sudo ./integrate-kong-wazuh.sh
```

## Reglas Personalizadas

### Regla 1: Bloqueo de endpoints admin
- **ID**: 900001
- **Descripción**: Solo permite acceso a `/admin` desde red interna (10.0.1.0/24)
- **Acción**: BLOCK
- **Severidad**: CRITICAL

### Regla 2: Path Traversal
- **ID**: 900002
- **Descripción**: Detecta patrones `../`, `etc/passwd`, etc.
- **Acción**: BLOCK
- **Severidad**: CRITICAL

### Regla 3-5: Rate Limiting Telemetría
- **IDs**: 900003, 900004, 900005
- **Descripción**: Limita requests a `/api/telemetry` a 20 req/min por IP
- **Acción**: BLOCK después del límite
- **Severidad**: WARNING

### Regla 4: Credenciales en URL
- **ID**: 900006
- **Descripción**: Detecta parámetros como `password`, `api_key`, `token` en URLs
- **Acción**: BLOCK
- **Severidad**: ERROR

### Regla 5: User-Agents maliciosos
- **ID**: 900007
- **Descripción**: Bloquea herramientas de escaneo (nikto, sqlmap, nmap, etc.)
- **Acción**: BLOCK
- **Severidad**: CRITICAL

### Regla 6: Validación JSON en APIs de energía
- **ID**: 900008
- **Descripción**: Valida Content-Type en POST a `/api/solar` y `/api/wind`
- **Acción**: BLOCK si no es application/json
- **Severidad**: WARNING

## Testing

### Test de funcionalidad básica

```bash
# Request normal
curl http://10.0.1.10:8000/wazuh

# Ver plugins activos
curl http://localhost:8001/plugins
```

### Test de reglas OWASP CRS

```bash
# SQL Injection (OWASP)
curl "http://10.0.1.10:8000/?id=1' OR '1'='1"

# XSS (OWASP)
curl "http://10.0.1.10:8000/?search=<script>alert(1)</script>"

# RCE attempt (OWASP)
curl "http://10.0.1.10:8000/?cmd=;cat /etc/passwd"
```

### Test de reglas personalizadas

```bash
# Regla 1: Admin desde IP externa (bloquear)
curl http://10.0.1.10:8000/admin

# Regla 2: Path Traversal
curl "http://10.0.1.10:8000/../../../etc/passwd"

# Regla 4: Credenciales en URL
curl "http://10.0.1.10:8000/?password=123456"

# Regla 5: User-Agent de scanner
curl -A "nikto" http://10.0.1.10:8000/

# Regla 6: JSON inválido en API energía
curl -X POST http://10.0.1.10:8000/api/solar \
  -H "Content-Type: text/plain" \
  -d "data"
```

## Verificación en Wazuh

### En el Dashboard de Wazuh

1. Acceder a: `https://<WAZUH_PUBLIC_IP>`
2. Login: `admin` / `admin`
3. Security events → Filtrar por:
   - `rule.id: 100010-100014` (ataques web)
   - `agent.name: vm-waf`

### En CLI del Manager

```bash
# SSH a Wazuh Manager (10.0.1.20)
ssh -i ~/.ssh/obligatorio-srd ubuntu@<WAZUH_PUBLIC_IP>

# Ver alertas en tiempo real
sudo tail -f /var/ossec/logs/alerts/alerts.log

# Ver alertas de WAF específicamente
sudo grep "ModSecurity" /var/ossec/logs/alerts/alerts.log

# Ver estadísticas del agente WAF
sudo /var/ossec/bin/agent_control -i 001  # Ajustar ID según corresponda
```

## Configuración de servicios

### Agregar nuevo servicio backend

```bash
# Crear servicio
curl -i -X POST http://localhost:8001/services/ \
  --data "name=mi-servicio" \
  --data "url=http://backend-ip:port"

# Crear ruta
curl -i -X POST http://localhost:8001/services/mi-servicio/routes \
  --data "paths[]=/api/mi-servicio"

# Agregar autenticación OIDC
curl -i -X POST http://localhost:8001/services/mi-servicio/plugins \
  --data "name=openid-connect" \
  --data "config.issuer=http://10.0.1.30:8080/realms/fosil-energias" \
  --data "config.client_id=kong-api" \
  --data "config.client_secret=kong-secret-2024"
```

## Logs

- **Kong Access**: `/var/log/kong/access.log`
- **Kong Error**: `/var/log/kong/error.log`
- **Kong Admin**: `/var/log/kong/admin_access.log`
- **ModSecurity Audit**: `/var/log/modsec_audit.log`
- **ModSecurity Debug**: `/var/log/modsec_debug.log`

## URLs importantes

- **Kong Proxy HTTP**: `http://10.0.1.10:8000`
- **Kong Proxy HTTPS**: `https://10.0.1.10:8443`
- **Kong Admin API**: `http://10.0.1.10:8001` (solo red interna)
- **Kong Admin SSL**: `https://10.0.1.10:8444` (solo red interna)

## Troubleshooting

### Kong no inicia

```bash
# Ver logs
sudo kong start -vv

# Ver estado
sudo systemctl status kong

# Verificar configuración
sudo kong check /etc/kong/kong.conf
```

### ModSecurity no bloquea

```bash
# Verificar que está habilitado
grep "SecRuleEngine" /etc/modsecurity/modsecurity.conf
# Debe decir: SecRuleEngine On

# Ver debug logs
sudo tail -f /var/log/modsec_debug.log
```

### Logs no llegan a Wazuh

```bash
# Verificar agente Wazuh
sudo /var/ossec/bin/wazuh-control status

# Ver logs del agente
sudo tail -f /var/ossec/logs/ossec.log

# Verificar permisos de logs
ls -la /var/log/modsec_*.log
ls -la /var/log/kong/*.log
```

## Referencias

- [Kong Gateway Docs](https://docs.konghq.com/)
- [ModSecurity Reference Manual](https://github.com/SpiderLabs/ModSecurity/wiki/Reference-Manual-(v3.x))
- [OWASP CRS](https://coreruleset.org/)
- [Wazuh Integration](https://documentation.wazuh.com/)