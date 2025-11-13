# SIEM - Wazuh

Wazuh SIEM desplegado automáticamente con 17 reglas personalizadas para 4 casos de uso.

## Instalado Automáticamente

- Wazuh Manager 4.13
- Wazuh Indexer (OpenSearch)
- Wazuh Dashboard (HTTPS)
- 17 reglas custom en `/var/ossec/etc/rules/local_rules.xml`
- 4 agentes auto-registrados (wazuh-siem, hardening-vm, waf-kong, vpn-iam)

## Verificación

```bash
# SSH a VM Wazuh
ssh -i ~/.ssh/obligatorio-srd ubuntu@$(terraform output -raw wazuh_public_ip)

# Verificar agentes conectados
sudo /var/ossec/bin/agent_control -l

# Ver reglas custom instaladas
sudo cat /var/ossec/etc/rules/local_rules.xml | grep "rule id"

# Ver logs de alertas
sudo tail -f /var/ossec/logs/alerts/alerts.log
```

**Dashboard:**
- URL: `https://<WAZUH_PUBLIC_IP>`
- Usuario: `admin`
- Password: `sudo cat /root/wazuh-password.txt`

## Casos de Uso Implementados

### Caso 1: Brute Force Authentication

**Reglas:** 100001-100003

```xml
<rule id="100001" level="10" frequency="5" timeframe="300">
  <if_matched_sid>5503</if_matched_sid>
  <description>Múltiples intentos de autenticación SSH fallidos</description>
  <mitre><id>T1110</id></mitre>
</rule>
```

**Testing:**
```bash
# Desde máquina local (6 intentos fallidos SSH)
for i in {1..6}; do ssh -i ~/.ssh/obligatorio-srd wronguser@<HARDENING_IP>; done

# Ver alerta en Dashboard: Security events → rule.id: 100001
```

**Detección:**
- 5 intentos fallidos en 5 minutos → Nivel 10
- IP externa (fuera de VPC) → Nivel 12
- Usuario privilegiado (root/admin) → Nivel 12

---

### Caso 2: Ataques Web OWASP Top 10

**Reglas:** 100010-100014

```xml
<rule id="100010" level="10">
  <if_sid>31100</if_sid>
  <match>sql|union|select|insert|drop</match>
  <description>Kong: Intento de SQL Injection detectado</description>
  <mitre><id>T1190</id></mitre>
</rule>
```

**Testing:**
```bash
# SQL Injection
curl "http://<WAF_IP>/?id=1' OR '1'='1"

# XSS
curl "http://<WAF_IP>/?q=<script>alert(1)</script>"

# Path Traversal
curl "http://<WAF_IP>/../../etc/passwd"

# Ver alertas en Dashboard: rule.id: 100010-100014
```

**Detección:**
- SQL Injection → Nivel 10
- XSS → Nivel 10
- RCE (Remote Code Execution) → Nivel 12
- 10+ ataques misma IP en 5min → Nivel 12

---

### Caso 3: File Integrity Monitoring

**Reglas:** 100020-100023

```xml
<rule id="100020" level="10">
  <if_sid>550</if_sid>
  <match>/etc/passwd|/etc/shadow|/etc/group</match>
  <description>Cambio en archivos de usuarios del sistema</description>
  <mitre><id>T1098</id></mitre>
</rule>
```

**Testing:**
```bash
# SSH a VM Hardening
ssh -i ~/.ssh/obligatorio-srd ubuntu@<HARDENING_IP>

# Modificar archivo monitoreado
sudo echo "test_user:x:9999:9999::/tmp:/bin/false" >> /etc/passwd

# Ver alerta inmediata en Dashboard: rule.id: 100020
```

**Archivos monitoreados:**
- `/etc/passwd`, `/etc/shadow`, `/etc/group` → Nivel 10
- `/etc/sudoers` → Nivel 12 (crítico)
- `/etc/ssh/sshd_config` → Nivel 10
- `/etc/ufw`, `/etc/iptables` → Nivel 10

---

### Caso 4: IAM Behavioral Analytics

**Reglas:** 100040-100043

```xml
<rule id="100041" level="10" frequency="5" timeframe="300">
  <if_matched_sid>100040</if_matched_sid>
  <description>Keycloak: Múltiples intentos de login fallidos (brute force)</description>
  <mitre><id>T1110</id></mitre>
</rule>
```

**Testing:**
```bash
# Keycloak brute force
# 1. Ir a http://<VPN_IP>:8080/realms/fosil/account
# 2. Intentar login con password incorrecto 6 veces

# Ver alerta en Dashboard: rule.id: 100041
```

**Detección:**
- 5 intentos login fallidos Keycloak → Nivel 10
- Login fuera horario (22h-6h) → Nivel 10
- Cambios en roles/permisos → Nivel 12

---

## Archivos de Configuración

### Reglas Custom

**Ubicación:** `/var/ossec/etc/rules/local_rules.xml`

```bash
# Ver todas las reglas custom
sudo cat /var/ossec/etc/rules/local_rules.xml

# Recargar reglas después de modificar
sudo systemctl restart wazuh-manager
```

### Agentes FIM

**hardening-vm:**
```xml
<directories check_all="yes" realtime="yes" report_changes="yes">/etc/passwd</directories>
<directories check_all="yes" realtime="yes" report_changes="yes">/etc/shadow</directories>
<directories check_all="yes" realtime="yes" report_changes="yes">/etc/sudoers</directories>
```

**waf-kong:**
```xml
<directories check_all="yes" realtime="yes">/etc/kong</directories>
<directories check_all="yes" realtime="yes">/etc/nginx</directories>
```

**vpn-iam:**
```xml
<directories check_all="yes" realtime="yes" report_changes="yes">/etc/wireguard</directories>
<directories check_all="yes" realtime="yes">/opt/keycloak/conf</directories>
```

## Troubleshooting

### Agente no aparece conectado

```bash
# En VM del agente
sudo systemctl status wazuh-agent
sudo systemctl restart wazuh-agent

# Ver logs
sudo tail -f /var/ossec/logs/ossec.log
```

### Reglas no disparan alertas

```bash
# Verificar que las reglas estén cargadas
sudo /var/ossec/bin/wazuh-logtest

# Verificar nivel de logging
sudo grep "logall_json" /var/ossec/etc/ossec.conf
```

### Dashboard no accesible

```bash
# Verificar servicios
sudo systemctl status wazuh-dashboard
sudo systemctl status wazuh-indexer

# Ver contraseña admin
sudo cat /root/wazuh-password.txt
```

## Queries Útiles Dashboard

```
# Todas las alertas de nivel alto
rule.level:>=10

# Alertas de casos de uso custom
rule.id:(100001 OR 100010 OR 100020 OR 100040)

# Brute force SSH
rule.id:100001 AND agent.name:hardening-vm

# Ataques web
rule.id:(100010 OR 100011 OR 100012)

# FIM - cambios críticos
rule.id:(100020 OR 100021 OR 100022)
```

## Referencias

- [Wazuh Documentation](https://documentation.wazuh.com/)
- [Custom Rules](https://documentation.wazuh.com/current/user-manual/ruleset/custom.html)
- [MITRE ATT&CK](https://attack.mitre.org/)
