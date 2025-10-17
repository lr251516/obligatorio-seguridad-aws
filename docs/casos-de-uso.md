# Casos de Uso - Testing y Validación

## Resumen

3 casos de uso personalizados para Fósil Energías, mapeados contra MITRE ATT&CK y con alertas configuradas en Wazuh.

---

## Caso 1: Detección de Brute Force

### Descripción
Detecta múltiples intentos fallidos de autenticación contra SSH, Keycloak o Kong.

### Reglas Wazuh

| ID | Nivel | Condición | Descripción |
|----|-------|-----------|-------------|
| 100001 | 10 | 5 intentos en 5 min | Múltiples intentos fallidos |
| 100002 | 12 | IP externa (fuera VPC) | Intentos desde Internet |
| 100003 | 12 | Usuario privilegiado | Ataque a root/admin/ubuntu |

**MITRE ATT&CK**: T1110 (Brute Force)

### Fuentes de Datos
- `/var/log/auth.log` (SSH)
- `/opt/keycloak/data/log/keycloak.log` (Keycloak)
- `/var/log/kong/access.log` (Kong)

### Respuesta Automática
Bloqueo de IP atacante por 10 minutos usando UFW (reglas 100002/100003).

### Testing

```bash
# Simular ataque SSH desde local
for i in {1..6}; do
  ssh -o ConnectTimeout=2 usuario_falso@<wazuh-ip>
done
```

**Resultado esperado:**
1. Alerta 100001 (nivel 10) tras 5 intentos
2. Alerta 100002 (nivel 12) por IP externa
3. UFW bloquea IP por 10 minutos
4. Dashboard muestra alerta con IP, usuario, timestamp

---

## Caso 2: Ataques Web (OWASP Top 10)

### Descripción
Detecta intentos de explotación web mediante análisis de logs de ModSecurity/Kong.

### Reglas Wazuh

| ID | Nivel | Tipo Ataque | MITRE |
|----|-------|-------------|-------|
| 100010 | 7 | ModSecurity warning | T1190 |
| 100011 | 10 | SQL Injection | T1190 |
| 100012 | 10 | XSS | T1059 |
| 100013 | 12 | RCE | T1059 |
| 100014 | 12 | 10 ataques en 2 min | T1190 |

**MITRE ATT&CK**: T1190 (Exploit Public-Facing Application), T1059 (Command Execution)

### Fuentes de Datos
- `/var/log/modsec_audit.log` (ModSecurity)
- `/var/log/kong/access.log` (Kong Access)
- `/var/log/kong/error.log` (Kong Error)

### Tipos de Ataques Detectados

**SQL Injection:**
```bash
curl "http://<waf-ip>:8000/api/users?id=1' OR '1'='1"
curl "http://<waf-ip>:8000/api/users?id=1 UNION SELECT * FROM passwords"
```

**XSS:**
```bash
curl "http://<waf-ip>:8000/api/search?q=<script>alert('xss')</script>"
curl "http://<waf-ip>:8000/api/search?q=<img src=x onerror=alert(1)>"
```

**RCE:**
```bash
curl "http://<waf-ip>:8000/api/exec?cmd=; ls -la"
curl "http://<waf-ip>:8000/api/exec?cmd=| cat /etc/passwd"
```

**Path Traversal:**
```bash
curl "http://<waf-ip>:8000/api/file?path=../../etc/passwd"
```

### Respuesta Automática
Bloqueo de IP por 30 minutos en ataques RCE o múltiples (reglas 100013/100014).

---

## Caso 3: File Integrity Monitoring

### Descripción
Monitorea cambios en tiempo real en archivos críticos del sistema.

### Reglas Wazuh

| ID | Nivel | Archivo | MITRE | Descripción |
|----|-------|---------|-------|-------------|
| 100020 | 10 | `/etc/passwd`, `/etc/shadow` | T1098 | Cambios en usuarios |
| 100021 | 12 | `/etc/sudoers` | T1548.003 | Cambios en sudo (crítico) |
| 100022 | 10 | `/etc/ssh/sshd_config` | T1098.004 | Cambios en SSH |
| 100023 | 10 | `/etc/ufw`, `/etc/iptables` | T1562.004 | Cambios en firewall |
| 100024 | 8 | `/var/ossec/etc`, `/etc/kong` | - | Cambios en apps críticas |

### Archivos Monitoreados

| Archivo | Criticidad | Realtime | Report Changes |
|---------|------------|----------|----------------|
| `/etc/passwd` | Alta | ✅ | ✅ |
| `/etc/shadow` | Crítica | ✅ | ✅ |
| `/etc/sudoers` | Crítica | ✅ | ✅ |
| `/etc/ssh/sshd_config` | Alta | ✅ | ✅ |
| `/root/.ssh` | Alta | ✅ | ✅ |
| `/etc/ufw` | Alta | ✅ | ✅ |
| `/etc/systemd/system` | Media | ✅ | ❌ |
| `/var/ossec/etc` | Alta | ✅ | ✅ |

**Configuración**: Frequency 300s, realtime monitoring, report changes con diff completo.

### Testing

**Test 1: Crear usuario backdoor**
```bash
sudo useradd -m -s /bin/bash backdoor
sudo usermod -aG sudo backdoor
```
**Esperado**: Alerta 100020 (nivel 10), diff en `/etc/passwd`

**Test 2: Modificar SSH (permitir root login)**
```bash
sudo sed -i 's/PermitRootLogin no/PermitRootLogin yes/' /etc/ssh/sshd_config
```
**Esperado**: Alerta 100022 (nivel 10), diff completo del cambio

**Test 3: Modificar sudoers**
```bash
echo "backdoor ALL=(ALL) NOPASSWD:ALL" | sudo tee -a /etc/sudoers
```
**Esperado**: Alerta 100021 (nivel 12 crítico), diff con línea agregada

**Test 4: Desactivar firewall**
```bash
sudo ufw disable
```
**Esperado**: Alerta 100023 (nivel 10), cambio en config UFW

### Report Changes (Diff)

Wazuh muestra diff exacto:
```diff
--- /etc/ssh/sshd_config (before)
+++ /etc/ssh/sshd_config (after)
@@ -32,7 +32,7 @@
-PermitRootLogin no
+PermitRootLogin yes
```

---

## Mapeo MITRE ATT&CK

| Caso de Uso | Táctica | Técnica | ID |
|-------------|---------|---------|-----|
| Brute Force | Credential Access | Brute Force | T1110 |
| Ataques Web | Initial Access | Exploit Public-Facing Application | T1190 |
| Ataques Web (XSS/RCE) | Execution | Command Execution | T1059 |
| Cambios Usuario | Persistence | Account Manipulation | T1098 |
| Cambios Sudo | Privilege Escalation | Sudo and Sudo Caching | T1548.003 |
| Cambios SSH | Persistence | SSH Authorized Keys | T1098.004 |
| Cambios Firewall | Defense Evasion | Impair Defenses | T1562.004 |

---

## Dashboard Wazuh

### Widgets Recomendados

1. **Top Alerts by Rule ID** - Filtrar: 100001-100024 (Bar chart)
2. **Authentication Failures Over Time** - Filtrar: group authentication_failures (Line chart)
3. **WAF Blocks by Attack Type** - Filtrar: group web,attack (Pie chart)
4. **FIM Changes by File** - Filtrar: group syscheck (Table)
5. **Top Attacking IPs** - Filtrar: level >= 10 (Data table)
6. **MITRE ATT&CK Coverage** - Técnicas detectadas (Heatmap)

---

## Métricas de Éxito

### Caso 1: Brute Force
- ✅ Detección < 5 minutos
- ✅ Bloqueo automático de IP
- ✅ Alerta visible en dashboard
- ✅ Email enviado para nivel 12

### Caso 2: Ataques Web
- ✅ Detección tiempo real
- ✅ Tipos de ataque identificados
- ✅ IP atacante registrada
- ✅ Bloqueo tras múltiples intentos

### Caso 3: FIM
- ✅ Detección < 1 minuto (realtime)
- ✅ Diff completo disponible
- ✅ Archivo exacto identificado
- ✅ Usuario que hizo cambio registrado
