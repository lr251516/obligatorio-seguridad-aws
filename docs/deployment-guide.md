# Guía de Despliegue - Fósil Energías Renovables

## Requisitos Previos

1. **AWS Account** con permisos administrativos
2. **Terraform** >= 1.0
3. **Par de claves SSH** generado:
   ```bash
   ssh-keygen -t rsa -b 4096 -f ~/.ssh/obligatorio-srd
   ```

4. **Variable MY_IP** configurada en terraform.tfvars:
   ```hcl
   my_ip = "TU_IP_PUBLICA/32"  # Importante: debe ser tu IP actual
   ```

## Despliegue de Infraestructura

### Paso 1: Configuración de Terraform

```bash
cd terraform
terraform init
terraform plan
terraform apply
```

**Salidas importantes:**
- IPs públicas de Wazuh, VPN y WAF
- Contraseña temporal de Wazuh (se genera durante instalación)

### Paso 2: Instalación de Wazuh SIEM

SSH a la VM de Wazuh:
```bash
ssh -i ~/.ssh/obligatorio-srd ubuntu@<WAZUH_PUBLIC_IP>
```

Ejecutar instalador oficial:
```bash
cd /tmp
curl -sO https://packages.wazuh.com/4.13/wazuh-install.sh
sudo bash wazuh-install.sh -a 2>&1 | tee wazuh-installation.log
```

**IMPORTANTE:** Guardar la contraseña que aparece al final de la instalación.

Extraer credenciales:
```bash
PASSWORD=$(grep "Password:" wazuh-installation.log | tail -1 | awk '{print $2}')
echo "Dashboard URL: https://$(hostname -I | awk '{print $1}')"
echo "Usuario: admin"
echo "Password: $PASSWORD"
```

### Paso 3: Configurar Reglas Personalizadas

Copiar reglas desde el repositorio:
```bash
sudo cp /opt/fosil/SIEM/scripts/wazuh-custom-rules.xml /var/ossec/etc/rules/local_rules.xml
sudo chown root:wazuh /var/ossec/etc/rules/local_rules.xml
sudo chmod 640 /var/ossec/etc/rules/local_rules.xml
```

Validar sintaxis:
```bash
sudo /var/ossec/bin/wazuh-logtest -t
```

Reiniciar manager:
```bash
sudo systemctl restart wazuh-manager
sudo systemctl status wazuh-manager
```

### Paso 4: Instalar Agente Wazuh en Hardening VM

**IMPORTANTE:** Verificar que tu IP pública esté permitida en el Security Group de Hardening VM.

SSH a la Hardening VM:
```bash
ssh -i ~/.ssh/obligatorio-srd ubuntu@<HARDENING_PRIVATE_IP>
# O usar la IP pública si está asignada
```

Ejecutar instalación del agente:
```bash
curl -s https://packages.wazuh.com/key/GPG-KEY-WAZUH | sudo apt-key add -
echo "deb https://packages.wazuh.com/4.x/apt/ stable main" | sudo tee /etc/apt/sources.list.d/wazuh.list
sudo apt update

# Si hay conflicto con postfix, eliminarlo primero
sudo apt remove --purge -y postfix

# Instalar agente
sudo WAZUH_MANAGER="10.0.1.20" \
     WAZUH_AGENT_NAME="hardening-vm" \
     DEBIAN_FRONTEND=noninteractive \
     apt install -y wazuh-agent
```

Configurar FIM (File Integrity Monitoring):
```bash
sudo sed -i '/<\/ossec_config>$/i \
  <syscheck>\n\
    <disabled>no</disabled>\n\
    <frequency>300</frequency>\n\
    <alert_new_files>yes</alert_new_files>\n\
    <directories check_all="yes" realtime="yes" report_changes="yes">/etc/passwd</directories>\n\
    <directories check_all="yes" realtime="yes" report_changes="yes">/etc/shadow</directories>\n\
    <directories check_all="yes" realtime="yes" report_changes="yes">/etc/group</directories>\n\
    <directories check_all="yes" realtime="yes" report_changes="yes">/etc/sudoers</directories>\n\
    <directories check_all="yes" realtime="yes" report_changes="yes">/etc/sudoers.d</directories>\n\
    <directories check_all="yes" realtime="yes" report_changes="yes">/etc/ssh/sshd_config</directories>\n\
    <directories check_all="yes" realtime="yes" report_changes="yes">/root/.ssh</directories>\n\
    <directories check_all="yes" realtime="yes" report_changes="yes">/etc/ufw</directories>\n\
    <ignore>/etc/mtab</ignore>\n\
    <ignore type="sregex">\\.log$</ignore>\n\
    <ignore type="sregex">\\.swp$</ignore>\n\
  </syscheck>' /var/ossec/etc/ossec.conf
```

Iniciar agente:
```bash
sudo systemctl daemon-reload
sudo systemctl enable wazuh-agent
sudo systemctl start wazuh-agent
sudo systemctl status wazuh-agent
```

Verificar conexión en el Manager:
```bash
# En la VM de Wazuh
sudo /var/ossec/bin/agent_control -l
```

## Problemas Comunes y Soluciones

### Error: Wazuh Indexer - Certificados

**Síntoma:**
```
ERROR: this tool try to find admin.pem and admin-key.pem
```

**Solución:**
Usar el instalador oficial `wazuh-install.sh -a` en lugar de instalación manual por paquetes.

### Error: XML Inválido en Reglas

**Síntoma:**
```
Invalid root element "email_alerts". Only "group" is allowed
```

**Solución:**
Las configuraciones de email van en `ossec.conf`, no en archivos de reglas. Las reglas deben tener solo elementos `<group>` como raíz.

### Error: if_matched_sid con múltiples SIDs

**Síntoma:**
```
Invalid 'if_matched_sid' value: '5503,5551'
```

**Solución:**
`if_matched_sid` solo acepta un SID único. Para múltiples condiciones, usar reglas separadas con `if_sid`.

### Error: Decoder no encontrado

**Síntoma:**
```
Invalid decoder name: 'modsecurity'
```

**Solución:**
Verificar que el decoder existe antes de usarlo. Decoders como modsecurity deben configurarse primero.

### Error: SSH Connection Timeout

**Síntoma:**
```
ssh: connect to host X.X.X.X port 22: Operation timed out
```

**Solución:**
1. Verificar Security Group permite tu IP pública en puerto 22
2. Verificar que la variable `my_ip` en terraform.tfvars tenga tu IP actual
3. Para Hardening VM, verificar que UFW permite SSH (puerto 22)

### Error: dpkg Lock durante instalación de agente

**Síntoma:**
```
Could not get lock /var/lib/dpkg/lock-frontend
```

**Solución:**
El script user-data puede estar ejecutándose. Esperar o eliminar procesos:
```bash
sudo killall apt apt-get
sudo rm /var/lib/apt/lists/lock
sudo rm /var/cache/apt/archives/lock
sudo rm /var/lib/dpkg/lock*
sudo dpkg --configure -a
```

### Error: Postfix Conflict

**Síntoma:**
```
new postfix package pre-installation script subprocess returned error exit status 127
```

**Solución:**
Eliminar postfix antes de instalar el agente:
```bash
sudo apt remove --purge -y postfix
```

### Error: Wazuh Agent Failed después de configurar FIM

**Síntoma:**
```
Active: failed (Result: exit-code)
```

**Solución:**
Verificar que la configuración FIM esté DENTRO de las tags `<ossec_config>...</ossec_config>`, no después del cierre.

## Verificación Post-Despliegue

### 1. Dashboard Wazuh
Acceder a `https://<WAZUH_PUBLIC_IP>` y verificar:
- Login exitoso con admin/<PASSWORD>
- Agentes conectados (hardening-vm debe aparecer como Active)

### 2. Reglas Personalizadas
En Dashboard > Management > Rules > Custom Rules:
- Verificar reglas 100001-100003 (Brute Force)
- Verificar reglas 100020-100023 (FIM)

### 3. File Integrity Monitoring
En Dashboard > Security Events > Integrity Monitoring:
- Debería mostrar baseline de archivos monitoreados
- Hacer cambio de prueba: `sudo touch /etc/test.conf`
- Verificar que aparece alerta de nuevo archivo

### 4. Security Configuration Assessment (SCA)
En Dashboard > Security Configuration Assessment:
- Verificar políticas CIS Ubuntu 22.04 ejecutadas
- Revisar hallazgos de compliance

## Testing de Casos de Uso

### Caso 1: Brute Force Detection

Simular intentos fallidos de SSH:
```bash
# Desde máquina externa
for i in {1..6}; do
  ssh -o PreferredAuthentications=password fake_user@<HARDENING_PUBLIC_IP>
done
```

Verificar en Dashboard > Security Events:
- Debe aparecer alerta con Rule ID 100001 o 100002
- Nivel: 10 o 12
- MITRE ATT&CK: T1110

### Caso 2: File Integrity Monitoring

Modificar archivo crítico:
```bash
# En Hardening VM
sudo usermod -aG sudo testuser  # Cambia /etc/group
sudo vi /etc/sudoers            # Cambia sudoers
```

Verificar en Dashboard:
- Rule ID 100020 (cambio en /etc/group)
- Rule ID 100021 (cambio en /etc/sudoers)
- Debe mostrar diff del cambio

## Estructura de Archivos Actualizados

```
SIEM/
├── scripts/
│   ├── install-wazuh.sh           # Instalador oficial (v4.13.1)
│   ├── wazuh-custom-rules.xml      # Reglas validadas
│   └── wazuh-agent-install.sh      # Con FIM configurado

terraform/
├── main.tf                         # Security groups actualizados
├── terraform.tfvars                # my_ip configurado
└── user-data/
    └── hardening-init.sh           # UFW permite SSH

docs/
└── deployment-guide.md             # Este archivo
```

## Notas de Seguridad

1. **Credenciales:** Guardar la contraseña de Wazuh en un gestor seguro
2. **Security Groups:** Después del testing, restringir SSH solo a VPN
3. **UFW:** En producción, configurar UFW para denegar todo excepto VPN
4. **Wazuh Dashboard:** Considerar usar proxy reverso con certificado SSL válido
5. **Actualizaciones:** Mantener Wazuh y agentes actualizados

## Próximos Pasos

1. Configurar Keycloak en VPN/IAM VM
2. Instalar Kong Gateway en WAF VM
3. Aplicar CIS Hardening completo en Hardening VM
4. Configurar alertas por email/Slack en Wazuh
5. Integrar WAF logs con Wazuh
