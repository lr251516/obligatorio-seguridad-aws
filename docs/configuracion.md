# Guía de Configuración Detallada

## Orden de Configuración Recomendado
```
1. Wazuh SIEM (VM2)          → Hub central de monitoreo
2. Keycloak IAM (VM3)         → Autenticación centralizada
3. WireGuard VPN (VM3 ↔ VM4) → Conectividad segura
4. Kong WAF (VM1)             → Protección de APIs
5. Hardening (VM4)            → CIS + SCA
6. Agentes Wazuh              → Todas las VMs
7. Integración SIEM           → Logs centralizados
```
---

## 1. Configurar Wazuh SIEM (VM2)

**Tiempo estimado**: 30-45 minutos

### Acceso a la VM
```bash
WAZUH_IP=$(cd terraform && terraform output -raw wazuh_public_ip)
ssh -i ~/.ssh/obligatorio-srd ubuntu@$WAZUH_IP
```

### Instalación de Wazuh Stack
```bash
# Descargar script
cd /opt/fosil/scripts
wget https://raw.githubusercontent.com/lr251516/obligatorio-seguridad-aws/main/SIEM/scripts/install-wazuh.sh
chmod +x install-wazuh.sh

# Ejecutar instalación (tarda ~20 minutos)
sudo ./install-wazuh.sh
```

**El script instala:**
- Wazuh Manager (motor de análisis)
- Wazuh Indexer (base de datos OpenSearch)
- Wazuh Dashboard (interfaz web)

### Verificar Instalación
```bash
# Servicios corriendo
sudo systemctl status wazuh-manager
sudo systemctl status wazuh-indexer
sudo systemctl status wazuh-dashboard

# Ver credenciales
echo "Dashboard: https://$WAZUH_IP"
echo "Usuario: admin"
echo "Password: admin"
```

### Acceder al Dashboard

1. Abrir en navegador: `https://<wazuh-ip>`
2. Aceptar certificado autofirmado
3. Login: `admin / admin`
4. Cambiar password en primer acceso

### Configurar Reglas Personalizadas
```bash
# Descargar reglas personalizadas
cd /var/ossec/etc/rules
sudo wget https://raw.githubusercontent.com/lr251516/obligatorio-seguridad-aws/main/SIEM/scripts/wazuh-custom-rules.xml -O local_rules.xml
sudo chown wazuh:wazuh local_rules.xml
sudo chmod 640 local_rules.xml

# Reiniciar para aplicar
sudo systemctl restart wazuh-manager
```

### Configurar Política SCA Personalizada
```bash
# Descargar política Fósil
cd /var/ossec/etc/shared
sudo wget https://raw.githubusercontent.com/lr251516/obligatorio-seguridad-aws/main/SIEM/scripts/wazuh-sca-custom-policy.yml -O fosil_security_policy.yml
sudo chown wazuh:wazuh fosil_security_policy.yml
sudo chmod 640 fosil_security_policy.yml

# Reiniciar
sudo systemctl restart wazuh-manager
```

**✅ Wazuh completado**

---

## 2. Configurar Keycloak IAM (VM3)

**Tiempo estimado**: 20-30 minutos

### Acceso a la VM
```bash
VPN_IP=$(cd terraform && terraform output -raw vpn_public_ip)
ssh -i ~/.ssh/obligatorio-srd ubuntu@$VPN_IP
```

### Instalación de Keycloak
```bash
# Descargar script
cd /opt/fosil/scripts
wget https://raw.githubusercontent.com/lr251516/obligatorio-seguridad-aws/main/VPN-IAM/scripts/install-keycloak.sh
chmod +x install-keycloak.sh

# Ejecutar instalación (tarda ~10 minutos)
sudo ./install-keycloak.sh
```

### Crear Realm de Fósil
```bash
# Descargar script
wget https://raw.githubusercontent.com/lr251516/obligatorio-seguridad-aws/main/VPN-IAM/scripts/create-realm.sh
chmod +x create-realm.sh

# Ejecutar
sudo ./create-realm.sh
```

**El script crea:**
- Realm: `fosil-energias`
- Roles: `admin-sistemas`, `admin-redes`, `operador-telemetria`, `auditor`
- Usuarios de prueba (con passwords)
- Clientes OAuth2: Kong, Wazuh, OpenVPN

### Acceder a Keycloak

1. URL: `http://<vpn-ip>:8080`
2. Login: `admin / admin`
3. Seleccionar realm: `fosil-energias`

### Verificar Configuración
```bash
# Ver usuarios creados
sudo -u keycloak /opt/keycloak/bin/kcadm.sh get users \
  -r fosil-energias \
  --server http://10.0.1.30:8080

# Ver clientes OAuth2
sudo -u keycloak /opt/keycloak/bin/kcadm.sh get clients \
  -r fosil-energias \
  --server http://10.0.1.30:8080
```

**✅ Keycloak completado**

---

## 3. Configurar WireGuard VPN (VM3 ↔ VM4)

**Tiempo estimado**: 15-20 minutos

### Configurar Servidor (VM3)
```bash
ssh -i ~/.ssh/obligatorio-srd ubuntu@$VPN_IP

# Descargar script
cd /opt/fosil/scripts
wget https://raw.githubusercontent.com/lr251516/obligatorio-seguridad-aws/main/VPN-IAM/scripts/setup-wireguard.sh
chmod +x setup-wireguard.sh

# Ejecutar como servidor
sudo ./setup-wireguard.sh server
```

**Importante**: Guardar la clave pública que se muestra.

### Configurar Cliente (VM4)
```bash
# Obtener IP pública de Hardening
HARD_IP=$(aws ec2 describe-instances \
  --filters "Name=tag:Name,Values=fosil-hardening" \
  --query 'Reservations[0].Instances[0].PublicIpAddress' \
  --output text \
  --profile ort)

# Conectar (necesitas VPN desde VM3 primero)
# Por ahora, SSH directo si tiene IP pública temporal
ssh -i ~/.ssh/obligatorio-srd ubuntu@$HARD_IP

# Descargar script
cd /opt/fosil/scripts
wget https://raw.githubusercontent.com/lr251516/obligatorio-seguridad-aws/main/VPN-IAM/scripts/setup-wireguard.sh
chmod +x setup-wireguard.sh

# Ejecutar como cliente
sudo ./setup-wireguard.sh client
```

**Importante**: Guardar la clave pública.

### Intercambiar Claves Públicas

**En VM3 (servidor):**
```bash
sudo nano /etc/wireguard/wg0.conf
# Reemplazar CLIENTE_PUBLIC_KEY_AQUI con la clave de VM4
```

**En VM4 (cliente):**
```bash
sudo nano /etc/wireguard/wg0.conf
# Reemplazar SERVIDOR_PUBLIC_KEY_AQUI con la clave de VM3
```

### Iniciar VPN

**En ambas VMs:**
```bash
sudo systemctl start wg-quick@wg0
sudo systemctl enable wg-quick@wg0

# Verificar
sudo wg show
```

### Test de Conectividad

**Desde VM4:**
```bash
# Ping al servidor VPN
ping -c 3 10.0.0.1

# Ping a Wazuh a través del túnel
ping -c 3 10.0.1.20

# Ping a VPN/IAM
ping -c 3 10.0.1.30
```

**✅ VPN completada**

---

## 4. Configurar Kong WAF (VM1)

**Tiempo estimado**: 30-40 minutos

### Acceso a la VM
```bash
WAF_IP=$(cd terraform && terraform output -raw waf_public_ip)
ssh -i ~/.ssh/obligatorio-srd ubuntu@$WAF_IP
```

### Instalación Kong + ModSecurity
```bash
# Scripts pendientes de implementación
# Por ahora, instalación manual
```

**✅ WAF pendiente**

---

## 5. Aplicar Hardening (VM4)

**Tiempo estimado**: 20-30 minutos

### Acceso a la VM
```bash
# Via VPN desde VM3
ssh -i ~/.ssh/obligatorio-srd ubuntu@10.0.1.40
```

### Aplicar CIS Hardening
```bash
# Descargar script
cd /opt/fosil/scripts
wget https://raw.githubusercontent.com/lr251516/obligatorio-seguridad-aws/main/Hardening/scripts/apply-cis-hardening.sh
chmod +x apply-cis-hardening.sh

# Ejecutar (tarda ~10 minutos)
sudo ./apply-cis-hardening.sh

# Reiniciar
sudo reboot
```

**El script aplica:**
- Filesystem hardening
- Kernel hardening
- SSH hardening
- Auditoría con auditd
- Firewall UFW
- Políticas de contraseñas
- Actualizaciones automáticas

**✅ Hardening completado**

---

## 6. Instalar Agentes Wazuh

**Instalar en VM1, VM3 y VM4**

### En cada VM:
```bash
cd /opt/fosil/scripts
wget https://raw.githubusercontent.com/lr251516/obligatorio-seguridad-aws/main/SIEM/scripts/wazuh-agent-install.sh
chmod +x wazuh-agent-install.sh

# Ejecutar según la VM
# VM1:
sudo ./wazuh-agent-install.sh waf-vm waf

# VM3:
sudo ./wazuh-agent-install.sh vpn-iam-vm vpn

# VM4:
sudo ./wazuh-agent-install.sh hardening-vm hardening
```

### Verificar en Wazuh Manager
```bash
# SSH a VM2
ssh -i ~/.ssh/obligatorio-srd ubuntu@$(terraform output -raw wazuh_public_ip)

# Ver agentes conectados
sudo /var/ossec/bin/agent_control -l
```

Deberías ver:
```
Available agents:
   ID: 001, Name: waf-vm, IP: 10.0.1.10, Active
   ID: 002, Name: vpn-iam-vm, IP: 10.0.1.30, Active
   ID: 003, Name: hardening-vm, IP: 10.0.1.40, Active
```

**✅ Agentes instalados**

---

## 7. Verificar SCA en Dashboard

1. Acceder a Wazuh Dashboard: `https://<wazuh-ip>`
2. Ir a: **Security Configuration Assessment**
3. Ver agents:
   - `hardening-vm` → Score esperado: 80-85%
   - `vpn-iam-vm` → Score: 60-70%
   - `waf-vm` → Score: 60-70%

---

## Troubleshooting

### Wazuh no inicia
```bash
# Ver logs
sudo tail -f /var/ossec/logs/ossec.log

# Verificar memoria
free -h

# Si falta memoria, reiniciar servicios
sudo systemctl restart wazuh-indexer
sudo systemctl restart wazuh-manager
```

### Keycloak lento
```bash
# Ver memoria
free -h

# Ver uso de swap
swapon -s

# Si usa mucho swap, es normal en t3.small
# Considerar upgrade a t3.small con más RAM
```

### VPN no conecta
```bash
# Ver logs WireGuard
sudo journalctl -u wg-quick@wg0 -f

# Verificar claves
sudo wg show

# Verificar Security Groups AWS permiten 51820/UDP
```

### Agente Wazuh no conecta
```bash
# Ver logs
sudo cat /var/ossec/logs/ossec.log

# Verificar conectividad al manager
telnet 10.0.1.20 1514

# Reiniciar agente
sudo systemctl restart wazuh-agent
```

---

## Próximos Pasos

1. ✅ Infraestructura desplegada
2. ✅ Wazuh configurado
3. ✅ Keycloak configurado
4. ✅ VPN funcionando
5. ⏳ Kong/WAF pendiente
6. ✅ Hardening aplicado
7. ✅ Agentes instalados
8. ⏳ Testing de casos de uso
9. ⏳ Documentación final

---

**Tiempo total estimado**: 2-3 horas para configuración completa