# VPN + IAM

## 🎯 Descripción

WireGuard VPN + Keycloak IAM desplegados automáticamente con políticas de acceso granulares basadas en roles.

**Deployment:** 100% automatizado via `terraform/user-data/vpn-init.sh`

## ✅ Instalado Automáticamente

- ✅ Keycloak 23.0.0 con PostgreSQL
- ✅ WireGuard kernel module
- ✅ Configuración HTTP para Keycloak (proyecto académico)
- ✅ Scripts de configuración en `/opt/fosil/VPN-IAM/scripts/`

## 🔐 Keycloak IAM

### Acceso Admin Console

```bash
# URL: http://<VPN_PUBLIC_IP>:8080
# Usuario: admin
# Password: admin
```

### Crear Realm "fosil" (Paso Manual Único)

```bash
ssh -i ~/.ssh/obligatorio-srd ubuntu@$(terraform output -raw vpn_public_ip)
cd /opt/fosil/VPN-IAM/scripts
chmod +x create-realm.sh
sudo ./create-realm.sh
```

**Esto crea automáticamente:**

**Realm:** `fosil`

**Roles VPN:**
- `infraestructura-admin`: Acceso completo VPC (10.0.1.0/24)
- `devops`: Solo SIEM + WAF (10.0.1.20 + 10.0.1.10)
- `viewer`: Solo SIEM read-only (10.0.1.20)

**Usuarios de prueba:**
| Usuario | Email | Password | Rol |
|---------|-------|----------|-----|
| Juan Pérez | jperez@fosil.uy | Admin123! | infraestructura-admin |
| María González | mgonzalez@fosil.uy | DevOps123! | devops |
| Ana Rodríguez | arodriguez@fosil.uy | Viewer123! | viewer |

### Verificar Realm

```bash
# En Admin Console: http://<VPN_IP>:8080
# 1. Cambiar de realm "master" → "fosil" (dropdown arriba izquierda)
# 2. Ir a "Users" → deberías ver 3 usuarios
# 3. Ir a "Realm roles" → deberías ver 3 roles
```

## 🔒 VPN WireGuard

### VPN Site-to-Site (VM VPN ↔ VM Hardening)

**Objetivo:** Conectar VM VPN (10.0.1.30) con VM Hardening (10.0.1.40) mediante túnel encriptado.

**Estado:** ⚠️ Configurado pero con limitaciones de AWS networking (IPs virtuales 10.0.0.x bloqueadas a nivel hypervisor)

**Setup Manual (si necesario):**

```bash
# 1. En VM VPN (servidor)
ssh -i ~/.ssh/obligatorio-srd ubuntu@$(terraform output -raw vpn_public_ip)
cd /opt/fosil/VPN-IAM/scripts
chmod +x setup-wireguard.sh
sudo ./setup-wireguard.sh server
# Copiar clave PÚBLICA mostrada

# 2. En VM Hardening (cliente)
ssh -i ~/.ssh/obligatorio-srd ubuntu@$(terraform output -raw hardening_public_ip)
cd /opt/fosil/VPN-IAM/scripts
chmod +x setup-wireguard.sh
sudo ./setup-wireguard.sh client
# Copiar clave PÚBLICA mostrada

# 3. Intercambiar claves
# VM VPN: sudo nano /etc/wireguard/wg0.conf → reemplazar CLIENTE_PUBLIC_KEY_AQUI
# VM Hardening: sudo nano /etc/wireguard/wg0.conf → reemplazar SERVIDOR_PUBLIC_KEY_AQUI

# 4. Iniciar túnel
sudo systemctl start wg-quick@wg0
sudo systemctl enable wg-quick@wg0

# 5. Verificar
sudo wg show
```

### VPN Remote Access (Usuarios → Cloud)

**Descripción:** Generar configuraciones WireGuard personalizadas por rol de usuario Keycloak.

**Script:** `vpn-config-generator.sh` (110 líneas, minimalista)

**Uso:**

```bash
ssh -i ~/.ssh/obligatorio-srd ubuntu@$(terraform output -raw vpn_public_ip)
cd /opt/fosil/VPN-IAM/scripts
chmod +x vpn-config-generator.sh

# Generar config para usuario infraestructura-admin
./vpn-config-generator.sh jperez@fosil.uy

# Generar config para usuario devops
./vpn-config-generator.sh mgonzalez@fosil.uy

# Generar config para usuario viewer
./vpn-config-generator.sh arodriguez@fosil.uy
```

**Output:** `/opt/fosil/vpn-configs/<username>-<role>.conf`

**Políticas de Acceso por Rol:**

| Rol | AllowedIPs | Servicios Accesibles |
|-----|------------|----------------------|
| `infraestructura-admin` | `10.0.0.0/24, 10.0.1.0/24` | Todo: SSH, Wazuh, WAF, Keycloak, VPN |
| `devops` | `10.0.0.0/24, 10.0.1.20/32, 10.0.1.10/32` | SIEM (10.0.1.20) + WAF (10.0.1.10) |
| `viewer` | `10.0.0.0/24, 10.0.1.20/32` | Solo SIEM read-only (10.0.1.20) |

**Ejemplo de config generada:**

```ini
[Interface]
PrivateKey = <generada automáticamente>
Address = 10.0.0.10/24
DNS = 1.1.1.1

[Peer]
PublicKey = <clave pública servidor VPN>
Endpoint = <VPN_PUBLIC_IP>:51820
AllowedIPs = 10.0.0.0/24, 10.0.1.20/32  # Ejemplo rol viewer
PersistentKeepalive = 25
```

**Usar en cliente (laptop/desktop):**

```bash
# 1. Instalar WireGuard
# macOS: brew install wireguard-tools
# Linux: apt install wireguard
# Windows: https://wireguard.com/install/

# 2. Copiar config
scp -i ~/.ssh/obligatorio-srd ubuntu@<VPN_IP>:/opt/fosil/vpn-configs/jperez-infraestructura-admin.conf ~/

# 3. Conectar
sudo wg-quick up ~/jperez-infraestructura-admin.conf

# 4. Verificar conectividad
ping 10.0.1.20  # Wazuh
ping 10.0.1.10  # WAF

# 5. Desconectar
sudo wg-quick down ~/jperez-infraestructura-admin.conf
```

## 🔍 IAM Behavioral Analytics (Caso de Uso 4)

**Objetivo:** Detectar anomalías en autenticación mediante event logging de Keycloak → Wazuh.

**Reglas Wazuh:** 100040-100043 (ya desplegadas automáticamente)

**Configuración Event Logging (Pendiente):**

```bash
# 1. Habilitar event logging en Keycloak
# Admin Console → Realm settings → Events → Save Events: ON
# Event Listeners: agregar "jboss-logging"

# 2. Configurar Wazuh agent para leer logs Keycloak
ssh -i ~/.ssh/obligatorio-srd ubuntu@$(terraform output -raw vpn_public_ip)
sudo nano /var/ossec/etc/ossec.conf

# Agregar:
# <localfile>
#   <log_format>syslog</log_format>
#   <location>/opt/keycloak/data/log/keycloak.log</location>
# </localfile>

sudo systemctl restart wazuh-agent
```

**Testing:**

```bash
# 1. Brute force Keycloak
# Ir a: http://<VPN_IP>:8080/realms/fosil/account
# Intentar login con jperez@fosil.uy y password incorrecto 6 veces

# 2. Ver alerta en Wazuh Dashboard
# rule.id: 100041 (Brute force Keycloak)
```

## 🔧 Troubleshooting

### Keycloak no carga UI

```bash
# Verificar servicio
sudo systemctl status keycloak
sudo journalctl -u keycloak -f

# Verificar que esté escuchando en puerto 8080
sudo netstat -tlnp | grep 8080

# Reiniciar
sudo systemctl restart keycloak
```

### Realm "fosil" no existe

```bash
# Ejecutar script de creación
cd /opt/fosil/VPN-IAM/scripts
sudo ./create-realm.sh

# Verificar en Admin Console
```

### WireGuard no conecta

```bash
# Verificar interfaz
sudo wg show
sudo ip a | grep wg0

# Ver logs
sudo journalctl -u wg-quick@wg0 -f

# Verificar iptables/firewall
sudo iptables -L -v -n
```

## 📁 Archivos de Configuración

**Keycloak:**
- Config: `/opt/keycloak/conf/keycloak.conf`
- Logs: `/opt/keycloak/data/log/keycloak.log`
- Database: PostgreSQL `keycloak` DB

**WireGuard:**
- Config servidor: `/etc/wireguard/wg0.conf`
- Claves: `/etc/wireguard/private.key`, `/etc/wireguard/public.key`

**Scripts:**
- `install-keycloak.sh`: Instalación Keycloak (ya ejecutado en deployment)
- `create-realm.sh`: Crear realm "fosil" con usuarios/roles
- `setup-wireguard.sh`: Configurar VPN site-to-site
- `vpn-config-generator.sh`: Generar configs VPN por rol

## 📝 Referencias

- [Keycloak Documentation](https://www.keycloak.org/documentation)
- [WireGuard Quick Start](https://www.wireguard.com/quickstart/)
- [OAuth2/OIDC](https://oauth.net/2/)
