# VPN + IAM

WireGuard VPN + Keycloak IAM con políticas de acceso granulares basadas en roles.

## Componentes

- Keycloak 23.0.0 con PostgreSQL
- WireGuard para VPN site-to-site y remote access
- Deployment automatizado via `terraform/user-data/vpn-init.sh`

## Keycloak IAM

### Acceso

```bash
# URL: http://<VPN_PUBLIC_IP>:8080
# Usuario: admin
# Password: admin
```

### Realm "fosil"

Se crea automáticamente al deployar. Incluye:

**Roles:**
- `infraestructura-admin`: Acceso completo a VPC (10.0.1.0/24)
- `devops`: SIEM + WAF (10.0.1.20, 10.0.1.10)
- `viewer`: Solo SIEM (10.0.1.20)

**Usuarios de prueba:**
| Email | Password | Rol |
|-------|----------|-----|
| jperez@fosil.uy | Admin123! | infraestructura-admin |
| mgonzalez@fosil.uy | DevOps123! | devops |
| arodriguez@fosil.uy | Viewer123! | viewer |

## VPN Remote Access

### 1. Configurar Servidor VPN

```bash
ssh -i ~/.ssh/obligatorio-srd ubuntu@$(terraform output -raw vpn_public_ip)
cd /opt/fosil/VPN-IAM/scripts
sudo ./setup-vpn-server.sh
```

### 2. Generar Configuración por Usuario

```bash
# Configurar variables
export VPN_SERVER_PUBLIC_IP=$(curl -s http://169.254.169.254/latest/meta-data/public-ipv4)
export VPN_SERVER_PUBLIC_KEY=$(sudo cat /etc/wireguard/public.key)

# Generar config
./vpn-config-generator.sh jperez@fosil.uy
```

Output: `/opt/fosil/vpn-configs/jperez-infraestructura-admin.conf`

### 3. Usar en Cliente

```bash
# Copiar config
scp -i ~/.ssh/obligatorio-srd ubuntu@<VPN_IP>:/opt/fosil/vpn-configs/jperez-infraestructura-admin.conf ~/

# Conectar (macOS/Linux)
sudo wg-quick up ~/jperez-infraestructura-admin.conf

# Verificar
ping 10.0.1.20  # Wazuh
ping 10.0.1.10  # WAF

# Desconectar
sudo wg-quick down ~/jperez-infraestructura-admin.conf
```

**Políticas granulares por rol:**

| Rol | Acceso |
|-----|--------|
| `infraestructura-admin` | Todas las VMs (10.0.1.0/24) |
| `devops` | Solo SIEM + WAF |
| `viewer` | Solo SIEM |

## VPN Site-to-Site

Conecta VM VPN (10.0.1.30) ↔ VM Hardening (10.0.1.40) mediante túnel WireGuard.

**Limitación:** AWS bloquea IPs virtuales (10.0.0.x) a nivel hypervisor. El túnel funciona pero el routing entre VMs está limitado.

## IAM Behavioral Analytics

Reglas Wazuh 100040-100043 para detectar:
- Brute force en Keycloak
- Login desde IPs externas
- Login fuera de horario laboral

Event logging configurado automáticamente en realm "fosil".

## Archivos de Configuración

**Keycloak:**
- Config: `/opt/keycloak/conf/keycloak.conf`
- Logs: `/opt/keycloak/data/log/keycloak.log`

**WireGuard:**
- Config servidor: `/etc/wireguard/wg0.conf`
- Claves: `/etc/wireguard/private.key`, `/etc/wireguard/public.key`
