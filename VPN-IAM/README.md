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

## VPN Site-to-Site (IPSec)

Conecta datacenter local (Multipass VM) ↔ AWS VPC mediante túnel IPSec con strongSwan.

### Topología

```
Datacenter Local (Multipass)    Internet    AWS VPN VM (10.0.1.30)
10.100.0.0/24              <--IPSec Túnel-->    10.0.0.0/16
                                                      |
                                           Acceso a todas las VMs
```

### Setup en Multipass (Datacenter)

```bash
# 1. Instalar Multipass
brew install multipass

# 2. Crear VM datacenter
multipass launch --name datacenter --cpus 1 --memory 1G --disk 5G

# 3. SSH a la VM
multipass shell datacenter

# 4. Instalar git y clonar scripts
sudo apt update && sudo apt install -y git
git clone https://github.com/lr251516/obligatorio-seguridad-aws.git
cd obligatorio-seguridad-aws/VPN-IAM/scripts

# 5. Configurar IPSec
chmod +x setup-ipsec-datacenter.sh
sudo ./setup-ipsec-datacenter.sh
# Te pedirá: IP pública AWS VPN + PSK (ej: "FosilSecureKey2024!")
```

### Setup en AWS VPN VM

```bash
# 1. SSH a AWS VPN VM
ssh -i ~/.ssh/obligatorio-srd ubuntu@$(terraform output -raw vpn_public_ip)

# 2. Ejecutar script IPSec
cd /opt/fosil/VPN-IAM/scripts
chmod +x setup-ipsec-aws.sh
sudo ./setup-ipsec-aws.sh
# Te pedirá: IP pública de tu Mac + mismo PSK que usaste arriba
```

**IMPORTANTE:** Para obtener tu IP pública en Mac: `curl https://api.ipify.org`

### Testing de Conectividad

Desde Multipass VM:

```bash
# Verificar estado del túnel
sudo ipsec status
# Debe mostrar: ESTABLISHED

# Ping a VMs en AWS
ping 10.0.1.20  # Wazuh SIEM
ping 10.0.1.10  # WAF Kong
ping 10.0.1.30  # VPN/IAM
ping 10.0.1.40  # Hardening

# Script de testing completo
cd obligatorio-seguridad-aws/VPN-IAM/scripts
chmod +x test-ipsec-connectivity.sh
./test-ipsec-connectivity.sh
```

### Troubleshooting

Si el túnel no se establece:

```bash
# Ver logs en tiempo real
sudo journalctl -u strongswan-starter -f

# Reiniciar túnel
sudo ipsec restart

# Verificar configuración
sudo ipsec statusall

# Verificar IPs
ip addr show  # Debe tener 10.100.0.1 en datacenter
```

Si el ping falla pero túnel está ESTABLISHED:

1. **Security Group AWS:** Agregar regla ICMP desde tu IP pública
2. **Firewall Mac:** `sudo pfctl -d` (deshabilitar temporalmente)
3. **IP forwarding:** `sysctl net.ipv4.ip_forward` debe ser `1`

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
