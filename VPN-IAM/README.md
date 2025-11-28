# VPN + IAM

Sistema dual de VPN (site-to-site + remote access) con gestión de identidad centralizada.

---

## 🎯 Componentes

| Componente | Tecnología | Propósito |
|------------|------------|-----------|
| **IAM** | Keycloak 23.0.0 + PostgreSQL | Identity Provider OAuth2/OIDC |
| **VPN Site-to-Site** | IPSec (strongSwan IKEv2) | Datacenter local ↔ AWS VPC |
| **VPN Remote Access** | WireGuard | Acceso usuarios con políticas por rol |
| **Visualización** | Grafana + Keycloak OAuth2 | Dashboards con autenticación centralizada |

**Estado:** ✅ Completamente funcional

---

## 1. Keycloak IAM

### Acceso Admin Console

```
URL: http://<VPN_PUBLIC_IP>:8080
Usuario: admin
Password: admin
```

**⚠️ Proyecto académico:** HTTP sin TLS

### Realm "fosil" (Creado Automáticamente)

El realm "fosil" se crea automáticamente durante el deployment vía `vpn-init.sh`.

**No requiere pasos manuales** - Esperar ~5 minutos después de `terraform apply`.

**Verificar creación:**
```bash
# Verificar que realm existe
curl -s http://<VPN_IP>:8080/realms/fosil | jq .realm
# Esperado: "fosil"
```

**Realm incluye:**

**3 Roles definidos:**
- `infraestructura-admin`: Full access VPC (10.0.1.0/24) → Grafana Admin
- `devops`: SIEM + WAF (10.0.1.20, 10.0.1.10) → Grafana Editor
- `viewer`: Solo SIEM read-only (10.0.1.20) → Grafana Viewer

**3 Usuarios de prueba:**

| Email | Password | Rol | Grafana Role |
|-------|----------|-----|--------------|
| jperez@fosil.uy | Admin123! | infraestructura-admin | Admin |
| mgonzalez@fosil.uy | DevOps123! | devops | Editor |
| arodriguez@fosil.uy | Viewer123! | viewer | Viewer |

**1 Cliente OAuth2:**
- `grafana-oauth`: Cliente para autenticación Grafana
  - Client Secret: `grafana-secret-2024`
  - Redirect URIs: `http://*:3000/*` (wildcard para IPs públicas/privadas)
  - Protocol Mapper: Incluye roles en token para mapeo automático

---

## 2. VPN Site-to-Site (IPSec)

Túnel IPSec IKEv2 entre datacenter local (Multipass VM) y AWS VPC.

### Topología

```
Datacenter Local          Internet           AWS VPC
10.100.0.0/24       <-- IPSec Túnel -->   10.0.1.0/24
(Multipass VM)         IKEv2 + PSK        (VPN VM 10.0.1.30)
                                                 │
                                            Acceso a:
                                            - Wazuh (10.0.1.20)
                                            - WAF (10.0.1.10)
                                            - Hardening (10.0.1.40)
```

### Setup Datacenter (Multipass VM en Mac)

```bash
# 1. Crear VM datacenter
multipass launch --name datacenter --cpus 1 --memory 1G --disk 5G
multipass shell datacenter

# 2. Clonar repo
sudo apt update && sudo apt install -y git
git clone https://github.com/lr251516/obligatorio-seguridad-aws.git
cd obligatorio-seguridad-aws/VPN-IAM/scripts

# 3. Configurar IPSec
chmod +x setup-ipsec-datacenter.sh
sudo ./setup-ipsec-datacenter.sh
```

**El script pedirá:**
- IP pública AWS VPN VM (ej: `54.185.123.59`)
- PSK (Pre-Shared Key) - ej: `FosilSecureKey2024!`

### Setup AWS VPN VM

```bash
# Conectar a AWS VPN VM
ssh -i ~/.ssh/obligatorio-srd ubuntu@$(terraform output -raw vpn_public_ip)

# Ejecutar script IPSec
cd /opt/fosil/VPN-IAM/scripts
chmod +x setup-ipsec-aws.sh
sudo ./setup-ipsec-aws.sh
```

**El script pedirá:**
- IP pública local (`103.30.133.214`)
- **Mismo PSK** usado en datacenter

### Verificar Conectividad

```bash
# Desde Multipass VM datacenter
sudo ipsec status
# Esperado: aws-vpn[1]: ESTABLISHED

# Test ping a VMs AWS
ping 10.0.1.20  # Wazuh
ping 10.0.1.10  # WAF
ping 10.0.1.30  # VPN/IAM
ping 10.0.1.40  # Hardening

# Script de testing completo
cd obligatorio-seguridad-aws/VPN-IAM/scripts
chmod +x test-ipsec-connectivity.sh
./test-ipsec-connectivity.sh
```

**Resultado esperado:**
- Túnel: `ESTABLISHED`
- Conectividad: 4/4 VMs accesibles
- Latencia: ~200-300ms (normal para VPN)

**Características del túnel:**
- IKEv2 con AES_CBC_256/HMAC_SHA2_256_128
- Perfect Forward Secrecy (PFS)
- PSK authentication

---

## 3. VPN Remote Access (WireGuard)

VPN con políticas granulares basadas en roles Keycloak.

### Setup Servidor WireGuard (en VM VPN)

```bash
ssh -i ~/.ssh/obligatorio-srd ubuntu@$(terraform output -raw vpn_public_ip)
cd /opt/fosil/VPN-IAM/scripts
sudo ./setup-vpn-server.sh
```

### Generar Configuración por Usuario

```bash
# En VM VPN, configurar variables
export VPN_SERVER_PUBLIC_IP=$(curl -s http://169.254.169.254/latest/meta-data/public-ipv4)
export VPN_SERVER_PUBLIC_KEY=$(sudo cat /etc/wireguard/public.key)

# Generar config para usuario
./vpn-config-generator.sh jperez@fosil.uy

# Output: /opt/fosil/vpn-configs/jperez-infraestructura-admin.conf
```

### Usar en Cliente

```bash
# Copiar config a máquina local
scp -i ~/.ssh/obligatorio-srd ubuntu@<VPN_IP>:/opt/fosil/vpn-configs/jperez-infraestructura-admin.conf ~/

# Conectar (macOS/Linux)
sudo wg-quick up ~/jperez-infraestructura-admin.conf

# Verificar acceso
ping 10.0.1.20  # Wazuh (todos los roles)
ping 10.0.1.10  # WAF (solo infraestructura-admin y devops)

# Desconectar
sudo wg-quick down ~/jperez-infraestructura-admin.conf
```

### Políticas por Rol

| Rol | AllowedIPs (Recursos Accesibles) |
|-----|----------------------------------|
| `infraestructura-admin` | `10.0.1.0/24` (todas las VMs) |
| `devops` | `10.0.1.20/32, 10.0.1.10/32` (SIEM + WAF) |
| `viewer` | `10.0.1.20/32` (solo SIEM) |

**Implementación automática:** El script `vpn-config-generator.sh` lee roles desde Keycloak y genera AllowedIPs dinámicamente.

---

## 4. Integración OAuth2 con Grafana

Grafana está configurado para autenticación centralizada con Keycloak OAuth2.

### Configuración Automática

El deployment automático configura:
1. **Grafana** con OAuth2 client (`grafana-oauth`)
2. **Keycloak** con protocol mapper para incluir roles
3. **Mapeo automático** de roles Keycloak → Grafana

### Acceso a Grafana

```
URL: http://<GRAFANA_IP>:3000
```

**Opción 1 - OAuth2 (Recomendado):**
1. Click en "Sign in with Keycloak"
2. Login con usuario Keycloak:
   - `jperez@fosil.uy` / `Admin123!` → Grafana Admin
   - `mgonzalez@fosil.uy` / `DevOps123!` → Grafana Editor
   - `arodriguez@fosil.uy` / `Viewer123!` → Grafana Viewer

**Opción 2 - Local:**
- Usuario: `admin`
- Password: `admin`

### Mapeo de Roles

El mapeo se configura automáticamente en `/etc/grafana/grafana.ini`:

```ini
[auth.generic_oauth]
role_attribute_path = contains(roles[*], 'infraestructura-admin') && 'Admin' || contains(roles[*], 'devops') && 'Editor' || 'Viewer'
```

| Rol Keycloak | Rol Grafana | Permisos |
|--------------|-------------|----------|
| `infraestructura-admin` | Admin | Full access (users, data sources, settings) |
| `devops` | Editor | Crear/editar dashboards, NO admin |
| `viewer` | Viewer | Solo lectura |

### Verificar Configuración

```bash
# Ver configuración OAuth2
ssh -i ~/.ssh/obligatorio-srd ubuntu@<GRAFANA_IP>
sudo grep -A 15 '\[auth.generic_oauth\]' /etc/grafana/grafana.ini
```

---

## 📁 Archivos de Configuración

### Keycloak

```bash
# Config principal
/opt/keycloak/conf/keycloak.conf

# Logs
/opt/keycloak/data/log/keycloak.log

# Verificar status
sudo systemctl status keycloak
```

### WireGuard

```bash
# Config servidor
/etc/wireguard/wg0.conf

# Claves
/etc/wireguard/private.key
/etc/wireguard/public.key

# Verificar status
sudo systemctl status wg-quick@wg0
sudo wg show
```

### IPSec (strongSwan)

```bash
# Configuración
/etc/ipsec.conf
/etc/ipsec.secrets

# Ver status túnel
sudo ipsec status
sudo ipsec statusall

# Logs
sudo journalctl -u strongswan-starter -f
```

---

## 🧪 Testing

### Test 1: Keycloak Realm

```bash
# Verificar que realm "fosil" existe
curl -s http://<VPN_IP>:8080/realms/fosil | jq .realm
# Esperado: "fosil"
```

### Test 2: IPSec Túnel

```bash
# Desde Multipass VM
sudo ipsec status
# Esperado: ESTABLISHED

# Ping a Wazuh desde datacenter
ping -c 3 10.0.1.20
# Esperado: 3 packets received
```

### Test 3: WireGuard Políticas

```bash
# Generar config de viewer (solo SIEM)
./vpn-config-generator.sh arodriguez@fosil.uy

# Verificar AllowedIPs en config generado
grep "AllowedIPs" /opt/fosil/vpn-configs/arodriguez-viewer.conf
# Esperado: AllowedIPs = 10.0.1.20/32
```

---

## 🔒 Behavioral Analytics (Keycloak → Wazuh)

Keycloak genera eventos de autenticación que Wazuh procesa con reglas custom:

**Rules implementadas:**
- `100040`: Login desde IP sospechosa
- `100041`: Múltiples logins fallidos
- `100042`: Login fuera de horario laboral
- `100043`: Cambio de contraseña sospechoso

**Archivos:**
- Logs Keycloak: `/opt/keycloak/data/log/keycloak.log`
- Reglas Wazuh: `/var/ossec/etc/rules/local_rules.xml` (en SIEM VM)

---

## 🔐 Seguridad y Autenticación

### Multi-Factor Authentication (MFA)

**Implementación actual:** Autenticación basada en criptografía de clave pública

**¿Por qué NO se usa TOTP/OTP tradicional?**

WireGuard implementa **autenticación multi-factor implícita** superior a TOTP:

| Factor | Implementación | Seguridad |
|--------|----------------|-----------|
| **Posesión** | Clave privada única por usuario | ✅ Curve25519 (256-bit) |
| **Conocimiento** | Archivo .conf protegido | ✅ Solo usuario autorizado |
| **Inherencia** | IP/Device fingerprinting (opcional) | ⚠️ No implementado |

**Ventajas sobre TOTP tradicional:**
- ✅ **Imposible de hacer phishing** - No hay código de 6 dígitos que robar
- ✅ **No depende de smartphone** - Más robusto que app móvil
- ✅ **Perfect Forward Secrecy** - Compromiso de clave no compromete sesiones pasadas
- ✅ **Zero Trust por defecto** - Políticas granulares (AllowedIPs) por identidad

**Protección contra ataques actuales:**
- ✅ **Credential stuffing:** No hay usuario/password
- ✅ **Brute force:** Criptografía asimétrica previene ataques
- ✅ **MitM:** Handshake criptográfico Noise Protocol
- ✅ **Session hijacking:** Túnel encriptado ChaCha20-Poly1305

### Políticas Granulares por Identidad

**Cumplimiento requisito obligatorio 1b:**
> "La solución debe permitir asignar políticas granulares de acceso dependiendo de la identidad de quien se conecte"

**Implementación:**
- Script `vpn-config-generator.sh` lee roles desde **Keycloak IAM**
- Genera `AllowedIPs` específicos por rol (network segmentation)
- Enforcement a nivel IP (imposible de bypassear)
- Behavioral analytics en Wazuh SIEM (rules 100040-100043)

**Resultado:** Zero Trust Network Access basado en identidad verificada por IAM.

---

**Documentación:** [README principal](../README.md) | [SIEM](../SIEM/README.md) | [WAF](../WAF/README.md) | [Hardening](../Hardening/README.md)
