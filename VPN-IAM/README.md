# VPN + IAM

Infraestructura de conectividad segura y gestión de identidad centralizada.

---

## 🎯 Arquitectura

```
Internet
   │
   ├─── VPN Site-to-Site (IPSec)
   │    └─ Datacenter Local ↔ AWS VPC
   │
   ├─── VPN Remote Access (WireGuard + MFA)
   │    └─ Usuarios con políticas por rol IAM
   │
   └─── IAM (Keycloak OAuth2/OIDC)
        └─ Identity Provider + TOTP MFA
```

**Componentes:**
- **Keycloak 23.0.0**: Identity Provider con OAuth2/OIDC
- **IPSec (strongSwan IKEv2)**: Túnel site-to-site datacenter ↔ cloud
- **WireGuard**: VPN remote access con políticas granulares por rol
- **PostgreSQL**: Backend Keycloak

**IP VM:** `10.0.1.30` (subnet privada), puerto `8080` (Keycloak HTTP)

---

## 1. Keycloak IAM

### Acceso

```
URL: http://<VPN_PUBLIC_IP>:8080
Usuario: admin
Password: admin
```

⚠️ **Proyecto académico:** HTTP sin TLS, contraseñas hardcodeadas.

### Realm "fosil" (Automático)

El realm se crea automáticamente en deployment. **No requiere pasos manuales.**

**Incluye:**
- **3 usuarios** con MFA TOTP obligatorio
- **3 roles** para políticas VPN y Grafana
- **1 cliente OAuth2** para Grafana

| Email | Password | Rol | VPN Access |
|-------|----------|-----|------------|
| jperez@fosil.uy | Admin123! | infraestructura-admin | Full VPC (10.0.1.0/24) |
| mgonzalez@fosil.uy | DevOps123! | devops | SIEM + WAF (10.0.1.20, 10.0.1.10) |
| arodriguez@fosil.uy | Viewer123! | viewer | Solo SIEM (10.0.1.20) |

**Verificar realm creado:**
```bash
curl -s http://<VPN_IP>:8080/realms/fosil | jq .realm
# Esperado: "fosil"
```

---

## 2. VPN Site-to-Site (IPSec)

Túnel IKEv2 entre datacenter local y AWS VPC.

**Topología:**
```
Datacenter Local          AWS VPC
10.100.0.0/24            10.0.1.0/24
(Multipass VM)     <-->  (VPN VM)
                IPSec
```

### Setup Datacenter

```bash
# 1. Crear VM local (Multipass en Mac)
multipass launch --name datacenter --cpus 1 --memory 1G --disk 5G
multipass shell datacenter

# 2. Configurar IPSec
git clone https://github.com/lr251516/obligatorio-seguridad-aws.git
cd obligatorio-seguridad-aws/VPN-IAM/scripts
chmod +x setup-ipsec-datacenter.sh
sudo ./setup-ipsec-datacenter.sh
# Ingresar: IP pública AWS + PSK
```

### Setup AWS

```bash
ssh -i ~/.ssh/obligatorio-srd ubuntu@<VPN_IP>
cd /opt/fosil/VPN-IAM/scripts
sudo ./setup-ipsec-aws.sh
# Ingresar: IP pública local + mismo PSK
```

### Verificar

```bash
# Desde Multipass VM
sudo ipsec status
# Esperado: ESTABLISHED

# Test conectividad
ping 10.0.1.20  # Wazuh
ping 10.0.1.10  # WAF
```

**Características:**
- IKEv2 con AES_CBC_256/HMAC_SHA2_256_128
- Perfect Forward Secrecy (PFS)
- PSK authentication

---

## 3. VPN Remote Access (WireGuard + MFA)

### Setup Servidor

```bash
ssh -i ~/.ssh/obligatorio-srd ubuntu@<VPN_IP>
cd /opt/fosil/VPN-IAM/scripts
sudo ./setup-vpn-server.sh
```

**Automático:** Genera claves, configura interfaz `wg0`, levanta servicio.

### Generar Config Usuario (con MFA)

```bash
# En VM VPN
export VPN_SERVER_PUBLIC_IP=$(curl -s http://169.254.169.254/latest/meta-data/public-ipv4)
export VPN_SERVER_PUBLIC_KEY=$(sudo cat /etc/wireguard/public.key)

# Ejecutar script (requiere MFA)
./vpn-config-generator.sh jperez@fosil.uy
```

**El script solicita:**
1. **Password de Keycloak:** `Admin123!`
2. **OTP Code (6 dígitos):** Código de Google Authenticator

**Output:** `/opt/fosil/vpn-configs/jperez-infraestructura-admin.conf`

**Políticas por rol (AllowedIPs automáticos):**
- `infraestructura-admin` → `10.0.1.0/24` (todas las VMs)
- `devops` → `10.0.1.20/32, 10.0.1.10/32` (SIEM + WAF)
- `viewer` → `10.0.1.20/32` (solo SIEM)

### Conectar desde Cliente

```bash
# Copiar config a máquina local
scp -i ~/.ssh/obligatorio-srd ubuntu@<VPN_IP>:/opt/fosil/vpn-configs/jperez-*.conf ~/

# Conectar
sudo wg-quick up ~/jperez-infraestructura-admin.conf

# Verificar
ping 10.0.1.20  # Wazuh (accesible para todos los roles)

# Desconectar
sudo wg-quick down ~/jperez-infraestructura-admin.conf
```

---

## 4. Multi-Factor Authentication (MFA)

### Implementación de Doble Capa

**Capa 1: MFA en Provisioning (TOTP)**

Antes de generar config VPN, el usuario autentica con Keycloak:

| Factor | Tecnología | Propósito |
|--------|------------|-----------|
| Conocimiento | Password de Keycloak | Verifica identidad |
| Posesión | OTP (Google Authenticator) | Segundo factor temporal |

**Características:**
- ✅ OTP **obligatorio** - No permite omitir
- ✅ Auto-configuración: `requiredActions=["CONFIGURE_TOTP"]` en primer login
- ✅ Keycloak valida antes de permitir generación de config VPN

**Capa 2: MFA en Conexión (Criptográfico)**

Una vez provisionado, WireGuard usa autenticación criptográfica:

| Factor | Tecnología |
|--------|------------|
| Posesión | Clave privada Curve25519 (256-bit) |
| Conocimiento | Archivo .conf protegido |

**Ventajas:**
- ✅ Imposible phishing (no hay código de 6 dígitos en conexión)
- ✅ Perfect Forward Secrecy (PFS)
- ✅ Zero Trust (políticas granulares por identidad)

### Configuración OTP (Primera Vez)

**Automático al primer login en Grafana:**

1. Login con `jperez@fosil.uy` / `Admin123!`
2. Keycloak fuerza configuración OTP (pantalla con QR code)
3. Escanear QR con Google Authenticator
4. Ingresar código de 6 dígitos para verificar
5. ✅ OTP configurado

**Uso posterior:** Cada vez que el script VPN pida OTP, usar código de Google Authenticator.

---

## 5. Integración OAuth2 con Grafana

Grafana usa Keycloak para autenticación centralizada.

**Acceso:**
```
URL: http://<GRAFANA_IP>:3000
Método: Click "Sign in with Keycloak"
```

**Mapeo automático de roles:**

| Rol Keycloak | Rol Grafana | Permisos |
|--------------|-------------|----------|
| infraestructura-admin | Admin | Full access (users, settings) |
| devops | Editor | Crear/editar dashboards |
| viewer | Viewer | Solo lectura |

**Configuración automática:** El deployment configura cliente OAuth2 `grafana-oauth` con secret `grafana-secret-2024`.

---

## 6. IAM Behavioral Analytics

Keycloak genera logs de autenticación procesados por Wazuh SIEM:

**Reglas custom:**
- `100040`: Login fallido (level 5)
- `100041`: Brute force - 5+ intentos en 300s (level 10)
- `100042`: Login desde IP externa a VPC (level 8)
- `100043`: Login fuera de horario laboral (level 7)

**Archivos:**
- Logs: `/opt/keycloak/data/log/keycloak.log` (formato JSON)
- Reglas: `/var/ossec/etc/rules/local_rules.xml` (en SIEM VM)

---

## 🧪 Testing Rápido

```bash
# 1. Verificar realm Keycloak
curl -s http://<VPN_IP>:8080/realms/fosil | jq .realm

# 2. Túnel IPSec (desde Multipass VM)
sudo ipsec status
ping -c 3 10.0.1.20

# 3. WireGuard server
ssh ubuntu@<VPN_IP> "sudo wg show"

# 4. Generar config VPN con MFA
./vpn-config-generator.sh jperez@fosil.uy
# Ingresar: Password + OTP

# 5. Verificar AllowedIPs en config
grep "AllowedIPs" /opt/fosil/vpn-configs/jperez-*.conf
# Esperado: 10.0.1.0/24 (infraestructura-admin)
```

---

## 📁 Archivos Clave

```bash
# Keycloak
/opt/keycloak/conf/keycloak.conf          # Config principal
/opt/keycloak/data/log/keycloak.log       # Logs JSON
sudo systemctl status keycloak            # Service status

# WireGuard
/etc/wireguard/wg0.conf                   # Server config
/etc/wireguard/private.key                # Server private key
/etc/wireguard/public.key                 # Server public key
sudo wg show                              # Active connections

# IPSec
/etc/ipsec.conf                           # IPSec config
/etc/ipsec.secrets                        # PSK
sudo ipsec status                         # Tunnel status
```

---

**Documentación:** [README principal](../README.md) | [SIEM](../SIEM/README.md) | [WAF](../WAF/README.md) | [Hardening](../Hardening/README.md)
