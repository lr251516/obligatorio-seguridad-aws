# VPN + IAM

## Componentes

- **WireGuard VPN**: Site-to-site (Datacenter↔Cloud) + Remote Access (Usuarios→Cloud)
- **Keycloak IAM**: OAuth2/OIDC + Roles + Event logging → Wazuh

## Instalación Rápida

### 1. Keycloak + Realm

```bash
ssh ubuntu@$(terraform output -raw vpn_public_ip)
cd /opt/fosil/VPN-IAM/scripts
sudo ./install-keycloak.sh
sudo ./create-realm.sh
```

**Usuarios creados:**
- jperez@fosil.uy / Admin123! (infraestructura-admin)
- mgonzalez@fosil.uy / DevOps123! (devops)
- arodriguez@fosil.uy / Viewer123! (viewer)

### 2. VPN Site-to-Site

```bash
# Servidor (VM VPN)
ssh ubuntu@$(terraform output -raw vpn_public_ip)
sudo ./setup-wireguard.sh server

# Cliente (VM Hardening)
ssh ubuntu@$(terraform output -raw hardening_public_ip)
sudo ./setup-wireguard.sh client

# Intercambiar claves públicas y iniciar
sudo systemctl start wg-quick@wg0
```

### 3. VPN Remote Access

```bash
# Generar config para usuario
./vpn-config-generator.sh jperez@fosil.uy
# Output: /opt/fosil/vpn-configs/jperez-infraestructura-admin.conf
```

## Políticas por Rol

| Rol | AllowedIPs | Acceso |
|-----|------------|--------|
| infraestructura-admin | 10.0.1.0/24 | Full (SSH, Admin APIs) |
| devops | 10.0.1.20/32, 10.0.1.10/32 | Wazuh + WAF |
| viewer | 10.0.1.20/32 | Solo Wazuh |

## Analítica IAM → SIEM

Keycloak events (LOGIN, LOGIN_ERROR) → Wazuh rules 100040-100044

Ver: [SIEM/scripts/wazuh-custom-rules.xml](../SIEM/scripts/wazuh-custom-rules.xml)
