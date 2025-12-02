#!/bin/bash
# Genera config WireGuard según rol de Keycloak con MFA
# Uso: ./vpn-config-generator.sh <email>
# Requiere autenticación MFA (Password + OTP si está habilitado)

set -e

USER_EMAIL="$1"
KEYCLOAK_URL="${KEYCLOAK_URL:-http://localhost:8080}"
REALM="fosil"
OUTPUT_DIR="/opt/fosil/vpn-configs"

if [ -z "$USER_EMAIL" ]; then
    echo "Uso: $0 <email-usuario>"
    echo "Ejemplo: $0 jperez@fosil.uy"
    exit 1
fi

# Variables del servidor VPN
VPN_SERVER_PUBLIC_IP="${VPN_SERVER_PUBLIC_IP:-$(curl -s http://169.254.169.254/latest/meta-data/public-ipv4 2>/dev/null)}"
VPN_SERVER_PUBLIC_KEY="${VPN_SERVER_PUBLIC_KEY:-$(sudo cat /etc/wireguard/public.key 2>/dev/null)}"

if [ -z "$VPN_SERVER_PUBLIC_IP" ] || [ -z "$VPN_SERVER_PUBLIC_KEY" ]; then
    echo "ERROR: Configurar VPN_SERVER_PUBLIC_IP y VPN_SERVER_PUBLIC_KEY"
    exit 1
fi

# ============================================
# PASO 1: Autenticación MFA del usuario
# ============================================
echo "======================================"
echo "  Generador de Config VPN WireGuard  "
echo "  Usuario: $USER_EMAIL"
echo "======================================"
echo ""
echo "🔐 Autenticación MFA requerida"
echo ""

echo -n "Password: "
read -rs USER_PASSWORD
echo ""

if [ -z "$USER_PASSWORD" ]; then
    echo "❌ ERROR: Password requerido"
    exit 1
fi

echo -n "OTP Code (Enter para omitir si no está habilitado): "
read -r OTP_CODE
echo ""

# Autenticar usuario con Keycloak (password + OTP si está configurado)
echo "[+] Validando credenciales..."
AUTH_RESPONSE=$(curl -s -X POST "${KEYCLOAK_URL}/realms/${REALM}/protocol/openid-connect/token" \
    -d "username=${USER_EMAIL}" \
    -d "password=${USER_PASSWORD}" \
    -d "grant_type=password" \
    -d "client_id=account" \
    ${OTP_CODE:+-d "totp=${OTP_CODE}"})

USER_TOKEN=$(echo "$AUTH_RESPONSE" | jq -r '.access_token')

if [ "$USER_TOKEN" = "null" ] || [ -z "$USER_TOKEN" ]; then
    ERROR_MSG=$(echo "$AUTH_RESPONSE" | jq -r '.error_description // .error // "Autenticación fallida"')
    echo "❌ ERROR: $ERROR_MSG"
    echo ""
    echo "Posibles causas:"
    echo "  - Password incorrecto"
    echo "  - OTP code incorrecto o expirado (si está habilitado)"
    echo "  - Usuario no existe en realm 'fosil'"
    echo "  - Primera vez: requiere configurar OTP en Keycloak"
    exit 1
fi

echo "✅ Autenticación exitosa: $USER_EMAIL"
echo ""

# ============================================
# PASO 2: Obtener rol del usuario (usando admin)
# ============================================
echo "[+] Obteniendo rol de usuario..."

# Obtener token de admin para consultar roles
ADMIN_TOKEN=$(curl -s -X POST "${KEYCLOAK_URL}/realms/master/protocol/openid-connect/token" \
    -d "username=admin" \
    -d "password=admin" \
    -d "grant_type=password" \
    -d "client_id=admin-cli" | jq -r '.access_token')

if [ "$ADMIN_TOKEN" = "null" ]; then
    echo "ERROR: No se pudo autenticar admin en Keycloak"
    exit 1
fi

# Buscar usuario y obtener rol (usando token de admin)
USER_ID=$(curl -s "${KEYCLOAK_URL}/admin/realms/${REALM}/users?email=${USER_EMAIL}" \
    -H "Authorization: Bearer ${ADMIN_TOKEN}" | jq -r '.[0].id')

if [ "$USER_ID" = "null" ]; then
    echo "ERROR: Usuario $USER_EMAIL no encontrado"
    exit 1
fi

USER_ROLE=$(curl -s "${KEYCLOAK_URL}/admin/realms/${REALM}/users/${USER_ID}/role-mappings/realm" \
    -H "Authorization: Bearer ${ADMIN_TOKEN}" | \
    jq -r '.[].name' | grep -E '^(infraestructura-admin|devops|viewer)$' | head -n1)

if [ -z "$USER_ROLE" ]; then
    USER_ROLE="viewer"
fi

echo "✅ Rol asignado: $USER_ROLE"
echo ""

# AllowedIPs según rol
case "$USER_ROLE" in
    infraestructura-admin)
        ALLOWED_IPS="10.0.0.0/24, 10.0.1.0/24"
        ;;
    devops)
        ALLOWED_IPS="10.0.0.0/24, 10.0.1.20/32, 10.0.1.10/32"
        ;;
    viewer)
        ALLOWED_IPS="10.0.0.0/24, 10.0.1.20/32"
        ;;
    *)
        ALLOWED_IPS="10.0.0.0/24"
        ;;
esac

# Generar claves
PRIVATE_KEY=$(wg genkey)
PUBLIC_KEY=$(echo "$PRIVATE_KEY" | wg pubkey)

# Asignar IP (simple: usar últimos 3 dígitos del user_id como IP)
IP_SUFFIX=$((16#$(echo "$USER_ID" | tail -c 4) % 240 + 10))
CLIENT_VPN_IP="10.0.0.$IP_SUFFIX"

# Crear directorio
sudo mkdir -p "$OUTPUT_DIR"

# Nombre archivo
USERNAME=$(echo "$USER_EMAIL" | cut -d'@' -f1)
CONFIG_FILE="${OUTPUT_DIR}/${USERNAME}-${USER_ROLE}.conf"

# Generar config
cat > "$CONFIG_FILE" <<EOF
[Interface]
Address = ${CLIENT_VPN_IP}/32
PrivateKey = ${PRIVATE_KEY}

[Peer]
PublicKey = ${VPN_SERVER_PUBLIC_KEY}
AllowedIPs = ${ALLOWED_IPS}
Endpoint = ${VPN_SERVER_PUBLIC_IP}:51820
PersistentKeepalive = 25
EOF

# Agregar peer al servidor (si WireGuard está corriendo)
if systemctl is-active --quiet wg-quick@wg0 2>/dev/null; then
    echo "[+] Agregando peer al servidor VPN..."
    sudo wg set wg0 peer "$PUBLIC_KEY" allowed-ips "$CLIENT_VPN_IP/32"

    # Persistir configuración agregando peer al archivo
    if ! sudo grep -q "$PUBLIC_KEY" /etc/wireguard/wg0.conf; then
        echo "" | sudo tee -a /etc/wireguard/wg0.conf > /dev/null
        echo "# Cliente: $USER_EMAIL ($USER_ROLE)" | sudo tee -a /etc/wireguard/wg0.conf > /dev/null
        echo "[Peer]" | sudo tee -a /etc/wireguard/wg0.conf > /dev/null
        echo "PublicKey = $PUBLIC_KEY" | sudo tee -a /etc/wireguard/wg0.conf > /dev/null
        echo "AllowedIPs = $CLIENT_VPN_IP/32" | sudo tee -a /etc/wireguard/wg0.conf > /dev/null
    fi
else
    echo "[!] WireGuard no está corriendo. Configurar servidor primero:"
    echo "    sudo /opt/fosil/VPN-IAM/scripts/setup-vpn-server.sh"
fi

echo "=========================================="
echo "✅ Config VPN generada exitosamente"
echo "=========================================="
echo "Usuario:   $USER_EMAIL"
echo "Rol:       $USER_ROLE"
echo "IP VPN:    $CLIENT_VPN_IP"
echo "Archivo:   $CONFIG_FILE"
echo ""
echo "🔐 MFA validado: Password + OTP"
echo ""
echo "Para conectar:"
echo "  sudo wg-quick up $CONFIG_FILE"
