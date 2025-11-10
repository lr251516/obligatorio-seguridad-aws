#!/bin/bash
# Genera config WireGuard según rol de Keycloak
# Uso: ./vpn-config-generator.sh <email>

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
VPN_SERVER_PUBLIC_IP="${VPN_SERVER_PUBLIC_IP:-$(curl -s http://169.254.169.254/latest/meta-data/public-ipv4)}"
VPN_SERVER_PUBLIC_KEY="${VPN_SERVER_PUBLIC_KEY:-$(sudo cat /etc/wireguard/public.key 2>/dev/null)}"

if [ -z "$VPN_SERVER_PUBLIC_IP" ] || [ -z "$VPN_SERVER_PUBLIC_KEY" ]; then
    echo "ERROR: Configurar VPN_SERVER_PUBLIC_IP y VPN_SERVER_PUBLIC_KEY"
    exit 1
fi

# Obtener token de Keycloak
TOKEN=$(curl -s -X POST "${KEYCLOAK_URL}/realms/master/protocol/openid-connect/token" \
    -d "username=admin" \
    -d "password=admin" \
    -d "grant_type=password" \
    -d "client_id=admin-cli" | jq -r '.access_token')

if [ "$TOKEN" = "null" ]; then
    echo "ERROR: No se pudo autenticar en Keycloak"
    exit 1
fi

# Buscar usuario y obtener rol
USER_ID=$(curl -s "${KEYCLOAK_URL}/admin/realms/${REALM}/users?email=${USER_EMAIL}" \
    -H "Authorization: Bearer ${TOKEN}" | jq -r '.[0].id')

if [ "$USER_ID" = "null" ]; then
    echo "ERROR: Usuario $USER_EMAIL no encontrado"
    exit 1
fi

USER_ROLE=$(curl -s "${KEYCLOAK_URL}/admin/realms/${REALM}/users/${USER_ID}/role-mappings/realm" \
    -H "Authorization: Bearer ${TOKEN}" | \
    jq -r '.[].name' | grep -E '^(infraestructura-admin|devops|viewer)$' | head -n1)

if [ -z "$USER_ROLE" ]; then
    USER_ROLE="viewer"
fi

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
Address = ${CLIENT_VPN_IP}/24
PrivateKey = ${PRIVATE_KEY}
DNS = 10.0.1.20

[Peer]
PublicKey = ${VPN_SERVER_PUBLIC_KEY}
AllowedIPs = ${ALLOWED_IPS}
Endpoint = ${VPN_SERVER_PUBLIC_IP}:51820
PersistentKeepalive = 25
EOF

# Agregar peer al servidor
if [ -f "/etc/wireguard/wg0.conf" ]; then
    sudo wg set wg0 peer "$PUBLIC_KEY" allowed-ips "$CLIENT_VPN_IP/32" 2>/dev/null || true
fi

echo "✅ Config generada: $CONFIG_FILE"
echo "   Usuario: $USER_EMAIL"
echo "   Rol: $USER_ROLE"
echo "   IP VPN: $CLIENT_VPN_IP"
