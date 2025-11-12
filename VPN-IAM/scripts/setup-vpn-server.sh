#!/bin/bash
# Configurar WireGuard como servidor VPN para acceso remoto de administradores

set -e

[ "$EUID" -ne 0 ] && { echo "[ERROR] Ejecutar como root"; exit 1; }

# Verificar que WireGuard esté instalado
if ! command -v wg &> /dev/null; then
    echo "[+] Instalando WireGuard..."
    apt update
    apt install -y wireguard wireguard-tools resolvconf
fi

# Generar claves si no existen
if [ ! -f /etc/wireguard/private.key ]; then
    echo "[+] Generando par de claves..."
    wg genkey | tee /etc/wireguard/private.key | wg pubkey > /etc/wireguard/public.key
    chmod 600 /etc/wireguard/private.key
fi

PRIVATE_KEY=$(cat /etc/wireguard/private.key)
PUBLIC_KEY=$(cat /etc/wireguard/public.key)

# Obtener IP pública
PUBLIC_IP=$(curl -s http://169.254.169.254/latest/meta-data/public-ipv4)
PRIVATE_IP=$(ip -4 addr show scope global | grep inet | awk '{print $2}' | cut -d/ -f1 | head -n1)

echo ""
echo " Información del Servidor VPN"
echo ""
echo "  IP Pública:  $PUBLIC_IP"
echo "  IP Privada:  $PRIVATE_IP"
echo "  Puerto VPN:  51820"
echo "  Red VPN:     10.0.0.0/24"
echo ""
echo "  Clave Pública del Servidor:"
echo "  $PUBLIC_KEY"
echo ""
echo ""

# Interfaz de red principal 
IFACE=$(ip route | grep default | awk '{print $5}' | head -n1)
echo "[+] Interfaz de red detectada: $IFACE"
echo ""

# Crear configuración base del servidor
echo "[+] Creando configuración del servidor VPN..."
cat > /etc/wireguard/wg0.conf <<EOF
[Interface]
# Dirección IP del servidor en la red VPN
Address = 10.0.0.1/24

# Puerto de escucha
ListenPort = 51820

# Clave privada del servidor
PrivateKey = $PRIVATE_KEY

# Habilitar IP forwarding y NAT
PostUp = sysctl -w net.ipv4.ip_forward=1
PostUp = iptables -A FORWARD -i wg0 -j ACCEPT
PostUp = iptables -A FORWARD -o wg0 -j ACCEPT
PostUp = iptables -t nat -A POSTROUTING -o $IFACE -j MASQUERADE
PostUp = iptables -A INPUT -p udp --dport 51820 -j ACCEPT

# Limpiar reglas al detener
PostDown = iptables -D FORWARD -i wg0 -j ACCEPT
PostDown = iptables -D FORWARD -o wg0 -j ACCEPT
PostDown = iptables -t nat -D POSTROUTING -o $IFACE -j MASQUERADE
PostDown = iptables -D INPUT -p udp --dport 51820 -j ACCEPT

# Los peers se agregarán automáticamente con vpn-config-generator.sh
EOF

chmod 600 /etc/wireguard/wg0.conf

# Configurar IP forwarding permanente
echo "[+] Configurando IP forwarding permanente..."
if ! grep -q "net.ipv4.ip_forward=1" /etc/sysctl.conf; then
    echo "net.ipv4.ip_forward=1" >> /etc/sysctl.conf
fi
sysctl -p > /dev/null 2>&1

# Habilitar servicio
echo "[+] Habilitando servicio WireGuard..."
systemctl enable wg-quick@wg0

# Verificar si ya está corriendo
if systemctl is-active --quiet wg-quick@wg0; then
    echo "[+] WireGuard ya está corriendo, reiniciando..."
    systemctl restart wg-quick@wg0
else
    echo "[+] Iniciando WireGuard..."
    systemctl start wg-quick@wg0
fi

# Verificar estado
sleep 2
if systemctl is-active --quiet wg-quick@wg0; then
    echo ""
    echo "[OK] Servidor VPN configurado exitosamente!"
    echo ""
    echo "📊 Estado del Servidor:"
    echo ""
    wg show
    echo ""
else
    echo ""
    echo "[ERROR] Error: WireGuard no pudo iniciarse"
    echo "   Verificar logs: journalctl -u wg-quick@wg0 -n 50"
    exit 1
fi

# Guardar información para referencia
cat > /opt/fosil/vpn-server-info.txt <<INFO
WireGuard VPN Server - Fósil Energías Renovables
=================================================

Configurado: $(date)

IP Pública:   $PUBLIC_IP
IP Privada:   $PRIVATE_IP
Puerto:       51820
Red VPN:      10.0.0.0/24
Interfaz:     $IFACE

Clave Pública del Servidor:
$PUBLIC_KEY

Archivos de configuración:
- /etc/wireguard/wg0.conf
- /etc/wireguard/private.key
- /etc/wireguard/public.key

Próximos pasos:
1. Crear realm 'fosil' en Keycloak: /opt/fosil/VPN-IAM/scripts/create-realm.sh
2. Generar configs de clientes: ./vpn-config-generator.sh <email>

Variables de entorno para vpn-config-generator.sh:
export VPN_SERVER_PUBLIC_IP=$PUBLIC_IP
export VPN_SERVER_PUBLIC_KEY=$PUBLIC_KEY
INFO

chmod 644 /opt/fosil/vpn-server-info.txt

echo ""
echo "   Información guardada en: /opt/fosil/vpn-server-info.txt"
echo ""
echo "   Próximos Pasos:"
echo ""
echo "  1. Verificar que Keycloak esté corriendo:"
echo "     systemctl status keycloak"
echo ""
echo "  2. Crear realm 'fosil' (si no existe):"
echo "     cd /opt/fosil/VPN-IAM/scripts"
echo "     sudo ./create-realm.sh"
echo ""
echo "  3. Configurar variables de entorno:"
echo "     export VPN_SERVER_PUBLIC_IP=$PUBLIC_IP"
echo "     export VPN_SERVER_PUBLIC_KEY=$PUBLIC_KEY"
echo ""
echo "  4. Generar config para usuario (ejemplo):"
echo "     ./vpn-config-generator.sh jperez@fosil.uy"
echo ""
echo "  5. Ver clientes conectados:"
echo "     sudo wg show"
echo ""
