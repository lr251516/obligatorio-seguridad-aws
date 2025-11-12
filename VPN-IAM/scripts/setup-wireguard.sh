#!/bin/bash
# Configuración WireGuard VPN site-to-site para AWS
# VM3 (VPN Server - 10.0.1.30) <---> VM4 (Hardening Client - 10.0.1.40)

set -e

ROLE=$1  # "server" o "client"

if [ -z "$ROLE" ]; then
    echo "Uso: $0 <server|client>"
    echo ""
    echo "Ejemplos:"
    echo "  VM3 (VPN/IAM):    $0 server"
    echo "  VM4 (Hardening):  $0 client"
    exit 1
fi

echo "================================================"
echo "  WireGuard VPN Setup - AWS EC2"
echo "  Role: $ROLE"
echo "================================================"
echo ""

# Instalar WireGuard
echo "[+] Instalando WireGuard..."
sudo apt update
sudo apt install -y wireguard wireguard-tools resolvconf

# Generar claves
echo "[+] Generando par de claves..."
wg genkey | sudo tee /etc/wireguard/private.key | wg pubkey | sudo tee /etc/wireguard/public.key
sudo chmod 600 /etc/wireguard/private.key

PRIVATE_KEY=$(sudo cat /etc/wireguard/private.key)
PUBLIC_KEY=$(sudo cat /etc/wireguard/public.key)

echo ""
echo "==================================="
echo "  CLAVES GENERADAS"
echo "==================================="
echo ""
echo "Clave PRIVADA (MANTENER SECRETA):"
echo "$PRIVATE_KEY"
echo ""
echo "Clave PÚBLICA (compartir con peer):"
echo "$PUBLIC_KEY"
echo ""
echo "==================================="
echo ""

# Obtener metadata de AWS
PRIVATE_IP=$(ec2-metadata --local-ipv4 | cut -d " " -f 2)
echo "[+] IP privada de esta instancia: $PRIVATE_IP"

# Configurar según rol
if [ "$ROLE" = "server" ]; then
    # ============================================
    # SERVIDOR: VM3 (VPN/IAM Server)
    # ============================================
    echo "[+] Configurando como SERVIDOR (VM3)..."
    echo ""
    
    if [ "$PRIVATE_IP" != "10.0.1.30" ]; then
        echo "[!] ADVERTENCIA: IP privada esperada 10.0.1.30, detectada: $PRIVATE_IP"
        echo "    Continuando de todas formas..."
    fi
    
    # Obtener IP pública del cliente (VM4)
    echo "Necesito la IP PÚBLICA del cliente (VM4 - Hardening)"
    echo "Obtenerla con: terraform output hardening_public_ip"
    echo "O desde AWS Console → EC2 → Hardening instance → Public IPv4"
    read -p "IP pública de VM4: " CLIENT_PUBLIC_IP
    
    if [ -z "$CLIENT_PUBLIC_IP" ]; then
        echo "[!] Error: IP pública del cliente requerida"
        exit 1
    fi
    
    sudo tee /etc/wireguard/wg0.conf > /dev/null <<EOF
[Interface]
# IP en el túnel VPN
Address = 10.0.0.1/24
# Puerto de escucha
ListenPort = 51820
# Clave privada
PrivateKey = $PRIVATE_KEY

# Habilitar IP forwarding y NAT (AWS usa ens5)
PostUp = sysctl -w net.ipv4.ip_forward=1
PostUp = iptables -A FORWARD -i wg0 -j ACCEPT
PostUp = iptables -A FORWARD -o wg0 -j ACCEPT
PostUp = iptables -t nat -A POSTROUTING -o ens5 -j MASQUERADE
PostUp = iptables -A INPUT -p udp --dport 51820 -j ACCEPT

PostDown = iptables -D FORWARD -i wg0 -j ACCEPT
PostDown = iptables -D FORWARD -o wg0 -j ACCEPT
PostDown = iptables -t nat -D POSTROUTING -o ens5 -j MASQUERADE
PostDown = iptables -D INPUT -p udp --dport 51820 -j ACCEPT

# Peer: VM4 (cliente)
[Peer]
# Clave pública del cliente - ACTUALIZAR CON LA CLAVE REAL
PublicKey = CLIENTE_PUBLIC_KEY_AQUI
# IP asignada al cliente en el túnel
AllowedIPs = 10.0.0.2/32
# IP pública del cliente (AWS Elastic IP)
Endpoint = ${CLIENT_PUBLIC_IP}:51820
# Mantener conexión viva
PersistentKeepalive = 25
EOF

    echo ""
    echo "==================================="
    echo "  CONFIGURACIÓN COMPLETADA"
    echo "==================================="
    echo ""
    echo "Archivo creado: /etc/wireguard/wg0.conf"
    echo ""
    echo "[WARN]  IMPORTANTE: Editar el archivo y reemplazar la clave pública del cliente"
    echo ""
    echo "1. Obtener clave pública del cliente (VM4)"
    echo "   SSH a VM4 y ejecutar: sudo cat /etc/wireguard/public.key"
    echo ""
    echo "2. Editar configuración:"
    echo "   sudo nano /etc/wireguard/wg0.conf"
    echo ""
    echo "3. Reemplazar 'CLIENTE_PUBLIC_KEY_AQUI' con la clave real"
    echo ""
    echo "4. Iniciar WireGuard:"
    echo "   sudo systemctl start wg-quick@wg0"
    echo "   sudo systemctl enable wg-quick@wg0"
    echo ""

elif [ "$ROLE" = "client" ]; then
    # ============================================
    # CLIENTE: VM4 (Hardening)
    # ============================================
    echo "[+] Configurando como CLIENTE (VM4)..."
    echo ""
    
    if [ "$PRIVATE_IP" != "10.0.1.40" ]; then
        echo "[!] ADVERTENCIA: IP privada esperada 10.0.1.40, detectada: $PRIVATE_IP"
        echo "    Continuando de todas formas..."
    fi
    
    # Obtener IP pública del servidor (VM3)
    echo "Necesito la IP PÚBLICA del servidor (VM3 - VPN/IAM)"
    echo "Obtenerla con: terraform output vpn_public_ip"
    echo "O desde AWS Console → EC2 → VPN-IAM instance → Public IPv4"
    read -p "IP pública de VM3: " SERVER_PUBLIC_IP
    
    if [ -z "$SERVER_PUBLIC_IP" ]; then
        echo "[!] Error: IP pública del servidor requerida"
        exit 1
    fi
    
    sudo tee /etc/wireguard/wg0.conf > /dev/null <<EOF
[Interface]
# IP en el túnel VPN
Address = 10.0.0.2/24
# Clave privada
PrivateKey = $PRIVATE_KEY

# Habilitar IP forwarding
PostUp = sysctl -w net.ipv4.ip_forward=1

# Peer: VM3 (servidor)
[Peer]
# Clave pública del servidor - ACTUALIZAR CON LA CLAVE REAL
PublicKey = SERVIDOR_PUBLIC_KEY_AQUI
# Redes accesibles a través del túnel:
# - 10.0.0.0/24: Red del túnel VPN
# - 10.0.1.0/24: Red interna AWS VPC (acceso a Wazuh, etc.)
AllowedIPs = 10.0.0.0/24, 10.0.1.0/24
# IP pública del servidor (AWS Elastic IP)
Endpoint = ${SERVER_PUBLIC_IP}:51820
# Mantener conexión viva
PersistentKeepalive = 25
EOF

    echo ""
    echo "==================================="
    echo "  CONFIGURACIÓN COMPLETADA"
    echo "==================================="
    echo ""
    echo "Archivo creado: /etc/wireguard/wg0.conf"
    echo ""
    echo "[WARN]  IMPORTANTE: Editar el archivo y reemplazar la clave pública del servidor"
    echo ""
    echo "1. Obtener clave pública del servidor (VM3)"
    echo "   SSH a VM3 y ejecutar: sudo cat /etc/wireguard/public.key"
    echo ""
    echo "2. Editar configuración:"
    echo "   sudo nano /etc/wireguard/wg0.conf"
    echo ""
    echo "3. Reemplazar 'SERVIDOR_PUBLIC_KEY_AQUI' con la clave real"
    echo ""
    echo "4. Iniciar WireGuard:"
    echo "   sudo systemctl start wg-quick@wg0"
    echo "   sudo systemctl enable wg-quick@wg0"
    echo ""

else
    echo "[!] Error: Role debe ser 'server' o 'client'"
    exit 1
fi

# Ajustar permisos
sudo chmod 600 /etc/wireguard/wg0.conf

# Configurar IP forwarding permanentemente
echo "[+] Configurando IP forwarding permanente..."
if ! grep -q "net.ipv4.ip_forward=1" /etc/sysctl.conf; then
    echo "net.ipv4.ip_forward=1" | sudo tee -a /etc/sysctl.conf
fi
sudo sysctl -p

# Habilitar servicio
sudo systemctl enable wg-quick@wg0

# Crear script de prueba
cat > /tmp/test-vpn.sh <<'EOF_TEST'
#!/bin/bash

echo "=========================================="
echo "  Test de Conectividad VPN WireGuard"
echo "=========================================="
echo ""

echo "[+] Estado de WireGuard:"
sudo wg show

echo ""
echo "[+] Rutas configuradas:"
ip route | grep -E "10\.0\.0\.|10\.0\.1\."

echo ""
echo "[+] Test de conectividad:"
echo ""

# Test túnel VPN
echo "  Test 1: Ping al peer en túnel VPN"
if ping -c 2 -W 2 10.0.0.1 &> /dev/null; then
    echo "    [✓] Servidor (10.0.0.1) alcanzable"
elif ping -c 2 -W 2 10.0.0.2 &> /dev/null; then
    echo "    [✓] Cliente (10.0.0.2) alcanzable"
else
    echo "    [✗] No hay conectividad en túnel VPN"
fi

echo ""
echo "  Test 2: Ping a Wazuh SIEM (10.0.1.20)"
if ping -c 2 -W 2 10.0.1.20 &> /dev/null; then
    echo "    [✓] Wazuh SIEM alcanzable"
else
    echo "    [✗] Wazuh SIEM no alcanzable"
fi

echo ""
echo "  Test 3: Ping a VPN/IAM (10.0.1.30)"
if ping -c 2 -W 2 10.0.1.30 &> /dev/null; then
    echo "    [✓] VPN/IAM alcanzable"
else
    echo "    [✗] VPN/IAM no alcanzable"
fi

echo ""
echo "  Test 4: Ping a WAF/Kong (10.0.1.10)"
if ping -c 2 -W 2 10.0.1.10 &> /dev/null; then
    echo "    [✓] WAF/Kong alcanzable"
else
    echo "    [✗] WAF/Kong no alcanzable"
fi

EOF_TEST

chmod +x /tmp/test-vpn.sh

# Guardar información
sudo tee /opt/fosil/wireguard-info.txt > /dev/null <<INFO
WireGuard Configuration
=======================

Role: $ROLE
Private IP: $PRIVATE_IP
Tunnel IP: $([ "$ROLE" = "server" ] && echo "10.0.0.1" || echo "10.0.0.2")

Public Key:
$PUBLIC_KEY

Configuration file: /etc/wireguard/wg0.conf
Test script: /tmp/test-vpn.sh

Configured: $(date)
INFO

echo "[✓] Configuración guardada en /opt/fosil/wireguard-info.txt"
echo ""