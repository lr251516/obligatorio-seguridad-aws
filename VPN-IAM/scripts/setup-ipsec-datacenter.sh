#!/bin/bash
set -e

# IPSec Site-to-Site - Datacenter Side (Multipass VM)
# Conecta datacenter local con AWS VPC
# Usar strongSwan (IPSec IKEv2)

echo "========================================="
echo "IPSec Site-to-Site Setup - Datacenter"
echo "========================================="

# Verificar que se ejecute como root
if [ "$EUID" -ne 0 ]; then
    echo "ERROR: Este script debe ejecutarse como root (sudo)"
    exit 1
fi

# Variables - EDITAR ESTAS
read -p "IP pública de AWS VPN VM: " AWS_PUBLIC_IP
read -sp "PSK (Pre-Shared Key - debe ser igual en AWS): " PSK
echo ""

# Variables Datacenter (auto-detect)
DATACENTER_PRIVATE_IP=$(ip -4 addr show $(ip route | grep default | awk '{print $5}') | grep -oP '(?<=inet\s)\d+(\.\d+){3}' | head -1)

# Detectar IP pública del host (Mac con Multipass)
echo "Detectando IP pública..."
DATACENTER_PUBLIC_IP=$(curl -s https://api.ipify.org)

echo ""
echo "Configuración detectada:"
echo "  Datacenter Private IP: $DATACENTER_PRIVATE_IP"
echo "  Datacenter Public IP: $DATACENTER_PUBLIC_IP"
echo "  AWS Public IP: $AWS_PUBLIC_IP"
echo ""

# Redes
DATACENTER_NETWORK="10.100.0.0/24"  # Red del datacenter local
AWS_NETWORK="10.0.0.0/16"           # VPC AWS

# 1. Configurar red interna 10.100.0.0/24
echo "[1/7] Configurando red interna del datacenter..."
ip addr add 10.100.0.1/24 dev lo 2>/dev/null || true
ip link set lo up

# 2. Instalar strongSwan
echo "[2/7] Instalando strongSwan..."
apt-get update -qq
apt-get install -y strongswan strongswan-pki libcharon-extra-plugins

# 3. Habilitar IP forwarding
echo "[3/7] Habilitando IP forwarding..."
sysctl -w net.ipv4.ip_forward=1
sysctl -w net.ipv4.conf.all.accept_redirects=0
sysctl -w net.ipv4.conf.all.send_redirects=0

# Hacer persistente
cat >> /etc/sysctl.conf <<EOF

# IPSec Site-to-Site
net.ipv4.ip_forward=1
net.ipv4.conf.all.accept_redirects=0
net.ipv4.conf.all.send_redirects=0
EOF

# 4. Configurar IPSec (ipsec.conf)
echo "[4/7] Configurando /etc/ipsec.conf..."
cat > /etc/ipsec.conf <<EOF
# IPSec Site-to-Site: Datacenter Local <-> AWS VPC
config setup
    charondebug="ike 2, knl 2, cfg 2, net 2, esp 2, dmn 2, mgr 2"
    uniqueids=never

conn datacenter-to-aws
    auto=start
    type=tunnel

    # IKEv2
    keyexchange=ikev2

    # Fase 1 (IKE)
    ike=aes256-sha256-modp2048!
    ikelifetime=28800s

    # Fase 2 (ESP)
    esp=aes256-sha256-modp2048!
    lifetime=3600s
    margintime=270s

    # Left (Datacenter)
    left=$DATACENTER_PRIVATE_IP
    leftid=$DATACENTER_PUBLIC_IP
    leftsubnet=$DATACENTER_NETWORK

    # Right (AWS)
    right=$AWS_PUBLIC_IP
    rightsubnet=$AWS_NETWORK

    # Auth
    authby=secret

    # DPD (Dead Peer Detection)
    dpdaction=restart
    dpddelay=30s
    dpdtimeout=120s

    # Otros
    compress=no
    rekeymargin=3m
    keyingtries=%forever
EOF

# 5. Configurar secretos (ipsec.secrets)
echo "[5/7] Configurando /etc/ipsec.secrets..."
cat > /etc/ipsec.secrets <<EOF
# PSK para túnel Datacenter <-> AWS
$DATACENTER_PUBLIC_IP $AWS_PUBLIC_IP : PSK "$PSK"
EOF
chmod 600 /etc/ipsec.secrets

# 6. Configurar firewall
echo "[6/7] Configurando firewall..."

# Instalar iptables-persistent si no existe
if ! command -v netfilter-persistent &> /dev/null; then
    DEBIAN_FRONTEND=noninteractive apt-get install -y iptables-persistent
fi

# Permitir IPSec
iptables -A INPUT -p udp --dport 500 -j ACCEPT  # IKE
iptables -A INPUT -p udp --dport 4500 -j ACCEPT # NAT-T
iptables -A INPUT -p esp -j ACCEPT              # ESP
iptables -A FORWARD -s $DATACENTER_NETWORK -d $AWS_NETWORK -j ACCEPT
iptables -A FORWARD -s $AWS_NETWORK -d $DATACENTER_NETWORK -j ACCEPT

# Guardar reglas
netfilter-persistent save

# 7. Iniciar strongSwan
echo "[7/7] Iniciando strongSwan..."
systemctl enable strongswan-starter
systemctl restart strongswan-starter

# Esperar a que el túnel se establezca
echo ""
echo "Esperando establecimiento del túnel (30 seg)..."
sleep 5
ipsec up datacenter-to-aws 2>/dev/null || true
sleep 25

# Verificar estado
echo ""
echo "========================================="
echo "Estado del túnel IPSec:"
echo "========================================="
ipsec status

echo ""
echo "========================================="
echo "Configuración completada!"
echo "========================================="
echo ""
echo "Testing de conectividad:"
echo "  ping 10.0.1.20  # Wazuh SIEM"
echo "  ping 10.0.1.10  # WAF/Kong"
echo "  ping 10.0.1.30  # VPN/IAM VM"
echo "  ping 10.0.1.40  # Hardening VM"
echo ""
echo "Comandos útiles:"
echo "  ipsec status         # Ver estado del túnel"
echo "  ipsec statusall      # Detalles completos"
echo "  ipsec restart        # Reiniciar IPSec"
echo "  journalctl -u strongswan-starter -f  # Logs"
echo ""
echo "NOTA: Si el ping no funciona, verifica:"
echo "  1. Security Group AWS permite ICMP desde tu IP"
echo "  2. ipsec status muestra ESTABLISHED"
echo "  3. Firewall local (Mac) permite forwarding"
echo ""
