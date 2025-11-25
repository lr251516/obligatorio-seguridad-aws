#!/bin/bash
set -e

# IPSec Site-to-Site - AWS VPN VM Side
# Conecta datacenter local (Multipass VM) con AWS VPC
# Usar strongSwan (IPSec IKEv2)

echo "========================================="
echo "IPSec Site-to-Site Setup - AWS Side"
echo "========================================="

# Verificar que se ejecute como root
if [ "$EUID" -ne 0 ]; then
    echo "ERROR: Este script debe ejecutarse como root (sudo)"
    exit 1
fi

# Variables 
read -p "IP pública de tu datacenter local (Multipass host): " DATACENTER_PUBLIC_IP
read -sp "PSK (Pre-Shared Key - debe ser igual en ambos lados): " PSK
echo ""

# Variables AWS (auto-detect)
AWS_PRIVATE_IP=$(ip -4 addr show $(ip route | grep default | awk '{print $5}') | grep -oP '(?<=inet\s)\d+(\.\d+){3}' | head -1)
AWS_PUBLIC_IP=$(curl -s http://169.254.169.254/latest/meta-data/public-ipv4)

echo ""
echo "Configuración detectada:"
echo "  AWS Private IP: $AWS_PRIVATE_IP"
echo "  AWS Public IP: $AWS_PUBLIC_IP"
echo "  Datacenter Public IP: $DATACENTER_PUBLIC_IP"
echo ""

# Redes
DATACENTER_NETWORK="10.100.0.0/24"  # Red del datacenter local
AWS_NETWORK="10.0.0.0/16"           # VPC AWS

# 1. Instalar strongSwan
echo "[1/6] Instalando strongSwan..."
apt-get update -qq
apt-get install -y strongswan strongswan-pki libcharon-extra-plugins

# 2. Habilitar IP forwarding (ya debería estar habilitado por WireGuard)
echo "[2/6] Habilitando IP forwarding..."
sysctl -w net.ipv4.ip_forward=1
sysctl -w net.ipv4.conf.all.accept_redirects=0
sysctl -w net.ipv4.conf.all.send_redirects=0

# 3. Configurar IPSec (ipsec.conf)
echo "[3/6] Configurando /etc/ipsec.conf..."
cat > /etc/ipsec.conf <<EOF
# IPSec Site-to-Site: AWS VPC <-> Datacenter Local
config setup
    charondebug="ike 2, knl 2, cfg 2, net 2, esp 2, dmn 2, mgr 2"
    uniqueids=never

conn aws-to-datacenter
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

    # Left (AWS)
    left=$AWS_PRIVATE_IP
    leftid=$AWS_PUBLIC_IP
    leftsubnet=$AWS_NETWORK

    # Right (Datacenter)
    right=$DATACENTER_PUBLIC_IP
    rightsubnet=$DATACENTER_NETWORK

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

# 4. Configurar secretos (ipsec.secrets)
echo "[4/6] Configurando /etc/ipsec.secrets..."
cat > /etc/ipsec.secrets <<EOF
# PSK para túnel AWS <-> Datacenter
$AWS_PUBLIC_IP $DATACENTER_PUBLIC_IP : PSK "$PSK"
EOF
chmod 600 /etc/ipsec.secrets

# 5. Configurar firewall (iptables/UFW)
echo "[5/6] Configurando firewall..."

# Permitir IPSec en UFW (si está activo)
if command -v ufw &> /dev/null && ufw status | grep -q "Status: active"; then
    ufw allow 500/udp comment 'IPSec IKE'
    ufw allow 4500/udp comment 'IPSec NAT-T'
    ufw allow proto esp comment 'IPSec ESP'
fi

# iptables para NAT traversal y forwarding
iptables -A INPUT -p udp --dport 500 -j ACCEPT  # IKE
iptables -A INPUT -p udp --dport 4500 -j ACCEPT # NAT-T
iptables -A INPUT -p esp -j ACCEPT              # ESP
iptables -A FORWARD -s $DATACENTER_NETWORK -d $AWS_NETWORK -j ACCEPT
iptables -A FORWARD -s $AWS_NETWORK -d $DATACENTER_NETWORK -j ACCEPT

# Guardar reglas iptables
if command -v netfilter-persistent &> /dev/null; then
    netfilter-persistent save
fi

# 6. Reiniciar strongSwan
echo "[6/6] Iniciando strongSwan..."
systemctl enable strongswan-starter
systemctl restart strongswan-starter

# Esperar a que el túnel se establezca
echo ""
echo "Esperando establecimiento del túnel (30 seg)..."
sleep 5
ipsec up aws-to-datacenter 2>/dev/null || true
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
echo "Próximos pasos:"
echo "1. Ejecutar setup-ipsec-datacenter.sh en tu Multipass VM"
echo "2. Verificar conectividad:"
echo "   ping 10.100.0.1  # IP de datacenter"
echo "   ping 10.0.1.20   # Wazuh desde datacenter"
echo ""
echo "Comandos útiles:"
echo "  ipsec status         # Ver estado del túnel"
echo "  ipsec statusall      # Detalles completos"
echo "  ipsec restart        # Reiniciar IPSec"
echo "  journalctl -u strongswan-starter -f  # Logs en tiempo real"
echo ""
