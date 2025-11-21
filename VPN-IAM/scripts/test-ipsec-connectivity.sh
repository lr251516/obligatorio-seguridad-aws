#!/bin/bash

# Script de Testing IPSec Site-to-Site
# Verifica conectividad Datacenter <-> AWS VPC

echo "========================================="
echo "IPSec Site-to-Site - Testing"
echo "========================================="
echo ""

# Detectar si estamos en AWS o Datacenter
if curl -s -m 2 http://169.254.169.254/latest/meta-data/public-ipv4 &>/dev/null; then
    LOCATION="AWS"
    TARGETS=(
        "10.100.0.1:Datacenter Loopback"
    )
else
    LOCATION="Datacenter"
    TARGETS=(
        "10.0.1.20:Wazuh SIEM"
        "10.0.1.10:WAF Kong"
        "10.0.1.30:VPN IAM"
        "10.0.1.40:Hardening VM"
    )
fi

echo "Ejecutando desde: $LOCATION"
echo ""

# 1. Estado del túnel IPSec
echo "========================================="
echo "1. Estado del túnel IPSec"
echo "========================================="
sudo ipsec status
echo ""

# 2. Routing table
echo "========================================="
echo "2. Rutas IPSec activas"
echo "========================================="
ip route | grep -E "10\.0\.|10\.100\." || echo "No hay rutas específicas (normal con IPSec)"
echo ""

# 3. SAs (Security Associations)
echo "========================================="
echo "3. Security Associations (SAs)"
echo "========================================="
sudo ipsec statusall | grep -A 5 "Security Associations"
echo ""

# 4. Testing de conectividad ICMP
echo "========================================="
echo "4. Testing Conectividad (ping)"
echo "========================================="

for target in "${TARGETS[@]}"; do
    IFS=':' read -r ip desc <<< "$target"
    printf "%-30s " "$desc ($ip):"

    if ping -c 3 -W 2 "$ip" &>/dev/null; then
        echo "✅ OK"
    else
        echo "❌ FAIL"
    fi
done
echo ""

# 5. Testing de conectividad TCP (si estamos en Datacenter)
if [ "$LOCATION" == "Datacenter" ]; then
    echo "========================================="
    echo "5. Testing Servicios (TCP)"
    echo "========================================="

    # Wazuh API (55000)
    printf "%-30s " "Wazuh API (10.0.1.20:55000):"
    if timeout 3 bash -c "echo >/dev/tcp/10.0.1.20/55000" 2>/dev/null; then
        echo "✅ OK"
    else
        echo "❌ FAIL (puede ser firewall)"
    fi

    # Kong Admin (8001)
    printf "%-30s " "Kong Admin (10.0.1.10:8001):"
    if timeout 3 bash -c "echo >/dev/tcp/10.0.1.10/8001" 2>/dev/null; then
        echo "✅ OK"
    else
        echo "❌ FAIL (puede ser firewall)"
    fi

    # Keycloak (8080)
    printf "%-30s " "Keycloak (10.0.1.30:8080):"
    if timeout 3 bash -c "echo >/dev/tcp/10.0.1.30/8080" 2>/dev/null; then
        echo "✅ OK"
    else
        echo "❌ FAIL (puede ser firewall)"
    fi

    echo ""
fi

# 6. Troubleshooting info
echo "========================================="
echo "6. Información de troubleshooting"
echo "========================================="
echo "IP forwarding: $(sysctl net.ipv4.ip_forward | awk '{print $3}')"
echo ""

# Ver últimos 10 logs de IPSec
echo "Últimos eventos IPSec:"
sudo journalctl -u strongswan-starter -n 10 --no-pager | tail -5
echo ""

echo "========================================="
echo "Testing completado!"
echo "========================================="
echo ""
echo "Si hay fallos, verificar:"
echo "  1. ipsec status -> debe mostrar ESTABLISHED"
echo "  2. Security Groups AWS -> permitir ICMP/TCP desde tu IP"
echo "  3. iptables -L -n -> reglas FORWARD activas"
echo "  4. journalctl -u strongswan-starter -f -> logs en tiempo real"
echo ""
