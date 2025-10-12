#!/bin/bash
# Configuración base para instancias AWS EC2

set -e

HOSTNAME=$1

if [ -z "$HOSTNAME" ]; then
    echo "Uso: $0 <hostname>"
    echo "Ejemplo: $0 wazuh-siem"
    exit 1
fi

echo "[+] Configurando $HOSTNAME en AWS EC2"

# Actualizar sistema
echo "[+] Actualizando sistema..."
sudo apt-get update
sudo apt-get upgrade -y

# Instalar herramientas base
echo "[+] Instalando herramientas base..."
sudo apt-get install -y \
    curl \
    wget \
    git \
    vim \
    htop \
    net-tools \
    jq \
    unzip

# Configurar hostname
echo "[+] Configurando hostname: $HOSTNAME"
sudo hostnamectl set-hostname "$HOSTNAME"

# Actualizar /etc/hosts con todas las instancias
echo "[+] Actualizando /etc/hosts con IPs internas AWS..."
sudo tee -a /etc/hosts > /dev/null <<HOSTS

# Obligatorio SRD - AWS Internal IPs
10.0.1.10   waf-kong       waf
10.0.1.20   wazuh-siem     wazuh
10.0.1.30   vpn-iam        vpn keycloak
10.0.1.40   hardening-vm   hardening
HOSTS

# Configurar timezone
echo "[+] Configurando timezone a America/Montevideo..."
sudo timedatectl set-timezone America/Montevideo

# Deshabilitar swap 
echo "[+] Deshabilitando swap..."
sudo swapoff -a
sudo sed -i '/ swap / s/^/#/' /etc/fstab

# Configurar límites del sistema
echo "[+] Configurando límites del sistema..."
sudo tee -a /etc/security/limits.conf > /dev/null <<LIMITS
* soft nofile 65536
* hard nofile 65536
* soft nproc 65536
* hard nproc 65536
LIMITS

# Configurar sysctl básico
echo "[+] Configurando parámetros sysctl básicos..."
sudo tee /etc/sysctl.d/99-fosil.conf > /dev/null <<SYSCTL
# Seguridad básica
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv4.icmp_echo_ignore_broadcasts = 1
net.ipv4.icmp_ignore_bogus_error_responses = 1

# Performance
vm.swappiness = 10
vm.max_map_count = 262144
SYSCTL

sudo sysctl -p /etc/sysctl.d/99-fosil.conf

# Crear estructura de directorios
echo "[+] Creando estructura de directorios..."
sudo mkdir -p /opt/fosil/{scripts,configs,logs,backups}
sudo chmod 755 /opt/fosil

# Instalar AWS CLI v2 si no está
if ! command -v aws &> /dev/null; then
    echo "[+] Instalando AWS CLI v2..."
    cd /tmp
    curl "https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip" -o "awscliv2.zip"
    unzip -q awscliv2.zip
    sudo ./aws/install
    rm -rf aws awscliv2.zip
fi

# Verificar metadata de EC2
echo "[+] Verificando metadata de instancia EC2..."
INSTANCE_ID=$(ec2-metadata --instance-id | cut -d " " -f 2)
INSTANCE_TYPE=$(ec2-metadata --instance-type | cut -d " " -f 2)
AZ=$(ec2-metadata --availability-zone | cut -d " " -f 2)
PRIVATE_IP=$(ec2-metadata --local-ipv4 | cut -d " " -f 2)

echo ""
echo "=== Información de la Instancia ==="
echo "Instance ID:   $INSTANCE_ID"
echo "Instance Type: $INSTANCE_TYPE"
echo "Availability:  $AZ"
echo "Private IP:    $PRIVATE_IP"
echo "Hostname:      $HOSTNAME"
echo ""

# Guardar info de instancia
sudo tee /opt/fosil/instance-info.txt > /dev/null <<INFO
Instance ID:   $INSTANCE_ID
Instance Type: $INSTANCE_TYPE
Availability:  $AZ
Private IP:    $PRIVATE_IP
Hostname:      $HOSTNAME
Configured:    $(date)
INFO

# Verificar conectividad interna
echo "[+] Verificando conectividad con otras instancias..."

# Test ping a otras instancias (solo si ya existen)
for ip in 10.0.1.10 10.0.1.20 10.0.1.30 10.0.1.40; do
    if [ "$PRIVATE_IP" != "$ip" ]; then
        if ping -c 1 -W 1 $ip &> /dev/null; then
            echo "  [✓] $ip alcanzable"
        else
            echo "  [!] $ip no alcanzable (puede estar apagada)"
        fi
    fi
done

# Verificar conectividad a Internet
echo "[+] Verificando conectividad a Internet..."
if ping -c 2 8.8.8.8 &> /dev/null; then
    echo "  [✓] Internet OK"
else
    echo "  [!] Sin conectividad a Internet"
fi

echo ""
echo "[✓] Configuración base completada para $HOSTNAME"
echo ""
echo "Siguiente paso: Instalar servicios específicos"
echo "  - Wazuh:    /opt/fosil/scripts/install-wazuh.sh"
echo "  - Keycloak: /opt/fosil/scripts/install-keycloak.sh"
echo "  - etc."
echo ""