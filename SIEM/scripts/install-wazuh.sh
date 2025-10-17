#!/bin/bash
# Instalación de Wazuh All-in-One usando instalador asistido oficial
# Versión: 4.13.1
# Para: Ubuntu 22.04

set -e

echo "=== Instalación de Wazuh SIEM All-in-One ==="
echo ""

# Verificar que se ejecuta como root o con sudo
if [ "$EUID" -ne 0 ]; then
   echo "Error: Ejecutar como root o con sudo"
   exit 1
fi

# Verificar memoria disponible
MEM_TOTAL=$(free -g | awk '/^Mem:/{print $2}')
if [ "$MEM_TOTAL" -lt 6 ]; then
    echo "⚠️  ADVERTENCIA: Se recomiendan al menos 8GB RAM"
    echo "   Memoria disponible: ${MEM_TOTAL}GB"
fi

# Descargar instalador oficial
echo "[1/3] Descargando instalador oficial de Wazuh..."
cd /tmp
curl -sO https://packages.wazuh.com/4.13/wazuh-install.sh

# Ejecutar instalación all-in-one
echo "[2/3] Ejecutando instalación (puede tardar 5-10 minutos)..."
echo "       Instalando: Manager + Indexer + Dashboard"
bash wazuh-install.sh -a 2>&1 | tee wazuh-installation.log

# Extraer credenciales
echo ""
echo "[3/3] Extrayendo credenciales..."
PASSWORD=$(grep "Password:" wazuh-installation.log | tail -1 | awk '{print $2}')

echo ""
echo "================================================"
echo "  ✅ INSTALACIÓN COMPLETADA"
echo "================================================"
echo ""
echo "Dashboard URL: https://$(hostname -I | awk '{print $1}')"
echo "Usuario: admin"
echo "Password: $PASSWORD"
echo ""
echo "Credenciales guardadas en: /tmp/wazuh-credentials.txt"
echo "$PASSWORD" > /tmp/wazuh-credentials.txt
chmod 600 /tmp/wazuh-credentials.txt

echo ""
echo "Siguiente paso: Configurar reglas personalizadas"
echo "  1. Copiar wazuh-custom-rules.xml a /var/ossec/etc/rules/local_rules.xml"
echo "  2. Reiniciar: systemctl restart wazuh-manager"
echo ""