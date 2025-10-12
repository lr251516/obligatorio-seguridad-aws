#!/bin/bash
# Script para conectarse a las instancias AWS

set -e

VM=$1

if [ -z "$VM" ]; then
    echo "Uso: $0 <wazuh|vpn|waf|hardening>"
    echo ""
    echo "Ejemplos:"
    echo "  $0 wazuh     - Conectar a Wazuh SIEM"
    echo "  $0 vpn       - Conectar a VPN/IAM"
    echo "  $0 waf       - Conectar a WAF/Kong"
    echo "  $0 hardening - Conectar a Hardening VM"
    exit 1
fi

# Verificar que Terraform está inicializado
if [ ! -d "terraform/.terraform" ]; then
    echo "[!] Error: Terraform no inicializado"
    echo "Ejecutar primero: cd terraform && terraform init"
    exit 1
fi

cd terraform

SSH_KEY="${HOME}/.ssh/obligatorio-srd"

case $VM in
    wazuh)
        IP=$(terraform output -raw wazuh_public_ip)
        echo "[+] Conectando a Wazuh SIEM ($IP)..."
        ssh -i "$SSH_KEY" -o StrictHostKeyChecking=no ubuntu@"$IP"
        ;;
    vpn|iam)
        IP=$(terraform output -raw vpn_public_ip)
        echo "[+] Conectando a VPN/IAM ($IP)..."
        ssh -i "$SSH_KEY" -o StrictHostKeyChecking=no ubuntu@"$IP"
        ;;
    waf|kong)
        IP=$(terraform output -raw waf_public_ip)
        echo "[+] Conectando a WAF/Kong ($IP)..."
        ssh -i "$SSH_KEY" -o StrictHostKeyChecking=no ubuntu@"$IP"
        ;;
    hardening|hard)
        IP=$(terraform output -raw hardening_private_ip)
        echo "[+] Conectando a Hardening VM ($IP)..."
        echo "[!] NOTA: Esta VM solo es accesible via VPN WireGuard"
        echo "Primero configurar VPN, luego:"
        echo "  ssh -i $SSH_KEY ubuntu@$IP"
        exit 1
        ;;
    *)
        echo "[!] VM desconocida: $VM"
        echo "Opciones: wazuh, vpn, waf, hardening"
        exit 1
        ;;
esac