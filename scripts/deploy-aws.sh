#!/bin/bash
# Script automatizado para desplegar infraestructura en AWS

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo "================================================"
echo "  Obligatorio SRD - AWS Deployment Script"
echo "  Universidad ORT Uruguay - Grupo N6A"
echo "================================================"
echo ""

# Verificar que estamos en el directorio correcto
if [ ! -f "terraform/main.tf" ]; then
    echo -e "${RED}[!] Error: No se encontró terraform/main.tf${NC}"
    echo "Ejecutar desde: ~/OBLIGATORIO-SRD-AWS/Hardening/"
    exit 1
fi

# Verificar herramientas instaladas
echo -e "${YELLOW}[+] Verificando herramientas necesarias...${NC}"

if ! command -v terraform &> /dev/null; then
    echo -e "${RED}[!] Terraform no instalado${NC}"
    echo "Instalar con: brew install hashicorp/tap/terraform"
    exit 1
fi

if ! command -v aws &> /dev/null; then
    echo -e "${RED}[!] AWS CLI no instalado${NC}"
    echo "Instalar con: brew install awscli"
    exit 1
fi

echo -e "${GREEN}[✓] Herramientas verificadas${NC}"
echo ""

# Verificar credenciales AWS
echo -e "${YELLOW}[+] Verificando credenciales AWS...${NC}"
if ! aws sts get-caller-identity &> /dev/null; then
    echo -e "${RED}[!] Credenciales AWS no configuradas${NC}"
    echo "Configurar con: aws configure"
    exit 1
fi

AWS_ACCOUNT=$(aws sts get-caller-identity --query Account --output text)
AWS_REGION=$(aws configure get region)
echo -e "${GREEN}[✓] AWS Account: $AWS_ACCOUNT${NC}"
echo -e "${GREEN}[✓] AWS Region: $AWS_REGION${NC}"
echo ""

# Verificar clave SSH
echo -e "${YELLOW}[+] Verificando clave SSH...${NC}"
SSH_KEY="${HOME}/.ssh/obligatorio-srd"

if [ ! -f "${SSH_KEY}.pub" ]; then
    echo -e "${RED}[!] Clave SSH no encontrada en ${SSH_KEY}${NC}"
    echo "Por favor, asegúrate de que exista ~/.ssh/obligatorio-srd y ~/.ssh/obligatorio-srd.pub"
    exit 1
else
    echo -e "${GREEN}[✓] Clave encontrada: ${SSH_KEY}${NC}"
fi
echo ""

# Verificar AWS_PROFILE
echo -e "${YELLOW}[+] Verificando AWS Profile...${NC}"
if [ -z "$AWS_PROFILE" ]; then
    echo -e "${YELLOW}[!] AWS_PROFILE no configurado, estableciendo a 'ort'${NC}"
    export AWS_PROFILE="ort"
fi
echo -e "${GREEN}[✓] AWS Profile: $AWS_PROFILE${NC}"
echo ""

# IP pública (Cloudflare VPN)
echo -e "${YELLOW}[+] Configurando IP pública...${NC}"
MY_IP="104.30.133.214"
echo -e "${GREEN}[✓] IP Cloudflare VPN: $MY_IP${NC}"
echo ""

# Crear terraform.tfvars si no existe
TFVARS_FILE="terraform/terraform.tfvars"
if [ ! -f "$TFVARS_FILE" ]; then
    echo -e "${YELLOW}[+] Creando terraform.tfvars...${NC}"
    
    # Preguntar tipo de instancia para Wazuh
    echo "Seleccionar tipo de instancia para Wazuh:"
    echo "1) t3.micro (FREE TIER, 1GB RAM, puede ser ajustado)"
    echo "2) t3.small (RECOMENDADO, 2GB RAM, ~\$17/mes)"
    read -p "Opción (1 o 2): " INSTANCE_CHOICE
    
    if [ "$INSTANCE_CHOICE" == "2" ]; then
        WAZUH_INSTANCE="t3.small"
    else
        WAZUH_INSTANCE="t3.micro"
    fi
    
    # Preguntar repo GitHub
    GITHUB_USER="lr251516"
    
    cat > "$TFVARS_FILE" <<EOF
# Configuración automática generada por deploy-aws.sh

my_ip               = "$MY_IP/32"
public_key_path     = "$SSH_KEY.pub"
aws_region          = "$AWS_REGION"
wazuh_instance_type = "$WAZUH_INSTANCE"
github_repo         = "https://github.com/$GITHUB_USER/obligatorio-seguridad-aws"
github_branch       = "main"
EOF
    
    echo -e "${GREEN}[✓] terraform.tfvars creado${NC}"
else
    echo -e "${GREEN}[✓] terraform.tfvars ya existe${NC}"
fi
echo ""

# Resumen antes de aplicar
echo "================================================"
echo "  RESUMEN DE DESPLIEGUE"
echo "================================================"
echo "Región AWS:      $AWS_REGION"
echo "Tu IP:           $MY_IP"
echo "Clave SSH:       $SSH_KEY"
echo "Instancia Wazuh: $(grep wazuh_instance_type $TFVARS_FILE | cut -d'=' -f2 | tr -d ' "')"
echo ""
echo "Se crearán:"
echo "  - 1 VPC"
echo "  - 1 Subnet pública"
echo "  - 1 Internet Gateway"
echo "  - 4 Security Groups"
echo "  - 4 EC2 Instances (Ubuntu 22.04)"
echo "  - 3 Elastic IPs"
echo ""

read -p "¿Continuar con el despliegue? (y/n): " -n 1 -r
echo ""
if [[ ! $REPLY =~ ^[Yy]$ ]]; then
    echo "Despliegue cancelado"
    exit 0
fi

# Terraform init
cd terraform
echo ""
echo -e "${YELLOW}[+] Inicializando Terraform...${NC}"
terraform init

# Terraform plan
echo ""
echo -e "${YELLOW}[+] Generando plan de ejecución...${NC}"
terraform plan -out=tfplan

# Mostrar plan
echo ""
read -p "¿Aplicar el plan? (y/n): " -n 1 -r
echo ""
if [[ ! $REPLY =~ ^[Yy]$ ]]; then
    echo "Despliegue cancelado"
    exit 0
fi

# Terraform apply
echo ""
echo -e "${YELLOW}[+] Aplicando configuración...${NC}"
echo "Esto puede tomar 3-5 minutos..."
terraform apply tfplan

# Mostrar outputs
echo ""
echo "================================================"
echo "  DESPLIEGUE COMPLETADO"
echo "================================================"
terraform output summary

# Guardar IPs en archivo
echo ""
echo -e "${YELLOW}[+] Guardando información de acceso...${NC}"
cat > ../aws-access-info.txt <<EOF
# AWS Access Information - Generated $(date)

Wazuh SIEM:
  Public IP:  $(terraform output -raw wazuh_public_ip)
  Dashboard:  $(terraform output -raw wazuh_dashboard_url)
  SSH:        ssh -i $SSH_KEY ubuntu@$(terraform output -raw wazuh_public_ip)

VPN/IAM:
  Public IP:  $(terraform output -raw vpn_public_ip)
  Keycloak:   $(terraform output -raw keycloak_url)
  SSH:        ssh -i $SSH_KEY ubuntu@$(terraform output -raw vpn_public_ip)

WAF/Kong:
  Public IP:  $(terraform output -raw waf_public_ip)
  Kong Proxy: $(terraform output -raw kong_proxy_url)
  Kong Admin: $(terraform output -raw kong_admin_url)
  SSH:        ssh -i $SSH_KEY ubuntu@$(terraform output -raw waf_public_ip)

Hardening:
  Private IP: $(terraform output -raw hardening_private_ip)
  SSH:        (via VPN después de configurar WireGuard)

NEXT STEPS:
1. Esperar 5 minutos para que user-data scripts completen
2. SSH a cada instancia y verificar: cat /tmp/user-data-completed.log
3. Seguir guía de configuración en docs/aws-deployment-guide.md
EOF

echo -e "${GREEN}[✓] Información guardada en: aws-access-info.txt${NC}"

echo ""
echo "================================================"
echo "  PRÓXIMOS PASOS"
echo "================================================"
echo "1. Esperar 5 minutos para inicialización"
echo "2. Verificar acceso SSH a Wazuh:"
echo "   ssh -i $SSH_KEY ubuntu@$(terraform output -raw wazuh_public_ip)"
echo ""
echo "3. Instalar Wazuh:"
echo "   cd /tmp"
echo "   wget https://raw.githubusercontent.com/lr251516/obligatorio-srd-aws/main/SIEM/scripts/install-wazuh.sh"
echo "   chmod +x install-wazuh.sh"
echo "   sudo ./install-wazuh.sh"
echo ""
echo "4. Acceder a Dashboard:"
echo "   $(terraform output -raw wazuh_dashboard_url)"
echo ""
echo "================================================"
echo ""

echo -e "${GREEN}[✓] ¡Despliegue exitoso!${NC}"
echo ""
echo "Para destruir todo: terraform destroy"