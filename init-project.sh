#!/bin/bash
# init-project.sh
# Crea la estructura completa del proyecto desde cero

set -e

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo "================================================"
echo "  Obligatorio SRD - Project Initialization"
echo "  Universidad ORT Uruguay - Grupo N6A"
echo "================================================"
echo ""

# Solicitar información
read -p "Nombre del directorio del proyecto [obligatorio-srd-n6a]: " PROJECT_NAME
PROJECT_NAME=${PROJECT_NAME:-obligatorio-srd-n6a}

read -p "Tu usuario de GitHub: " GITHUB_USER
if [ -z "$GITHUB_USER" ]; then
    echo "Error: Usuario de GitHub requerido"
    exit 1
fi

echo ""
echo -e "${YELLOW}[+] Creando estructura de proyecto: $PROJECT_NAME${NC}"
echo ""

# Crear directorio principal
mkdir -p "$PROJECT_NAME"
cd "$PROJECT_NAME"

# Crear estructura de carpetas
echo -e "${YELLOW}[+] Creando estructura de carpetas...${NC}"

mkdir -p docs
mkdir -p scripts
mkdir -p SIEM/scripts
mkdir -p VPN-IAM/scripts
mkdir -p WAF-APIgw/scripts
mkdir -p Hardening/terraform/user-data
mkdir -p Hardening/scripts/modules
mkdir -p .github

echo -e "${GREEN}[✓] Estructura creada${NC}"

# ============================================
# .gitignore
# ============================================
echo -e "${YELLOW}[+] Creando .gitignore...${NC}"

cat > .gitignore << 'EOF'
# Environment files
*.env
.env.*
terraform.tfvars

# SSH Keys
*.pem
*.key
id_rsa*
fosil-aws-key*

# Terraform
.terraform/
*.tfstate*
*.tfplan
.terraform.lock.hcl

# OS files
.DS_Store
Thumbs.db

# IDE
.vscode/
.idea/
*.swp
*.swo

# Logs
*.log
logs/

# Temporary files
tmp/
temp/

# AWS
aws-access-info.txt

# Virtual machines
*.vdi
*.vmdk
*.iso
EOF

echo -e "${GREEN}[✓] .gitignore creado${NC}"

# ============================================
# README.md principal
# ============================================
echo -e "${YELLOW}[+] Creando README.md principal...${NC}"

cat > README.md << EOF
# Obligatorio: Seguridad en Redes y Datos
**Universidad ORT Uruguay - Grupo N6A**

## 📋 Descripción

Implementación de infraestructura de seguridad para Fósil Energías Renovables S.A., dividida en 4 maquetas independientes pero interconectadas, desplegadas en AWS.

## 🏗️ Arquitectura

\`\`\`
┌─────────────────────────────────────────┐
│           AWS Cloud (Free Tier)         │
├─────────────────────────────────────────┤
│  ┌──────────────┐  ┌──────────────┐    │
│  │  Maqueta 1   │  │  Maqueta 2   │    │
│  │ WAF + API GW │─▶│     SIEM     │    │
│  │   (Kong)     │  │   (Wazuh)    │    │
│  └──────────────┘  └──────┬───────┘    │
│         │                  │            │
│  ┌──────▼───────┐         │            │
│  │  Maqueta 3   │─────────┘            │
│  │  VPN + IAM   │                       │
│  │  (Keycloak)  │                       │
│  └──────┬───────┘                       │
│         │                                │
│  ┌──────▼────────┐                      │
│  │   Maqueta 4   │                      │
│  │   Hardening   │                      │
│  └───────────────┘                      │
└─────────────────────────────────────────┘
\`\`\`

## 🚀 Quick Start

### Prerequisitos

- AWS CLI configurado
- Terraform >= 1.0
- Par de claves SSH

### Despliegue

\`\`\`bash
# Clonar repositorio
git clone https://github.com/$GITHUB_USER/$PROJECT_NAME.git
cd $PROJECT_NAME

# Desplegar infraestructura
cd Hardening/terraform
chmod +x ../deploy-aws.sh
../deploy-aws.sh

# Esperar 5 minutos y configurar servicios
\`\`\`

## 📚 Documentación

- [Guía de Despliegue AWS](docs/aws-deployment-guide.md)
- [Arquitectura Detallada](docs/arquitectura.md)
- [Configuración de Servicios](docs/configuracion.md)

## 🔧 Maquetas

### Maqueta 1: WAF + API Gateway
- Kong Gateway
- ModSecurity + OWASP CRS
- Protección contra OWASP Top 10

### Maqueta 2: SIEM (Wazuh)
- Monitoreo centralizado
- 3 casos de uso personalizados
- Dashboard personalizado

### Maqueta 3: VPN + IAM
- WireGuard VPN site-to-site
- Keycloak (OAuth2/OIDC)
- Gestión centralizada de identidades

### Maqueta 4: Hardening
- Ubuntu 22.04 endurecido
- CIS Benchmarks Level 1
- Lynis score >= 80

## 📊 Estructura del Proyecto

\`\`\`
$PROJECT_NAME/
├── docs/                 # Documentación
├── scripts/              # Scripts comunes
├── SIEM/                 # Maqueta 2
├── VPN-IAM/              # Maqueta 3
├── WAF-APIgw/            # Maqueta 1
└── Hardening/            # Maqueta 4 + Terraform
\`\`\`

## 👥 Autores

- Grupo N6A
- Universidad ORT Uruguay
- Analista en Infraestructura Informática

## 📝 Licencia

Proyecto académico - Universidad ORT Uruguay
EOF

echo -e "${GREEN}[✓] README.md principal creado${NC}"

# ============================================
# Scripts comunes
# ============================================
echo -e "${YELLOW}[+] Creando scripts comunes...${NC}"

# setup-vm-base.sh (ya lo tienes, aquí una versión simplificada para AWS)
cat > scripts/setup-base.sh << 'EOF'
#!/bin/bash
# setup-base.sh
# Configuración base para instancias AWS

set -e

HOSTNAME=$1
INTERNAL_IP=$2

if [ -z "$HOSTNAME" ] || [ -z "$INTERNAL_IP" ]; then
    echo "Uso: $0 <hostname> <internal-ip>"
    exit 1
fi

echo "[+] Configurando $HOSTNAME ($INTERNAL_IP)"

# Actualizar sistema
sudo apt-get update
sudo apt-get upgrade -y

# Instalar herramientas base
sudo apt-get install -y \
    curl \
    wget \
    git \
    vim \
    htop \
    net-tools \
    ufw

# Configurar hostname
sudo hostnamectl set-hostname "$HOSTNAME"

# Agregar a /etc/hosts
sudo tee -a /etc/hosts > /dev/null <<HOSTS
10.0.1.10   waf-kong
10.0.1.20   wazuh-siem
10.0.1.30   vpn-iam
10.0.1.40   hardening-vm
HOSTS

echo "[✓] Configuración base completada"
EOF

chmod +x scripts/setup-base.sh

echo -e "${GREEN}[✓] Scripts comunes creados${NC}"

# ============================================
# Scripts SIEM (Wazuh)
# ============================================
echo -e "${YELLOW}[+] Creando scripts SIEM...${NC}"

cat > SIEM/README.md << 'EOF'
# Maqueta 2: SIEM (Wazuh)

## Componentes

- Wazuh Manager
- Wazuh Indexer (OpenSearch)
- Wazuh Dashboard

## Instalación

\`\`\`bash
cd scripts
./install-wazuh.sh
\`\`\`

## Casos de Uso

1. Detección de intentos de autenticación fallidos
2. Detección de ataques web via WAF
3. Cambios no autorizados en configuración
EOF

# Los scripts install-wazuh.sh, etc. ya los tienes en tu repo actual
# Los moveremos después

echo -e "${GREEN}[✓] Estructura SIEM creada${NC}"

# ============================================
# Scripts VPN-IAM
# ============================================
echo -e "${YELLOW}[+] Creando estructura VPN-IAM...${NC}"

cat > VPN-IAM/README.md << 'EOF'
# Maqueta 3: VPN + IAM

## Componentes

- WireGuard (VPN site-to-site)
- Keycloak (Identity Provider)

## Instalación

\`\`\`bash
# Keycloak
cd scripts
./install-keycloak.sh
./create-realm.sh

# WireGuard
./setup-wireguard.sh server 10.0.1.40
\`\`\`
EOF

echo -e "${GREEN}[✓] Estructura VPN-IAM creada${NC}"

# ============================================
# Scripts WAF
# ============================================
echo -e "${YELLOW}[+] Creando estructura WAF...${NC}"

cat > WAF-APIgw/README.md << 'EOF'
# Maqueta 1: WAF + API Gateway

## Componentes

- Kong Gateway
- ModSecurity + OWASP CRS

## Instalación

\`\`\`bash
cd scripts
# Scripts pendientes de implementación
\`\`\`
EOF

echo -e "${GREEN}[✓] Estructura WAF creada${NC}"

# ============================================
# Terraform (Infraestructura)
# ============================================
echo -e "${YELLOW}[+] Creando archivos Terraform...${NC}"

# main.tf - ARCHIVO GRANDE, lo pondremos al final
cat > Hardening/terraform/main.tf << 'EOFTF'
# Ver artifact: terraform_main para contenido completo
# Este archivo será reemplazado por el contenido del artifact
EOFTF

# variables.tf
cat > Hardening/terraform/variables.tf << 'EOFTF'
variable "aws_region" {
  description = "AWS region to deploy resources"
  type        = string
  default     = "us-east-1"
}

variable "my_ip" {
  description = "Your public IP address for SSH access (CIDR format)"
  type        = string
}

variable "public_key_path" {
  description = "Path to your SSH public key"
  type        = string
  default     = "~/.ssh/fosil-aws-key.pub"
}

variable "wazuh_instance_type" {
  description = "Instance type for Wazuh"
  type        = string
  default     = "t2.small"
}

variable "github_repo" {
  description = "GitHub repository URL"
  type        = string
}

variable "github_branch" {
  description = "GitHub branch"
  type        = string
  default     = "main"
}
EOFTF

# outputs.tf
cat > Hardening/terraform/outputs.tf << 'EOFTF'
output "wazuh_public_ip" {
  value = aws_eip.wazuh.public_ip
}

output "wazuh_dashboard_url" {
  value = "https://${aws_eip.wazuh.public_ip}"
}

output "vpn_public_ip" {
  value = aws_eip.vpn.public_ip
}

output "keycloak_url" {
  value = "http://${aws_eip.vpn.public_ip}:8080"
}

output "waf_public_ip" {
  value = aws_eip.waf.public_ip
}

output "kong_proxy_url" {
  value = "http://${aws_eip.waf.public_ip}:8000"
}

output "hardening_private_ip" {
  value = aws_instance.hardening.private_ip
}

output "ssh_commands" {
  value = {
    wazuh     = "ssh -i ~/.ssh/fosil-aws-key ubuntu@${aws_eip.wazuh.public_ip}"
    vpn       = "ssh -i ~/.ssh/fosil-aws-key ubuntu@${aws_eip.vpn.public_ip}"
    waf       = "ssh -i ~/.ssh/fosil-aws-key ubuntu@${aws_eip.waf.public_ip}"
  }
}
EOFTF

# User-data scripts
cat > Hardening/terraform/user-data/wazuh-init.sh << 'EOFUD'
#!/bin/bash
set -e
apt-get update
apt-get upgrade -y
apt-get install -y git curl
hostnamectl set-hostname wazuh-siem
mkdir -p /opt/fosil/scripts
echo "Wazuh init completed" > /tmp/user-data-completed.log
EOFUD

cat > Hardening/terraform/user-data/vpn-init.sh << 'EOFUD'
#!/bin/bash
set -e
apt-get update
apt-get upgrade -y
apt-get install -y git curl wireguard-tools
hostnamectl set-hostname vpn-iam
mkdir -p /opt/fosil/scripts
echo "VPN init completed" > /tmp/user-data-completed.log
EOFUD

cat > Hardening/terraform/user-data/waf-init.sh << 'EOFUD'
#!/bin/bash
set -e
apt-get update
apt-get upgrade -y
apt-get install -y git curl
hostnamectl set-hostname waf-kong
mkdir -p /opt/fosil/scripts
echo "WAF init completed" > /tmp/user-data-completed.log
EOFUD

cat > Hardening/terraform/user-data/hardening-init.sh << 'EOFUD'
#!/bin/bash
set -e
apt-get update
apt-get upgrade -y
apt-get install -y git curl wireguard-tools lynis auditd
hostnamectl set-hostname hardening-vm
mkdir -p /opt/fosil/scripts
echo "Hardening init completed" > /tmp/user-data-completed.log
EOFUD

echo -e "${GREEN}[✓] Archivos Terraform creados${NC}"

# ============================================
# Scripts de deployment
# ============================================
echo -e "${YELLOW}[+] Creando scripts de deployment...${NC}"

cat > Hardening/deploy-aws.sh << 'EOFDEPLOY'
#!/bin/bash
# Ver artifact: deploy_aws_script para contenido completo
echo "Script de deployment - Por implementar contenido del artifact"
EOFDEPLOY

chmod +x Hardening/deploy-aws.sh

cat > Hardening/connect-aws.sh << 'EOFCONNECT'
#!/bin/bash
# Ver artifact: aws_connect_script para contenido completo
echo "Script de conexión - Por implementar contenido del artifact"
EOFCONNECT

chmod +x Hardening/connect-aws.sh

echo -e "${GREEN}[✓] Scripts de deployment creados${NC}"

# ============================================
# Documentación
# ============================================
echo -e "${YELLOW}[+] Creando documentación...${NC}"

cat > docs/arquitectura.md << 'EOF'
# Arquitectura del Sistema

## Componentes

### Maqueta 1: WAF + API Gateway
- **Kong Gateway**: API Gateway y reverse proxy
- **ModSecurity**: Web Application Firewall
- **OWASP CRS**: Reglas de seguridad

### Maqueta 2: SIEM (Wazuh)
- **Wazuh Manager**: Motor de análisis
- **Wazuh Indexer**: Base de datos de eventos
- **Wazuh Dashboard**: Visualización

### Maqueta 3: VPN + IAM
- **WireGuard**: VPN site-to-site
- **Keycloak**: Identity Provider

### Maqueta 4: Hardening
- **Ubuntu 22.04**: Sistema endurecido
- **CIS Benchmarks**: Estándares de seguridad
- **Lynis**: Auditoría

## Flujo de Comunicación

\`\`\`
Usuario → Kong (WAF) → Backend APIs
    ↓
  Wazuh (Logs)
    ↑
VPN + IAM (Autenticación)
    ↑
Hardening VM (Monitoreo)
\`\`\`
EOF

cat > docs/configuracion.md << 'EOF'
# Guía de Configuración

## Orden de Configuración

1. Wazuh (SIEM) - Hub central
2. Keycloak (IAM) - Autenticación
3. Kong (WAF) - Protección APIs
4. Hardening VM - Servidor endurecido

## Configuración Detallada

Ver README de cada maqueta.
EOF

echo -e "${GREEN}[✓] Documentación creada${NC}"

# ============================================
# Git initialization
# ============================================
echo -e "${YELLOW}[+] Inicializando Git...${NC}"

git init
git add .
git commit -m "feat: initial project structure"

echo -e "${GREEN}[✓] Git inicializado${NC}"

# ============================================
# Summary
# ============================================
echo ""
echo "================================================"
echo "  ✅ PROYECTO CREADO EXITOSAMENTE"
echo "================================================"
echo ""
echo "Directorio: $(pwd)"
echo "GitHub User: $GITHUB_USER"
echo ""
echo "Estructura creada:"
tree -L 2 -a || ls -la
echo ""
echo "================================================"
echo "  PRÓXIMOS PASOS"
echo "================================================"
echo ""
echo "1. Crear repositorio en GitHub:"
echo "   https://github.com/new"
echo "   Nombre: $PROJECT_NAME"
echo ""
echo "2. Conectar con GitHub:"
echo "   git remote add origin https://github.com/$GITHUB_USER/$PROJECT_NAME.git"
echo "   git branch -M main"
echo "   git push -u origin main"
echo ""
echo "3. Copiar scripts específicos desde tu repo anterior:"
echo "   - SIEM/scripts/install-wazuh.sh"
echo "   - SIEM/scripts/wazuh-agent-install.sh"
echo "   - VPN-IAM/scripts/install-keycloak.sh"
echo "   - etc."
echo ""
echo "4. Reemplazar placeholders en Terraform:"
echo "   - Hardening/terraform/main.tf (usar artifact completo)"
echo "   - Hardening/deploy-aws.sh (usar artifact completo)"
echo "   - Hardening/connect-aws.sh (usar artifact completo)"
echo ""
echo "5. Desplegar en AWS:"
echo "   cd Hardening"
echo "   ./deploy-aws.sh"
echo ""
echo "================================================"
echo ""

# Crear un TODO.md para seguir trabajando
cat > TODO.md << EOF
# TODO - Próximos Pasos

## Estructura completada ✅
- [x] Estructura de carpetas
- [x] .gitignore
- [x] README principal
- [x] Git inicializado

## Pendiente

### 1. Completar archivos Terraform
- [ ] Reemplazar Hardening/terraform/main.tf con contenido del artifact
- [ ] Reemplazar Hardening/deploy-aws.sh con contenido del artifact
- [ ] Reemplazar Hardening/connect-aws.sh con contenido del artifact

### 2. Copiar scripts desde repo anterior
- [ ] SIEM/scripts/install-wazuh.sh
- [ ] SIEM/scripts/wazuh-agent-install.sh
- [ ] SIEM/scripts/wazuh-custom-rules.xml
- [ ] SIEM/scripts/wazuh-fim-config.xml
- [ ] VPN-IAM/scripts/install-keycloak.sh
- [ ] VPN-IAM/scripts/create-realm.sh
- [ ] VPN-IAM/scripts/setup-wireguard.sh

### 3. GitHub
- [ ] Crear repo en GitHub
- [ ] Conectar remoto
- [ ] Push inicial

### 4. AWS Deployment
- [ ] Instalar Terraform
- [ ] Configurar AWS CLI
- [ ] Ejecutar deploy-aws.sh

### 5. Configuración de servicios
- [ ] Wazuh
- [ ] Keycloak
- [ ] Kong/ModSecurity
- [ ] Hardening
EOF

echo -e "${GREEN}[✓] TODO.md creado con próximos pasos${NC}"
echo ""
echo "Consultar: cat TODO.md"
echo ""
EOF

chmod +x init-project.sh

echo -e "${GREEN}[✓] Script de inicialización creado${NC}"