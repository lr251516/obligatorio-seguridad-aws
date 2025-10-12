# Obligatorio: Seguridad en Redes y Datos
**Universidad ORT Uruguay - Grupo N6A**

## 📋 Descripción

Implementación de infraestructura de seguridad para Fósil Energías Renovables S.A., dividida en 4 maquetas independientes pero interconectadas, desplegadas en AWS.

## 🏗️ Arquitectura

```
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
```

## 🚀 Quick Start

### Prerequisitos

- AWS CLI configurado
- Terraform >= 1.0
- Par de claves SSH

### Despliegue

```bash
# Clonar repositorio
git clone https://github.com/lr251516/obligatorio-srd-aws.git
cd obligatorio-srd-aws

# Desplegar infraestructura
cd Hardening/terraform
chmod +x ../deploy-aws.sh
../deploy-aws.sh

# Esperar 5 minutos y configurar servicios
```

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

```
obligatorio-srd-aws/
├── docs/                 # Documentación
├── scripts/              # Scripts comunes
├── SIEM/                 # Maqueta 2
├── VPN-IAM/              # Maqueta 3
├── WAF-APIgw/            # Maqueta 1
└── Hardening/            # Maqueta 4 + Terraform
```

## 👥 Autores

- Grupo N6A
- Universidad ORT Uruguay
- Analista en Infraestructura Informática

## 📝 Licencia

Proyecto académico - Universidad ORT Uruguay
