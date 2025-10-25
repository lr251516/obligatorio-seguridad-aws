# Obligatorio: Seguridad en Redes y Datos
**Universidad ORT Uruguay - Grupo N6A**

## 📋 Descripción

Implementación de infraestructura de seguridad para **Fósil Energías Renovables S.A.**, empresa uruguaya del sector energético en proceso de transformación digital hacia energías renovables.

La solución incluye 4 componentes de seguridad críticos desplegados en AWS, utilizando infraestructura como código (Terraform) y siguiendo estándares de la industria (CIS Benchmarks, OWASP Top 10).

## 🏗️ Arquitectura
```
┌─────────────────────────────────────────────────────────┐
│              AWS Cloud (us-east-1)                      │
│              VPC: 10.0.0.0/16                           │
├─────────────────────────────────────────────────────────┤
│                                                         │
│  ┌────────────────────┐    ┌────────────────────┐       │
│  │   WAF + API GW     │───▶│   SIEM (Wazuh)     │       │
│  │   Kong Gateway     │    │   8GB RAM          │       │
│  │   ModSecurity      │    │   m7i-flex.large   │       │
│  │   10.0.1.10        │    │   10.0.1.20        │       │
│  │   t3.micro         │    │                    │       │
│  └────────────────────┘    └──────────┬─────────┘       │
│           │                           │                 │
│           │                           │                 │
│  ┌────────▼──────────┐                │                 │
│  │   VPN + IAM       │────────────────┘                 │
│  │   Keycloak        │                                  │
│  │   WireGuard       │                                  │
│  │   10.0.1.30       │         ┌────────────────────┐   │
│  │   t3.small        │────────▶│   Hardening VM     │   │
│  │                   │   VPN   │   CIS Benchmarks   │   │
│  └───────────────────┘         │   SCA (Wazuh)      │   │
│                                │   10.0.1.40        │   │
│                                │   t3.micro         │   │
│                                └────────────────────┘   │
└─────────────────────────────────────────────────────────┘
```

## 🚀 Quick Start

### Prerequisitos

- **AWS Account** con Free Tier activo
- **AWS CLI** configurado con perfil `ort`
- **Terraform** >= 1.0
- **Par de claves SSH** en `~/.ssh/obligatorio-srd`

### Despliegue
```bash
git clone https://github.com/lr251516/obligatorio-seguridad-aws.git
cd obligatorio-seguridad-aws/terraform

export AWS_PROFILE=ort
terraform init
terraform apply

# Guardar outputs
terraform output > aws-deployment-info.txt
```

### Acceso SSH
```bash
ssh -i ~/.ssh/obligatorio-srd ubuntu@$(terraform output -raw wazuh_public_ip)      # Wazuh
ssh -i ~/.ssh/obligatorio-srd ubuntu@$(terraform output -raw vpn_public_ip)        # VPN/IAM
ssh -i ~/.ssh/obligatorio-srd ubuntu@$(terraform output -raw waf_public_ip)        # WAF
ssh -i ~/.ssh/obligatorio-srd ubuntu@$(terraform output -raw hardening_public_ip)  # Hardening
```

## 📚 Componentes

### 1. WAF + API Gateway → [WAF/README.md](WAF/README.md)
- Kong Gateway con ModSecurity + OWASP CRS
- Protección: SQL Injection, XSS, RCE, OWASP Top 10
- Logs integrados con Wazuh SIEM

### 2. SIEM - Wazuh → [SIEM/README.md](SIEM/README.md)
- Wazuh Manager + Indexer + Dashboard
- 3 casos de uso personalizados
- Security Configuration Assessment (SCA)

### 3. VPN + IAM → [VPN-IAM/README.md](VPN-IAM/README.md)
- WireGuard VPN site-to-site
- Keycloak Identity Provider (OAuth2/OIDC)
- SSO para todos los servicios

### 4. Hardening con SCA → [Hardening/README.md](Hardening/README.md)
- CIS Benchmarks Level 1 para Ubuntu 22.04
- Security Configuration Assessment automático
- Objetivo: Score SCA >= 80%

## 🎯 Casos de Uso Implementados

### Caso 1: Brute Force Detection
Detecta múltiples intentos de autenticación fallidos (SSH, Keycloak, Kong).
- **Reglas Wazuh**: 100001-100003
- **Alertas**: 5 intentos/5min → Nivel 10 | IP externa/root → Nivel 12
- **MITRE**: T1110 (Brute Force)

### Caso 2: Ataques Web (OWASP Top 10)
Detecta y bloquea intentos de explotación web via ModSecurity.
- **Reglas Wazuh**: 100010-100014
- **Alertas**: SQL Injection/XSS → Nivel 10 | RCE/10 ataques → Nivel 12
- **MITRE**: T1190 (Exploit Public-Facing Application)

### Caso 3: File Integrity Monitoring
Monitorea cambios en archivos críticos del sistema.
- **Reglas Wazuh**: 100020-100024
- **Archivos**: `/etc/passwd`, `/etc/shadow`, `/etc/sudoers`, `/etc/ssh/sshd_config`
- **MITRE**: T1098 (Account Manipulation), T1548.003 (Sudo Caching)

## 🔧 Orden de Configuración

1. Desplegar infraestructura (Terraform) - **Los agentes Wazuh se instalan automáticamente via user-data**
2. Configurar Wazuh SIEM (hub central) → [SIEM/README.md](SIEM/README.md)
3. Verificar agentes Wazuh conectados (hardening-vm, waf-kong, vpn-iam)
4. Configurar Keycloak + WireGuard VPN → [VPN-IAM/README.md](VPN-IAM/README.md)
5. Configurar Kong/WAF → [WAF/README.md](WAF/README.md)
6. Aplicar Hardening + SCA → [Hardening/README.md](Hardening/README.md)
7. Testing de casos de uso → [docs/deployment-guide.md](docs/deployment-guide.md)

## 🛡️ Estándares Implementados

- CIS Benchmarks Ubuntu 22.04 Level 1
- OWASP Top 10 (protección WAF)
- MITRE ATT&CK (mapeo casos de uso)

## 📝 Documentación

- [Guía de Despliegue](docs/deployment-guide.md) - Pasos completos, troubleshooting y lecciones aprendidas
- READMEs específicos por componente: [SIEM](SIEM/), [WAF](WAF/), [VPN-IAM](VPN-IAM/), [Hardening](Hardening/)

## 👥 Autores

**Universidad ORT Uruguay - Analista en Infraestructura Informática**
- Lucas Rodriguez ([@lr251516](https://github.com/lr251516))
- Materia: Seguridad en Redes y Datos - Grupo N6A
- Diciembre 2025

## ⚠️ Notas

**Seguridad**: Proyecto académico. Para producción:
- Usar certificados SSL/TLS reales
- Cambiar contraseñas por defecto
- Implementar MFA
- Configurar backups automáticos
- Usar AWS Secrets Manager

**Infraestructura**: Ejecutar `terraform destroy` para eliminar todos los recursos cuando finalice el proyecto.

---

Proyecto académico - Universidad ORT Uruguay