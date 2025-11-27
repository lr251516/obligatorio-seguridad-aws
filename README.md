<div align="center">

# Fósil Energías Renovables
## Infraestructura de Seguridad Empresarial en AWS

[![Infraestructura](https://img.shields.io/badge/IaC-Terraform-623CE4?style=for-the-badge&logo=terraform)]()
[![SIEM](https://img.shields.io/badge/SIEM-Wazuh%204.13-00A4EF?style=for-the-badge)]()
[![WAF](https://img.shields.io/badge/WAF-ModSecurity-orange?style=for-the-badge)]()
[![Región](https://img.shields.io/badge/AWS-us--west--2-FF9900?style=for-the-badge&logo=amazon-aws)]()

**Plataforma de seguridad integral con SIEM, WAF, IAM, VPN y hardening automatizado**

[Inicio Rápido](#-inicio-rápido) • [Arquitectura](#️-arquitectura) • [Características](#-características) • [Documentación](#-documentación)

</div>

---

## Aspectos Destacados

- 🚀 **Deployment 100% Automatizado** - Un único `terraform apply` despliega toda la infraestructura (10-12 min)
- 🛡️ **Defensa en Profundidad** - 5 capas de seguridad: WAF → SIEM → IAM → VPN → Hardening
- 📊 **Mejora Medible de Seguridad** - Score CIS Benchmark: 45% → 65% (+20%)
- 🔍 **17 Reglas de Detección Custom** - Cubren OWASP Top 10, fuerza bruta, integridad de archivos y análisis comportamental
- 🎯 **Cero Pasos Manuales** - Realm Keycloak, agentes Wazuh, servicios Kong auto-configurados

---

## 🚀 Inicio Rápido

```bash
# 1. Clonar y configurar
git clone https://github.com/lr251516/obligatorio-seguridad-aws.git
cd obligatorio-seguridad-aws/terraform

# 2. Configurar credenciales AWS
export AWS_ACCESS_KEY_ID="tu_access_key"
export AWS_SECRET_ACCESS_KEY="tu_secret_key"

# 3. Desplegar (10-12 minutos)
terraform init
terraform apply -auto-approve

# 4. Obtener URLs de acceso
terraform output infrastructure_summary
```

**¡Listo!** Todos los servicios están configurados y listos para usar.

---

## 🏗️ Arquitectura

```
┌─────────────────────────────────────────────────────────────────────┐
│                        AWS VPC 10.0.1.0/24                          │
│                          us-west-2 (Oregon)                         │
├─────────────────────────────────────────────────────────────────────┤
│                                                                     │
│  ┌──────────────────┐         ┌──────────────────┐                  │
│  │  Wazuh SIEM      │◀────────│  WAF/Kong        │◀───── Internet   │
│  │  10.0.1.20       │  agent  │  10.0.1.10       │       (Port 80)  │
│  │  m7i-flex.large  │         │  ModSecurity     │                  │
│  │  (8GB)           │         │  t3.micro        │                  │
│  └────────┬─────────┘         └──────────────────┘                  │
│           │ agents                                                  │
│           ├───────────────────────────┐                             │
│           ▼                           ▼                             │
│  ┌──────────────────┐       ┌──────────────────┐                    │
│  │  VPN/IAM         │       │  Grafana         │◀───── Internet     │
│  │  10.0.1.30       │◀──────│  10.0.1.50       │    (Port 3000)     │
│  │  Keycloak        │ OAuth2│  + Wazuh agent   │                    │
│  │  WireGuard       │       │  t3.micro        │                    │
│  │  c7i-flex (4GB)  │       └──────────────────┘                    │
│  └──────────────────┘                                               │
│           │                                                         │
│           │ agent                                                   │
│           ▼                                                         │
│  ┌──────────────────┐                                               │
│  │  Hardening VM    │                                               │
│  │  10.0.1.40       │                                               │
│  │  CIS L1 (65%)    │                                               │
│  │  t3.micro        │                                               │
│  └──────────────────┘                                               │
│                                                                     │
└─────────────────────────────────────────────────────────────────────┘
         ▲
         │ Túnel IPSec (IKEv2 + PSK)
         │
┌────────┴───────────┐
│  Datacenter Local  │
│  10.100.0.0/24     │
│  (Multipass VM)    │
└────────────────────┘
```

### Flujo de Datos

**Tráfico Entrante (Internet → Servicios Internos)**
1. Request externo → ModSecurity WAF (OWASP CRS + 6 reglas custom)
2. WAF → Kong Gateway (rate limiting, enrutamiento)
3. Kong → Servicios backend
4. Todos los eventos → Wazuh SIEM (17 reglas custom)

**Identidad y Acceso**
- Keycloak OAuth2/OIDC → Dashboards Grafana (acceso basado en roles)
- VPN WireGuard → Acceso granular a la red por rol IAM
- Túnel IPSec → Conectividad segura site-to-site

**Monitoreo y Detección**
- 5 agentes Wazuh → SIEM centralizado
- 4 casos de uso: Fuerza bruta SSH, ataques web, integridad de archivos, analítica IAM
- Alertas en tiempo real sobre eventos de seguridad

---

## 🎯 Características

### 🛡️ Web Application Firewall (WAF)
- **ModSecurity v3** con OWASP Core Rule Set v3.3.5
- **6 reglas personalizadas**: SQL injection, XSS, path traversal, exposición de credenciales, detección de scanners, protección de panel admin
- **Kong Gateway**: Gestión de APIs, rate limiting (20 req/min), enrutamiento de servicios
- **Integración Wazuh**: Todos los ataques bloqueados se registran y analizan en SIEM

[→ Documentación completa WAF](WAF/README.md)

### 🔍 Security Information & Event Management (SIEM)
- **Wazuh 4.13** con gestión centralizada
- **17 reglas de detección personalizadas** en 4 casos de uso:
  1. Fuerza bruta SSH (reglas 100001-100004)
  2. Ataques web - OWASP Top 10 (reglas 100010-100014)
  3. Monitoreo de integridad de archivos (reglas 100020-100023)
  4. Analítica comportamental IAM (reglas 100040-100043)
- **5 agentes**: Monitoreando todos los componentes de infraestructura
- **Mapeo MITRE ATT&CK** para inteligencia de amenazas

[→ Documentación completa SIEM](SIEM/README.md)

### 🔐 Identity & Access Management (IAM)
- **Keycloak 23.0.0** como proveedor de identidad centralizado
- **Integración OAuth2/OIDC** con Grafana
- **3 roles** con permisos granulares:
  - `infraestructura-admin`: Acceso completo VPC → Grafana Admin
  - `devops`: Acceso SIEM + WAF → Grafana Editor
  - `viewer`: Solo lectura SIEM → Grafana Viewer
- **Event logging** para análisis comportamental (reglas Wazuh 100040-100043)

[→ Documentación completa IAM](VPN-IAM/README.md)

### 🌐 Virtual Private Network (VPN)
- **IPSec site-to-site** (strongSwan IKEv2): Datacenter ↔ AWS VPC
- **WireGuard acceso remoto**: Políticas de red basadas en roles
  - Generación automática de configuraciones por usuario (`vpn-config-generator.sh`)
  - Segmentación de red por rol IAM
- **Tunelización segura** con criptografía moderna (ChaCha20, Curve25519)

[→ Documentación completa VPN](VPN-IAM/README.md)

### 🔒 Hardening de Sistemas
- **CIS Benchmark Level 1** para Ubuntu 22.04
- **4 requisitos fundamentales** (según especificaciones del obligatorio):
  1. Firewall local (UFW)
  2. Auditoría del sistema (auditd con 15+ reglas)
  3. Acceso administrativo seguro (hardening SSH + fail2ban)
  4. Integración SIEM (agente Wazuh con FIM)
- **Mejora medible**: Score SCA 45% → 65% (+20%)
- **Script automatizado**: Hardening con un único comando y reinicio automático

[→ Documentación completa Hardening](Hardening/README.md)

### 📊 Monitoreo y Visualización
- **Grafana** con autenticación OAuth2 Keycloak
- **Dashboards basados en roles**: Niveles de acceso Admin, Editor, Viewer
- **Agente Wazuh** monitoreando la propia instancia Grafana
- **Auto-configurado**: Setup de cliente OAuth2 durante el deployment

---

## 📚 Documentación

Cada componente tiene documentación detallada con procedimientos de testing y troubleshooting:

| Componente | Descripción | Link |
|-----------|-------------|------|
| **SIEM** | Configuración Wazuh, reglas custom, casos de uso | [SIEM/README.md](SIEM/README.md) |
| **WAF** | Reglas ModSecurity, Kong Gateway, testing OWASP Top 10 | [WAF/README.md](WAF/README.md) |
| **VPN/IAM** | Setup Keycloak, configuración VPN, integración OAuth2 | [VPN-IAM/README.md](VPN-IAM/README.md) |
| **Hardening** | Script CIS Benchmark, mejora SCA, FIM | [Hardening/README.md](Hardening/README.md) |

---

## 🧪 Testing y Validación

Todos los controles de seguridad han sido validados:

**Protección WAF**
```bash
export WAF_IP=$(terraform output -raw waf_public_ip)

# SQL Injection → 403 Forbidden
curl -i 'http://'"$WAF_IP"'/?id=1%27%20OR%20%271%27=%271'

# Rate limiting → 429 después de 20 requests
for i in {1..25}; do curl -s -o /dev/null -w "%{http_code}\n" http://$WAF_IP/api/telemetria; done
```

**Detección SIEM**
```bash
# SSH brute force → Dispara regla 100004
for i in {1..6}; do ssh -p 2222 wronguser@<HARDENING_IP>; sleep 2; done

# Verificar en Wazuh Dashboard: Threat Hunting → rule.id: 100004
```

**Integración OAuth2**
```bash
# Login Grafana con Keycloak
# http://<GRAFANA_IP>:3000 → "Sign in with Keycloak"
# jperez@fosil.uy / Admin123! → Rol Grafana Admin
```

---

## 🛠️ Stack Tecnológico

**Infraestructura como Código**
- Terraform 1.5+
- AWS (EC2, VPC, Security Groups, Elastic IPs)

**Seguridad**
- Wazuh 4.13 (SIEM)
- ModSecurity v3 + OWASP CRS v3.3.5 (WAF)
- Kong Gateway 3.4 (API Gateway)
- Keycloak 23.0.0 (IAM)
- strongSwan (VPN IPSec)
- WireGuard (VPN acceso remoto)
- fail2ban, auditd, UFW (Hardening)

**Monitoreo**
- Grafana (Dashboards)
- Wazuh SCA (Escaneo de cumplimiento)

**Sistema Operativo**
- Ubuntu 22.04 LTS

---

## 📋 Requisitos del Obligatorio Cumplidos

Este proyecto cumple con todos los requisitos del curso "Seguridad en Redes y Datos" de la Universidad ORT Uruguay:

| Requisito | Implementación | Estado |
|-----------|----------------|--------|
| **1a) VPN Site-to-Site** | IPSec (strongSwan IKEv2) | ✅ |
| **1b) VPN Acceso Remoto + IAM** | WireGuard + roles Keycloak | ✅ |
| **2a) API Gateway** | Kong Gateway 3.4 | ✅ |
| **2b) WAF - OWASP Top 10** | ModSecurity + OWASP CRS | ✅ |
| **2c) 2+ Reglas WAF Custom** | 6 reglas personalizadas | ✅ |
| **2d) Integración WAF → SIEM** | Agente Wazuh monitoreando error.log | ✅ |
| **3a) SIEM** | Wazuh 4.13 | ✅ |
| **3b) 3 Casos de Uso (1 auth)** | 4 casos de uso, 17 reglas custom | ✅ |
| **3c) Integración** | 5 agentes Wazuh | ✅ |
| **4a) IAM OAuth2/OIDC** | Keycloak 23.0.0 | ✅ |
| **4b) Analítica Comportamental** | Reglas 100040-100043 | ✅ |
| **5a) Scripts Hardening** | Script bash CIS L1 | ✅ |
| **5b) CIS Benchmark** | Score SCA 65% | ✅ |
| **5c) Firewall + Auditoría + SSH + SIEM** | UFW + auditd + SSH:2222 + Wazuh | ✅ |

---

## 🗑️ Limpieza

**IMPORTANTE:** Destruir la infraestructura después de usar para evitar cargos AWS:

```bash
cd terraform
terraform destroy -auto-approve
```

Costo estimado si se deja corriendo: ~$50-70/mes (principalmente instancias m7i-flex.large y c7i-flex.large)

---

## 👤 Autor

**Lucas Rodriguez**
- GitHub: [@lr251516](https://github.com/lr251516)
- Email: lucasro01@gmail.com

**Proyecto Académico** \
Universidad ORT Uruguay \
Analista en Infraestructura Informática \
Seguridad en Redes y Datos - Grupo N6A   
2025

---

## 📄 Licencia

Este proyecto es de uso académico. Todo el código se proporciona tal cual para fines educativos.

---