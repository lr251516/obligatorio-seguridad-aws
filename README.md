# Obligatorio: Seguridad en Redes y Datos
---

## 📋 Descripción del Proyecto

Implementación de infraestructura de seguridad para **Fósil Energías Renovables S.A.**, empresa uruguaya del sector energético con más de 50 años de trayectoria. El proyecto está dividido en 4 maquetas independientes pero interconectadas, desplegadas completamente en **AWS Cloud**.

### Contexto de la Empresa

Fósil Energías Renovables es una empresa híbrida que combina:
- **Infraestructura tradicional**: Oleoductos, plantas de almacenamiento y distribución de combustibles
- **Energías renovables**: Parques solares y aerogeneradores
- **Personal**: ~500 colaboradores
- **Infraestructura IT**: Centro de datos en Montevideo + plataformas cloud + soluciones IoT/telemetría

---

## 🏗️ Arquitectura del Sistema

```
┌─────────────────────────────────────────────────────┐
│              AWS Cloud (Free Tier)                  │
│              VPC: 10.0.0.0/16                       │
│              Subnet: 10.0.1.0/24                    │
├─────────────────────────────────────────────────────┤
│                                                     │
│  ┌──────────────┐         ┌──────────────┐          │
│  │  Maqueta 1   │         │  Maqueta 2   │          │
│  │  WAF + Kong  │────────▶│ SIEM Wazuh   │          │
│  │  10.0.1.10   │  Logs   │  10.0.1.20   │          │
│  └──────┬───────┘         └──────┬───────┘          │
│         │                        │                  │
│         │ OAuth2/OIDC            │ Logs             │
│         │                        │                  │
│  ┌──────▼────────┐               │                  │
│  │  Maqueta 3    │───────────────┘                  │
│  │  VPN + IAM    │                                  │
│  │  Keycloak     │                                  │
│  │  10.0.1.30    │                                  │
│  └──────┬────────┘                                  │
│         │                                           │
│         │ WireGuard VPN (10.0.0.0/24)               │
│         │ Site-to-Site                              │
│         │                                           │
│  ┌──────▼────────┐                                  │
│  │  Maqueta 4    │                                  │
│  │  Hardening    │                                  │
│  │  10.0.1.40    │                                  │
│  └───────────────┘                                  │
│                                                     │
└─────────────────────────────────────────────────────┘

```

### Componentes por Maqueta

| Maqueta | IP Privada | IP Pública | Componentes | Función |
|---------|-----------|-----------|-------------|---------|
| **1. WAF** | 10.0.1.10 | Elastic IP | Kong Gateway + ModSecurity + OWASP CRS | Protección de aplicaciones web |
| **2. SIEM** | 10.0.1.20 | Elastic IP | Wazuh Manager + Indexer + Dashboard | Monitoreo centralizado |
| **3. VPN/IAM** | 10.0.1.30 | Elastic IP | WireGuard + Keycloak | VPN site-to-site + gestión de identidades |
| **4. Hardening** | 10.0.1.40 | - | Ubuntu 22.04 hardenizado + Lynis | Servidor endurecido (solo acceso via VPN) |

---

## 🚀 Quick Start

### Prerequisitos

```bash
# Verificar herramientas instaladas
aws --version          # AWS CLI
terraform --version    # Terraform >= 1.0
ssh -V                 # OpenSSH

# Verificar credenciales AWS
export AWS_PROFILE=ort
aws sts get-caller-identity

# Verificar claves SSH
ls -la ~/.ssh/obligatorio-srd*
```

### Despliegue Rápido

```bash
# 1. Clonar repositorio
git clone https://github.com/lr251516/obligatorio-seguridad-aws.git
cd obligatorio-seguridad-aws

# 2. Desplegar infraestructura AWS
export AWS_PROFILE=ort
chmod +x scripts/deploy-aws.sh
./scripts/deploy-aws.sh

# 3. Esperar 5 minutos para user-data scripts
# 4. Seguir la guía de configuración en docs/configuracion.md
```

---

## 📂 Estructura del Proyecto

```
obligatorio-seguridad-aws/
├── terraform/                         # Infraestructura como Código
│   ├── main.tf                        # Recursos principales (VPC, EC2, SG, EIP)
│   ├── variables.tf                   # Variables configurables
│   ├── outputs.tf                     # Outputs (IPs, URLs, SSH commands)
│   ├── terraform.tfvars               # Valores específicos (gitignored)
│   └── user-data/                     # Scripts de inicialización EC2
│       ├── wazuh-init.sh
│       ├── vpn-init.sh
│       ├── waf-init.sh
│       └── hardening-init.sh
│
├── SIEM/                              # Maqueta 2: Wazuh SIEM
│   ├── README.md
│   └── scripts/
│       ├── install-wazuh.sh           # Instalación completa del stack
│       ├── wazuh-agent-install.sh     # Deploy de agentes
│       ├── wazuh-custom-rules.xml     # 3 casos de uso personalizados
│       └── wazuh-fim-config.xml       # File Integrity Monitoring
│
├── VPN-IAM/                           # Maqueta 3: VPN + Identity Management
│   ├── README.md
│   └── scripts/
│       ├── setup-wireguard.sh         # VPN site-to-site
│       ├── install-keycloak.sh        # IAM provider
│       └── create-realm.sh            # Realm de Fósil Energías
│
├── WAF/                               # Maqueta 1: Web Application Firewall
│   ├── README.md
│   └── scripts/
│       ├── install-kong.sh            # Kong + ModSecurity
│       ├── custom-rules.conf          # 6 reglas personalizadas
│       └── integrate-kong-wazuh.sh    # Integración con SIEM
│
├── Hardening/                         # Maqueta 4: Server Hardening
│   ├── README.md
│   └── scripts/
│       └── apply-hardening.sh         # CIS Benchmark Level 1
│
├── docs/                              # Documentación del proyecto
│   ├── arquitectura.md                # Arquitectura detallada
│   └── configuracion.md               # Guía de configuración paso a paso
│
├── scripts/                           # Scripts comunes y de deployment
│   ├── deploy-aws.sh                  # Despliegue automatizado Terraform
│   ├── connect-aws.sh                 # Conexión SSH rápida a VMs
│   └── setup-base.sh                  # Configuración base de EC2
│
├── .gitignore                         # Archivos excluidos (claves, tfvars, etc.)
└── README.md                          # README del proyecto
```

---

## 🔧 Maquetas Implementadas

### Maqueta 1: WAF + API Gateway (Kong)

**Ubicación:** `/WAF/`

**Componentes:**
- Kong Gateway 3.4.1 (API Gateway y reverse proxy)
- ModSecurity 3 (Web Application Firewall)
- OWASP CRS (Core Rule Set)
- 6 reglas personalizadas para Fósil Energías

**Funcionalidades:**
- Protección contra OWASP Top 10
- Bloqueo de endpoints administrativos desde IPs no autorizadas
- Rate limiting en APIs de telemetría
- Detección de credenciales expuestas en URLs
- Bloqueo de User-Agents de herramientas de escaneo
- Validación de formato JSON en APIs de energía
- Integración con Keycloak (OAuth2/OIDC)
- Logs enviados a Wazuh SIEM

**Instalación:**
```bash
cd WAF/scripts
sudo ./install-kong.sh
sudo cp custom-rules.conf /opt/coreruleset/rules/REQUEST-900-CUSTOM-RULES.conf
sudo kong restart
sudo ./integrate-kong-wazuh.sh
```

**URLs:**
- Kong Proxy: `http://10.0.1.10:8000`
- Kong Admin: `http://10.0.1.10:8001`
- ModSecurity Logs: `/var/log/modsec_audit.log`

---

### Maqueta 2: SIEM (Wazuh)

**Ubicación:** `/SIEM/`

**Componentes:**
- Wazuh Manager 4.x (Motor de análisis)
- Wazuh Indexer (OpenSearch)
- Wazuh Dashboard (Visualización web)
- Agentes en todas las VMs

**Casos de Uso Implementados:**

#### Caso 1: Detección de Intentos de Autenticación Fallidos
- **Rule ID:** 100001-100003
- **Threshold:** 5 intentos en 5 minutos
- **Niveles:** 10 (básico), 12 (IP externa o usuario privilegiado)
- **Detección:** Múltiples intentos fallidos vía SSH, login, etc.

#### Caso 2: Detección de Ataques Web via WAF
- **Rule ID:** 100010-100014
- **Detección:** SQL Injection, XSS, RCE, Path Traversal
- **Fuente:** Logs de ModSecurity en Kong
- **Niveles:** 7-12 según severidad

#### Caso 3: Cambios No Autorizados en Configuración
- **Rule ID:** 100020-100024
- **Monitoreo:** `/etc/passwd`, `/etc/sudoers`, `/etc/ssh/sshd_config`, firewall
- **FIM:** Realtime + report_changes
- **Niveles:** 8-12 según criticidad

**Instalación:**
```bash
cd SIEM/scripts
sudo ./install-wazuh.sh
```

**Acceso:**
- Dashboard: `https://<WAZUH_PUBLIC_IP>`
- Usuario: `admin`
- Password: `admin`

---

### Maqueta 3: VPN + IAM (WireGuard + Keycloak)

**Ubicación:** `/VPN-IAM/`

**Componentes:**

#### WireGuard VPN
- VPN site-to-site entre VM3 (servidor) y VM4 (cliente)
- Red del túnel: `10.0.0.0/24`
- VM3 (servidor): `10.0.0.1`
- VM4 (cliente): `10.0.0.2`
- Puerto: `51820/UDP`

#### Keycloak IAM
- Identity Provider con OAuth2/OIDC
- Realm: `fosil-energias`
- 4 roles: admin-sistemas, admin-redes, operador-telemetria, auditor
- 4 usuarios de prueba
- 3 clientes OAuth2: kong-api, wazuh-dashboard, openvpn
- Eventos enviados a Wazuh SIEM

**Instalación:**
```bash
# Keycloak
cd VPN-IAM/scripts
sudo ./install-keycloak.sh
sudo ./create-realm.sh

# WireGuard (en VM3 - servidor)
sudo ./setup-wireguard.sh server

# WireGuard (en VM4 - cliente)
sudo ./setup-wireguard.sh client
```

**Acceso:**
- Keycloak: `http://<VPN_PUBLIC_IP>:8080`
- Usuario: `admin`
- Password: `admin`

---

### Maqueta 4: Hardening (CIS Benchmark)

**Ubicación:** `/Hardening/`

**Componente:**
- Script de hardening basado en CIS Benchmark Level 1 para Ubuntu 22.04

**Módulos Implementados:**

1. **Filesystem Hardening**: Deshabilita filesystems no utilizados
2. **Network Security**: Sysctl hardening (SYN cookies, IP forwarding, anti-spoofing)
3. **Firewall (UFW)**: Deny por defecto, rate limiting SSH
4. **Auditoría (auditd)**: Monitoreo de cambios críticos
5. **SSH Hardening**: Root login disabled, solo claves públicas, criptografía fuerte
6. **Fail2Ban**: Protección contra brute force
7. **Password Policies**: Complejidad mínima, aging
8. **Services Management**: Deshabilitación de servicios innecesarios
9. **File Permissions**: Ajuste de permisos críticos
10. **Lynis**: Instalación para auditorías (target: score >= 80)

**Instalación:**
```bash
cd Hardening/scripts
sudo ./apply-hardening.sh
sudo lynis audit system
```

**Verificación:**
```bash
# UFW
sudo ufw status verbose

# Auditd
sudo aureport --summary

# Fail2Ban
sudo fail2ban-client status

# Lynis score
sudo lynis audit system | grep "Hardening index"
```

---

## 🎯 Casos de Uso - Testing

### Test Caso 1: Autenticación Fallida

```bash
# Generar 5 intentos fallidos
for i in {1..5}; do
  ssh -o PreferredAuthentications=password ubuntu@10.0.1.40
done

# Verificar en Wazuh Dashboard
# Filtrar: rule.id: 100001 OR rule.id: 100002 OR rule.id: 100003
```

### Test Caso 2: Ataques Web

```bash
WAF_IP=<WAF_PUBLIC_IP>

# SQL Injection
curl "$WAF_IP:8000/?id=1' OR '1'='1"

# XSS
curl "$WAF_IP:8000/?q=<script>alert(1)</script>"

# Path Traversal (regla personalizada 900002)
curl "$WAF_IP:8000/../../etc/passwd"

# Admin desde IP no autorizada (regla 900001)
curl "$WAF_IP:8000/admin"

# User-Agent malicioso (regla 900007)
curl -A "sqlmap" "$WAF_IP:8000/"

# Verificar en Wazuh Dashboard
# Filtrar: rule.id: 100010-100014
```

### Test Caso 3: FIM (File Integrity Monitoring)

```bash
# SSH a cualquier VM
ssh -i ~/.ssh/obligatorio-srd ubuntu@<VM_IP>

# Modificar archivo crítico
sudo nano /etc/passwd
# Agregar una línea de comentario y guardar

# Verificar en Wazuh Dashboard en segundos
# Filtrar: rule.id: 100020-100024
```

---

## 📝 Configuración Paso a Paso

### Orden de Configuración (IMPORTANTE)

La configuración debe seguir esta secuencia obligatoria:

1. **Wazuh SIEM** (VM2 - 10.0.1.20) - Hub central de logs
2. **Keycloak IAM** (VM3 - 10.0.1.30) - Autenticación
3. **WireGuard VPN** (VM3 ↔ VM4) - Conectividad
4. **Kong WAF** (VM1 - 10.0.1.10) - Protección de APIs
5. **Hardening** (VM4 - 10.0.1.40) - Endurecimiento

Ver guía detallada en: [`docs/configuracion.md`](docs/configuracion.md)

---

## 🔑 Información de Acceso

### Conexión SSH

```bash
# Script helper para conexión rápida
./scripts/connect-aws.sh <vm>

# Opciones:
./scripts/connect-aws.sh wazuh     # VM2: Wazuh SIEM
./scripts/connect-aws.sh vpn       # VM3: VPN/IAM
./scripts/connect-aws.sh waf       # VM1: WAF/Kong

# VM4 (hardening) solo accesible via VPN:
ssh -i ~/.ssh/obligatorio-srd ubuntu@10.0.1.40
```

### URLs de Servicios

```bash
# Ver todas las URLs después del deployment
cd terraform
terraform output

# URLs principales:
# - Wazuh Dashboard: https://<WAZUH_PUBLIC_IP>
# - Keycloak: http://<VPN_PUBLIC_IP>:8080
# - Kong Proxy: http://<WAF_PUBLIC_IP>:8000
# - Kong Admin: http://<WAF_PUBLIC_IP>:8001
```
---

## 🔒 Seguridad y Cumplimiento

### Standards Implementados

- **OWASP Top 10**: Protección via Kong + ModSecurity
- **CIS Benchmark Level 1**: Ubuntu 22.04 hardening
- **NIST Cybersecurity Framework**: Monitoreo con Wazuh
- **MITRE ATT&CK**: Reglas de detección mapeadas

### Security Groups AWS

| VM | SSH (22) | Servicios | Notas |
|----|---------|-----------|-------|
| Wazuh | Tu IP | 443, 1514 | Dashboard público |
| VPN/IAM | Tu IP | 8080, 51820 | Keycloak público, WG |
| WAF | Tu IP | 8000, 8001, 8443 | Kong público |
| Hardening | Solo VPN | 51820 | Sin acceso público directo |

### Firewall Local (UFW)

Todas las VMs tienen UFW configurado con:
- Deny incoming por defecto
- Allow outgoing por defecto
- SSH solo desde red interna AWS (10.0.1.0/24)
- Rate limiting en SSH
- Logging habilitado

---

## 🛠️ Troubleshooting

### Terraform

```bash
# Ver estado actual
cd terraform
terraform show

# Refrescar outputs
terraform refresh
terraform output

# Recrear recurso específico
terraform taint aws_instance.wazuh
terraform apply

# Destruir y recrear todo
terraform destroy
terraform apply
```

### Wazuh

```bash
# Verificar servicios
sudo systemctl status wazuh-manager
sudo systemctl status wazuh-indexer
sudo systemctl status wazuh-dashboard

# Ver logs
sudo tail -f /var/ossec/logs/ossec.log
sudo tail -f /var/ossec/logs/alerts/alerts.log

# Listar agentes conectados
sudo /var/ossec/bin/agent_control -l
```

### Kong

```bash
# Estado de Kong
sudo kong health

# Ver configuración
curl http://localhost:8001/

# Ver plugins activos
curl http://localhost:8001/plugins

# Logs
sudo tail -f /var/log/kong/error.log
sudo tail -f /var/log/modsec_audit.log
```

### WireGuard

```bash
# Ver estado
sudo wg show

# Logs
sudo journalctl -u wg-quick@wg0 -f

# Reiniciar
sudo systemctl restart wg-quick@wg0

# Test de conectividad
ping 10.0.0.1  # Desde cliente a servidor
ping 10.0.0.2  # Desde servidor a cliente
```

---

## 📚 Documentación Adicional

- **Arquitectura detallada**: [`docs/arquitectura.md`](docs/arquitectura.md)
- **Guía de configuración**: [`docs/configuracion.md`](docs/configuracion.md)
- **Maqueta 1 (WAF)**: [`WAF/README.md`](WAF/README.md)
- **Maqueta 2 (SIEM)**: [`SIEM/README.md`](SIEM/README.md)
- **Maqueta 3 (VPN/IAM)**: [`VPN-IAM/README.md`](VPN-IAM/README.md)
- **Maqueta 4 (Hardening)**: [`Hardening/README.md`](Hardening/README.md)

---

## 👥 Autores

**Universidad ORT Uruguay**  
**Integrantes:** Lucas Rodriguez (lr251516)
**Carrera:** Analista en Infraestructura Informática  
**Materia:** Seguridad en Redes y Datos  
**Fecha de Entrega:** 03/12/2025

---

## 📄 Licencia

Proyecto académico - Universidad ORT Uruguay

---

**Última actualización:** $(date +%Y-%m-%d)

---