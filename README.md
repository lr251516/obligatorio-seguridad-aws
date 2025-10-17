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
│  ┌────────────────────┐    ┌────────────────────┐     │
│  │   WAF + API GW     │───▶│   SIEM (Wazuh)     │     │
│  │   Kong Gateway     │    │   8GB RAM          │     │
│  │   ModSecurity      │    │   m7i-flex.large   │     │
│  │   10.0.1.10        │    │   10.0.1.20        │     │
│  │   t3.micro (FREE)  │    │   $24/proyecto     │     │
│  └────────────────────┘    └──────────┬─────────┘     │
│           │                           │                │
│           │                           │                │
│  ┌────────▼──────────┐                │                │
│  │   VPN + IAM       │────────────────┘                │
│  │   Keycloak        │                                 │
│  │   WireGuard       │                                 │
│  │   10.0.1.30       │         ┌────────────────────┐ │
│  │   t3.small        │────────▶│   Hardening VM     │ │
│  │   $3.32/proyecto  │   VPN   │   CIS Benchmarks   │ │
│  └───────────────────┘         │   SCA (Wazuh)      │ │
│                                │   10.0.1.40        │ │
│                                │   t3.micro (FREE)  │ │
│                                └────────────────────┘ │
└─────────────────────────────────────────────────────────┘
```

## 💰 Modelo de Costos

**Arquitectura optimizada para Free Tier + Créditos AWS**

| Componente | Tipo Instancia | RAM | Costo/hora | Costo Proyecto* |
|------------|---------------|-----|------------|-----------------|
| WAF/Kong | t3.micro | 1GB | $0 | **GRATIS** |
| Wazuh SIEM | m7i-flex.large | 8GB | $0.15 | $24.00 |
| VPN/IAM | t3.small | 2GB | $0.02 | $3.32 |
| Hardening | t3.micro | 1GB | $0 | **GRATIS** |
| **TOTAL** | | | **$0.17/h** | **$27.32** |

*Proyecto: 160 horas de trabajo (4h/día, 5d/semana, 8 semanas)

**Con créditos de $118.13 disponibles:**
- Costo del proyecto: $27.32
- Créditos restantes: $90.81 (77%)
- **Costo real de bolsillo: $0**

## 🚀 Quick Start

### Prerequisitos

- **AWS Account** con Free Tier activo
- **AWS CLI** configurado con perfil `ort`
- **Terraform** >= 1.0
- **Par de claves SSH** en `~/.ssh/obligatorio-srd`

### Despliegue Rápido
```bash
# 1. Clonar repositorio
git clone https://github.com/lr251516/obligatorio-seguridad-aws.git
cd obligatorio-seguridad-aws/Hardening

# 2. Configurar AWS
export AWS_PROFILE=ort
aws sts get-caller-identity

# 3. Desplegar infraestructura
cd terraform
terraform init
terraform plan
terraform apply

# 4. Guardar IPs
terraform output > ../aws-deployment-info.txt

# 5. Esperar 3-5 minutos que user-data complete
# Ver: cat /tmp/user-data-completed.log en cada VM
```

### Acceso SSH
```bash
# Wazuh SIEM
ssh -i ~/.ssh/obligatorio-srd ubuntu@$(terraform output -raw wazuh_public_ip)

# VPN/IAM
ssh -i ~/.ssh/obligatorio-srd ubuntu@$(terraform output -raw vpn_public_ip)

# WAF/Kong
ssh -i ~/.ssh/obligatorio-srd ubuntu@$(terraform output -raw waf_public_ip)

# Hardening (via VPN después de configurar WireGuard)
ssh -i ~/.ssh/obligatorio-srd ubuntu@10.0.1.40
```

## 📚 Componentes

### 1. WAF + API Gateway (Maqueta 1)
- **Kong Gateway**: API Gateway open-source
- **ModSecurity + OWASP CRS**: Web Application Firewall
- **Protección**: SQL Injection, XSS, RCE, OWASP Top 10
- **Integración**: Logs enviados a Wazuh SIEM

📖 [Ver documentación completa](WAF/README.md)

### 2. SIEM - Wazuh (Maqueta 2)
- **Wazuh Manager**: Motor de análisis de seguridad
- **Wazuh Indexer**: Base de datos de eventos (OpenSearch)
- **Wazuh Dashboard**: Visualización web
- **Casos de Uso Personalizados**: 3 implementados
- **SCA**: Security Configuration Assessment

📖 [Ver documentación completa](SIEM/README.md)

### 3. VPN + IAM (Maqueta 3)
- **WireGuard**: VPN site-to-site moderna y eficiente
- **Keycloak**: Identity Provider (OAuth2/OIDC)
- **Integración**: SSO para todos los servicios
- **Gestión**: Roles, usuarios, clientes OAuth2

📖 [Ver documentación completa](VPN-IAM/README.md)

### 4. Hardening con SCA (Maqueta 4)
- **CIS Benchmarks Level 1**: Ubuntu 22.04
- **Security Configuration Assessment**: Evaluación automática
- **Auditd**: Auditoría del sistema
- **Objetivo**: Score SCA >= 80%

📖 [Ver documentación completa](Hardening/README.md)

## 🎯 Casos de Uso Implementados

### Caso 1: Autenticación Fallida (Brute Force Detection)
**Descripción**: Detectar múltiples intentos de autenticación fallidos que puedan indicar un ataque de fuerza bruta.

**Regla Wazuh**: ID 100001-100003
- 5 intentos fallidos en 5 minutos → Alerta nivel 10
- Desde IP externa (fuera de VPC) → Alerta nivel 12
- Usuario privilegiado (root/admin) → Alerta nivel 12

**Fuente de logs**: 
- `/var/log/auth.log` (SSH)
- Keycloak events
- Kong authentication logs

**MITRE ATT&CK**: T1110 (Brute Force)

### Caso 2: Ataques Web via WAF (OWASP Top 10)
**Descripción**: Detectar y bloquear intentos de explotación de vulnerabilidades web comunes.

**Regla Wazuh**: ID 100010-100014
- SQL Injection → Nivel 10
- XSS (Cross-Site Scripting) → Nivel 10
- RCE (Remote Code Execution) → Nivel 12
- 10 ataques en 2 minutos desde misma IP → Nivel 12

**Fuente de logs**: 
- ModSecurity audit logs
- Kong access logs

**MITRE ATT&CK**: T1190 (Exploit Public-Facing Application)

### Caso 3: Cambios No Autorizados en Configuración (FIM)
**Descripción**: Monitorear cambios en archivos críticos del sistema que puedan indicar compromiso o mala configuración.

**Regla Wazuh**: ID 100020-100024
- `/etc/passwd`, `/etc/shadow` → Nivel 10
- `/etc/sudoers` → Nivel 12
- `/etc/ssh/sshd_config` → Nivel 10
- Reglas de firewall → Nivel 10

**Configuración FIM**:
- Realtime monitoring: Sí
- Report changes: Sí (con diff)
- Frecuencia: 5 minutos

**MITRE ATT&CK**: T1098 (Account Manipulation), T1548.003 (Sudo/Sudo Caching)

## 📊 Estructura del Proyecto
```
obligatorio-seguridad-aws/
├── docs/                      # Documentación general
│   ├── arquitectura.md
│   ├── configuracion.md
│   └── casos-de-uso.md
├── scripts/                   # Scripts comunes
│   ├── setup-base.sh
│   └── connect-aws.sh
├── terraform/                 # Infraestructura como código
│   ├── main.tf               # Recursos AWS
│   ├── variables.tf          # Variables
│   ├── outputs.tf            # Outputs
│   ├── terraform.tfvars      # Configuración
│   └── user-data/            # Scripts de inicialización
│       ├── wazuh-init.sh
│       ├── vpn-init.sh
│       ├── waf-init.sh
│       └── hardening-init.sh
├── SIEM/                     # Maqueta 2: Wazuh
│   ├── README.md
│   └── scripts/
│       ├── install-wazuh.sh
│       ├── wazuh-agent-install.sh
│       ├── wazuh-custom-rules.xml
│       ├── wazuh-fim-config.xml
│       └── wazuh-sca-custom-policy.yml
├── VPN-IAM/                  # Maqueta 3: VPN + Keycloak
│   ├── README.md
│   └── scripts/
│       ├── setup-wireguard.sh
│       ├── install-keycloak.sh
│       └── create-realm.sh
├── WAF/                      # Maqueta 1: Kong + ModSec
│   ├── README.md
│   └── scripts/
│       └── (pendiente implementación)
├── Hardening/                # Maqueta 4: CIS + SCA
│   ├── README.md
│   └── scripts/
│       └── apply-cis-hardening.sh
└── README.md                 # Este archivo
```

## 🔧 Orden de Configuración

**Secuencia recomendada:**

1. **Desplegar infraestructura** (Terraform) ✅
2. **Configurar Wazuh SIEM** (Hub central) → [Guía](SIEM/README.md)
3. **Configurar Keycloak IAM** → [Guía](VPN-IAM/README.md)
4. **Configurar WireGuard VPN** → [Guía](VPN-IAM/README.md)
5. **Configurar Kong/WAF** → [Guía](WAF/README.md)
6. **Aplicar Hardening + SCA** → [Guía](Hardening/README.md)
7. **Instalar agentes Wazuh** en todas las VMs
8. **Configurar casos de uso** personalizados
9. **Testing y documentación**

## 🛡️ Estándares y Compliance

- **CIS Benchmarks**: Ubuntu 22.04 Level 1
- **OWASP Top 10**: Protección via WAF
- **NIST**: Controles de seguridad aplicables
- **MITRE ATT&CK**: Mapeo de casos de uso
- **GDPR**: Consideraciones de privacidad

## 📈 Métricas de Éxito

- ✅ Score SCA >= 80% en VM Hardening
- ✅ 3 casos de uso implementados y documentados
- ✅ Dashboard Wazuh personalizado
- ✅ Detección exitosa de ataques simulados
- ✅ VPN site-to-site funcional
- ✅ SSO funcionando con Keycloak
- ✅ WAF bloqueando OWASP Top 10

## 💾 Gestión de Recursos

### Iniciar Trabajo
```bash
cd terraform

# Las instancias FREE (WAF, Hardening) están siempre ON
# Solo las pagas (Wazuh, VPN/IAM) necesitan gestión

# Iniciar VMs pagas
aws ec2 start-instances \
  --instance-ids $(terraform output -raw wazuh_instance_id) $(terraform output -raw vpn_instance_id) \
  --profile ort

# Esperar que estén running
aws ec2 wait instance-running \
  --instance-ids $(terraform output -raw wazuh_instance_id) $(terraform output -raw vpn_instance_id) \
  --profile ort
```

### Detener Trabajo (IMPORTANTE)
```bash
# Detener VMs pagas para no consumir créditos
aws ec2 stop-instances \
  --instance-ids $(terraform output -raw wazuh_instance_id) $(terraform output -raw vpn_instance_id) \
  --profile ort

# Las VMs FREE siguen corriendo (no hay costo)
```

### Destruir Todo
```bash
cd terraform
terraform destroy
# Usar solo al finalizar completamente el proyecto
```

## 📝 Documentación Adicional

- [Guía de Despliegue AWS](docs/aws-deployment-guide.md)
- [Arquitectura Detallada](docs/arquitectura.md)
- [Configuración de Servicios](docs/configuracion.md)
- [Casos de Uso](docs/casos-de-uso.md)

## 🔗 Referencias

- **Wazuh**: https://documentation.wazuh.com/
- **Terraform AWS**: https://registry.terraform.io/providers/hashicorp/aws/
- **CIS Benchmarks**: https://www.cisecurity.org/cis-benchmarks
- **Kong Gateway**: https://docs.konghq.com/
- **Keycloak**: https://www.keycloak.org/documentation
- **WireGuard**: https://www.wireguard.com/

## 👥 Autores

- **Lucas Rodriguez** - Universidad ORT Uruguay
- **Carrera**: Analista en Infraestructura Informática
- **Materia**: Seguridad en Redes y Datos
- **Grupo**: N6A
- **Fecha**: Diciembre 2025

## 📧 Contacto

- **GitHub**: [@lr251516](https://github.com/lr251516)
- **Repositorio**: https://github.com/lr251516/obligatorio-seguridad-aws

## 📄 Licencia

Proyecto académico - Universidad ORT Uruguay

---

## ⚠️ Notas Importantes

1. **Seguridad**: Este proyecto es para fines académicos. En producción:
   - Usar certificados SSL reales
   - Cambiar todas las contraseñas por defecto
   - Implementar MFA
   - Configurar backups automáticos
   - Usar secretos de AWS Secrets Manager

2. **Costos**: Siempre **detener las VMs pagas** (Wazuh, VPN/IAM) cuando no trabajes para no consumir créditos innecesariamente.

3. **Datos**: Las instancias detenidas conservan todos los datos. Solo se pierde información si ejecutas `terraform destroy`.

4. **Free Tier**: Las instancias t3.micro (WAF, Hardening) pueden correr 24/7 sin costo durante 12 meses.

---

**Estado del Proyecto**: 🟢 Activo - En desarrollo

**Última actualización**: Octubre 2025