# Obligatorio: Seguridad en Redes y Datos
**Universidad ORT Uruguay - Grupo N6A**

## 📋 Descripción

Implementación de infraestructura de seguridad para **Fósil Energías Renovables S.A.**, desplegada completamente en AWS usando Infrastructure as Code (Terraform) con deployment 100% automatizado.

**Componentes implementados:**
- ✅ SIEM (Wazuh) con 17 reglas custom en 4 casos de uso
- ✅ WAF (Kong + ModSecurity) con OWASP CRS + 6 reglas personalizadas
- ✅ IAM (Keycloak) con OAuth2/OIDC y behavioral analytics
- ✅ VPN (WireGuard) site-to-site + remote access con políticas granulares
- ✅ Hardening (CIS Benchmark L1) con SCA automatizado

## 🏗️ Arquitectura

```
┌──────────────────────────────────────────────────────────────┐
│                  AWS VPC (10.0.1.0/24)                       │
├──────────────────────────────────────────────────────────────┤
│                                                              │
│  ┌─────────────────┐         ┌─────────────────┐            │
│  │  Wazuh SIEM     │◀────────│  WAF/Kong       │            │
│  │  10.0.1.20      │  logs   │  10.0.1.10      │            │
│  │  m7i-flex.large │         │  ModSecurity    │            │
│  │  (8GB RAM)      │         │  t3.micro       │            │
│  └────────┬────────┘         └─────────────────┘            │
│           │                                                  │
│           │ agents                                           │
│           ▼                                                  │
│  ┌─────────────────┐         ┌─────────────────┐            │
│  │  VPN/IAM        │◀───VPN──│  Hardening VM   │            │
│  │  10.0.1.30      │         │  10.0.1.40      │            │
│  │  Keycloak       │         │  CIS L1 + FIM   │            │
│  │  WireGuard      │         │  t3.micro       │            │
│  │  c7i-flex.large │         └─────────────────┘            │
│  │  (4GB RAM)      │                                        │
│  └─────────────────┘                                        │
│                                                              │
│  VPN Tunnel: 10.0.0.0/24 (WireGuard overlay network)        │
└──────────────────────────────────────────────────────────────┘
```

## 🚀 Deployment Completo (5 Minutos)

### Prerequisitos

- AWS Account con Free Tier activo
- AWS CLI configurado: `aws configure`
- Terraform >= 1.0: `brew install terraform`
- Par de claves SSH: `ssh-keygen -t rsa -b 4096 -f ~/.ssh/obligatorio-srd`

### Deployment Automatizado

```bash
# 1. Clonar repositorio
git clone https://github.com/lr251516/obligatorio-seguridad-aws.git
cd obligatorio-seguridad-aws/terraform

# 2. Desplegar infraestructura completa
terraform init
terraform apply -auto-approve

# 3. Guardar outputs (IPs públicas)
terraform output > ../deployment-info.txt
```

**Esto despliega automáticamente:**
- ✅ 4 EC2 instances (Wazuh, VPN/IAM, WAF, Hardening)
- ✅ Wazuh Manager + Indexer + Dashboard
- ✅ 4 agentes Wazuh auto-registrados
- ✅ Keycloak 23.0.0 con PostgreSQL
- ✅ Kong Gateway + ModSecurity + OWASP CRS
- ✅ 17 reglas Wazuh custom desplegadas
- ✅ Repositorio clonado en todas las VMs

**Tiempo total:** ~20-25 minutos (instalación de Wazuh tarda más)

## 🔍 Verificación Post-Deployment

### 1. Verificar Servicios (Esperar 25 min)

```bash
# Obtener IPs
cd terraform
export WAZUH_IP=$(terraform output -raw wazuh_public_ip)
export VPN_IP=$(terraform output -raw vpn_public_ip)
export WAF_IP=$(terraform output -raw waf_public_ip)
export HARD_IP=$(terraform output -raw hardening_public_ip)

# Verificar logs de instalación
ssh -i ~/.ssh/obligatorio-srd ubuntu@$WAZUH_IP "cat /tmp/user-data-completed.log"
ssh -i ~/.ssh/obligatorio-srd ubuntu@$VPN_IP "cat /tmp/user-data-completed.log"
ssh -i ~/.ssh/obligatorio-srd ubuntu@$WAF_IP "cat /tmp/user-data-completed.log"
ssh -i ~/.ssh/obligatorio-srd ubuntu@$HARD_IP "cat /tmp/user-data-completed.log"
```

### 2. Verificar Agentes Wazuh

```bash
ssh -i ~/.ssh/obligatorio-srd ubuntu@$WAZUH_IP
sudo /var/ossec/bin/agent_control -l

# Debe mostrar 4 agentes activos:
# - 000: wazuh-siem (server)
# - 001: hardening-vm
# - 002: waf-kong
# - 003: vpn-iam
```

### 3. Acceder a Dashboards

**Wazuh Dashboard:**
```bash
echo "https://$WAZUH_IP"
# Usuario: admin
# Password: cat en /root/wazuh-password.txt
```

**Keycloak Console:**
```bash
echo "http://$VPN_IP:8080"
# Usuario: admin
# Password: admin
```

## 📦 Configuración Post-Deployment

### Solo si necesitas crear realm Keycloak manualmente

**El realm "fosil" debe crearse una vez:**

```bash
ssh -i ~/.ssh/obligatorio-srd ubuntu@$VPN_IP
cd /opt/fosil/VPN-IAM/scripts
chmod +x create-realm.sh
sudo ./create-realm.sh
```

Esto crea:
- Realm "fosil"
- 3 roles: `infraestructura-admin`, `devops`, `viewer`
- 3 usuarios de prueba: jperez@fosil.uy, mgonzalez@fosil.uy, arodriguez@fosil.uy

## 🎯 Casos de Uso SIEM

Todos implementados automáticamente en `/var/ossec/etc/rules/local_rules.xml`:

### Caso 1: Brute Force Detection
- **Reglas:** 100001-100003
- **Detección:** 5 intentos fallidos en 5 minutos (SSH/Keycloak)
- **MITRE:** T1110 (Brute Force)

### Caso 2: Ataques Web OWASP Top 10
- **Reglas:** 100010-100014
- **Detección:** SQL Injection, XSS, RCE, Path Traversal via ModSecurity
- **MITRE:** T1190 (Exploit Public-Facing Application)

### Caso 3: File Integrity Monitoring
- **Reglas:** 100020-100023
- **Archivos:** /etc/passwd, /etc/shadow, /etc/sudoers, SSH config
- **MITRE:** T1098, T1548.003

### Caso 4: IAM Behavioral Analytics
- **Reglas:** 100040-100043
- **Detección:** Brute force Keycloak, login fuera horario, cambios permisos
- **MITRE:** T1078, T1078.004

## 🧪 Testing Rápido

### Test FIM (2 min)
```bash
ssh -i ~/.ssh/obligatorio-srd ubuntu@$HARD_IP
sudo echo "test" >> /etc/passwd
# Ver alerta en Wazuh Dashboard
```

### Test Brute Force (2 min)
```bash
# Desde tu máquina local
for i in {1..6}; do ssh -i ~/.ssh/obligatorio-srd wronguser@$HARD_IP; done
# Ver alerta nivel 10 en Wazuh
```

### Test WAF (2 min)
```bash
curl "http://$WAF_IP/?id=1' OR '1'='1"
# Debe retornar 403 Forbidden
# Ver alerta en Wazuh Dashboard
```

## 📚 Documentación Detallada

- **SIEM:** [SIEM/README.md](SIEM/README.md) - Reglas custom, testing casos de uso
- **VPN/IAM:** [VPN-IAM/README.md](VPN-IAM/README.md) - WireGuard + Keycloak + políticas granulares
- **WAF:** [WAF/README.md](WAF/README.md) - Kong + ModSecurity + reglas custom
- **Hardening:** [Hardening/README.md](Hardening/README.md) - CIS Benchmark L1

## 🔧 Componentes Técnicos

| Componente | Tecnología | VM | IP |
|------------|------------|----|----|
| SIEM | Wazuh 4.13 | m7i-flex.large (8GB) | 10.0.1.20 |
| IAM | Keycloak 23.0.0 | c7i-flex.large (4GB) | 10.0.1.30 |
| WAF | Kong + ModSecurity 3 | t3.micro | 10.0.1.10 |
| Hardening | Ubuntu 22.04 + CIS L1 | t3.micro | 10.0.1.40 |
| VPN | WireGuard | (en VM IAM) | 10.0.0.0/24 |

## 🗑️ Limpieza

```bash
cd terraform
terraform destroy -auto-approve
```

## 👥 Autores

**Universidad ORT Uruguay - Analista en Infraestructura Informática**
- Lucas Rodriguez ([@lr251516](https://github.com/lr251516))
- Materia: Seguridad en Redes y Datos - Grupo N6A
- Diciembre 2025

## ⚠️ Notas de Seguridad

**Proyecto académico.** Para producción implementar:
- Certificados SSL/TLS válidos
- Rotar contraseñas por defecto
- Habilitar MFA en Keycloak
- AWS Secrets Manager para credenciales
- Backups automatizados
- Monitoreo 24/7

---

**Deployment Time:** 25 minutos | **Manual Steps:** 1 (crear realm Keycloak) | **Cost:** AWS Free Tier
