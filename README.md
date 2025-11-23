# Obligatorio: Seguridad en Redes y Datos

**Universidad ORT Uruguay - Analista en Infraestructura Informática**
**Materia:** Seguridad en Redes y Datos - Grupo N6A
**Región AWS:** us-west-2 (Oregon)

Infraestructura de seguridad para **Fósil Energías Renovables S.A.** desplegada en AWS con Terraform.

---

## 🎯 Componentes Implementados

| Componente | Tecnología | Descripción |
|------------|------------|-------------|
| **SIEM** | Wazuh 4.13 | 17 reglas custom + 4 casos de uso |
| **WAF + API Gateway** | Kong 3.4 + ModSecurity + OWASP CRS v3.3.5 | 6 reglas custom |
| **IAM** | Keycloak 23.0.0 | OAuth2/OIDC + 5 roles + behavioral analytics |
| **VPN Site-to-Site** | IPSec (strongSwan IKEv2) | Datacenter ↔ AWS VPC |
| **VPN Remote Access** | WireGuard | Políticas granulares por rol IAM |
| **Hardening** | CIS Benchmark L1 | Script manual 55+ checks (65% SCA score) |

**Estado:** ✅ 100% COMPLETADO - Testing end-to-end funcional

---

## 🏗️ Arquitectura

```
┌────────────────────────────────────────────────────────────────┐
│                     AWS VPC 10.0.1.0/24                        │
│                       us-west-2 (Oregon)                       │
├────────────────────────────────────────────────────────────────┤
│                                                                │
│  ┌──────────────────┐         ┌──────────────────┐            │
│  │  Wazuh SIEM      │◀────────│  WAF/Kong        │◀─── Internet
│  │  10.0.1.20       │  agent  │  10.0.1.10       │    (Port 80)
│  │  m7i-flex.large  │         │  ModSecurity     │            │
│  │  (8GB RAM)       │         │  OWASP CRS       │            │
│  └────────┬─────────┘         │  t3.micro        │            │
│           │                   └──────────────────┘            │
│           │ agents                                            │
│           ▼                                                   │
│  ┌──────────────────┐         ┌──────────────────┐            │
│  │  VPN/IAM         │◀────────│  Hardening VM    │            │
│  │  10.0.1.30       │  agent  │  10.0.1.40       │            │
│  │  Keycloak        │         │  CIS L1 (65%)    │            │
│  │  WireGuard       │         │  SSH port 2222   │            │
│  │  IPSec Endpoint  │         │  t3.micro        │            │
│  │  c7i-flex.large  │         └──────────────────┘            │
│  │  (4GB RAM)       │                                         │
│  └──────────────────┘                                         │
│                                                               │
└────────────────────────────────────────────────────────────────┘
         ▲
         │ IPSec Tunnel (IKEv2 + PSK)
         │
┌────────┴───────────┐
│  Datacenter Local  │
│  10.100.0.0/24     │
│  (Multipass VM)    │
└────────────────────┘
```

---

## 🚀 Deployment Completo

### 1. Clonar repositorio

```bash
git clone https://github.com/lr251516/obligatorio-seguridad-aws.git
cd obligatorio-seguridad-aws
```

### 2. Configurar credenciales AWS

```bash
export AWS_ACCESS_KEY_ID="tu_access_key"
export AWS_SECRET_ACCESS_KEY="tu_secret_key"
export AWS_DEFAULT_REGION="us-west-2"
```

### 3. Desplegar infraestructura

```bash
cd terraform
terraform init
terraform apply -auto-approve
```

**Tiempo:** ~25 minutos (infraestructura + user-data scripts)

### 4. Obtener IPs públicas

```bash
terraform output
```

Guarda estas IPs para los siguientes pasos.

---

## ✅ Verificación Post-Deployment

### Wazuh: 4 agentes conectados

```bash
WAZUH_IP=$(terraform output -raw wazuh_public_ip)
ssh -i ~/.ssh/obligatorio-srd ubuntu@$WAZUH_IP "sudo /var/ossec/bin/agent_control -l"
```

**Esperado:** 4 agentes activos (wazuh-siem, waf-kong, vpn-iam, hardening-vm)

### Keycloak: Verificar realm "fosil"

El realm se crea automáticamente. Verificar:

```bash
VPN_IP=$(terraform output -raw vpn_public_ip)
curl -s http://$VPN_IP:8080/realms/fosil | jq .realm
# Esperado: "fosil"
```

### Kong Gateway: Verificar servicios

Los servicios Kong se configuran automáticamente. Verificar:

```bash
WAF_IP=$(terraform output -raw waf_public_ip)
curl -s http://$WAF_IP:8001/services | jq '.data[].name'
# Esperado: "telemetria-api", "admin-panel", "public-api"
```

---

## 🔐 Accesos

### Wazuh Dashboard

```
URL: https://<WAZUH_IP>
Usuario: admin
Password: (ejecutar en VM: sudo cat /root/wazuh-passwords.txt | grep admin)
```

### Keycloak Admin Console

```
URL: http://<VPN_IP>:8080
Usuario: admin
Password: admin
```

**⚠️ Proyecto académico:** Keycloak configurado en HTTP sin TLS.

---

## 🧪 Testing de Casos de Uso

### Caso 1: SSH Brute Force (Rules 100001, 100004, 100002)

```bash
HARDENING_IP=$(terraform output -raw hardening_public_ip)

# Generar 5 intentos fallidos SSH
for i in {1..5}; do ssh -p 2222 wronguser@$HARDENING_IP; done
```

**Verificar en Wazuh Dashboard:**
- Filtro: `rule.id: (100001 OR 100004 OR 100002)`
- Esperado: Alertas de correlación SSH brute force

### Caso 2: WAF → SIEM Integration (Rules 100010-100014)

```bash
WAF_IP=$(terraform output -raw waf_public_ip)

# SQL Injection
curl "http://$WAF_IP/?id=1' OR '1'='1"

# XSS
curl "http://$WAF_IP/?search=<script>alert(1)</script>"

# Path Traversal
curl "http://$WAF_IP/?file=../../etc/passwd"
```

**Esperado:** Todos devuelven `403 Forbidden`

**Verificar en Wazuh Dashboard:**
- Filtro: `rule.id: (100010 OR 100011 OR 100013)`
- Esperado: Eventos ModSecurity bloqueando ataques

### Caso 3: File Integrity Monitoring (Rules 100020-100023)

```bash
ssh -i ~/.ssh/obligatorio-srd -p 2222 ubuntu@$HARDENING_IP
sudo echo "test_fim:x:9999:9999::/tmp:/bin/false" >> /etc/passwd
```

**Verificar en Wazuh Dashboard:**
- Filtro: `rule.id: 100020`
- Esperado: Alerta inmediata de cambio en `/etc/passwd`

---

## 📚 Documentación Detallada

Cada componente tiene su README específico con instrucciones completas:

- **[SIEM/README.md](SIEM/README.md)** - Reglas custom Wazuh + casos de uso
- **[WAF/README.md](WAF/README.md)** - Kong Gateway + ModSecurity + reglas custom
- **[VPN-IAM/README.md](VPN-IAM/README.md)** - IPSec + WireGuard + Keycloak
- **[Hardening/README.md](Hardening/README.md)** - CIS Benchmark L1 scripts

---

## 🗑️ Limpieza

```bash
cd terraform
terraform destroy -auto-approve
```

**⚠️ IMPORTANTE:** Ejecutar destroy al finalizar para evitar cargos AWS.

---

## 📋 Requisitos del Obligatorio

| Requisito | Estado | Implementación |
|-----------|--------|----------------|
| **1a) VPN Site-to-Site** | ✅ | IPSec (strongSwan IKEv2) - Datacenter ↔ AWS |
| **1b) VPN Remote Access con IAM** | ✅ | WireGuard + Keycloak roles |
| **2a) API Gateway** | ✅ | Kong Gateway 3.4 |
| **2b) WAF OWASP Top 10** | ✅ | ModSecurity + OWASP CRS v3.3.5 |
| **2c) 2+ reglas WAF custom** | ✅ | 6 reglas custom |
| **2d) WAF → SIEM** | ✅ | Logs a Wazuh agent |
| **3a) SIEM** | ✅ | Wazuh 4.13 |
| **3b) 3 casos de uso (1 authn)** | ✅ | 4 casos (17 reglas custom) |
| **3c) Integración VPN/WAF/Hardening** | ✅ | 4 agentes Wazuh |
| **4a) IAM OAuth2/OIDC** | ✅ | Keycloak 23.0.0 |
| **4b) Behavioral analytics** | ✅ | Rules 100040-100043 |
| **5a) Hardening GNU/Linux scripts** | ✅ | CIS L1 bash scripts |
| **5b) CIS Benchmark** | ✅ | 55+ checks (65% SCA) |
| **5c) Firewall + Auditd + SSH + SIEM** | ✅ | UFW + Auditd + SSH 2222 + Wazuh |

---

## 🔧 Notas Técnicas

### Región AWS: us-west-2 (Oregon)

Cambio desde us-east-1 por disponibilidad de instance types:
- `m7i-flex.large` (Wazuh - 8GB RAM requeridos)
- `c7i-flex.large` (VPN/IAM - Keycloak 4GB RAM)

### Limitaciones CIS Hardening

**Score final: 65%** (vs 100% teórico)

**Checks NO implementados (35%):**
- 23 checks requieren **particiones separadas** (/tmp, /var, /home) - imposible sin recrear VM
- 9 checks de **firewall nativo** (iptables/nftables) - conflicto con UFW
- 1 check **bootloader password** - rompe boot automático AWS EC2

**Checks implementados: 55+** (todos los posibles sin limitaciones de infraestructura)

### Deployment 100% Automatizado

- **User-data scripts** instalan y configuran cada VM
- **Sin pasos manuales** - Todo se configura automáticamente
- **Git clone** automático del repositorio en cada VM
- **Wazuh agents** se auto-registran al SIEM
- **Keycloak realm "fosil"** se crea automáticamente
- **Kong Gateway services** se configuran automáticamente

---

## 👤 Autor

**Lucas Rodriguez**
GitHub: [@lr251516](https://github.com/lr251516)
Email: lucasrodriguez@ort.edu.uy

**Universidad ORT Uruguay**
Analista en Infraestructura Informática
Materia: Seguridad en Redes y Datos
Grupo: N6A
Año: 2025

**Repositorio:** https://github.com/lr251516/obligatorio-seguridad-aws
