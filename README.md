# Obligatorio: Seguridad en Redes y Datos

**Universidad ORT Uruguay - Grupo N6A**

Infraestructura de seguridad para Fósil Energías Renovables S.A. desplegada en AWS con Terraform.

## Componentes

- SIEM (Wazuh) con 17 reglas custom
- WAF (Kong + ModSecurity) con OWASP CRS
- IAM (Keycloak) con OAuth2/OIDC
- VPN (WireGuard) con políticas granulares por rol
- Hardening (CIS Benchmark L1)

## Arquitectura

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

## Deployment

```bash
# Clonar repo
git clone https://github.com/lr251516/obligatorio-seguridad-aws.git
cd obligatorio-seguridad-aws/terraform

# Desplegar (20-25 min)
terraform init
terraform apply -auto-approve

# Obtener IPs
terraform output
```

## Verificar Deployment

```bash
# Agentes Wazuh (deben ser 4)
export WAZUH_IP=$(terraform output -raw wazuh_public_ip)
ssh -i ~/.ssh/obligatorio-srd ubuntu@$WAZUH_IP "sudo /var/ossec/bin/agent_control -l"
```

## Accesos

**Wazuh Dashboard:**
```
https://<WAZUH_IP>
Usuario: admin
Password: (ver en /root/wazuh-password.txt de la VM)
```

**Keycloak:**
```
http://<VPN_IP>:8080
Usuario: admin
Password: admin
```

## Testing Rápido

**FIM:**
```bash
ssh -i ~/.ssh/obligatorio-srd ubuntu@<HARDENING_IP>
sudo echo "test" >> /etc/passwd
# Ver alerta en Wazuh Dashboard
```

**WAF:**
```bash
curl "http://<WAF_IP>/?id=1' OR '1'='1"
# Debe retornar 403
```

## Documentación por Componente

- [SIEM/README.md](SIEM/README.md) - Reglas custom y casos de uso
- [VPN-IAM/README.md](VPN-IAM/README.md) - WireGuard + Keycloak
- [WAF/README.md](WAF/README.md) - Kong + ModSecurity
- [Hardening/README.md](Hardening/README.md) - CIS Benchmark

## Limpieza

```bash
terraform destroy -auto-approve
```

---

**Autor:** Lucas Rodriguez ([@lr251516](https://github.com/lr251516))
**Universidad ORT Uruguay** - Seguridad en Redes y Datos - Diciembre 2025
