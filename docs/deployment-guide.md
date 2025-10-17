# Guía de Despliegue

## Requisitos Previos

1. AWS Account con permisos administrativos
2. Terraform >= 1.0
3. Par de claves SSH: `ssh-keygen -t rsa -b 4096 -f ~/.ssh/obligatorio-srd`
4. Variable `my_ip` configurada en terraform.tfvars con tu IP pública

## Despliegue

```bash
cd terraform
terraform init
terraform apply
```

Los agentes Wazuh se instalan automáticamente via user-data en todas las VMs.

## Instalación Wazuh SIEM

SSH a Wazuh VM y ejecutar instalador oficial:

```bash
ssh -i ~/.ssh/obligatorio-srd ubuntu@<WAZUH_PUBLIC_IP>
cd /tmp
curl -sO https://packages.wazuh.com/4.13/wazuh-install.sh
sudo bash wazuh-install.sh -a 2>&1 | tee wazuh-installation.log

PASSWORD=$(grep "Password:" wazuh-installation.log | tail -1 | awk '{print $2}')
echo "Dashboard: https://$(hostname -I | awk '{print $1}')"
echo "User: admin / Password: $PASSWORD"
```

## Configurar Reglas Personalizadas

```bash
sudo cp /opt/fosil/SIEM/scripts/wazuh-custom-rules.xml /var/ossec/etc/rules/local_rules.xml
sudo chown root:wazuh /var/ossec/etc/rules/local_rules.xml
sudo chmod 640 /var/ossec/etc/rules/local_rules.xml
sudo systemctl restart wazuh-manager
```

## Verificar Agentes

Esperar 3-5 minutos después del terraform apply.

```bash
sudo /var/ossec/bin/agent_control -l
```

Deberías ver:
- **hardening-vm** (ID 001): FIM de archivos críticos del sistema
- **waf-kong** (ID 002): FIM de configuraciones Kong/Nginx
- **vpn-iam** (ID 003): FIM de WireGuard/Keycloak

## Problemas Comunes

### Wazuh: Error de Certificados
**Solución:** Usar instalador oficial `wazuh-install.sh -a`

### Wazuh: XML Inválido
**Solución:** Email alerts van en `ossec.conf`, no en archivos de reglas

### Wazuh: if_matched_sid con múltiples SIDs
**Solución:** Solo acepta un SID único, usar reglas separadas

### SSH Connection Timeout
**Solución:** Verificar Security Group permite tu IP en puerto 22 y variable `my_ip` en terraform.tfvars

### dpkg Lock
**Solución:** User-data ejecutándose, esperar o matar procesos apt

### Postfix Conflict
**Solución:** `sudo apt remove --purge -y postfix`

### Wazuh Agent Failed
**Solución:** Config FIM debe estar dentro de tags `<ossec_config>`

## Testing

### Brute Force Detection
```bash
for i in {1..6}; do ssh -o PreferredAuthentications=password fake@<IP>; done
```
Verificar alertas Rule 100001-100003 en Dashboard

### File Integrity Monitoring
```bash
sudo usermod -aG sudo testuser
sudo vi /etc/sudoers
```
Verificar alertas Rule 100020-100023 con diff de cambios

## Configuraciones FIM

**Hardening VM:** `/etc/passwd`, `/etc/shadow`, `/etc/sudoers`, `/root/.ssh`
**WAF VM:** `/etc/kong`, `/etc/nginx`
**VPN VM:** `/etc/wireguard`, `/opt/keycloak/conf`
