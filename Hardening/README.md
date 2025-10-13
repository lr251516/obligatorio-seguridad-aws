# Maqueta 4: Hardening + Terraform

## Descripción

Esta maqueta contiene:
1. **Infraestructura Terraform**: Despliegue completo en AWS
2. **Scripts de Hardening**: Basados en CIS Benchmark Level 1
3. **Scripts de deployment**: Automatización del despliegue

## Estructura

```
Hardening/
├── terraform/              # Infraestructura AWS
│   ├── main.tf
│   ├── variables.tf
│   ├── outputs.tf
│   ├── terraform.tfvars   # (generado, no commitear)
│   └── user-data/         # Scripts de inicialización EC2
├── scripts/
│   ├── apply-hardening.sh # Script principal de hardening
│   └── modules/           # Módulos CIS específicos
├── deploy-aws.sh          # Deployment automatizado
└── README.md
```

## CIS Benchmark Coverage

El script `apply-hardening.sh` implementa los siguientes controles:

### 1. Filesystem Hardening
- Deshabilita filesystems no utilizados
- Protección contra módulos del kernel maliciosos

### 2. Network Security (Sysctl)
- IP Forwarding controlado (para VPN)
- SYN Cookies (anti-SYN flood)
- Protección contra IP spoofing
- Deshabilitación de ICMP redirects
- Rechazo de source routing
- Log de paquetes sospechosos (martians)
- Hardening de TCP

### 3. Firewall (UFW)
- Política por defecto: deny incoming
- SSH solo desde red interna (10.0.1.0/24)
- WireGuard permitido (51820/UDP)
- Rate limiting en SSH
- Logging habilitado

### 4. Auditoría (auditd)
- Monitoreo de autenticación
- Cambios en usuarios y grupos
- Modificaciones a sudoers
- Cambios en SSH config
- Eventos de red (socket, connect)
- Comandos privilegiados (sudo, su)
- Montajes de filesystems

### 5. SSH Hardening
- Root login deshabilitado
- Solo autenticación por clave pública
- Timeouts configurados
- Máximo 3 intentos de autenticación
- Forwarding deshabilitado
- Criptografía fuerte (Curve25519, AES-GCM, ChaCha20)
- Banner de advertencia

### 6. Fail2Ban
- Protección contra fuerza bruta SSH
- Bantime: 1 hora
- Máximo 3 intentos en 10 minutos

### 7. Password Policies
- Mínimo 12 caracteres
- Requiere mayúsculas, minúsculas, dígitos y símbolos
- Password aging: 90 días máximo
- Mínimo 7 días entre cambios
- Advertencia 14 días antes de expirar

### 8. Services Management
- Deshabilitación de servicios innecesarios:
  - CUPS (impresoras)
  - Avahi (mDNS)
  - Bluetooth

### 9. File Permissions
- `/etc/passwd`: 644
- `/etc/shadow`: 640 (root:shadow)
- `/etc/group`: 644
- `/etc/gshadow`: 640 (root:shadow)
- `/boot/grub/grub.cfg`: 600

### 10. Auditoría con Lynis
- Instalación de Lynis para auditorías continuas
- Target: Score >= 80

## Deployment

### Prerequisitos

```bash
# Verificar herramientas
aws --version
terraform --version

# Configurar AWS profile
export AWS_PROFILE=ort

# Verificar credenciales
aws sts get-caller-identity

# Verificar SSH keys
ls -la ~/.ssh/obligatorio-srd*
```

### Desplegar infraestructura

```bash
cd ~/obligatorio-seguridad-aws/Hardening
chmod +x deploy-aws.sh
./deploy-aws.sh
```

El script:
1. Verifica herramientas necesarias
2. Crea `terraform.tfvars`
3. Ejecuta `terraform init/plan/apply`
4. Guarda información de acceso en `aws-access-info.txt`

### Aplicar Hardening

```bash
# Conectar a la VM (después de configurar VPN)
ssh -i ~/.ssh/obligatorio-srd ubuntu@10.0.1.40

# Copiar script
cd /tmp
wget https://raw.githubusercontent.com/lr251516/obligatorio-seguridad-aws/main/Hardening/scripts/apply-hardening.sh
chmod +x apply-hardening.sh

# Aplicar hardening
sudo ./apply-hardening.sh

# El script guarda log en:
# /opt/fosil/hardening-YYYYMMDD-HHMMSS.log
```

## Auditoría con Lynis

### Ejecutar auditoría completa

```bash
sudo lynis audit system
```

### Ver score

```bash
sudo lynis audit system | grep "Hardening index"
```

### Revisar sugerencias

```bash
sudo lynis audit system --tests-from-group security
```

### Informe detallado

```bash
sudo lynis audit system --report-file /opt/fosil/lynis-report.txt
```

## Verificación

### Comprobar UFW

```bash
# Estado
sudo ufw status verbose

# Ver reglas numeradas
sudo ufw status numbered

# Ver logs
sudo tail -f /var/log/ufw.log
```

### Comprobar auditd

```bash
# Estado del servicio
sudo systemctl status auditd

# Ver eventos recientes
sudo aureport --summary

# Eventos de autenticación
sudo aureport --auth

# Modificaciones de archivos
sudo aureport --file

# Ver logs en tiempo real
sudo tail -f /var/log/audit/audit.log
```

### Comprobar Fail2Ban

```bash
# Estado
sudo fail2ban-client status

# Ver jail de SSH
sudo fail2ban-client status sshd

# IPs baneadas
sudo fail2ban-client get sshd banip
```

### Comprobar SSH

```bash
# Verificar configuración
sudo sshd -T | grep -i "permitroot\|password\|pubkey"

# Test de conexión (debe fallar con password)
ssh -o PreferredAuthentications=password ubuntu@10.0.1.40
```

## Integración con Wazuh

El script de hardening prepara el sistema para ser monitoreado por Wazuh:

```bash
# Instalar agente Wazuh
cd /tmp
wget https://raw.githubusercontent.com/lr251516/obligatorio-seguridad-aws/main/SIEM/scripts/wazuh-agent-install.sh
chmod +x wazuh-agent-install.sh
sudo ./wazuh-agent-install.sh vm-hardening hardening
```

Wazuh monitoreará:
- Logs de autenticación (`/var/log/auth.log`)
- Logs de UFW (`/var/log/ufw.log`)
- Logs de auditd (`/var/log/audit/audit.log`)
- Cambios en archivos críticos (FIM)

## Troubleshooting

### UFW bloqueó mi conexión SSH

```bash
# Desde AWS Console → EC2 → Session Manager (browser-based SSH)
sudo ufw allow from <TU_IP> to any port 22
sudo ufw reload
```

### Auditd consume mucho espacio

```bash
# Ver tamaño de logs
du -sh /var/log/audit/

# Configurar rotación más agresiva
sudo nano /etc/audit/auditd.conf
# Modificar: max_log_file_action = rotate

# Reiniciar
sudo systemctl restart auditd
```

### Lynis score bajo

```bash
# Ver todas las advertencias
sudo lynis audit system --quick | grep -A 5 "Warnings"

# Implementar sugerencias de Lynis
sudo lynis audit system | grep "Suggestion"
```

### Password policy muy estricta

```bash
# Editar para menos restricciones
sudo nano /etc/pam.d/common-password

# Ejemplo: cambiar minlen=12 a minlen=8
```

## Comandos útiles

### Terraform

```bash
# Ver outputs
cd terraform && terraform output

# Ver estado
terraform show

# Refrescar estado
terraform refresh

# Destruir todo
terraform destroy
```

### AWS CLI

```bash
# Listar instancias
aws ec2 describe-instances --profile ort \
  --filters "Name=tag:Project,Values=Obligatorio-SRD" \
  --query 'Reservations[].Instances[].[Tags[?Key==`Name`].Value|[0],State.Name,PublicIpAddress]' \
  --output table

# Stop instancias (conservar datos)
aws ec2 stop-instances --instance-ids i-xxxxx --profile ort

# Start instancias
aws ec2 start-instances --instance-ids i-xxxxx --profile ort
```

### System Info

```bash
# Ver info del sistema
hostnamectl

# Ver recursos
free -h
df -h

# Ver conexiones
ss -tupln

# Ver procesos
ps aux --sort=-%mem | head
```

## Backup y Restore

### Backup de configuración

```bash
# El script crea backups automáticamente en:
ls -la /opt/fosil/backups/

# Backup manual de config importante
sudo tar czf /opt/fosil/backups/config-backup-$(date +%Y%m%d).tar.gz \
  /etc/ssh/sshd_config* \
  /etc/ufw/ \
  /etc/audit/ \
  /etc/fail2ban/
```

### Restore

```bash
# Restaurar un archivo específico
sudo cp /opt/fosil/backups/YYYYMMDD/sshd_config.bak /etc/ssh/sshd_config
sudo systemctl restart sshd
```

## Referencias

- [CIS Ubuntu 22.04 Benchmark](https://www.cisecurity.org/benchmark/ubuntu_linux)
- [Lynis Documentation](https://cisofy.com/documentation/lynis/)
- [UFW Documentation](https://help.ubuntu.com/community/UFW)
- [Auditd Guide](https://linux-audit.com/configuring-and-auditing-linux-systems-with-audit-daemon/)