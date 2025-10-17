# Maqueta 4: Hardening con SCA

## Enfoque

Esta maqueta utiliza **Security Configuration Assessment (SCA)** de Wazuh para evaluar y reportar el nivel de hardening del sistema.

## Componentes

- Ubuntu 22.04 LTS hardened
- CIS Benchmarks Level 1
- Wazuh Agent con SCA habilitado
- Auditoría con auditd
- Firewall UFW
- Fail2ban

## Proceso de Implementación

### 1. Aplicar Hardening CIS
```bash
# SSH a VM4
ssh -i ~/.ssh/obligatorio-srd ubuntu@10.0.1.40

# Descargar y ejecutar script
cd /opt/fosil/scripts
wget https://raw.githubusercontent.com/lr251516/obligatorio-seguridad-aws/main/Hardening/scripts/apply-cis-hardening.sh
chmod +x apply-cis-hardening.sh
sudo ./apply-cis-hardening.sh

# Reiniciar
sudo reboot
```

### 2. Instalar Wazuh Agent con SCA
```bash
# SSH nuevamente
ssh -i ~/.ssh/obligatorio-srd ubuntu@10.0.1.40

# Instalar agente
cd /opt/fosil/scripts
wget https://raw.githubusercontent.com/lr251516/obligatorio-seguridad-aws/main/SIEM/scripts/wazuh-agent-install.sh
chmod +x wazuh-agent-install.sh
sudo ./wazuh-agent-install.sh hardening-vm hardening
```

### 3. Instalar Política SCA Personalizada
```bash
# En el Wazuh Manager (VM2)
ssh -i ~/.ssh/obligatorio-srd ubuntu@10.0.1.20

# Descargar política
cd /var/ossec/etc/shared
sudo wget https://raw.githubusercontent.com/lr251516/obligatorio-seguridad-aws/main/SIEM/scripts/wazuh-sca-custom-policy.yml -O fosil_security_policy.yml
sudo chown wazuh:wazuh fosil_security_policy.yml
sudo chmod 640 fosil_security_policy.yml

# Reiniciar manager
sudo systemctl restart wazuh-manager
```

### 4. Ver Score en Dashboard

1. Acceder a Wazuh Dashboard: `https://<wazuh-ip>`
2. Ir a: **Security Configuration Assessment**
3. Seleccionar agente: **hardening-vm**
4. Ver score y checks fallados

## Score Esperado

- **Sin hardening:** 40-50%
- **Con hardening CIS L1:** 80-85%
- **Con política Fósil:** 85-90%

## Documentar

En el obligatorio, incluir:
- Screenshots del dashboard SCA
- Score antes/después del hardening
- Lista de checks que pasaron/fallaron
- Justificación de checks fallados (si aplica)